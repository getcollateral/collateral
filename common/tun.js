// Device-wide TUN mode (macOS, v1). Instead of the best-effort system SOCKS proxy, this
// captures *all* of the machine's TCP traffic at the IP layer and routes it through the same
// VLESS tunnel — the way a real VPN client works. We don't reinvent the utun stack: we drive
// `tun2socks` (a tiny, pinned, checksum-verified helper) which creates the utun and forwards
// every flow into our existing SOCKS5 client on 127.0.0.1. So the whole protocol path
// (VLESS · WebSocket · TLS · server) is unchanged; TUN is just a new front door.
//
// Safety is the hard part of a VPN, so the design is deliberately conservative:
//   • We never edit the real default route. We add two /1 routes (0.0.0.0/1 + 128.0.0.0/1)
//     bound to the utun. They out-specific the default, so they win — and the kernel deletes
//     them automatically the moment the utun disappears. So if tun2socks dies for ANY reason,
//     the machine's networking heals itself.
//   • A host route for the server's own IP via the real gateway keeps the tunnel's own packets
//     off the utun (otherwise they'd loop forever).
//   • Host routes for the active public DNS servers keep name resolution working directly (DNS
//     is NOT tunnelled: macOS resolves via mDNSResponder, which doesn't follow the utun routes,
//     so forcing DNS through the tunnel needs a local DNS forwarder — a TODO). Fine for the
//     school/office threat model, which mostly blocks by SNI/IP, not DNS.
//   • One admin prompt (a macOS GUI dialog) starts a root "session" script that owns tun2socks
//     and *watches the app's PID*: if the app exits or crashes, the script tears everything
//     down. The app asks it to stop by touching a file — no root needed to turn it off.
//
// Known v1 limits: macOS + IPv4 only. TCP + UDP both relay through the tunnel (the server has a
// dgram UDP relay). DNS is resolved directly (see above); IPv6 is not captured (v4-only TUN).

import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { primaryService } from "./sysproxy.js";

const exec = promisify(execFile);

const TUN2SOCKS_VERSION = "v2.7.0";
// Pinned SHA-256 of each release asset. darwin-arm64 was verified by download; the rest come
// from the GitHub release API. A download that doesn't match its pin is rejected.
const SHA256 = {
  "darwin-arm64": "7c5ebfe2ffb60ecf6e958cc5bbf3e06e74b8b33575ffbb4ba4f6f785a647f1ad",
  "darwin-amd64": "6e654da8bab9ca1645862f0e251a69980e0966680713011feea7b1e5901b2a95",
  "linux-amd64": "a612baa287a3b6de6221f74fd02b442a50888508227ecf51e1288a5ccbb77381",
  "linux-arm64": "3931476c9cfa8fa236d23aeaf36767df0eb27cc11ecaab699faba57744450f49",
};

const TUN_ADDR = "198.18.0.1";        // RFC 2544 benchmarking range — safe, non-routable
const HOME = os.homedir();
const DIR = path.join(HOME, ".collateral");
const BIN_DIR = path.join(DIR, "bin");
const BIN = path.join(BIN_DIR, "tun2socks");
const STOP_FILE = path.join(DIR, "tun.stop");
const READY_FILE = path.join(DIR, "tun.ready");
const OWNER_FILE = path.join(DIR, "tun.owner");
const SESSION_SH = path.join(DIR, "tun-session.sh");
const LOG_FILE = path.join(DIR, "tun.log");

export function supported() { return process.platform === "darwin"; }

// e.g. "darwin-arm64". Node's process.arch uses x64/arm64; releases use amd64/arm64.
export function platArch() {
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return `${process.platform}-${arch}`;
}
export function assetName() { return `tun2socks-${platArch()}`; }
export function assetUrl() {
  return `https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/${assetName()}.zip`;
}

// RFC 1918 / link-local / loopback — a DNS server in these ranges is on the LAN and is already
// reached via the more-specific subnet route, so it must NOT be host-routed to the gateway.
export function isPrivateIp(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || "");
  if (!m) return true; // treat unparseable / IPv6 as "don't touch"
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0;
}

// Parse `route -n get default` → { gateway, interface }.
export function parseDefaultRoute(text) {
  const gateway = (/^\s*gateway:\s*(\S+)/m.exec(text) || [])[1] || "";
  const iface = (/^\s*interface:\s*(\S+)/m.exec(text) || [])[1] || "";
  return { gateway, interface: iface };
}

// Parse `scutil --dns` for the public resolvers to keep reachable (host-routed direct).
export function parsePublicDns(text) {
  const ips = new Set();
  for (const m of text.matchAll(/nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)/g)) {
    if (!isPrivateIp(m[1])) ips.add(m[1]);
  }
  return [...ips];
}

// Pick a utun index not currently in use (macOS system uses low ones; stay high).
export function firstFreeUtun(ifconfigList, base = 123, limit = 240) {
  const used = new Set((ifconfigList.match(/utun\d+/g) || []).map((n) => Number(n.slice(4))));
  for (let n = base; n <= limit; n++) if (!used.has(n)) return `utun${n}`;
  return `utun${base}`;
}

async function sh(cmd, args) { return (await exec(cmd, args)).stdout; }

export async function defaultGateway() {
  try { return parseDefaultRoute(await sh("route", ["-n", "get", "default"])); }
  catch { return { gateway: "", interface: "" }; }
}
export async function publicDnsServers() {
  try { return parsePublicDns(await sh("scutil", ["--dns"])); } catch { return []; }
}
async function freeUtun() {
  try { return firstFreeUtun(await sh("ifconfig", ["-l"])); } catch { return "utun123"; }
}
export async function resolveServerIp(host) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
  const { address } = await dns.lookup(host, { family: 4 });
  return address;
}

// Download + verify + unpack the helper the first time it's needed. Returns the binary path.
export async function ensureBinary(onLog = () => {}) {
  if (fs.existsSync(BIN)) return BIN;
  const key = platArch();
  const want = SHA256[key];
  if (!want) throw new Error(`no pinned tun2socks build for ${key}`);
  fs.mkdirSync(BIN_DIR, { recursive: true });
  onLog(`downloading tun2socks ${TUN2SOCKS_VERSION} (${key})…`);
  const res = await fetch(assetUrl());
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = crypto.createHash("sha256").update(buf).digest("hex");
  if (got !== want) throw new Error(`checksum mismatch (expected ${want.slice(0, 12)}…, got ${got.slice(0, 12)}…) — refusing to run it`);
  const zip = path.join(BIN_DIR, `${assetName()}.zip`);
  fs.writeFileSync(zip, buf);
  onLog("verifying + unpacking…");
  await sh("unzip", ["-o", "-q", zip, "-d", BIN_DIR]);        // macOS/Linux ship unzip
  const extracted = path.join(BIN_DIR, assetName());
  fs.renameSync(extracted, BIN);
  fs.chmodSync(BIN, 0o755);
  try { fs.unlinkSync(zip); } catch {}
  onLog("tun2socks ready.");
  return BIN;
}

// The root session script. It owns tun2socks, applies the routing, then blocks until asked to
// stop / the app dies / tun2socks dies — and always tears down on the way out (trap on EXIT).
export function sessionScript({ dev, socksPort, serverIp, dnsIps, service, ownerPid }) {
  const dnsAdd = dnsIps.map((d) => `route -n add -host ${d} "$GW" 2>/dev/null || true`).join("\n  ");
  const dnsDel = dnsIps.map((d) => `route -n delete -host ${d} 2>/dev/null || true`).join("\n  ");
  return `#!/bin/bash
# Collateral TUN session — runs as root. Self-heals on exit.
set -u
BIN=${JSON.stringify(BIN)}
DEV=${JSON.stringify(dev)}
ADDR=${JSON.stringify(TUN_ADDR)}
SERVER_IP=${JSON.stringify(serverIp)}
OWNER=${JSON.stringify(String(ownerPid))}
STOP=${JSON.stringify(STOP_FILE)}
READY=${JSON.stringify(READY_FILE)}
SOCKS=${JSON.stringify(String(socksPort))}
SERVICE=${JSON.stringify(service || "")}
rm -f "$STOP" "$READY"

cleanup() {
  [ -n "\${TPID:-}" ] && kill "$TPID" 2>/dev/null
  route -n delete -host "$SERVER_IP" 2>/dev/null || true
  ${dnsDel || ": no public dns to unroute"}
  [ -n "$SERVICE" ] && networksetup -setv6automatic "$SERVICE" 2>/dev/null || true  # restore IPv6
  # the /1 routes + the utun itself disappear automatically when tun2socks exits
  rm -f "$STOP" "$READY"
}
trap cleanup EXIT INT TERM

"$BIN" --device "$DEV" --proxy "socks5://127.0.0.1:$SOCKS" --loglevel warn &
TPID=$!

# wait for tun2socks to create the interface
for i in $(seq 1 60); do ifconfig "$DEV" >/dev/null 2>&1 && break; sleep 0.1; done
ifconfig "$DEV" "$ADDR" "$ADDR" up || exit 21
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')
[ -z "$GW" ] && { echo "no default gateway"; exit 22; }

route -n add -host "$SERVER_IP" "$GW"            # tunnel's own packets bypass the utun (no loop)
${dnsAdd || ": no public dns to route"}
route -n add -net 0.0.0.0/1 "$ADDR"              # capture everything else via the utun...
route -n add -net 128.0.0.0/1 "$ADDR"            # ...without ever touching the real default route
# IPv6: the TUN is v4-only, so disable v6 on the primary service — otherwise v6 traffic bypasses
# the tunnel. cleanup() restores it to automatic. (DNS stays direct; tunnelling it needs a local
# forwarder, a separate TODO — macOS mDNSResponder doesn't follow the utun routes.)
[ -n "$SERVICE" ] && networksetup -setv6off "$SERVICE" 2>/dev/null || true
touch "$READY"

# hold until: stop requested, app gone, or tun2socks died — then the trap heals the network
while [ ! -f "$STOP" ] && kill -0 "$OWNER" 2>/dev/null && kill -0 "$TPID" 2>/dev/null; do
  sleep 1
done
`;
}

// AppleScript string-escape (for embedding inside `do shell script "..."`).
const asEsc = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

// Start device-wide TUN. Needs the SOCKS client already listening on `socksPort`. Prompts once
// for admin (GUI). Resolves when the interface is up and routed; rejects with the log tail on
// failure. Reuses the existing tunnel — no server changes.
export async function startTun({ socksPort, serverHost, onLog = () => {} }) {
  if (!supported()) throw new Error("TUN mode is macOS-only in this version.");
  await ensureBinary(onLog);
  const serverIp = await resolveServerIp(serverHost);
  const dev = await freeUtun();
  const dnsIps = await publicDnsServers();
  const service = await primaryService().catch(() => ""); // for IPv6 leak control (may be "")
  fs.mkdirSync(DIR, { recursive: true });
  for (const f of [STOP_FILE, READY_FILE]) { try { fs.unlinkSync(f); } catch {} }
  fs.writeFileSync(OWNER_FILE, String(process.pid));
  fs.writeFileSync(SESSION_SH, sessionScript({ dev, socksPort, serverIp, dnsIps, service, ownerPid: process.pid }));

  onLog("requesting admin access (one prompt)…");
  // No nohup: under `do shell script … with administrator privileges` there's no controlling
  // terminal, so nohup errors ("can't detach from console"). Redirecting all three fds and
  // backgrounding detaches it cleanly; with no tty there's no SIGHUP to survive, and the job
  // is reparented to launchd when the privileged shell returns.
  const shellCmd = `bash '${SESSION_SH}' </dev/null >'${LOG_FILE}' 2>&1 &`;
  await exec("osascript", ["-e", `do shell script "${asEsc(shellCmd)}" with administrator privileges`]);

  // Wait for the session to signal readiness.
  for (let i = 0; i < 150; i++) {
    if (fs.existsSync(READY_FILE)) { onLog(`full tunnel up on ${dev} — all TCP now routes through the server.`); return { dev, serverIp }; }
    await new Promise((r) => setTimeout(r, 100));
  }
  let tail = "";
  try { tail = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").slice(-3).join(" "); } catch {}
  throw new Error("TUN didn't come up" + (tail ? ` — ${tail}` : "") + ` (log: ${LOG_FILE})`);
}

// Ask the root session to stop — just touch the stop file (no admin needed). Resolves once the
// interface is gone (network restored).
export async function stopTun(onLog = () => {}) {
  try { fs.writeFileSync(STOP_FILE, "1"); } catch {}
  onLog("turning off full tunnel…");
  for (let i = 0; i < 100; i++) {
    if (!fs.existsSync(READY_FILE)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false; // didn't confirm; caller may warn
}

// Best-effort synchronous stop for process-exit handlers (can't await there).
export function requestStopSync() { try { fs.writeFileSync(STOP_FILE, "1"); } catch {} }

// Is a TUN session currently active (e.g. left over from a previous run)?
export async function isActive() {
  if (!fs.existsSync(READY_FILE)) return false;
  try { return (await sh("ifconfig", ["-l"])).includes("utun") && /utun\d+/.test(await sh("ifconfig", [])); }
  catch { return fs.existsSync(READY_FILE); }
}

// Small CLI for recovery: `node common/tun.js status|down`.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cmd = process.argv[2];
  if (cmd === "down") { requestStopSync(); console.log("Stop requested. If a TUN was active it will tear down within ~1s."); }
  else if (cmd === "status") {
    console.log("binary:", fs.existsSync(BIN) ? BIN : "(not downloaded)");
    console.log("ready flag:", fs.existsSync(READY_FILE) ? "present (a session may be active)" : "absent");
    console.log("owner file:", fs.existsSync(OWNER_FILE) ? fs.readFileSync(OWNER_FILE, "utf8") : "(none)");
  } else console.log("usage: node common/tun.js status|down");
}
