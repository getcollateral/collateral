// Device-wide TUN mode (macOS + Linux). Instead of the best-effort system SOCKS proxy, this
// captures *all* of the machine's TCP traffic at the IP layer and routes it through the same
// VLESS tunnel - the way a real VPN client works. We don't reinvent the utun stack: we drive
// `tun2socks` (a tiny, pinned, checksum-verified helper) which creates the utun and forwards
// every flow into our existing SOCKS5 client on 127.0.0.1. So the whole protocol path
// (VLESS · WebSocket · TLS · server) is unchanged; TUN is just a new front door.
//
// Safety is the hard part of a VPN, so the design is deliberately conservative:
//   • We never edit the real default route. We add two /1 routes (0.0.0.0/1 + 128.0.0.0/1)
//     bound to the utun. They out-specific the default, so they win - and the kernel deletes
//     them automatically the moment the utun disappears. So if tun2socks dies for ANY reason,
//     the machine's networking heals itself.
//   • A host route for the server's own IP via the real gateway keeps the tunnel's own packets
//     off the utun (otherwise they'd loop forever).
//   • Host routes for the active public DNS servers keep name resolution working directly (DNS
//     is NOT tunnelled: macOS resolves via mDNSResponder, which doesn't follow the utun routes,
//     so forcing DNS through the tunnel needs a local DNS forwarder - a TODO). Fine for the
//     school/office threat model, which mostly blocks by SNI/IP, not DNS.
//   • One admin prompt (a macOS GUI dialog) starts a root "session" script that owns tun2socks
//     and *watches the app's PID*: if the app exits or crashes, the script tears everything
//     down. The app asks it to stop by touching a file - no root needed to turn it off.
//
// Known limits: macOS + Linux, IPv4 only. TCP + UDP both relay through the tunnel (the server has
// a dgram UDP relay). DNS is resolved directly (see above); IPv6 is not captured (v4-only TUN).
//
// Linux uses the same design with different tools: tun2socks creates a `collateral0` tun, routing
// is `ip route` (the same 0/1 + 128/1 split), the one admin prompt is `pkexec` (polkit), public
// DNS upstreams are host-routed direct, and IPv6 is disabled via sysctl (restored on teardown).

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

const TUN_ADDR = "198.18.0.1";        // RFC 2544 benchmarking range - safe, non-routable
const HOME = os.homedir();
const DIR = path.join(HOME, ".collateral");
const BIN_DIR = path.join(DIR, "bin");
const BIN = path.join(BIN_DIR, "tun2socks");
const STOP_FILE = path.join(DIR, "tun.stop");
const READY_FILE = path.join(DIR, "tun.ready");
const OWNER_FILE = path.join(DIR, "tun.owner");
const RESTART_FILE = path.join(DIR, "tun.restart"); // app touches this to relaunch a wedged tun2socks in place
const SESSION_SH = path.join(DIR, "tun-session.sh");
const LOG_FILE = path.join(DIR, "tun.log");
const KS_FILE = path.join(DIR, "killswitch.pf.conf");   // macOS pf anchor rules for the kill switch
const DNS_SCRIPT = fileURLToPath(new URL("./dns.js", import.meta.url)); // forwarder, run as root on :53 (macOS)

const IS_LINUX = process.platform === "linux";
export function supported() { return process.platform === "darwin" || IS_LINUX; }

// e.g. "darwin-arm64". Node's process.arch uses x64/arm64; releases use amd64/arm64.
export function platArch() {
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return `${process.platform}-${arch}`;
}
export function assetName() { return `tun2socks-${platArch()}`; }
export function assetUrl() {
  return `https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/${assetName()}.zip`;
}

// RFC 1918 / link-local / loopback - a DNS server in these ranges is on the LAN and is already
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

// Parse `ip route show default` → "default via 192.168.1.1 dev wlan0 proto dhcp metric 600".
export function parseLinuxDefaultRoute(text) {
  const gateway = (/\bvia\s+(\d+\.\d+\.\d+\.\d+)/.exec(text) || [])[1] || "";
  const iface = (/\bdev\s+(\S+)/.exec(text) || [])[1] || "";
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

// Linux: public resolvers from /etc/resolv.conf (skips the systemd-resolved 127.0.0.53 stub).
export function parseResolvConf(text) {
  const ips = new Set();
  for (const m of (text || "").matchAll(/^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)/gm)) {
    if (!isPrivateIp(m[1])) ips.add(m[1]);
  }
  return [...ips];
}

// Linux fallback: upstreams from `resolvectl status` (only DNS-Server lines, public IPs).
export function parseResolvectl(text) {
  const ips = new Set();
  for (const line of (text || "").split("\n")) {
    if (!/DNS Server/i.test(line)) continue;
    for (const m of line.matchAll(/(\d+\.\d+\.\d+\.\d+)/g)) if (!isPrivateIp(m[1])) ips.add(m[1]);
  }
  return [...ips];
}

// --- Kill switch (fail-closed) rule generation. Pure, so it's unit-testable. ---
// The lockdown blocks ALL egress except: loopback, the tun device, the server's own IP (so the
// tunnel can stay up / reconnect), and DNS. It's independent of the utun, so if tun2socks dies
// nothing leaks - the exact hole the auto-vanishing /1 routes can't cover.

// macOS pf anchor body. `quick` = first-match-wins, so the passes short-circuit before the block.
export function pfKillSwitchRules(serverIp, dnsIps = [], dev = "") {
  return [
    "pass quick on lo0 all",
    dev ? `pass quick on ${dev} all` : null,
    `pass out quick inet proto tcp to ${serverIp}`,
    `pass out quick inet proto udp to ${serverIp}`,
    dnsIps.length ? `pass out quick inet proto { tcp udp } to { ${dnsIps.join(" ")} } port 53` : null,
    "block drop out inet all",
  ].filter(Boolean).join("\n") + "\n";
}

// Linux: a dedicated COLLATERAL_KS chain hooked at the top of OUTPUT (non-destructive, easy to
// remove cleanly). Returns the setup command lines.
export function iptablesKillSwitchSetup(serverIp, dnsIps = [], dev = "") {
  return [
    "iptables -N COLLATERAL_KS 2>/dev/null || iptables -F COLLATERAL_KS",
    "iptables -A COLLATERAL_KS -o lo -j ACCEPT",
    dev ? `iptables -A COLLATERAL_KS -o ${dev} -j ACCEPT` : null,
    `iptables -A COLLATERAL_KS -d ${serverIp} -j ACCEPT`,
    ...dnsIps.map((d) => `iptables -A COLLATERAL_KS -d ${d} -j ACCEPT`),
    "iptables -A COLLATERAL_KS -j DROP",
    "iptables -C OUTPUT -j COLLATERAL_KS 2>/dev/null || iptables -I OUTPUT 1 -j COLLATERAL_KS",
  ].filter(Boolean).join("\n");
}
export function iptablesKillSwitchTeardown() {
  return [
    "iptables -D OUTPUT -j COLLATERAL_KS 2>/dev/null || true",
    "iptables -F COLLATERAL_KS 2>/dev/null || true",
    "iptables -X COLLATERAL_KS 2>/dev/null || true",
  ].join("\n");
}

// --- DNS-through-tunnel (Linux): redirect the machine's port-53 traffic to the local forwarder,
// which relays it over the tunnel. The forwarder's own upstream uses the SOCKS port (not :53), so
// it can never loop back through this rule. (macOS can't redirect locally-originated :53 via pf, so
// it points the system resolver at the forwarder instead - see sessionScript.) Pure, unit-testable.
export function iptablesDnsRedirect(dnsPort) {
  return [
    `iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports ${dnsPort}`,
    `iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports ${dnsPort}`,
  ].join("\n");
}
export function iptablesDnsRedirectTeardown(dnsPort) {
  return [
    `iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports ${dnsPort} 2>/dev/null || true`,
    `iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports ${dnsPort} 2>/dev/null || true`,
  ].join("\n");
}

// Pick a utun index not currently in use (macOS system uses low ones; stay high).
export function firstFreeUtun(ifconfigList, base = 123, limit = 240) {
  const used = new Set((ifconfigList.match(/utun\d+/g) || []).map((n) => Number(n.slice(4))));
  for (let n = base; n <= limit; n++) if (!used.has(n)) return `utun${n}`;
  return `utun${base}`;
}

// Linux: pick a `collateralN` name not already present in `ip link show`.
export function firstFreeTun(ipLinkList, base = 0, limit = 99) {
  const used = new Set((ipLinkList.match(/collateral\d+/g) || []).map((n) => Number(n.slice(10))));
  for (let n = base; n <= limit; n++) if (!used.has(n)) return `collateral${n}`;
  return `collateral${base}`;
}

async function sh(cmd, args) { return (await exec(cmd, args)).stdout; }

export async function defaultGateway() {
  if (IS_LINUX) {
    try { return parseLinuxDefaultRoute(await sh("ip", ["route", "show", "default"])); }
    catch { return { gateway: "", interface: "" }; }
  }
  try { return parseDefaultRoute(await sh("route", ["-n", "get", "default"])); }
  catch { return { gateway: "", interface: "" }; }
}
async function linuxDnsServers() {
  const out = new Set();
  try { for (const ip of parseResolvConf(fs.readFileSync("/etc/resolv.conf", "utf8"))) out.add(ip); } catch {}
  if (out.size === 0) { try { for (const ip of parseResolvectl(await sh("resolvectl", ["status"]))) out.add(ip); } catch {} }
  return [...out];
}
export async function publicDnsServers() {
  if (IS_LINUX) return linuxDnsServers();
  try { return parsePublicDns(await sh("scutil", ["--dns"])); } catch { return []; }
}
async function freeDev() {
  if (IS_LINUX) { try { return firstFreeTun(await sh("ip", ["link", "show"])); } catch { return "collateral0"; } }
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
  if (got !== want) throw new Error(`checksum mismatch (expected ${want.slice(0, 12)}…, got ${got.slice(0, 12)}…). Refusing to run it`);
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
// stop / the app dies / tun2socks dies - and always tears down on the way out (trap on EXIT).
export function sessionScript({ dev, socksPort, serverIp, dnsIps, service, ownerPid, killSwitch = false, dnsTunnel = false, dnsNode = "", dnsScript = "", dnsUpstream = "1.1.1.1" }) {
  // When DNS is tunnelled we must NOT host-route the resolvers direct (that was the leak).
  const dnsAdd = dnsTunnel ? "" : dnsIps.map((d) => `route -n add -host ${d} "$GW" 2>/dev/null || true`).join("\n  ");
  const dnsDel = dnsTunnel ? "" : dnsIps.map((d) => `route -n delete -host ${d} 2>/dev/null || true`).join("\n  ");
  const ksSetup = killSwitch ? `
# kill switch: lock down all egress except loopback, the tun, the server, and DNS.
cat > ${JSON.stringify(KS_FILE)} <<'PFEOF'
${pfKillSwitchRules(serverIp, dnsIps, dev)}PFEOF
KSTOKEN=$(pfctl -E 2>&1 | awk '/Token/{print $3; exit}')
{ cat /etc/pf.conf 2>/dev/null; printf 'anchor "collateral"\\nload anchor "collateral" from "%s"\\n' ${JSON.stringify(KS_FILE)}; } | pfctl -f - 2>/dev/null || true` : "";
  const ksTeardown = killSwitch ? `
  pfctl -a collateral -F all 2>/dev/null || true
  pfctl -f /etc/pf.conf 2>/dev/null || true
  [ -n "\${KSTOKEN:-}" ] && pfctl -X "$KSTOKEN" 2>/dev/null || true
  rm -f ${JSON.stringify(KS_FILE)}` : "";
  // DNS-through-tunnel (macOS): pf can't redirect locally-originated :53, so point the system
  // resolver at a local forwarder on :53 (run as root here) that relays over the SOCKS tunnel. The
  // previous DNS is saved and restored by cleanup(), which runs on stop AND on crash/app-death via
  // the same trap + PID watchdog that heals the routes - so system DNS can never get stuck.
  const useDns = !!(dnsTunnel && dnsScript && service);
  const dnsSetup = useDns ? `
OLD_DNS=$(networksetup -getdnsservers "$SERVICE" 2>/dev/null)
SOCKS_PORT="$SOCKS" DNS_PORT=53 DNS_UPSTREAM=${JSON.stringify(dnsUpstream)} ${JSON.stringify(dnsNode)} ${JSON.stringify(dnsScript)} </dev/null >/dev/null 2>&1 &
DPID=$!
for i in $(seq 1 20); do lsof -nP -iUDP:53 >/dev/null 2>&1 && break; sleep 0.1; done
networksetup -setdnsservers "$SERVICE" 127.0.0.1
dscacheutil -flushcache 2>/dev/null || true; killall -HUP mDNSResponder 2>/dev/null || true` : "";
  const dnsRestore = useDns ? `
  [ -n "\${DPID:-}" ] && kill "$DPID" 2>/dev/null
  if printf '%s' "\${OLD_DNS:-}" | grep -qi "aren't any"; then networksetup -setdnsservers "$SERVICE" "Empty" 2>/dev/null || true
  else networksetup -setdnsservers "$SERVICE" \${OLD_DNS:-Empty} 2>/dev/null || true; fi
  dscacheutil -flushcache 2>/dev/null || true; killall -HUP mDNSResponder 2>/dev/null || true` : "";
  const relaunch = `kill "$TPID" 2>/dev/null
    "$BIN" --device "$DEV" --proxy "socks5://127.0.0.1:$SOCKS" --loglevel warn &
    TPID=$!
    for i in $(seq 1 60); do ifconfig "$DEV" >/dev/null 2>&1 && break; sleep 0.1; done
    ifconfig "$DEV" "$ADDR" "$ADDR" up 2>/dev/null || true
    route -n add -net 0.0.0.0/1 "$ADDR" 2>/dev/null || true
    route -n add -net 128.0.0.0/1 "$ADDR" 2>/dev/null || true`;
  const holdLoop = killSwitch ? `
# kill-switch mode: relaunch tun2socks if it dies OR the app flags it wedged (RESTART file). Stop only
# on request/app-gone - then the trap flushes the firewall and heals the network.
while [ ! -f "$STOP" ] && kill -0 "$OWNER" 2>/dev/null; do
  if [ -f "$RESTART" ] || ! kill -0 "\${TPID:-0}" 2>/dev/null; then
    rm -f "$RESTART"
    ${relaunch}
  fi
  sleep 1
done` : `
# hold until stop/app-gone. On an app-flagged wedge (RESTART file) relaunch tun2socks in place; if it
# dies on its own, exit so the trap heals the network (fail-open).
while [ ! -f "$STOP" ] && kill -0 "$OWNER" 2>/dev/null; do
  if [ -f "$RESTART" ]; then
    rm -f "$RESTART"
    ${relaunch}
  elif ! kill -0 "\${TPID:-0}" 2>/dev/null; then
    break
  fi
  sleep 1
done`;
  return `#!/bin/bash
# Collateral TUN session - runs as root. Self-heals on exit.
set -u
BIN=${JSON.stringify(BIN)}
DEV=${JSON.stringify(dev)}
ADDR=${JSON.stringify(TUN_ADDR)}
SERVER_IP=${JSON.stringify(serverIp)}
OWNER=${JSON.stringify(String(ownerPid))}
STOP=${JSON.stringify(STOP_FILE)}
READY=${JSON.stringify(READY_FILE)}
RESTART=${JSON.stringify(RESTART_FILE)}
SOCKS=${JSON.stringify(String(socksPort))}
SERVICE=${JSON.stringify(service || "")}
rm -f "$STOP" "$READY" "$RESTART"

cleanup() {
  [ -n "\${TPID:-}" ] && kill "$TPID" 2>/dev/null
  route -n delete -host "$SERVER_IP" 2>/dev/null || true
  ${dnsDel || ": no public dns to unroute"}
  [ -n "$SERVICE" ] && networksetup -setv6automatic "$SERVICE" 2>/dev/null || true  # restore IPv6${ksTeardown}${dnsRestore}
  # the /1 routes + the utun itself disappear automatically when tun2socks exits
  rm -f "$STOP" "$READY" "$RESTART"
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
# IPv6: the TUN is v4-only, so disable v6 on the primary service - otherwise v6 traffic bypasses
# the tunnel. cleanup() restores it to automatic. (DNS is host-routed direct, unless the DNS-tunnel
# option is on, in which case the local forwarder set up just below handles it.)
[ -n "$SERVICE" ] && networksetup -setv6off "$SERVICE" 2>/dev/null || true${ksSetup}${dnsSetup}
touch "$READY"
${holdLoop}
`;
}

// The Linux root session script. Same shape as the macOS one, but driven by `ip` instead of
// `route`/`ifconfig`/`networksetup`, and IPv6 toggled via sysctl. Run as root via pkexec.
export function linuxSessionScript({ dev, socksPort, serverIp, dnsIps, ownerPid, killSwitch = false, dnsTunnel = false, dnsPort = 5353 }) {
  // When DNS is tunnelled we must NOT host-route the resolvers direct (that was the leak).
  const dnsAdd = dnsTunnel ? "" : dnsIps.map((d) => `ip route add ${d}/32 via "$GW" dev "$OIF" 2>/dev/null || ip route add ${d}/32 via "$GW" 2>/dev/null || true`).join("\n");
  const dnsDel = dnsTunnel ? "" : dnsIps.map((d) => `ip route del ${d}/32 2>/dev/null || true`).join("\n  ");
  const ksSetup = (killSwitch || dnsTunnel) ? `
# ${[dnsTunnel ? "redirect :53 to the local DNS forwarder" : "", killSwitch ? "kill-switch lockdown" : ""].filter(Boolean).join(" + ")}
${[dnsTunnel ? iptablesDnsRedirect(dnsPort) : "", killSwitch ? iptablesKillSwitchSetup(serverIp, dnsIps, dev) : ""].filter(Boolean).join("\n")}` : "";
  const ksTeardown = (killSwitch || dnsTunnel) ? `
  ${[dnsTunnel ? iptablesDnsRedirectTeardown(dnsPort) : "", killSwitch ? iptablesKillSwitchTeardown() : ""].filter(Boolean).join("\n").split("\n").join("\n  ")}` : "";
  const relaunch = `kill "$TPID" 2>/dev/null
    "$BIN" --device "tun://$DEV" --proxy "socks5://127.0.0.1:$SOCKS" --loglevel warn &
    TPID=$!
    for i in $(seq 1 60); do ip link show "$DEV" >/dev/null 2>&1 && break; sleep 0.1; done
    ip addr add "$ADDR"/32 dev "$DEV" 2>/dev/null || true
    ip link set "$DEV" up 2>/dev/null || true
    ip route add 0.0.0.0/1 dev "$DEV" 2>/dev/null || true
    ip route add 128.0.0.0/1 dev "$DEV" 2>/dev/null || true`;
  const holdLoop = killSwitch ? `
# kill-switch mode: relaunch tun2socks if it dies OR the app flags it wedged (RESTART file). Stop only
# on request/app-gone - then the trap flushes the firewall and heals the network.
while [ ! -f "$STOP" ] && kill -0 "$OWNER" 2>/dev/null; do
  if [ -f "$RESTART" ] || ! kill -0 "\${TPID:-0}" 2>/dev/null; then
    rm -f "$RESTART"
    ${relaunch}
  fi
  sleep 1
done` : `
# hold until stop/app-gone. On an app-flagged wedge (RESTART file) relaunch tun2socks in place; if it
# dies on its own, exit so the trap heals the network (fail-open).
while [ ! -f "$STOP" ] && kill -0 "$OWNER" 2>/dev/null; do
  if [ -f "$RESTART" ]; then
    rm -f "$RESTART"
    ${relaunch}
  elif ! kill -0 "\${TPID:-0}" 2>/dev/null; then
    break
  fi
  sleep 1
done`;
  return `#!/bin/bash
# Collateral TUN session (Linux) - runs as root. Self-heals on exit.
set -u
BIN=${JSON.stringify(BIN)}
DEV=${JSON.stringify(dev)}
ADDR=${JSON.stringify(TUN_ADDR)}
SERVER_IP=${JSON.stringify(serverIp)}
OWNER=${JSON.stringify(String(ownerPid))}
STOP=${JSON.stringify(STOP_FILE)}
READY=${JSON.stringify(READY_FILE)}
RESTART=${JSON.stringify(RESTART_FILE)}
SOCKS=${JSON.stringify(String(socksPort))}
rm -f "$STOP" "$READY" "$RESTART"

# default route BEFORE we add tun routes: gateway + outbound interface
GW=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="via"){print $(i+1);exit}}')
OIF=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
[ -z "$GW" ] && { echo "no default gateway"; exit 22; }
V6WAS=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)

cleanup() {
  [ -n "\${TPID:-}" ] && kill "$TPID" 2>/dev/null
  ip route del "$SERVER_IP"/32 2>/dev/null || true
  ${dnsDel || ": no public dns to unroute"}
  sysctl -w net.ipv6.conf.all.disable_ipv6="$V6WAS" >/dev/null 2>&1 || true${ksTeardown}
  # the /1 routes + the tun device disappear automatically when tun2socks exits
  rm -f "$STOP" "$READY" "$RESTART"
}
trap cleanup EXIT INT TERM

"$BIN" --device "tun://$DEV" --proxy "socks5://127.0.0.1:$SOCKS" --loglevel warn &
TPID=$!

# wait for tun2socks to create the interface
for i in $(seq 1 60); do ip link show "$DEV" >/dev/null 2>&1 && break; sleep 0.1; done
ip link show "$DEV" >/dev/null 2>&1 || { echo "tun device $DEV never appeared"; exit 21; }
ip addr add "$ADDR"/32 dev "$DEV" 2>/dev/null || true
ip link set "$DEV" up || exit 23

ip route add "$SERVER_IP"/32 via "$GW" dev "$OIF" 2>/dev/null || ip route add "$SERVER_IP"/32 via "$GW" 2>/dev/null || true
${dnsAdd || ": no public dns to route"}
ip route add 0.0.0.0/1 dev "$DEV"       # capture everything via the tun...
ip route add 128.0.0.0/1 dev "$DEV"     # ...without touching the real default route
# IPv6 leak guard: v4-only tun, so disable v6 while up (restored in cleanup)
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true${ksSetup}
touch "$READY"
${holdLoop}
`;
}

// AppleScript string-escape (for embedding inside `do shell script "..."`).
const asEsc = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

// Start device-wide TUN. Needs the SOCKS client already listening on `socksPort`. Prompts once
// for admin (GUI). Resolves when the interface is up and routed; rejects with the log tail on
// failure. Reuses the existing tunnel - no server changes.
export async function startTun({ socksPort, serverHost, onLog = () => {}, killSwitch = false, dnsTunnel = false, dnsPort = 5353 }) {
  if (!supported()) throw new Error("Device-wide tunnel is supported on macOS and Linux.");
  await ensureBinary(onLog);
  const serverIp = await resolveServerIp(serverHost);
  const dev = await freeDev();
  const dnsIps = await publicDnsServers();
  fs.mkdirSync(DIR, { recursive: true });
  for (const f of [STOP_FILE, READY_FILE, RESTART_FILE]) { try { fs.unlinkSync(f); } catch {} }
  fs.writeFileSync(OWNER_FILE, String(process.pid));

  onLog("requesting admin access (one prompt)…");
  if (IS_LINUX) {
    fs.writeFileSync(SESSION_SH, linuxSessionScript({ dev, socksPort, serverIp, dnsIps, ownerPid: process.pid, killSwitch, dnsTunnel, dnsPort }));
    // pkexec pops the polkit prompt and runs the session as root; setsid + & detaches it so this
    // call returns immediately and we then wait on the READY flag.
    const inner = `setsid bash '${SESSION_SH}' </dev/null >'${LOG_FILE}' 2>&1 &`;
    try { await exec("pkexec", ["bash", "-c", inner]); }
    catch (e) {
      const m = String((e && e.message) || e);
      if (/not found|ENOENT/i.test(m)) throw new Error("pkexec not found - install polkit, or run the app under sudo");
      throw new Error("admin authorization was cancelled or failed");
    }
  } else {
    const service = await primaryService().catch(() => ""); // for IPv6 leak control (may be "")
    fs.writeFileSync(SESSION_SH, sessionScript({ dev, socksPort, serverIp, dnsIps, service, ownerPid: process.pid, killSwitch, dnsTunnel, dnsNode: process.execPath, dnsScript: DNS_SCRIPT }));
    // No nohup: under `do shell script … with administrator privileges` there's no controlling
    // terminal, so nohup errors ("can't detach from console"). Redirecting all three fds and
    // backgrounding detaches it cleanly; with no tty there's no SIGHUP to survive, and the job
    // is reparented to launchd when the privileged shell returns.
    const shellCmd = `bash '${SESSION_SH}' </dev/null >'${LOG_FILE}' 2>&1 &`;
    await exec("osascript", ["-e", `do shell script "${asEsc(shellCmd)}" with administrator privileges`]);
  }

  // Wait for the session to signal readiness.
  for (let i = 0; i < 150; i++) {
    if (fs.existsSync(READY_FILE)) { onLog(`full tunnel up on ${dev}, all TCP now routes through the server.`); return { dev, serverIp }; }
    await new Promise((r) => setTimeout(r, 100));
  }
  let tail = "";
  try { tail = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").slice(-3).join(" "); } catch {}
  throw new Error("TUN didn't come up" + (tail ? `: ${tail}` : "") + ` (log: ${LOG_FILE})`);
}

// Ask the root session to stop - just touch the stop file (no admin needed). Resolves once the
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

// Ask the root session to relaunch tun2socks in place (no admin re-prompt) - used when the app
// detects the helper wedged: alive but no longer forwarding, so the device is black-holed.
export function requestRestart() { try { fs.writeFileSync(RESTART_FILE, "1"); } catch {} }

// Is a TUN session currently active (e.g. left over from a previous run)?
export async function isActive() {
  if (!fs.existsSync(READY_FILE)) return false;
  try {
    if (IS_LINUX) return /collateral\d+/.test(await sh("ip", ["link", "show"]));
    return /utun\d+/.test(await sh("ifconfig", []));
  } catch { return fs.existsSync(READY_FILE); }
}

// Small CLI for recovery: `node common/tun.js status|down`.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cmd = process.argv[2];
  if (cmd === "down") {
    requestStopSync();
    console.log("Stop requested. If a TUN was active it will tear down within ~1s (kill switch flushed with it).");
    console.log("If a kill switch was ever left on after a hard crash, restore networking with:");
    console.log(IS_LINUX
      ? "  sudo iptables -D OUTPUT -j COLLATERAL_KS; sudo iptables -F COLLATERAL_KS; sudo iptables -X COLLATERAL_KS"
      : "  sudo pfctl -f /etc/pf.conf   (then `sudo pfctl -d` if pf wasn't already on before)");
  }
  else if (cmd === "status") {
    console.log("binary:", fs.existsSync(BIN) ? BIN : "(not downloaded)");
    console.log("ready flag:", fs.existsSync(READY_FILE) ? "present (a session may be active)" : "absent");
    console.log("owner file:", fs.existsSync(OWNER_FILE) ? fs.readFileSync(OWNER_FILE, "utf8") : "(none)");
  } else console.log("usage: node common/tun.js status|down");
}
