#!/usr/bin/env node
// Collateral - terminal control panel. Full-screen, centered, single-keypress, no
// browser, no dependencies. Runs in any terminal on any OS.
//
//   node tui.js        (or: npm run tui)
//
// Controls: c connect/disconnect · e connection details · t test · g generate key
//           s server setup · d system proxy · f full tunnel · x share (QR) · i import (QR)
//           m saved machines · k friends · p proxy help · q quit

import readline from "node:readline";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startClient } from "./client.js";
import { startDnsForwarder } from "./common/dns.js";
import { getExitIP } from "./common/probe.js";
import { loadConfig, saveConfig } from "./common/store.js";
import { provisionVps, addKey, removeKey } from "./provision/vps.js";
import { setSocks, socksEnabled, primaryService, supported as sysproxySupported } from "./common/sysproxy.js";
import * as tun from "./common/tun.js";
import { qrToTerminal } from "./common/qr.js";
import { vlessUriFromConfig, parseVlessUri } from "./common/config.js";
import { diagnose } from "./common/doctor.js";
import { scanQrViaCamera, supported as scanSupported } from "./common/qrscan.js";

const VPS_STEPS = [
  ["connect", "Connect to your VM over SSH"],
  ["dns", "Verify your domain points at the VM"], // custom-domain setups only
  ["upload", "Upload the server"],
  ["install", "Install & configure (Node, Caddy, HTTPS)"],
  ["tls", "Issue the HTTPS certificate"],
];


const A = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  amber: "\x1b[38;5;214m", teal: "\x1b[38;5;37m", green: "\x1b[38;5;71m",
  red: "\x1b[38;5;167m", muted: "\x1b[38;5;245m",
};
const HIDE = "\x1b[?25l", SHOW = "\x1b[?25h";
const NOWRAP = "\x1b[?7l", WRAP = "\x1b[?7h";
// Enter/leave a full-screen app view. The load-bearing part beyond 1049 (alt screen)
// is smkx = "\x1b[?1h\x1b=" (DECCKM + application keypad): Terminal.app only engages its
// alternate-screen scroll - which locks our frame in place instead of scrolling the
// buffer - when application-cursor mode is on. This is exactly what htop/vim/less emit.
// 1007h (alternate scroll) covers xterm/VTE/kitty/Windows Terminal; it's a no-op on
// Terminal.app. Ordered per xterm ctlseqs; exit is the exact reverse.
// ...plus mouse tracking. 1003 = any-event (report motion too, so we can HOVER-highlight),
// 1006 = SGR coords. This also hard-locks scroll regardless of the terminal's alt-scroll
// setting. Clicks + moves both reach us on stdin.
const MOUSE_ON = "\x1b[?1003h\x1b[?1006h", MOUSE_OFF = "\x1b[?1006l\x1b[?1003l";
const SCREEN_ON = "\x1b[?1049h" + "\x1b[?1h\x1b=" + "\x1b[?1007h" + MOUSE_ON;
const SCREEN_OFF = MOUSE_OFF + "\x1b[?1007l" + "\x1b[?1l\x1b>" + "\x1b[?1049l";
const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SEP = "\x00sep\x00"; // sentinel: a separator row
const w = (s) => process.stdout.write(s);

// Our own version, for the update check (best-effort; a missing file just disables it).
let PKG_VERSION = "0.0.0";
try { PKG_VERSION = JSON.parse(fs.readFileSync(new URL("./package.json", import.meta.url), "utf8")).version || PKG_VERSION; } catch {}

const savedCfg = loadConfig();
const state = { ...savedCfg, connected: false, reconnecting: false, socksPort: null, exitIP: null, busy: false, busyText: "", view: "main", hover: null, systemProxy: false, tunActive: false, netService: null, msg: savedCfg.workerUrl ? "Ready. Press c to connect, or e to change connection details." : "New here? Press s to set up your server (or e if you already have one), then c to connect." };
let socks = null, spinI = 0, inPrompt = false, renderTimer = null, lastBuilt = null, quitting = false;
let dnsFwd = null;            // the DNS-through-tunnel forwarder, when active
const DNS_PORT = 5353;       // local forwarder port; the tun session redirects :53 here
let healthTimer = null, healthFails = 0, tunFails = 0;
const HEALTH_OK_MS = Number(process.env.COLLATERAL_HEALTH_MS) || 30000; // healthy poll interval (test knob)

const isWsUrl = (s) => /^wss?:\/\/[^\s]+$/i.test(s || "");
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");

// Demo/recording mode. Enter the nil UUID as the access key (with any wss:// endpoint) and the
// panel shows "connected" - and d/f toggle on - while touching NO network at all. It's for clean
// screenshots and screen recordings without exposing a real server. Not a backdoor: it only
// changes what's DISPLAYED; it never opens a socket, proxies, or routes a single packet.
const DEMO_UUID = "00000000-0000-0000-0000-000000000000";
const DEMO_EXIT_IP = "203.0.113.42"; // RFC 5737 documentation range - obviously not a real host
const isDemo = () => state.uuid === DEMO_UUID;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
const visLen = (s) => stripAnsi(s).length;
const ellip = (s, n) => (s.length <= n ? s : s.slice(0, Math.max(1, n - 1)) + "…");
function truncVis(s, n) {
  let out = "", vis = 0, i = 0;
  while (i < s.length && vis < n) {
    if (s[i] === "\x1b") { const m = /^\x1b\[[0-9;]*m/.exec(s.slice(i)); if (m) { out += m[0]; i += m[0].length; continue; } }
    out += s[i]; vis++; i++;
  }
  return out + (vis >= n && vis < visLen(s) ? A.reset : "");
}
const padEndVis = (s, n) => s + " ".repeat(Math.max(0, n - visLen(s)));

// Word-wrap an ANSI-colored string to `width` visible columns, preserving colors and
// re-applying the active color at the start of each wrapped line.
function wrapAnsi(s, width) {
  const lines = [];
  let line = "", vis = 0, active = "", lastSpace = -1;
  const brk = (rest, restVis) => { lines.push(line + A.reset); line = active + rest; vis = restVis; lastSpace = -1; };
  for (let i = 0; i < s.length; ) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;]*m/.exec(s.slice(i));
      if (m) { line += m[0]; active = (m[0] === "\x1b[0m" || m[0] === "\x1b[m") ? "" : active + m[0]; i += m[0].length; continue; }
    }
    const ch = s[i++];
    if (ch === "\n") { brk("", 0); continue; }
    if (vis >= width) {
      if (lastSpace >= 0) { const rest = line.slice(lastSpace + 1); line = line.slice(0, lastSpace); brk(rest, visLen(rest)); }
      else brk("", 0);
    }
    if (ch === " ") lastSpace = line.length;
    line += ch; vis++;
  }
  lines.push(line + A.reset);
  return lines;
}

// A menu cell padded to `width`. The whole cell is the click target; when it's the hovered
// item the entire cell becomes a reverse-video highlight bar, so it's obvious it's clickable.
// No brackets around the key - just the amber key letter, then the label.
function menuCell(s, k, l, width, hlTrim = 0) {
  const styled = `${A.amber}${k}${A.reset}  ${l}`;
  if (k === s.hover) {
    const plain = `${k}  ${stripAnsi(l)}`;
    const hlW = Math.max(plain.length, width - hlTrim); // shorten the bar so it doesn't crowd the border
    return `\x1b[7m${plain}${" ".repeat(Math.max(0, hlW - plain.length))}\x1b[27m` + " ".repeat(Math.max(0, width - hlW));
  }
  return styled + " ".repeat(Math.max(0, width - visLen(styled)));
}

// The brand mark [•] doubles as the status light: filled amber dot = connected, empty
// = idle, spinner = busy. Brackets are the logo's teal.
function markStr(s) {
  const dot = s.busy ? A.amber + SPIN[spinI] + A.reset
    : s.connected ? A.amber + "•" + A.reset : " ";
  return `${A.teal}[${A.reset}${dot}${A.teal}]${A.reset}`;
}

// Build the panel. Returns { lines, zones } where zones are clickable regions:
// { line (index into lines), x0, x1 (0-based content columns), key }.
// The in-app "how to create your VM" walkthrough, one page per screen (view === "guide").
// Covers the Oracle Always-Free path and the generic "any Ubuntu VM" path.
const GUIDE_PAGES = [
  [
    `${A.bold}Create your VM${A.reset}  ${A.dim}the one-time part${A.reset}`, SEP,
    `You need one Linux ${A.bold}Ubuntu${A.reset} VM with a public IP + SSH.`,
    `Two easy paths:`,
    `  ${A.amber}1${A.reset}  ${A.bold}Oracle Cloud Always-Free${A.reset}  ${A.dim}free forever, recommended${A.reset}`,
    `  ${A.amber}2${A.reset}  ${A.bold}Any Ubuntu VM you already have${A.reset}  ${A.dim}VPS / cloud / home${A.reset}`,
    ``,
    `${A.dim}Already have a VM? Space through to the last page.${A.reset}`,
  ],
  [
    `${A.bold}Oracle${A.reset}  ${A.dim}create the free account${A.reset}`, SEP,
    `${A.amber}1.${A.reset} Sign up at ${A.teal}oracle.com/cloud/free${A.reset}`,
    `   ${A.dim}A card verifies you - Always-Free never charges.${A.reset}`,
    `${A.amber}2.${A.reset} Choose your ${A.bold}home region${A.reset} = the one nearest you,`,
    `   for lower latency. ${A.dim}You can't change it later.${A.reset}`,
  ],
  [
    `${A.bold}Oracle${A.reset}  ${A.dim}launch an Ubuntu instance${A.reset}`, SEP,
    `Console: ${A.muted}Menu → Compute → Instances → Create${A.reset}`,
    `  ${A.amber}•${A.reset} Image:  ${A.bold}Canonical Ubuntu${A.reset} ${A.dim}(22.04 or 24.04)${A.reset}`,
    `  ${A.amber}•${A.reset} Shape:  an ${A.bold}Always-Free-eligible${A.reset} one`,
    `     ${A.dim}VM.Standard.A1.Flex (1 OCPU/6GB) or E2.1.Micro${A.reset}`,
  ],
  [
    `${A.bold}Oracle${A.reset}  ${A.dim}key, IP, and ports${A.reset}`, SEP,
    `  ${A.amber}•${A.reset} SSH keys: pick ${A.bold}Generate a key pair${A.reset}, then`,
    `     ${A.bold}download the private key${A.reset} ${A.dim}(save it, e.g. in ~/.ssh/)${A.reset}`,
    `  ${A.amber}•${A.reset} After it boots, copy the ${A.bold}Public IP address${A.reset}`,
    `  ${A.amber}•${A.reset} Open ports: the subnet's ${A.muted}Security List${A.reset} → add`,
    `     Ingress  source ${A.teal}0.0.0.0/0${A.reset}  TCP  ports ${A.teal}80${A.reset} and ${A.teal}443${A.reset}`,
    `     ${A.dim}(the one thing setup can't do for you)${A.reset}`,
  ],
  [
    `${A.bold}Any Ubuntu VM instead${A.reset}`, SEP,
    `Already run a server somewhere? You just need:`,
    `  ${A.amber}•${A.reset} ${A.bold}Ubuntu${A.reset} with a ${A.bold}public IP${A.reset}`,
    `  ${A.amber}•${A.reset} SSH in as a user with ${A.bold}passwordless sudo${A.reset}`,
    `  ${A.amber}•${A.reset} Ports ${A.teal}80${A.reset} + ${A.teal}443${A.reset} open in its firewall / security group`,
    ``,
    `${A.dim}DigitalOcean, AWS, Hetzner, a home box - all fine.${A.reset}`,
  ],
  [
    `${A.bold}You're ready${A.reset}`, SEP,
    `Setup will ask for three things:`,
    `  ${A.teal}public IP${A.reset}   the VM's address`,
    `  ${A.teal}SSH user${A.reset}    ${A.dim}ubuntu on Oracle, or your VM's login${A.reset}`,
    `  ${A.teal}key path${A.reset}    the private key file you saved`,
    ``,
    `Press ${A.amber}enter${A.reset} to start setup now, or ${A.amber}esc${A.reset} to do it later.`,
  ],
];

function buildBox(s) {
  const cols = process.stdout.columns || 80;
  const innerW = Math.max(46, Math.min(72, cols - 4));
  const half = Math.floor(innerW / 2);
  const bar = A.dim + "│" + A.reset;
  const top = A.dim + "╭" + "─".repeat(innerW + 2) + "╮" + A.reset;
  const sep = A.dim + "├" + "─".repeat(innerW + 2) + "┤" + A.reset;
  const bot = A.dim + "╰" + "─".repeat(innerW + 2) + "╯" + A.reset;
  // Reset before the right border so a content color (e.g. the status word, which fills the line
  // exactly to the edge) can't bleed into the space + frame `│`.
  const line = (c) => `${bar} ${padEndVis(truncVis(c, innerW), innerW)}${A.reset} ${bar}`;
  const body = [], zones = [];
  const finish = () => ({
    lines: [top, ...body.map((b) => (b === SEP ? sep : line(b))), bot],
    zones: zones.map((z) => ({ line: z.i + 1, x0: z.x0, x1: z.x1, key: z.key })), // +1 for top border
  });

  const brand = `${markStr(s)} ${A.bold}collateral${A.reset}${A.amber}_${A.reset}`;

  if (s.view === "help") {
    const port = s.socksPort || "<port>";
    body.push(
      `${brand}  ${A.dim}proxy setup${A.reset}`, SEP,
      `Point any app at this SOCKS5 proxy:`,
      `  ${A.teal}host${A.reset} 127.0.0.1    ${A.teal}port${A.reset} ${port}`, ``,
      `${A.muted}Zen/Firefox${A.reset}  Manual proxy → SOCKS v5,`,
      `             tick "Proxy DNS when using SOCKS v5"`,
      `${A.muted}system proxy${A.reset} (d)  flips the macOS system proxy;`,
      `             Apple treats it as best-effort.`,
      `${A.muted}full tunnel${A.reset} (f)  captures the whole device (mac/Linux),`,
      `             TCP + UDP - the real device-wide mode.`,
      `${A.muted}curl${A.reset}         curl --socks5-hostname 127.0.0.1:${port} …`, ``,
      `${A.dim}Your VM reaches every site directly, nothing to${A.reset}`,
      `${A.dim}configure per site.${A.reset}`, SEP,
      `${A.dim}press any key or click to go back${A.reset}`,
    );
    return finish();
  }

  if (s.view === "guide") {
    const i = Math.max(0, Math.min(s.guideStep || 0, GUIDE_PAGES.length - 1));
    const nav = [];
    if (i > 0) nav.push(`${A.amber}b${A.reset}${A.dim} back${A.reset}`);
    nav.push(i < GUIDE_PAGES.length - 1 ? `${A.amber}space${A.reset}${A.dim} next${A.reset}` : `${A.amber}enter${A.reset}${A.dim} start setup${A.reset}`);
    nav.push(`${A.amber}esc${A.reset}${A.dim} exit${A.reset}`);
    body.push(...GUIDE_PAGES[i], SEP, nav.join(`${A.dim}  ·  ${A.reset}`) + `   ${A.muted}${i + 1}/${GUIDE_PAGES.length}${A.reset}`);
    return finish();
  }

  if (s.view === "setup") {
    const icon = (st) => st === "ok" ? A.green + "●" + A.reset
      : st === "fail" ? A.red + "✗" + A.reset
      : st === "run" ? A.amber + SPIN[spinI] + A.reset : A.dim + "○" + A.reset;
    body.push(
      `${brand}  ${A.dim}first-time setup${A.reset}`, SEP,
      ...(s.steps || []).map((st) =>
        `${icon(st.status)}  ${st.status === "pending" ? A.dim + st.label + A.reset : st.label}` +
        (st.note ? `  ${A.dim}${st.note}${A.reset}` : "")),
      SEP, `${A.dim}this can take a minute…${A.reset}`,
    );
    return finish();
  }

  if (s.view === "prompt") {
    const p = s.prompt || { lines: [], value: "", current: "" };
    const avail = innerW - 4;
    let shown = p.value || "";
    if (shown.length > avail) shown = "…" + shown.slice(shown.length - (avail - 1)); // scroll the tail into view
    body.push(
      brand, SEP,
      ...(p.lines || []),
      ``,
      `${A.dim}›${A.reset} ${shown}${A.amber}▏${A.reset}`,
      ``,
      `${A.dim}enter to confirm · esc to cancel${A.reset}`,
    );
    return finish();
  }

  // main view - header: brand + subtitle + right-aligned status word (the [•] mark = state)
  const statusWord = s.busy ? A.amber + s.busyText + A.reset
    : s.connected && s.reconnecting ? A.amber + "reconnecting…" + A.reset
    : s.connected ? A.green + "connected" + A.reset : A.muted + "disconnected" + A.reset;
  const gap = Math.max(1, innerW - visLen(brand) - visLen(statusWord));
  body.push(brand + " ".repeat(gap) + statusWord);
  body.push(`${A.dim}your own private proxy${A.reset}`);
  if (s.updateAvailable) body.push(`${A.amber}update available: ${s.updateAvailable}${A.reset}${A.dim} · npx getcollateral@latest${A.reset}`);

  const row = (label, val) => `${A.muted}${label.padEnd(9)}${A.reset}  ${val}`;
  const none = A.dim + "-" + A.reset;
  const vw = innerW - 13;
  body.push(SEP,
    row("proxy", s.connected ? `${A.teal}socks5${A.reset}  127.0.0.1:${s.socksPort}` : none),
    row("server", s.workerUrl ? ellip(s.workerUrl, vw) : A.dim + "(not set, press e)" + A.reset),
    row("key", s.uuid ? ellip(s.uuid, vw) : A.dim + "(not set, press e or g)" + A.reset),
    row("exit ip", s.exitIP ? A.teal + s.exitIP + A.reset : none),
    row("transport", `${A.dim}VLESS · WebSocket · TLS · :443${A.reset}`),
    ...(s.connected ? [
      row("traffic", `${A.green}↓${A.reset} ${fmtRate(s.downRate)}   ${A.teal}↑${A.reset} ${fmtRate(s.upRate)}   ${A.dim}${fmtBytes(s.totalBytes)}${A.reset}`),
      row("ping", s.latency != null ? `${latColor(s.latency)}${s.latency} ms${A.reset}  ${latBar(s.latency)}` : `${A.dim}measuring…${A.reset}`),
    ] : []),
    ...(s.tunActive && s.tunKillSwitch ? [row("lockdown", `${A.amber}armed${A.reset} ${A.dim}- kill switch blocks traffic if the tunnel drops${A.reset}`)] : []),
    ...(s.tunActive && s.tunDns ? [row("dns", `${A.teal}tunnelled${A.reset} ${A.dim}- no plaintext DNS leak${A.reset}`)] : []),
    SEP,
  );

  const dw = s.systemProxy ? `${A.green}on${A.reset}` : `${A.muted}off${A.reset}`;
  const tw = s.tunActive ? `${A.green}on${A.reset}` : `${A.muted}off${A.reset}`;
  const menu = [
    [["s", `${A.bold}first-time setup${A.reset}`], ["c", s.connected ? "disconnect" : "connect"]],
    [["e", "connection details"], ["t", "test connection"]],
    [["g", "generate new key"], ["x", "share config (QR)"]],
    [["d", `system proxy: ${dw}`], ["f", `full tunnel: ${tw}`]],
    [["m", "saved machines"], ["k", "friends"]],
    [["p", "proxy setup help"], ["q", "quit"]],
  ];
  for (const [l, r] of menu) {
    const i = body.length;
    // Right-column bars are trimmed one char so they don't crowd the border.
    body.push(r ? menuCell(s, l[0], l[1], half, 1) + menuCell(s, r[0], r[1], innerW - half, 1)
                : menuCell(s, l[0], l[1], innerW, 1));
    zones.push({ i, x0: 0, x1: r ? half : innerW, key: l[0] });
    if (r) zones.push({ i, x0: half, x1: innerW, key: r[0] });
  }
  const all = wrapAnsi(s.msg || "", innerW - 2);
  const msgLines = all.slice(0, 4);
  if (all.length > 4) msgLines[3] = truncVis(msgLines[3], innerW - 3) + "…";
  body.push(SEP, ...msgLines.map((l, i) => (i === 0 ? `${A.dim}›${A.reset} ` : "  ") + l));
  return finish();
}

export function renderFrame(s) { return buildBox(s).lines.join("\n"); }

// Human-readable formatting for the live stats rows. Pure, so they're unit-testable.
export function fmtBytes(n) {
  n = n || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i === 0 ? Math.round(n) : n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}
function fmtRate(bps) { return fmtBytes(bps) + "/s"; }
function latColor(ms) { return ms == null ? A.dim : ms < 90 ? A.green : ms < 180 ? A.amber : A.red; }
// Signal level 0-4: more bars = lower latency (null = no reading yet).
export function latLevel(ms) { return ms == null ? 0 : ms < 40 ? 4 : ms < 90 ? 3 : ms < 180 ? 2 : 1; }
// A 4-glyph signal bar: more bars + greener = lower latency.
function latBar(ms) {
  const lvl = latLevel(ms);
  const col = lvl >= 3 ? A.green : lvl === 2 ? A.amber : A.red;
  const g = "▁▃▅▇";
  let out = "";
  for (let i = 0; i < 4; i++) out += (i < lvl ? col : A.dim) + g[i] + A.reset;
  return out;
}

// Map a click at 1-based terminal (X, Y) to a zone's key, accounting for the centered
// layout. Pure, so it's unit-testable without a terminal.
export function hitTest(built, cols, rows, X, Y) {
  const boxW = Math.max(...built.lines.map(visLen));
  const leftPad = Math.max(0, Math.floor((cols - boxW) / 2));
  const topPad = Math.max(0, Math.floor((rows - built.lines.length) / 2));
  for (const z of built.zones) {
    const rowY = topPad + z.line + 1;             // 1-based terminal row
    const x0 = leftPad + z.x0 + 3;                // leftPad + "│ " (2) + content col, 1-based
    const x1 = leftPad + z.x1 + 3;
    if (Y === rowY && X >= x0 && X < x1) return z.key;
  }
  return null;
}

// Full-screen rendering in the alternate screen buffer - the model vim/htop/less use.
// Paint the ENTIRE screen every frame (box centered, blank padding around it) from home,
// so no terminal history shows and the panel is centered. The key to not breaking on
// scroll: only repaint on EVENTS (keypress, state change, resize, spinner-tick-while-busy),
// never on an idle timer. Then a scroll gesture behaves exactly like it does in vim - the
// terminal shows scrollback while scrolled and restores the frame on the way back.
function draw() {
  if (!process.stdout.isTTY) { w(renderFrame(state) + "\n"); return; }
  const cols = process.stdout.columns || 80, rows = process.stdout.rows || 24;
  let box;
  if (state.view === "share") { box = buildShare(state); lastBuilt = null; }
  else { lastBuilt = buildBox(state); box = lastBuilt.lines; }
  const boxW = Math.max(...box.map(visLen));
  const left = " ".repeat(Math.max(0, Math.floor((cols - boxW) / 2)));
  // Top-align if the content is taller than the screen (the QR must not be clipped at the top).
  const top = box.length >= rows ? 0 : Math.max(0, Math.floor((rows - box.length) / 2));
  let out = "\x1b[H";
  for (let r = 0; r < rows; r++) {
    out += "\x1b[2K";
    if (r >= top && r < top + box.length) out += left + box[r - top];
    if (r < rows - 1) out += "\r\n";
  }
  w(out);
}

// The share view: a scannable QR of the vless:// config + the link, so a new user can import
// the whole endpoint in one scan/paste - no SSH, no first-time setup.
// Two kinds of feedback for the share view:
//  • "warn" (amber) - the QR genuinely won't SCAN here: no color (black/white contrast), a
//    non-UTF-8 locale (the block glyphs), or the terminal is too narrow. Use the text link.
//  • "note" (dim) - it scans, but this terminal draws block characters from the FONT (Terminal
//    .app), so it looks seamy/rectangular. GPU terminals (Ghostty/Kitty/WezTerm/Alacritty) draw
//    them geometrically = crisp. We only flag the known font-based one so it stays quiet elsewhere.
function qrTerminalNote(qrWidth, cols) {
  const blockers = [];
  if (typeof process.stdout.hasColors === "function" && !process.stdout.hasColors()) blockers.push("no color support");
  const loc = (process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || "").toLowerCase();
  if (process.platform !== "darwin" && loc && !/utf-?8/.test(loc)) blockers.push("non-UTF-8 locale");
  if (qrWidth > cols) blockers.push(`too narrow: needs ${qrWidth} cols, you have ${cols}`);
  if (blockers.length) return { tone: "warn", text: `⚠ this terminal may not render a scannable QR (${blockers.join("; ")}). Copy the link below.` };
  if (process.env.TERM_PROGRAM === "Apple_Terminal") return { tone: "note", text: "Terminal.app draws block characters from the font, so this QR may look seamy (it still scans). Ghostty · Kitty · WezTerm render it crisply." };
  return null;
}

function buildShare(s) {
  const cols = process.stdout.columns || 80;
  const uri = s.shareUri || "";
  const qr = qrToTerminal(uri, { ecl: "L", quiet: 2 }).replace(/\n$/, "").split("\n");
  const note = qrTerminalNote(Math.max(...qr.map(visLen)), cols);
  // Back-hint lives in the title so it's visible even if the QR is taller than the terminal.
  const hint = s.shareCopied ? `${A.green}link copied ✓${A.reset}` : `${A.dim}c copy link · any key to go back${A.reset}`;
  const lines = [`${markStr(s)} ${A.bold}collateral${A.reset}${A.amber}_${A.reset}  ${hint}`, ``];
  if (note) {
    const c = note.tone === "warn" ? A.amber : A.dim;
    lines.push(...wrapAnsi(`${c}${note.tone === "note" ? "note: " : ""}${note.text}${A.reset}`, Math.min(cols - 2, 76)), ``);
  }
  for (const q of qr) lines.push(q);
  lines.push(``);
  for (const l of wrapAnsi(`${A.teal}${uri}${A.reset}`, Math.min(cols - 4, 72))) lines.push(l);
  lines.push(``,
    `${A.dim}Scan with a VLESS app (v2rayNG · Streisand · Shadowrocket · sing-box), or copy the link.${A.reset}`,
    `${A.red}Anyone with this link can use your server.${A.reset}`);
  return lines;
}

// Copy text to the clipboard. The TUI's raw mode + mouse lock means you can't select text, so this
// is the only way to get the link out. Uses the OS tool when present, plus an OSC 52 escape (which
// many terminals honor even over SSH), so at least one usually lands.
function copyToClipboard(text) {
  try { process.stdout.write(`\x1b]52;c;${Buffer.from(text || "").toString("base64")}\x07`); } catch {}
  const cmds = process.platform === "darwin" ? [["pbcopy"]]
    : process.platform === "win32" ? [["clip"]]
    : [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]];
  for (const [cmd, ...args] of cmds) {
    try { const r = spawnSync(cmd, args, { input: text || "" }); if (!r.error && r.status === 0) return true; } catch {}
  }
  return false;
}

function copyShare() {
  copyToClipboard(state.shareUri || "");
  state.shareCopied = true;
  draw();
}

function shareConfig() {
  if (!isWsUrl(state.workerUrl) || !isUuid(state.uuid)) {
    return setMsg(A.red + "Nothing to share yet: set a server + key, or run setup (s)." + A.reset);
  }
  try { state.shareUri = vlessUriFromConfig({ workerUrl: state.workerUrl, uuid: state.uuid }); }
  catch (e) { return setMsg(A.red + `Couldn't build the share link: ${e.message || e}` + A.reset); }
  state.shareCopied = false;
  state.view = "share";
  draw();
}

// Import a config from another instance by scanning its share QR (`x`) with the Mac camera.
async function importFromCamera() {
  if (!scanSupported()) return setMsg(A.red + "Camera import is macOS-only in this version." + A.reset);
  state.busy = true; state.busyText = "opening camera to scan the other Mac's QR…"; draw();
  let uri;
  try { uri = await scanQrViaCamera(); }
  catch (e) { state.busy = false; return setMsg(A.red + `Camera: ${e.message || e}` + A.reset); }
  state.busy = false;
  if (!uri) return setMsg("Scan cancelled.");
  let cfg;
  try { cfg = parseVlessUri(uri); }
  catch { return setMsg(A.red + "That QR isn't a Collateral / VLESS config." + A.reset); }
  if (!isWsUrl(cfg.workerUrl) || !isUuid(cfg.uuid)) return setMsg(A.red + "Scanned config is incomplete (need a wss:// endpoint + a UUID key)." + A.reset);
  state.workerUrl = cfg.workerUrl; state.uuid = cfg.uuid;
  saveConfig({ workerUrl: cfg.workerUrl, uuid: cfg.uuid });
  let host = cfg.workerUrl; try { host = new URL(cfg.workerUrl).host; } catch {}
  setMsg(A.green + `Imported ${host}. Press c to connect.` + A.reset);
}
function setMsg(m) { state.msg = m; draw(); }

function startSocks(workerUrl, uuid, port) {
  return new Promise((resolve, reject) => {
    const srv = startClient({ socksPort: port, workerUrl, uuid, quiet: true });
    srv.once("listening", () => resolve(srv));
    srv.once("error", reject);
  });
}

async function connect() {
  if (!isWsUrl(state.workerUrl)) return setMsg(A.red + "Set a server address first (wss://…). Press e." + A.reset);
  if (!isUuid(state.uuid)) return setMsg(A.red + "Set a valid access key first. Press e or g." + A.reset);
  if (isDemo()) {  // recording mode: play the real connect animation, touch no network
    state.busy = true; state.busyText = "connecting…"; draw();
    await sleep(600);
    state.busyText = "testing tunnel…"; draw();
    await sleep(800);
    state.socksPort = 1080; state.exitIP = DEMO_EXIT_IP;
    state.connected = true; state.reconnecting = false; state.busy = false;
    startStats();
    return setMsg(A.green + `Connected, traffic exits via ${DEMO_EXIT_IP}.` + A.reset);
  }
  state.busy = true; state.busyText = "connecting…"; draw();
  try {
    try { socks = await startSocks(state.workerUrl, state.uuid, 1080); }
    catch (e) { if (e && e.code === "EADDRINUSE") socks = await startSocks(state.workerUrl, state.uuid, 0); else throw e; }
    state.socksPort = socks.address().port;
    // Actually verify the tunnel works before claiming connected.
    state.busyText = "testing tunnel…"; draw();
    const ip = await getExitIP(state.socksPort);
    state.exitIP = ip; state.connected = true; state.reconnecting = false; state.busy = false;
    startHealthMonitor();
    startStats();
    setMsg(A.green + `Connected, traffic exits via ${ip}.` + A.reset);
  } catch (e) {
    const revoked = !!(socks && socks.authRejected);
    if (socks) { try { socks.close(); } catch {} }
    socks = null; state.socksPort = null; state.connected = false; state.exitIP = null;
    state.busy = false;
    setMsg(A.red + (revoked
      ? "Access key rejected - it was revoked, or doesn't match this server. Get a fresh link (press e, then l)."
      : `Couldn't establish the tunnel: ${e.message || e}. Check the server is set up and the key matches.`) + A.reset);
  }
}

async function disconnect() {
  if (isDemo()) {  // demo mode was display-only; just reset the flags, nothing real to tear down
    state.tunActive = false; state.systemProxy = false;
    state.connected = false; state.reconnecting = false; state.socksPort = null; state.exitIP = null;
    stopHealthMonitor();
    stopStats();
    return setMsg("Disconnected.");
  }
  // Turn off device-wide capture FIRST - leaving the system proxy or the TUN pointed at a dead
  // tunnel would break the user's internet.
  if (state.tunActive) {
    state.busy = true; state.busyText = "turning off full tunnel…"; draw();
    try { await tun.stopTun(); } catch {}
    try { dnsFwd && dnsFwd.close(); } catch {} dnsFwd = null;
    state.tunActive = false; state.tunKillSwitch = false; state.tunDns = false; state.busy = false;
  }
  if (state.systemProxy && state.netService) {
    state.busy = true; state.busyText = "turning off system proxy…"; draw();
    try { await setSocks(state.netService, false); } catch {}
    state.systemProxy = false; state.busy = false;
  }
  stopHealthMonitor();
  stopStats();
  if (socks) { try { socks.close(); } catch {} }
  socks = null; state.connected = false; state.reconnecting = false; state.socksPort = null; state.exitIP = null;
  setMsg("Disconnected.");
}

// Health monitor: while connected, periodically verify the tunnel still reaches the internet.
// Each app connection opens its own WebSocket, so the tunnel already self-heals when the server
// returns - this keeps the STATUS honest (shows "reconnecting…" during an outage, flips back to
// "connected" when it recovers) and refreshes the exit IP. Needs two consecutive failures before
// flagging (rides out transient blips); polls slowly when healthy, retries fast while down.
function startHealthMonitor() { healthFails = 0; tunFails = 0; scheduleHealth(HEALTH_OK_MS); }
function stopHealthMonitor() { if (healthTimer) { clearTimeout(healthTimer); healthTimer = null; } healthFails = 0; tunFails = 0; }

// Probe the DEVICE data path (through the utun), not the SOCKS loopback - so a wedged tun2socks
// (alive but not forwarding, black-holing the whole device) is caught even though the SOCKS->server
// path stays healthy. Dials a public web host that is neither the server nor a DNS resolver, so it
// is NOT host-routed around the tunnel: a healthy full tunnel connects; a wedged one times out.
function deviceProbe(timeoutMs = 6000) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "cloudflare.com", port: 443 });
    let done = false;
    const finish = (ok) => { if (done) return; done = true; try { s.destroy(); } catch {} resolve(ok); };
    s.setTimeout(timeoutMs);
    s.once("connect", () => finish(true));
    s.once("timeout", () => finish(false));
    s.once("error", () => finish(false));
  });
}
function scheduleHealth(ms) { if (healthTimer) clearTimeout(healthTimer); healthTimer = setTimeout(healthTick, ms); }
async function healthTick() {
  healthTimer = null;
  if (!state.connected) return;
  if (state.busy || inPrompt || !socks) return scheduleHealth(Math.min(6000, HEALTH_OK_MS)); // defer during manual ops
  try {
    const ip = await getExitIP(state.socksPort); // getExitIP enforces its own 9s timeout internally
    state.exitIP = ip; healthFails = 0;
    if (state.reconnecting) { state.reconnecting = false; setMsg(A.green + `Tunnel recovered, exits via ${ip}.` + A.reset); }
    // Full tunnel: getExitIP above rides the SOCKS loopback, which bypasses the utun. So ALSO verify
    // the device path forwards - a wedged tun2socks passes the SOCKS check but black-holes everything.
    if (state.tunActive && !isDemo()) {
      const flowing = await deviceProbe();
      if (!flowing) {
        if (++tunFails >= 2) {  // two strikes while the SOCKS path is healthy = the helper is wedged
          tunFails = 0;
          tun.requestRestart(); // root session relaunches tun2socks in place (no admin re-prompt)
          setMsg(A.amber + "Full tunnel stalled, restarting the tunnel helper…" + A.reset);
          return scheduleHealth(Math.min(9000, HEALTH_OK_MS));
        }
        return scheduleHealth(Math.min(5000, HEALTH_OK_MS));
      }
      if (tunFails) { tunFails = 0; setMsg(A.green + `Full tunnel recovered, exits via ${ip}.` + A.reset); }
    }
    scheduleHealth(HEALTH_OK_MS);
  } catch {
    if (socks && socks.authRejected) { // the owner revoked this key mid-session - reconnecting won't help
      state.reconnecting = false;
      return setMsg(A.red + "Access revoked - your key no longer works on this server. Press c to disconnect." + A.reset);
    }
    healthFails++;
    if (healthFails >= 2 && !state.reconnecting) {
      state.reconnecting = true;
      setMsg(A.amber + (state.tunKillSwitch
        ? "Tunnel down - traffic BLOCKED by the kill switch, reconnecting…"
        : "Tunnel unreachable, reconnecting automatically…") + A.reset);
    }
    scheduleHealth(healthFails >= 2 ? Math.min(8000, HEALTH_OK_MS) : Math.min(4000, HEALTH_OK_MS));
  }
}

// Live throughput + latency. Samples the client's byte counters each second to derive up/down
// rates, and TCP-pings the server every ~5s for a round-trip reading. Only repaints in the main
// view (nothing there scrolls), so scroll-lock in the QR/help views is preserved.
let statsTimer = null, prevUp = 0, prevDown = 0, prevAt = 0, pingN = 0;
function startStats() {
  prevUp = (socks && socks.bytesUp) || 0;
  prevDown = (socks && socks.bytesDown) || 0;
  prevAt = Date.now();
  pingN = 0;
  state.upRate = 0; state.downRate = 0; state.totalBytes = 0; state.latency = null;
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(statsTick, 1000);
  if (!isDemo()) pingServer(); // first reading right away
}
function stopStats() {
  if (statsTimer) { clearInterval(statsTimer); statsTimer = null; }
  state.upRate = 0; state.downRate = 0; state.totalBytes = 0; state.latency = null;
}
function statsTick() {
  if (!state.connected) return;
  if (isDemo()) { // recording mode: plausible fluctuating numbers so it feels alive
    state.downRate = 900e3 + Math.random() * 1600e3;
    state.upRate = 60e3 + Math.random() * 180e3;
    state.totalBytes = (state.totalBytes || 0) + state.downRate + state.upRate;
    state.latency = 18 + Math.round(Math.random() * 12);
  } else {
    if (!socks) return;
    const now = Date.now();
    const up = socks.bytesUp || 0, down = socks.bytesDown || 0;
    const dt = Math.max(0.001, (now - prevAt) / 1000);
    state.upRate = Math.max(0, (up - prevUp) / dt);
    state.downRate = Math.max(0, (down - prevDown) / dt);
    state.totalBytes = up + down;
    prevUp = up; prevDown = down; prevAt = now;
    if (++pingN % 5 === 0) pingServer(); // re-ping every ~5s
  }
  if (state.view === "main" && !inPrompt && !state.busy) draw(); // main view has nothing to scroll
}
// TCP round-trip to a server URL, resolving latency in ms (or null if unreachable). No tunnel
// overhead - just how far away the endpoint is. Feeds both the live ping row and fastest-pick.
export function pingUrl(workerUrl, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let host, port;
    try {
      const u = new URL(workerUrl);
      host = u.hostname;
      port = Number(u.port) || (u.protocol === "wss:" ? 443 : 80);
    } catch { return resolve(null); }
    const t0 = Date.now();
    const s = net.connect({ host, port });
    let done = false;
    const finish = (val) => { if (done) return; done = true; try { s.destroy(); } catch {} resolve(val); };
    s.setTimeout(timeoutMs);
    s.once("connect", () => finish(Date.now() - t0));
    s.once("timeout", () => finish(null));
    s.once("error", () => finish(null));
  });
}
function pingServer() { pingUrl(state.workerUrl).then((ms) => { state.latency = ms; }); }

// Full-tunnel (TUN): true device-wide capture of all TCP + UDP via a utun, using our existing tunnel.
// Mutually exclusive with the system SOCKS proxy. Needs admin (one GUI prompt) and macOS.
async function toggleTun() {
  if (isDemo()) {  // display-only in recording mode
    if (state.tunActive) { state.tunActive = false; return setMsg("Full tunnel off, networking restored."); }
    if (!state.connected) return setMsg(A.red + "Connect first. The full tunnel routes every app through the tunnel." + A.reset);
    state.busy = true; state.busyText = "starting full tunnel…"; draw();
    await sleep(700);
    state.systemProxy = false; state.tunActive = true; state.busy = false;
    return setMsg(A.green + "Full tunnel ON, all your traffic (TCP + UDP) now routes through the server." + A.reset + `  ${A.dim}(press f to turn off)${A.reset}`);
  }
  if (!tun.supported()) return setMsg(A.red + "Full tunnel is available on macOS and Linux only (Windows is planned)." + A.reset);
  if (state.tunActive) {
    state.busy = true; state.busyText = "turning off full tunnel…"; draw();
    const ok = await tun.stopTun();
    try { dnsFwd && dnsFwd.close(); } catch {} dnsFwd = null;
    state.tunActive = false; state.tunKillSwitch = false; state.tunDns = false; state.busy = false;
    return setMsg(ok ? "Full tunnel off, networking restored." : A.red + "Couldn't confirm the full tunnel turned off - your traffic may still route through it. Press f again, or quit (q) to restore networking." + A.reset);
  }
  if (!state.connected) return setMsg(A.red + "Connect first. The full tunnel routes every app through the tunnel." + A.reset);
  if (state.systemProxy) { try { await setSocks(state.netService, false); } catch {} state.systemProxy = false; } // exclusive
  const ans = (await promptStart([
    `${A.amber}${A.bold}Full tunnel (device-wide TUN)${A.reset}`,
    ``,
    `This captures ${A.bold}all traffic (TCP and UDP)${A.reset} from every app at the network layer -`,
    `the real VPN-style path, not the best-effort system proxy.`,
    ``,
    `• Needs ${A.bold}admin${A.reset} once (a macOS password dialog).`,
    `• First time, downloads a small verified helper (~4 MB).`,
    `• ${A.bold}Kill switch${A.reset} (type ${A.amber}lock${A.reset}): if the tunnel drops, ${A.bold}block${A.reset} traffic`,
    `  instead of falling back to your normal connection - no leak.`,
    `• Turns off automatically on disconnect, quit, or if this app crashes.`,
    ``,
    `Type ${A.amber}yes${A.reset} to start, ${A.amber}lock${A.reset} for the kill switch, or enter to cancel.`,
  ], "")).trim().toLowerCase();
  if (ans !== "yes" && ans !== "lock") { draw(); return setMsg("Full tunnel cancelled."); }
  const killSwitch = ans === "lock";
  state.busy = true; state.busyText = "starting full tunnel…"; draw();
  try {
    const host = new URL(state.workerUrl).host;
    // Linux redirects :53 to an in-app forwarder; macOS runs the forwarder on :53 inside the root
    // session (privileged port) and points system DNS at it - so only start the app one on Linux.
    if (state.dnsTunnel && process.platform === "linux") { try { dnsFwd && dnsFwd.close(); } catch {} dnsFwd = startDnsForwarder({ socksPort: state.socksPort, port: DNS_PORT, quiet: true }); }
    await tun.startTun({ socksPort: state.socksPort, serverHost: host, killSwitch, dnsTunnel: state.dnsTunnel, dnsPort: DNS_PORT, onLog: (m) => { state.busyText = m; draw(); } });
    state.tunActive = true; state.tunKillSwitch = killSwitch; state.tunDns = state.dnsTunnel; state.busy = false;
    saveConfig({ killSwitch });
    setMsg(A.green + (killSwitch
      ? "Full tunnel ON, kill switch armed - if the tunnel drops, traffic is blocked (no leak)."
      : "Full tunnel ON, all your traffic (TCP + UDP) now routes through the server.") + (state.dnsTunnel ? " DNS is tunnelled too." : "") + A.reset + `  ${A.dim}(press f to turn off)${A.reset}`);
  } catch (e) {
    try { dnsFwd && dnsFwd.close(); } catch {} dnsFwd = null;
    state.tunActive = false; state.tunKillSwitch = false; state.tunDns = false; state.busy = false;
    setMsg(A.red + `Full tunnel failed: ${e.message || e}` + A.reset);
  }
}

async function toggleSystemProxy() {
  if (isDemo()) {  // display-only in recording mode
    const turnOn = !state.systemProxy;
    if (turnOn && !state.connected) return setMsg(A.red + "Connect first. The system proxy routes apps through the tunnel." + A.reset);
    if (turnOn) {
      state.busy = true; state.busyText = "enabling system proxy…"; draw();
      await sleep(500);
      state.tunActive = false; state.busy = false;
    }
    state.systemProxy = turnOn;
    return setMsg(turnOn
      ? A.green + "System proxy ON, apps that honor it now route through the tunnel." + A.reset + `  ${A.dim}(press d to turn off before quitting)${A.reset}`
      : "System proxy off, apps use your normal connection again.");
  }
  if (!sysproxySupported()) return setMsg(A.red + "System proxy is macOS-only here. Set your OS proxy manually (press p)." + A.reset);
  if (!state.netService) state.netService = await primaryService();
  if (!state.netService) return setMsg(A.red + "Couldn't find your network service." + A.reset);
  const turnOn = !state.systemProxy;
  if (turnOn && !state.connected) return setMsg(A.red + "Connect first. The system proxy routes apps through the tunnel." + A.reset);
  if (turnOn && state.tunActive) { try { await tun.stopTun(); } catch {} state.tunActive = false; } // exclusive with full tunnel
  state.busy = true; state.busyText = turnOn ? "enabling system proxy (may ask for your password)…" : "disabling system proxy…"; draw();
  const ok = await setSocks(state.netService, turnOn, "127.0.0.1", state.socksPort || 1080);
  state.busy = false;
  if (!ok) return setMsg(A.red + "Couldn't change the system proxy (cancelled or failed)." + A.reset);
  state.systemProxy = turnOn;
  setMsg(turnOn
    ? A.green + "System proxy ON, apps that honor it now route through the tunnel." + A.reset + `  ${A.dim}(press d to turn off before quitting)${A.reset}`
    : "System proxy off, apps use your normal connection again.");
}

async function test() {
  if (!state.connected) return setMsg(A.red + "Connect first. Press c." + A.reset);
  if (isDemo()) return setMsg(A.teal + `Traffic exits via ${DEMO_EXIT_IP}.` + A.reset);
  state.busy = true; state.busyText = "testing…"; draw();
  try {
    const ip = await getExitIP(state.socksPort);
    state.exitIP = ip; state.busy = false;
    setMsg(A.teal + `Traffic exits via ${ip}.` + A.reset);
  } catch (e) {
    state.busy = false;
    setMsg(A.red + `Test failed: ${e.message || e}` + A.reset);
  }
}

// Generating a new key orphans the current one: the server keeps expecting the OLD key until
// you re-run setup. That's easy to trigger by accident and locks you out, so require a confirm.
async function regenKey() {
  const ok = await confirmWord([
    `${A.amber}${A.bold}Generate a new access key?${A.reset}`,
    ``,
    `current key  ${A.dim}${state.uuid ? ellip(state.uuid, 40) : "(none)"}${A.reset}`,
    ``,
    `This ${A.bold}replaces${A.reset} your key. Your server still expects the current one, so you'll`,
    `${A.bold}lose access until you re-run setup${A.reset} (press ${A.amber}s${A.reset}), which uploads the new key.`,
    ``,
    `Type ${A.amber}yes${A.reset} to generate a new key, or press enter to cancel.`,
  ], "yes");
  if (!ok) { draw(); return setMsg("Kept your current key."); }
  state.uuid = crypto.randomUUID(); saveConfig({ uuid: state.uuid });
  setMsg(A.green + "New key generated." + A.reset + ` ${A.dim}Press s → re-run setup to upload it to your server.${A.reset}`);
}

// In-box prompt: renders as a centered box view (state.view = "prompt") and reads input in
// raw mode - no jump to a bare top-left fullscreen readline. Returns the entered text.
function promptStart(lines, current) {
  return new Promise((resolve) => {
    inPrompt = true;
    state.prompt = { lines, current: current || "", value: "", resolve };
    state.view = "prompt";
    w(MOUSE_OFF); // stop mouse reports so moves/scroll can't inject into the field
    draw();
  });
}
function finishPrompt(value) {
  const p = state.prompt;
  state.prompt = null;
  state.view = "main";
  inPrompt = false;
  w(MOUSE_ON);
  p.resolve(value); // caller redraws (avoids a flash between chained prompts)
}
function promptKey(str) {
  const p = state.prompt;
  if (!p) return;
  if (str === "\x1b") return finishPrompt(p.current);  // ESC → keep current / cancel
  if (str.charCodeAt(0) === 27) return;                // other escape seq (arrows/mouse) → ignore
  const nl = str.search(/[\r\n]/);
  for (const c of (nl >= 0 ? str.slice(0, nl) : str)) {
    if (c === "\x7f" || c === "\b") p.value = p.value.slice(0, -1);
    else if (c >= " ") p.value += c;
  }
  if (nl >= 0) return finishPrompt(p.value.trim() || p.current);
  draw();
}
function promptLine(label, current) {
  const lines = [`${A.amber}${label}${A.reset}`];
  if (current) lines.push(`${A.dim}current: ${ellip(current, 60)}${A.reset}`);
  return promptStart(lines, current);
}
async function confirmWord(lines, word) { return (await promptStart(lines, "")).toLowerCase() === word; }

// The `s` key: SSH into your own VM and stand up the server automatically.
async function setupVps() {
  const ans = (await promptStart([
    `${A.amber}${A.bold}Set up your own server${A.reset}`,
    ``,
    `You need a Linux VM with SSH access. An ${A.bold}Oracle Cloud Always-Free${A.reset}`,
    `${A.bold}Ubuntu${A.reset} instance is ideal (free forever). Before continuing, open`,
    `${A.bold}ports 80 and 443${A.reset} in its cloud console security list (one-time).`,
    ``,
    `This app will SSH in and install everything: server, HTTPS, firewall,`,
    `and a background service. Nothing to type on the VM.`,
    ``,
    `${A.dim}Optional: use your own domain (A record → the VM) for a stronger,`,
    `unblockable endpoint, or press enter for automatic ${A.reset}${A.dim}<ip>.sslip.io.${A.reset}`,
    ``,
    `${A.dim}No VM yet? Type ${A.reset}${A.amber}guide${A.reset}${A.dim} for a step-by-step walkthrough.${A.reset}`,
    `Type ${A.amber}yes${A.reset} to continue, ${A.amber}guide${A.reset} for help, or enter to cancel.`,
  ], "")).trim().toLowerCase();
  if (ans === "guide") { state.view = "guide"; state.guideStep = 0; return draw(); }
  if (ans !== "yes") { draw(); return setMsg("Setup cancelled."); }

  const host = await promptLine("VM public IP address", state.vpsHost || "");
  if (!host) { draw(); return setMsg("Cancelled, no IP entered."); }
  const user = await promptLine("SSH username (ubuntu for Ubuntu, opc for Oracle Linux)", state.vpsUser || "ubuntu");
  const keyRaw = await promptLine("Path to your SSH private key", state.vpsKey || `${os.homedir()}/.ssh/id_rsa`);
  const keyPath = keyRaw.replace(/^~(?=$|\/)/, os.homedir());
  if (!keyPath || !fs.existsSync(keyPath)) { draw(); return setMsg(A.red + `No SSH key file at ${keyRaw || "(empty)"} - check the path and try again (Oracle downloads it as a .key, usually in ~/Downloads).` + A.reset); }
  const domainRaw = await promptLine("Custom domain (A record → this VM), or enter for automatic sslip.io", state.vpsDomain || "");
  const domain = (domainRaw || "").trim();
  saveConfig({ vpsHost: host, vpsUser: user, vpsKey: keyRaw, vpsDomain: domain });
  Object.assign(state, { vpsHost: host, vpsUser: user, vpsKey: keyRaw, vpsDomain: domain });

  state.view = "setup";
  // The DNS-verify step only applies when a custom domain was given.
  state.steps = VPS_STEPS.filter(([name]) => name !== "dns" || domain).map(([name, label]) => ({ name, label, status: "pending" }));
  state.busy = true; draw();
  const logFile = `${os.homedir()}/.collateral-setup.log`;
  try { fs.writeFileSync(logFile, ""); } catch {}
  try {
    const res = await provisionVps({
      host, user, keyPath, domain: domain || undefined,
      uuid: isUuid(state.uuid) ? state.uuid : undefined, // keep the client key as source of truth - upload it
      log: (m) => { try { fs.appendFileSync(logFile, m); } catch {} },
      onStep: (name, status, note) => {
        const st = state.steps.find((x) => x.name === name);
        if (st) { st.status = status; if (note) st.note = note; }
        draw();
      },
    });
    state.busy = false;
    state.workerUrl = res.workerUrl; state.uuid = res.uuid;
    // freshen a matching saved machine's creds, so switching back to it later still targets it right
    const savePatch = { workerUrl: res.workerUrl, uuid: res.uuid };
    if (Array.isArray(state.machines)) {
      const mm = state.machines.find((m) => m.workerUrl === res.workerUrl);
      if (mm) { Object.assign(mm, { uuid: res.uuid, vpsHost: state.vpsHost, vpsUser: state.vpsUser, vpsKey: state.vpsKey, vpsDomain: state.vpsDomain }); savePatch.machines = state.machines; }
    }
    saveConfig(savePatch);
    state.view = "main";
    setMsg(A.green + `Server ready at ${res.domain}. Connecting…` + A.reset);
    await connect();
  } catch (e) {
    state.busy = false;
    const running = (state.steps || []).find((x) => x.status === "run");
    if (running) running.status = "fail";
    state.view = "main";
    setMsg(A.red + `Setup failed: ${e.message || e}` + A.reset + `  ${A.dim}(full log: ~/.collateral-setup.log)${A.reset}`);
  }
}

// Saved machines: keep several server+key configs (with a description) and switch between them
// fast - e.g. a real VM and the demo endpoint. Stored in ~/.collateral-config.json as `machines`.
async function machines() {
  const list = Array.isArray(state.machines) ? state.machines : [];
  const lines = [`${A.amber}${A.bold}Saved machines${A.reset}`, ``];
  if (!list.length) {
    lines.push(`${A.dim}(none saved yet)${A.reset}`, ``);
  } else {
    list.forEach((m, i) => {
      lines.push(`  ${A.amber}${i + 1}${A.reset}  ${A.bold}${m.desc || "(no description)"}${A.reset}`);
      lines.push(`     ${A.dim}${ellip(m.workerUrl || "", 54)}${A.reset}`);
    });
    lines.push(``);
  }
  const fastHint = list.length >= 2 ? ` · ${A.amber}f${A.reset} fastest` : "";
  lines.push(`${A.amber}number${A.reset} switch · ${A.amber}s${A.reset} save current${fastHint}${list.length ? ` · ${A.amber}dN${A.reset} delete #N` : ""}`);
  lines.push(`${A.amber}e${A.reset} export backup · ${A.amber}i${A.reset} import backup · ${A.dim}enter cancels${A.reset}`);
  const ans = (await promptStart(lines, "")).trim().toLowerCase();
  if (!ans) return setMsg("Cancelled.");
  if (ans === "s") return saveMachine();
  if (ans === "f") return connectFastest();
  if (ans === "e") return exportConfig();
  if (ans === "i") return importConfig();
  const del = /^d\s*0*(\d+)$/.exec(ans);
  if (del) return deleteMachine(Number(del[1]) - 1);
  const n = Number(ans);
  if (Number.isInteger(n) && n >= 1 && n <= list.length) {
    const m = list[n - 1];
    adoptMachine(m);
    return setMsg(A.green + `Switched to ${m.desc || "that machine"}.` + A.reset + ` ${A.dim}Press c to connect.${A.reset}`);
  }
  return setMsg(A.red + "Didn't recognize that - type a number, or s / f / e / i / dN." + A.reset);
}

// Make a saved machine the active one: adopt its endpoint + key, plus its SSH creds if it has them.
// Older saved machines predate per-machine creds, so keep the current creds when a field is absent.
function adoptMachine(m) {
  state.workerUrl = m.workerUrl || ""; state.uuid = m.uuid || "";
  for (const f of ["vpsHost", "vpsUser", "vpsKey", "vpsDomain"]) if (m[f] != null) state[f] = m[f];
  saveConfig({ workerUrl: state.workerUrl, uuid: state.uuid, vpsHost: state.vpsHost, vpsUser: state.vpsUser, vpsKey: state.vpsKey, vpsDomain: state.vpsDomain });
}

async function saveMachine() {
  if (!isWsUrl(state.workerUrl) || !isUuid(state.uuid)) {
    return setMsg(A.red + "Set a server + key first (press e), then save." + A.reset);
  }
  const desc = (await promptLine("Name this machine (e.g. home VM, demo)", "")).trim();
  const list = Array.isArray(state.machines) ? state.machines.slice() : [];
  const entry = { desc: desc || "(no description)", workerUrl: state.workerUrl, uuid: state.uuid,
    vpsHost: state.vpsHost, vpsUser: state.vpsUser, vpsKey: state.vpsKey, vpsDomain: state.vpsDomain };
  const idx = list.findIndex((m) => m.workerUrl === entry.workerUrl && m.uuid === entry.uuid);
  if (idx >= 0) list[idx] = entry; else list.push(entry);          // update in place if already saved
  state.machines = list; saveConfig({ machines: list });
  return setMsg(A.green + `Saved "${entry.desc}".` + A.reset);
}

// Pure: from [{m, ms}] (ms null = unreachable) pick the reachable entry with the lowest latency.
export function pickFastest(results) {
  const reachable = (results || []).filter((r) => r && r.ms != null).sort((a, b) => a.ms - b.ms);
  return reachable[0] || null;
}

// Merge two lists, skipping items whose key already exists. Pure -> unit-testable. Folds an
// imported backup's saved machines / friends into the current ones without creating duplicates.
export function mergeBy(current, incoming, keyFn) {
  const out = Array.isArray(current) ? current.slice() : [];
  const seen = new Set(out.map(keyFn));
  let added = 0;
  for (const x of (incoming || [])) {
    if (!x) continue;
    const k = keyFn(x);
    if (!seen.has(k)) { out.push(x); seen.add(k); added++; }
  }
  return { list: out, added };
}

// Build the backup payload from a config: captures the active server as a machine too, so it's
// always restorable even if it was never explicitly saved. Pure (timestamp passed in).
export function buildBackup(cfg, nowIso) {
  const machines = Array.isArray(cfg.machines) ? cfg.machines.slice() : [];
  if (isWsUrl(cfg.workerUrl) && isUuid(cfg.uuid) && !machines.some((m) => m.workerUrl === cfg.workerUrl && m.uuid === cfg.uuid)) {
    machines.push({ desc: "current server", workerUrl: cfg.workerUrl, uuid: cfg.uuid });
  }
  return { _collateral: "backup", version: 1, exportedAt: nowIso, config: { ...cfg, machines } };
}

// Plan how an imported config folds into the current one: merge machines + friends (no dupes), and
// adopt the backup's server/key + VPS settings only where this machine has none. Pure.
export function planImport(cur, imp) {
  const m = mergeBy(cur.machines, imp.machines, (x) => `${x.workerUrl}|${x.uuid}`);
  const fr = mergeBy(cur.friends, imp.friends, (x) => x.uuid);
  const patch = { machines: m.list, friends: fr.list };
  if (!isWsUrl(cur.workerUrl) || !isUuid(cur.uuid)) {
    if (isWsUrl(imp.workerUrl)) patch.workerUrl = imp.workerUrl;
    if (isUuid(imp.uuid)) patch.uuid = imp.uuid;
  }
  for (const f of ["vpsHost", "vpsUser", "vpsKey", "vpsDomain"]) if (!cur[f] && imp[f] != null) patch[f] = imp[f];
  return { patch, addedMachines: m.added, addedFriends: fr.added };
}

// Compare dotted versions: is a strictly newer than b? Pure -> unit-testable.
export function semverGt(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0); }
  return false;
}

// Ping every saved machine and connect to the lowest-latency one. Reuses the same TCP probe that
// feeds the live ping row; the closest / least-loaded endpoint usually wins.
async function connectFastest() {
  const list = Array.isArray(state.machines) ? state.machines : [];
  const targets = list.filter((m) => isWsUrl(m.workerUrl) && isUuid(m.uuid));
  if (targets.length < 2) return setMsg(A.red + "Save at least two machines first (press s here) to compare them." + A.reset);
  state.busy = true; state.busyText = `pinging ${targets.length} servers…`; draw();
  const results = await Promise.all(targets.map(async (m) => ({ m, ms: await pingUrl(m.workerUrl) })));
  state.busy = false;
  const best = pickFastest(results);
  if (!best) { draw(); return setMsg(A.red + "None of your saved servers responded - check they're set up." + A.reset); }
  adoptMachine(best.m);
  const rest = results.filter((r) => r.ms != null && r !== best).sort((a, b) => a.ms - b.ms)
    .map((r) => `${r.m.desc} ${r.ms}ms`).join(", ");
  setMsg(A.green + `Fastest: ${best.m.desc} at ${best.ms} ms.` + A.reset + (rest ? ` ${A.dim}(${rest})${A.reset}` : "") + ` ${A.dim}Connecting…${A.reset}`);
  return connect();
}

function deleteMachine(i) {
  const list = Array.isArray(state.machines) ? state.machines.slice() : [];
  if (!Number.isInteger(i) || i < 0 || i >= list.length) return setMsg(A.red + "No machine with that number." + A.reset);
  const [removed] = list.splice(i, 1);
  state.machines = list; saveConfig({ machines: list });
  return setMsg(`Deleted "${removed.desc || "machine"}".`);
}

// Back up your whole setup (saved machines, friends, current server/key, VPS settings) to a file -
// a backup, or a way to move everything to another computer. Restored by importConfig().
async function exportConfig() {
  const def = path.join(os.homedir(), "collateral-backup.json");
  const dest = expandKey((await promptLine("Save backup to", def)).trim() || def);
  const payload = buildBackup(loadConfig(), new Date().toISOString());
  const count = payload.config.machines.length;
  try { fs.writeFileSync(dest, JSON.stringify(payload, null, 2)); }
  catch (e) { return setMsg(A.red + `Couldn't write ${dest}: ${e.message || e}` + A.reset); }
  return setMsg(A.green + `Backed up ${count} machine${count === 1 ? "" : "s"} to ${dest}.` + A.reset + ` ${A.dim}(contains your keys - keep it private)${A.reset}`);
}

// Restore a backup: merge its saved machines + friends into yours (no duplicates), and adopt its
// server/key + VPS settings if this machine has none set yet (a fresh computer).
async function importConfig() {
  const src = expandKey((await promptLine("Restore from backup file", path.join(os.homedir(), "collateral-backup.json"))).trim());
  if (!src) return setMsg("Cancelled.");
  let payload;
  try { payload = JSON.parse(fs.readFileSync(src, "utf8")); }
  catch (e) { return setMsg(A.red + `Couldn't read ${src}: ${e.message || e}` + A.reset); }
  const imp = payload && payload.config ? payload.config : payload; // accept our wrapper or a bare config file
  if (!imp || typeof imp !== "object" || (!Array.isArray(imp.machines) && !isWsUrl(imp.workerUrl))) {
    return setMsg(A.red + "That file isn't a Collateral backup." + A.reset);
  }
  const { patch, addedMachines, addedFriends } = planImport(state, imp);
  Object.assign(state, patch);
  saveConfig(patch);
  if (!addedMachines && !addedFriends) return setMsg(A.green + "Backup read - nothing new to add (already up to date)." + A.reset);
  return setMsg(A.green + `Imported +${addedMachines} machine${addedMachines === 1 ? "" : "s"}${addedFriends ? `, +${addedFriends} friend${addedFriends === 1 ? "" : "s"}` : ""}.` + A.reset + ` ${A.dim}Press m to pick one, then c to connect.${A.reset}`);
}

// One place to set the connection: paste a link (which carries both endpoint + key), scan a QR, or
// set the server / key by hand.
async function details() {
  const lines = [
    `${A.amber}${A.bold}Connection details${A.reset}`, ``,
    `  ${A.muted}server${A.reset}  ${state.workerUrl ? A.teal + ellip(state.workerUrl, 44) + A.reset : A.dim + "(not set)" + A.reset}`,
    `  ${A.muted}key${A.reset}     ${state.uuid ? ellip(state.uuid, 44) : A.dim + "(not set)" + A.reset}`,
    ``,
    `${A.amber}l${A.reset} import a link (vless://…)`,
    `${A.amber}w${A.reset} set server address`,
    `${A.amber}u${A.reset} set access key`,
    ...(scanSupported() ? [`${A.amber}s${A.reset} scan a QR with the camera`] : []),
    ``,
    `${A.amber}a${A.reset} auto-connect on launch: ${state.autoConnect ? A.green + "on" + A.reset : A.muted + "off" + A.reset}`,
    ...(process.platform === "linux" ? [`${A.amber}d${A.reset} tunnel DNS (full tunnel, Linux): ${state.dnsTunnel ? A.green + "on" + A.reset : A.muted + "off" + A.reset}`] : []),
    ``,
    `${A.dim}enter to go back${A.reset}`,
  ];
  const ans = (await promptStart(lines, "")).trim().toLowerCase();
  if (ans === "l") return importLink();
  if (ans === "w") return setServer();
  if (ans === "u") return setKey();
  if (ans === "s" && scanSupported()) return importFromCamera();
  if (ans === "a") { state.autoConnect = !state.autoConnect; saveConfig({ autoConnect: state.autoConnect }); return setMsg(state.autoConnect ? A.green + "Auto-connect on launch is ON." + A.reset : "Auto-connect on launch is off."); }
  if (ans === "d" && process.platform === "linux") { state.dnsTunnel = !state.dnsTunnel; saveConfig({ dnsTunnel: state.dnsTunnel }); return setMsg(state.dnsTunnel ? A.green + "DNS will tunnel through the full tunnel (no plaintext DNS leak)." + A.reset : "DNS tunnelling off."); }
  return draw(); // enter / anything else -> back to main
}

async function importLink() {
  const link = (await promptLine("Paste a vless:// link", "")).trim();
  if (!link) return setMsg("Cancelled.");
  let cfg;
  try { cfg = parseVlessUri(link); }
  catch { return setMsg(A.red + "That isn't a vless:// link." + A.reset); }
  if (!isWsUrl(cfg.workerUrl) || !isUuid(cfg.uuid)) return setMsg(A.red + "That link is missing a wss:// endpoint or a valid key." + A.reset);
  state.workerUrl = cfg.workerUrl; state.uuid = cfg.uuid;
  saveConfig({ workerUrl: cfg.workerUrl, uuid: cfg.uuid });
  let host = cfg.workerUrl; try { host = new URL(cfg.workerUrl).host; } catch {}
  return setMsg(A.green + `Imported ${host}. Press c to connect.` + A.reset);
}

async function setServer() {
  const v = await promptLine("Server address (wss://your-domain or wss://<ip>.sslip.io)", state.workerUrl);
  if (v && !isWsUrl(v)) return setMsg(A.red + "Server address must start with wss:// (or ws://). Not saved." + A.reset);
  state.workerUrl = v || ""; saveConfig({ workerUrl: state.workerUrl });
  return setMsg(state.workerUrl ? "Saved server address." : "Cleared server address.");
}

async function setKey() {
  const v = await promptLine("Access key (UUID): paste it", state.uuid);
  if (v && !isUuid(v)) return setMsg(A.red + "That doesn't look like an access key - it should be a UUID. Not saved." + A.reset);
  state.uuid = v || ""; saveConfig({ uuid: state.uuid });
  return setMsg(state.uuid ? "Saved access key." : "Cleared access key.");
}

const expandKey = (p) => String(p || "").replace(/^~(?=$|\/)/, os.homedir());

// Friends: let other people use YOUR server. Each friend gets their own key, appended to the VM's
// keys file over SSH (the server picks it up live, no redeploy). Revoking removes their line. Their
// labels live in your local config; the VM's keys file is the source of truth.
async function friends() {
  if (!isWsUrl(state.workerUrl)) return setMsg(A.red + "Set up your server first (press s)." + A.reset);
  if (!state.vpsHost) return setMsg(A.red + "Managing friends needs your VM's SSH details from setup (press s)." + A.reset);
  const list = Array.isArray(state.friends) ? state.friends : [];
  const lines = [`${A.amber}${A.bold}Friends${A.reset} ${A.dim}(people who can use your server)${A.reset}`, ``];
  if (!list.length) lines.push(`${A.dim}(none yet)${A.reset}`, ``);
  else {
    list.forEach((f, i) => lines.push(`  ${A.amber}${i + 1}${A.reset}  ${A.bold}${f.label || "(friend)"}${A.reset}  ${A.dim}${ellip(f.uuid || "", 20)}${A.reset}`));
    lines.push(``);
  }
  lines.push(`${A.amber}a${A.reset} add${list.length ? ` · ${A.amber}N${A.reset} show/copy · ${A.amber}rN${A.reset} revoke` : ""} · ${A.dim}enter cancels${A.reset}`);
  const ans = (await promptStart(lines, "")).trim().toLowerCase();
  if (!ans) return setMsg("Cancelled.");
  if (ans === "a") return addFriend();
  const rev = /^r\s*0*(\d+)$/.exec(ans);
  if (rev) return revokeFriend(Number(rev[1]) - 1);
  const num = Number(ans);
  if (Number.isInteger(num) && num >= 1 && num <= list.length) return showFriend(num - 1);
  return setMsg(A.red + "Didn't recognize that - a to add, N to show, rN to revoke." + A.reset);
}

// Re-display a friend's config (their key + your endpoint) as a QR/link to re-send or re-copy.
function showFriend(i) {
  const f = (Array.isArray(state.friends) ? state.friends : [])[i];
  if (!f) return setMsg(A.red + "No friend with that number." + A.reset);
  try { state.shareUri = vlessUriFromConfig({ workerUrl: state.workerUrl, uuid: f.uuid }); }
  catch (e) { return setMsg(A.red + `Couldn't build the link: ${e.message || e}` + A.reset); }
  state.shareCopied = false;
  state.view = "share";
  draw();
}

// Friends live on the server your link points at (workerUrl), which - with saved machines /
// fastest-pick - can differ from the box you first set up (vpsHost). SSH to the link's host so the
// key lands where the friend actually connects. (SSH creds stay the shared vpsUser/vpsKey.)
function friendSshHost() {
  try { return new URL(state.workerUrl).hostname; } catch { return state.vpsHost; }
}

async function addFriend() {
  const label = (await promptLine("Friend's name (e.g. alice)", "")).trim();
  const uuid = crypto.randomUUID();
  state.busy = true; state.busyText = "adding their key to your server…"; draw();
  try {
    await addKey({ host: friendSshHost(), user: state.vpsUser || "ubuntu", keyPath: expandKey(state.vpsKey), uuid });
    const list = [...(Array.isArray(state.friends) ? state.friends : []), { label: label || "(friend)", uuid }];
    state.friends = list; saveConfig({ friends: list });
    state.busy = false;
    state.shareUri = vlessUriFromConfig({ workerUrl: state.workerUrl, uuid }); // hand the friend THEIR config
    state.shareCopied = false; state.view = "share"; draw();
    setMsg(A.green + `Added ${label || "friend"} on ${friendSshHost()}. Send them this QR / link (any key to go back).` + A.reset);
  } catch (e) {
    state.busy = false;
    setMsg(A.red + `Couldn't add friend: ${String(e.message || e).split("\n").pop()}` + A.reset);
  }
}

async function revokeFriend(i) {
  const list = Array.isArray(state.friends) ? state.friends.slice() : [];
  if (!Number.isInteger(i) || i < 0 || i >= list.length) return setMsg(A.red + "No friend with that number." + A.reset);
  const f = list[i];
  state.busy = true; state.busyText = "revoking on your server…"; draw();
  try {
    await removeKey({ host: friendSshHost(), user: state.vpsUser || "ubuntu", keyPath: expandKey(state.vpsKey), uuid: f.uuid });
    list.splice(i, 1); state.friends = list; saveConfig({ friends: list });
    state.busy = false;
    setMsg(A.green + `Revoked ${f.label || "friend"} - their key no longer works.` + A.reset);
  } catch (e) {
    state.busy = false;
    setMsg(A.red + `Couldn't revoke: ${String(e.message || e).split("\n").pop()}` + A.reset);
  }
}

async function handleKey(k) {
  switch (k) {
    case "q": return quit();
    case "s": return setupVps();
    case "d": return toggleSystemProxy();
    case "f": return toggleTun();
    case "x": return shareConfig();
    case "i": return importFromCamera();
    case "c": return state.connected ? disconnect() : connect();
    case "t": return test();
    case "g": return regenKey();
    case "m": return machines();
    case "k": return friends();
    case "p": state.view = "help"; return draw();
    case "e": return details();
    default: return;
  }
}

function keyHandler(str) {
  if (str === "\x03") return quit(); // Ctrl-C
  if (state.view === "prompt") return promptKey(str);
  // SGR mouse event: \x1b[<button;x;yM (press) / m (release). Act on left press only;
  // ignore release, drag, and wheel (64/65) - the wheel is swallowed so scroll stays locked.
  // A single stdin chunk can carry several mouse events (rapid motion) and/or a trailing
  // keystroke. Handle the last click (or last move) and then any leftover key.
  const events = [...str.matchAll(/\x1b\[<(\d+);(\d+);(\d+)([Mm])/g)];
  if (events.length) {
    let click = null, move = null;
    for (const m of events) {
      const b = Number(m[1]);
      if (b === 64 || b === 65) continue;                  // wheel: swallow (scroll stays locked)
      if (b === 0 && m[4] === "m") click = m;              // left RELEASE = click (so the release can't leak into a prompt)
      else if (m[4] === "M") move = m;                     // press/motion → hover position
    }
    if (click) onClick(Number(click[2]), Number(click[3]));
    else if (move) updateHover(Number(move[2]), Number(move[3]));
    str = str.replace(/\x1b\[<\d+;\d+;\d+[Mm]/g, ""); // strip mouse; fall through for a trailing key
  }
  if (state.view === "guide") { handleGuideKey(str); return; }
  const k = str.length === 1 ? str.toLowerCase() : "";
  if (k === "q") return quit();                 // quit works even mid-connect/setup
  if (!k) { if (events.length) return; return draw(); } // no key: mouse-only chunk, or re-sync
  if (state.view === "share" && k === "c") return copyShare();
  if (state.view === "help" || state.view === "share") { state.view = "main"; return draw(); }
  if (state.busy) return;
  handleKey(k);
}

function hitAt(X, Y) {
  return hitTest(lastBuilt || buildBox(state), process.stdout.columns || 80, process.stdout.rows || 24, X, Y);
}

function onClick(X, Y) {
  if (state.view === "guide") return;   // walkthrough is keyboard-navigated
  if (state.view === "help" || state.view === "share") { state.view = "main"; return draw(); }
  if (state.busy) return;
  const key = hitAt(X, Y);
  if (key) handleKey(key);
}

// Highlight the menu item under the cursor. Only redraw when the hovered item changes,
// so continuous motion events don't cause a repaint storm.
function updateHover(X, Y) {
  const next = (state.view === "main" && !state.busy) ? hitAt(X, Y) : null;
  if (next !== state.hover) { state.hover = next; draw(); }
}

// Paged VM walkthrough navigation: space/enter/n/→ advance, b/backspace/← go back, esc/q exit,
// and enter on the last page jumps straight into setup.
function handleGuideKey(str) {
  const last = GUIDE_PAGES.length - 1;
  const i = state.guideStep || 0;
  if (str === "\x1b" || str.toLowerCase() === "q") { state.view = "main"; state.guideStep = 0; return draw(); }
  if (str === "\x7f" || str === "\b" || str.toLowerCase() === "b" || str === "\x1b[D") { state.guideStep = Math.max(0, i - 1); return draw(); }
  if (str === "\r" || str === "\n" || str === " " || str.toLowerCase() === "n" || str === "\x1b[C") {
    if (i >= last) { state.view = "main"; state.guideStep = 0; return setupVps(); }
    state.guideStep = i + 1; return draw();
  }
}

let cleaned = false;
function cleanup() {
  if (cleaned) return; cleaned = true;
  if (renderTimer) clearInterval(renderTimer);
  stopHealthMonitor();
  stopStats();
  try { dnsFwd && dnsFwd.close(); } catch {}
  // Signal the root TUN session to tear down (restores routing). Synchronous file touch, safe
  // here; the session also self-heals via its owner-PID watchdog if this never runs.
  if (state.tunActive && !isDemo()) tun.requestStopSync();
  if (socks) { try { socks.close(); } catch {} }
  try { process.stdin.setRawMode(false); } catch {}
  // Synchronous write so the terminal is restored even though process.exit() follows -
  // an async write would be truncated and leave the terminal stuck in the alt buffer.
  try { fs.writeSync(process.stdout.fd, SHOW + WRAP + SCREEN_OFF); }
  catch { w(SHOW + WRAP + SCREEN_OFF); }
}
async function quit() {
  if (quitting) return;
  quitting = true;
  // Best-effort: don't leave the user's traffic pointed at a dead proxy/TUN on exit.
  if (state.tunActive && !isDemo()) {
    state.busy = true; state.busyText = "restoring network…"; draw();
    try { await tun.stopTun(); } catch {}
    state.tunActive = false;
  }
  if (state.systemProxy && state.netService && !isDemo()) {
    state.busy = true; state.busyText = "restoring network…"; draw();
    try { await setSocks(state.netService, false); } catch {}
  }
  cleanup();
  process.exit(0);
}

// Quiet check for a newer published version; a one-line nudge if there is one. Never blocks or throws.
async function checkForUpdate() {
  if (process.env.COLLATERAL_NO_UPDATE_CHECK || isDemo()) return;
  try {
    const res = await fetch("https://registry.npmjs.org/getcollateral/latest", { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return;
    const data = await res.json();
    if (data && data.version && semverGt(data.version, PKG_VERSION)) { state.updateAvailable = data.version; draw(); }
  } catch { /* offline / registry down - stay silent */ }
}

function main() {
  if (!process.stdin.isTTY) {
    process.stdout.write(renderFrame(state) + "\n\n  (interactive controls need a real terminal, run: node tui.js)\n");
    process.exit(0);
  }
  w(SCREEN_ON + HIDE + NOWRAP);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", keyHandler);
  process.on("exit", cleanup);
  process.on("SIGTERM", quit);
  process.stdout.on("resize", draw);
  // Animate the spinner ONLY while busy. When idle we don't repaint at all, so the
  // static frame just sits in the buffer and scrolling never fights a redraw.
  renderTimer = setInterval(() => { if (!inPrompt && state.busy) { spinI = (spinI + 1) % SPIN.length; draw(); } }, 120);
  draw();
  // Detect the current system-proxy state (read-only, no prompt). Warn if a previous
  // session left it on while we're not connected - that would strand the user's traffic.
  if (sysproxySupported()) (async () => {
    state.netService = await primaryService();
    state.systemProxy = await socksEnabled(state.netService);
    if (state.systemProxy && !state.connected) {
      state.msg = A.red + "System proxy is ON but not connected. Press c to connect, or d to turn it off." + A.reset;
    }
    // A leftover TUN session from a crashed run would strand traffic - surface it so f turns it off.
    if (tun.supported() && await tun.isActive().catch(() => false)) {
      state.tunActive = true;
      state.msg = A.red + "A full tunnel from a previous run is still active. Press f to turn it off." + A.reset;
    }
    draw();
  })();
  checkForUpdate();
  if (state.autoConnect && !isDemo() && isWsUrl(state.workerUrl) && isUuid(state.uuid)) connect();
}

// Run main() when this file IS the entry point. Resolve symlinks on both sides - when launched
// via the `bin` (npx/global install), process.argv[1] is a symlink to this file, so a plain
// string compare fails and the app would exit silently.
function isEntrypoint() {
  if (!process.argv[1]) return false;
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); }
  catch { return false; }
}
// `collateral doctor` - non-interactive health check. Runs the checklist and exits (0 = all good,
// 1 = a problem). Doesn't touch the terminal / raw mode, so it's safe to pipe or run in scripts.
async function doctorCli() {
  const cfg = loadConfig();
  const TTY = process.stdout.isTTY;
  const paint = (code) => (s) => TTY ? `${code}${s}${A.reset}` : s;
  const g = paint(A.green), rd = paint(A.red), am = paint(A.amber), dm = paint(A.dim), bd = paint(A.bold), tl = paint(A.teal);
  const sym = { ok: g("✓"), warn: am("!"), fail: rd("✗"), skip: dm("·") };
  process.stdout.write(`\n${tl("[•]")} ${bd("collateral doctor")}\n\n`);
  if (cfg.uuid === DEMO_UUID) {
    process.stdout.write(`  ${dm("·")}  ${bd("demo config")} - display-only, no real server to check.\n     ${dm("Switch to a real machine first (press m in the app).")}\n\n`);
    process.exit(0);
  }
  let bad = 0, warn = 0;
  for await (const res of diagnose(cfg)) {
    if (res.status === "fail") bad++; else if (res.status === "warn") warn++;
    process.stdout.write(`  ${sym[res.status] || " "}  ${bd(res.name.padEnd(11))}  ${dm(res.detail)}\n`);
  }
  const summary = bad ? rd(`\n${bad} problem${bad > 1 ? "s" : ""} found - fix the ✗ line${bad > 1 ? "s" : ""} above.`)
    : warn ? am(`\nWorks, with ${warn} warning${warn > 1 ? "s" : ""}.`)
    : g("\nAll good.");
  process.stdout.write(summary + "\n\n");
  process.exit(bad ? 1 : 0);
}

// --- Headless CLI: `collateral up|down|status`, for servers and scripts (no TUI, no raw mode). ---
// `up` spawns a detached background agent that runs the SOCKS client; `down` stops it; `status`
// probes it. Exit codes are script-friendly: status is 0 when up + healthy, non-zero otherwise.
const AGENT_DIR = path.join(os.homedir(), ".collateral");
const AGENT_FILE = path.join(AGENT_DIR, "agent.json");
const AGENT_LOG = path.join(AGENT_DIR, "agent.log");
function readAgent() { try { return JSON.parse(fs.readFileSync(AGENT_FILE, "utf8")); } catch { return null; } }
function pidAlive(pid) { if (!pid) return false; try { process.kill(pid, 0); return true; } catch { return false; } }

// Hidden `__agent` mode: the long-lived headless process. Binds the SOCKS client and stays up
// until signalled, registering itself in agent.json so `down`/`status` can find it.
async function agentMode() {
  const cfg = loadConfig();
  if (!isWsUrl(cfg.workerUrl) || !isUuid(cfg.uuid)) { console.error("agent: no valid server/key in config"); process.exit(1); }
  const listen = (p) => new Promise((res, rej) => { const s = startClient({ socksPort: p, workerUrl: cfg.workerUrl, uuid: cfg.uuid, quiet: true }); s.once("listening", () => res(s)); s.once("error", rej); });
  const want = Number(process.env.COLLATERAL_SOCKS_PORT || 1080);
  let srv;
  try { srv = await listen(want); }
  catch (e) { if (e && e.code === "EADDRINUSE") srv = await listen(0); else { console.error("agent: " + (e.message || e)); process.exit(1); } }
  const port = srv.address().port;
  try { fs.mkdirSync(AGENT_DIR, { recursive: true }); } catch {}
  fs.writeFileSync(AGENT_FILE, JSON.stringify({ pid: process.pid, socksPort: port, workerUrl: cfg.workerUrl, startedAt: Date.now() }));
  const bye = () => { try { fs.unlinkSync(AGENT_FILE); } catch {} process.exit(0); };
  process.on("SIGTERM", bye); process.on("SIGINT", bye);   // the SOCKS server keeps the loop alive
}

async function cliUp() {
  const cfg = loadConfig();
  if (!isWsUrl(cfg.workerUrl) || !isUuid(cfg.uuid)) { console.error("No server/key configured. Open the app once (or run `collateral doctor`) to set it up."); process.exit(1); }
  const cur = readAgent();
  if (cur && pidAlive(cur.pid)) { console.log(`Already up (pid ${cur.pid}, SOCKS 127.0.0.1:${cur.socksPort}).`); process.exit(0); }
  try { fs.mkdirSync(AGENT_DIR, { recursive: true }); } catch {}
  const out = fs.openSync(AGENT_LOG, "a");
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "__agent"], { detached: true, stdio: ["ignore", out, out] });
  child.unref();
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const a = readAgent();
    if (a && a.pid === child.pid && pidAlive(a.pid)) {
      try { const ip = await getExitIP(a.socksPort); console.log(`collateral up - exit IP ${ip}, SOCKS 127.0.0.1:${a.socksPort} (pid ${a.pid}).`); process.exit(0); }
      catch { /* tunnel not verified yet, keep waiting */ }
    }
    if (!pidAlive(child.pid)) break; // agent died during startup
    await new Promise((r) => setTimeout(r, 400));
  }
  try { process.kill(child.pid, "SIGTERM"); } catch {}
  console.error(`Couldn't bring the tunnel up - run \`collateral doctor\` to see why. (log: ${AGENT_LOG})`);
  process.exit(1);
}

function cliDown() {
  const a = readAgent();
  if (!a || !pidAlive(a.pid)) { try { fs.unlinkSync(AGENT_FILE); } catch {} console.log("Not running."); process.exit(0); }
  const pid = a.pid;
  try { process.kill(pid, "SIGTERM"); } catch {}
  const deadline = Date.now() + 5000;
  (function waitGone() {
    if (!pidAlive(pid)) { try { fs.unlinkSync(AGENT_FILE); } catch {} console.log("collateral down."); process.exit(0); }
    if (Date.now() > deadline) { console.error(`Sent stop but pid ${pid} is still alive.`); process.exit(1); }
    setTimeout(waitGone, 200);
  })();
}

async function cliStatus() {
  const a = readAgent();
  if (!a || !pidAlive(a.pid)) { console.log("down"); process.exit(3); }
  try {
    const ip = await getExitIP(a.socksPort);
    const up = Math.max(0, Math.round((Date.now() - (a.startedAt || Date.now())) / 1000));
    console.log(`up - exit IP ${ip}, SOCKS 127.0.0.1:${a.socksPort}, pid ${a.pid}, uptime ${up}s`);
    process.exit(0);
  } catch {
    console.log(`up but the tunnel isn't responding (pid ${a.pid}, SOCKS 127.0.0.1:${a.socksPort}) - try \`collateral down\` then \`up\`.`);
    process.exit(4);
  }
}

function printCliHelp() {
  process.stdout.write(
    `collateral - a private tunnel you own end to end\n\n` +
    `  collateral            open the control panel (interactive)\n` +
    `  collateral up         connect in the background, print the exit IP\n` +
    `  collateral down       stop the background tunnel\n` +
    `  collateral status     tunnel status + exit IP  (exit 0 = up, non-zero = down)\n` +
    `  collateral doctor     run the connection health check\n\n` +
    `Set up your server once in the app; config lives in ~/.collateral-config.json.\n` +
    `Env: COLLATERAL_SOCKS_PORT overrides the local SOCKS port (default 1080).\n`);
  process.exit(0);
}

if (isEntrypoint()) {
  // WebSocket (and other globals we rely on) are only built in on Node >= 22. Debian/Ubuntu ship
  // Node 18, so fail fast with an actionable message instead of a cryptic ReferenceError at connect.
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  if (nodeMajor < 22) {
    console.error(`\nCollateral needs Node 22 or newer - you're on ${process.version}.\n` +
      `Install a newer Node and re-run:  nvm install 22   (or https://nodejs.org)\n`);
    process.exit(1);
  }
  const sub = process.argv[2];
  if (sub === "doctor") doctorCli();
  else if (sub === "__agent") agentMode();
  else if (sub === "up") cliUp();
  else if (sub === "down") cliDown();
  else if (sub === "status") cliStatus();
  else if (sub === "help" || sub === "--help" || sub === "-h") printCliHelp();
  else main();
}
