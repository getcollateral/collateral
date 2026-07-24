// Collateral — terminal control panel. Full-screen, centered, single-keypress, no
// browser, no dependencies. Runs in any terminal on any OS.
//
//   node tui.js        (or: npm run tui)
//
// Controls: c connect/disconnect · t test · w set worker · u set key · g generate
//           k token link · p proxy help · q quit

import readline from "node:readline";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { exec } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startClient } from "./client.js";
import { getExitIP } from "./common/probe.js";
import { loadConfig, saveConfig } from "./common/store.js";
import { buildTokenDeepLink } from "./provision/deeplink.js";
import { deployToAccount } from "./provision/deploy.js";
import { provisionVps } from "./provision/vps.js";
import { setSocks, socksEnabled, primaryService, supported as sysproxySupported } from "./common/sysproxy.js";
import * as tun from "./common/tun.js";

const VPS_STEPS = [
  ["connect", "Connect to your VM over SSH"],
  ["upload", "Upload the server"],
  ["install", "Install & configure (Node, Caddy, HTTPS)"],
  ["tls", "Issue the HTTPS certificate"],
];

const SETUP_STEPS = [
  ["verify", "Verify token"],
  ["account", "Find your account"],
  ["subdomain", "Set up workers.dev subdomain"],
  ["key", "Generate access key"],
  ["upload", "Deploy the worker"],
  ["enable", "Enable the endpoint"],
  ["health", "Health check"],
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
// alternate-screen scroll — which locks our frame in place instead of scrolling the
// buffer — when application-cursor mode is on. This is exactly what htop/vim/less emit.
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

const state = { ...loadConfig(), connected: false, socksPort: null, exitIP: null, busy: false, busyText: "", view: "main", hover: null, systemProxy: false, tunActive: false, netService: null, msg: "Set your worker + key, then press c to connect." };
let socks = null, spinI = 0, inPrompt = false, renderTimer = null, lastBuilt = null, quitting = false;

const isWsUrl = (s) => /^wss?:\/\/[^\s]+$/i.test(s || "");
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");

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
// No brackets around the key — just the amber key letter, then the label.
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
function buildBox(s) {
  const cols = process.stdout.columns || 80;
  const innerW = Math.max(46, Math.min(72, cols - 4));
  const half = Math.floor(innerW / 2);
  const bar = A.dim + "│" + A.reset;
  const top = A.dim + "╭" + "─".repeat(innerW + 2) + "╮" + A.reset;
  const sep = A.dim + "├" + "─".repeat(innerW + 2) + "┤" + A.reset;
  const bot = A.dim + "╰" + "─".repeat(innerW + 2) + "╯" + A.reset;
  const line = (c) => `${bar} ${padEndVis(truncVis(c, innerW), innerW)} ${bar}`;
  const body = [], zones = [];
  const finish = () => ({
    lines: [top, ...body.map((b) => (b === SEP ? sep : line(b))), bot],
    zones: zones.map((z) => ({ line: z.i + 1, x0: z.x0, x1: z.x1, key: z.key })), // +1 for top border
  });

  const brand = `${markStr(s)} ${A.bold}collateral${A.reset}`;

  if (s.view === "help") {
    const port = s.socksPort || "<port>";
    body.push(
      `${brand}  ${A.dim}proxy setup${A.reset}`, SEP,
      `Point any app at this SOCKS5 proxy:`,
      `  ${A.teal}host${A.reset} 127.0.0.1    ${A.teal}port${A.reset} ${port}`, ``,
      `${A.muted}Zen/Firefox${A.reset}  Manual proxy → SOCKS v5,`,
      `             tick "Proxy DNS when using SOCKS v5"`,
      `${A.muted}device-wide${A.reset} (d)  flips the macOS system proxy;`,
      `             Apple treats it as best-effort.`,
      `${A.muted}curl${A.reset}         curl --socks5-hostname 127.0.0.1:${port} …`, ``,
      `${A.dim}Cloudflare-hosted sites (Discord, ChatGPT) need${A.reset}`,
      `${A.dim}a relay you control — see the README.${A.reset}`, SEP,
      `${A.dim}press any key or click to go back${A.reset}`,
    );
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

  // main view — header: brand + subtitle + right-aligned status word (the [•] mark = state)
  const statusWord = s.busy ? A.amber + s.busyText + A.reset
    : s.connected ? A.green + "connected" + A.reset : A.muted + "disconnected" + A.reset;
  const gap = Math.max(1, innerW - visLen(brand) - visLen(statusWord));
  body.push(brand + " ".repeat(gap) + statusWord);
  body.push(`${A.dim}your own private proxy${A.reset}`);

  const row = (label, val) => `${A.muted}${label.padEnd(9)}${A.reset}  ${val}`;
  const none = A.dim + "—" + A.reset;
  const vw = innerW - 13;
  body.push(SEP,
    row("proxy", s.connected ? `${A.teal}socks5${A.reset}  127.0.0.1:${s.socksPort}` : none),
    row("endpoint", s.workerUrl ? ellip(s.workerUrl, vw) : A.dim + "(not set — press w)" + A.reset),
    row("key", s.uuid ? ellip(s.uuid, vw) : A.dim + "(not set — press u or g)" + A.reset),
    row("exit ip", s.exitIP ? A.teal + s.exitIP + A.reset : none),
    row("transport", `${A.dim}VLESS · WebSocket · TLS · :443${A.reset}`),
    SEP,
  );

  const dw = s.systemProxy ? `${A.green}on${A.reset}` : `${A.muted}off${A.reset}`;
  const tw = s.tunActive ? `${A.green}on${A.reset}` : `${A.muted}off${A.reset}`;
  const menu = [
    [["s", `${A.bold}first-time setup${A.reset}`], ["c", s.connected ? "disconnect" : "connect"]],
    [["t", "test connection"], ["w", "set worker address"]],
    [["u", "set access key"], ["g", "generate new key"]],
    [["k", "cloudflare token link"], ["p", "proxy setup help"]],
    [["d", `system proxy: ${dw}`], ["f", `full tunnel: ${tw}`]],
    [["q", "quit"]],
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

// Full-screen rendering in the alternate screen buffer — the model vim/htop/less use.
// Paint the ENTIRE screen every frame (box centered, blank padding around it) from home,
// so no terminal history shows and the panel is centered. The key to not breaking on
// scroll: only repaint on EVENTS (keypress, state change, resize, spinner-tick-while-busy),
// never on an idle timer. Then a scroll gesture behaves exactly like it does in vim — the
// terminal shows scrollback while scrolled and restores the frame on the way back.
function draw() {
  if (!process.stdout.isTTY) { w(renderFrame(state) + "\n"); return; }
  const cols = process.stdout.columns || 80, rows = process.stdout.rows || 24;
  lastBuilt = buildBox(state);
  const box = lastBuilt.lines;
  const boxW = Math.max(...box.map(visLen));
  const left = " ".repeat(Math.max(0, Math.floor((cols - boxW) / 2)));
  const top = Math.max(0, Math.floor((rows - box.length) / 2));
  let out = "\x1b[H";
  for (let r = 0; r < rows; r++) {
    out += "\x1b[2K";
    if (r >= top && r < top + box.length) out += left + box[r - top];
    if (r < rows - 1) out += "\r\n";
  }
  w(out);
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
  if (!isWsUrl(state.workerUrl)) return setMsg(A.red + "Set a worker address first (wss://…) — press w." + A.reset);
  if (!isUuid(state.uuid)) return setMsg(A.red + "Set a valid access key first — press u or g." + A.reset);
  state.busy = true; state.busyText = "connecting…"; draw();
  try {
    try { socks = await startSocks(state.workerUrl, state.uuid, 1080); }
    catch (e) { if (e && e.code === "EADDRINUSE") socks = await startSocks(state.workerUrl, state.uuid, 0); else throw e; }
    state.socksPort = socks.address().port;
    // Actually verify the tunnel works before claiming connected.
    state.busyText = "testing tunnel…"; draw();
    const ip = await getExitIP(state.socksPort);
    state.exitIP = ip; state.connected = true; state.busy = false;
    setMsg(A.green + `Connected — traffic exits via ${ip}.` + A.reset);
  } catch (e) {
    if (socks) { try { socks.close(); } catch {} }
    socks = null; state.socksPort = null; state.connected = false; state.exitIP = null;
    state.busy = false;
    setMsg(A.red + `Couldn't establish the tunnel: ${e.message || e}. Check the worker is deployed and the key matches.` + A.reset);
  }
}

async function disconnect() {
  // Turn off device-wide capture FIRST — leaving the system proxy or the TUN pointed at a dead
  // tunnel would break the user's internet.
  if (state.tunActive) {
    state.busy = true; state.busyText = "turning off full tunnel…"; draw();
    try { await tun.stopTun(); } catch {}
    state.tunActive = false; state.busy = false;
  }
  if (state.systemProxy && state.netService) {
    state.busy = true; state.busyText = "turning off system proxy…"; draw();
    try { await setSocks(state.netService, false); } catch {}
    state.systemProxy = false; state.busy = false;
  }
  if (socks) { try { socks.close(); } catch {} }
  socks = null; state.connected = false; state.socksPort = null; state.exitIP = null;
  setMsg("Disconnected.");
}

// Full-tunnel (TUN): true device-wide capture of all TCP via a utun, using our existing tunnel.
// Mutually exclusive with the system SOCKS proxy. Needs admin (one GUI prompt) and macOS.
async function toggleTun() {
  if (!tun.supported()) return setMsg(A.red + "Full tunnel is macOS-only in this version." + A.reset);
  if (state.tunActive) {
    state.busy = true; state.busyText = "turning off full tunnel…"; draw();
    const ok = await tun.stopTun();
    state.tunActive = false; state.busy = false;
    return setMsg(ok ? "Full tunnel off — networking restored." : A.red + "Couldn't confirm teardown — check `node common/tun.js status`." + A.reset);
  }
  if (!state.connected) return setMsg(A.red + "Connect first — the full tunnel routes every app through the tunnel." + A.reset);
  if (state.systemProxy) { try { await setSocks(state.netService, false); } catch {} state.systemProxy = false; } // exclusive
  const go = await confirmWord([
    `${A.amber}${A.bold}Full tunnel (device-wide TUN)${A.reset}`,
    ``,
    `This captures ${A.bold}all TCP traffic${A.reset} from every app at the network layer —`,
    `the real VPN-style path, not the best-effort system proxy.`,
    ``,
    `• Needs ${A.bold}admin${A.reset} once (a macOS password dialog).`,
    `• First time, downloads a small verified helper (~4 MB).`,
    `• ${A.dim}UDP/QUIC isn't relayed yet (server is TCP-only) — browsers fall back to TCP.${A.reset}`,
    `• Turns off automatically on disconnect, quit, or if this app crashes.`,
    ``,
    `Type ${A.amber}yes${A.reset} to continue, or enter to cancel.`,
  ], "yes");
  if (!go) { draw(); return setMsg("Full tunnel cancelled."); }
  state.busy = true; state.busyText = "starting full tunnel…"; draw();
  try {
    const host = new URL(state.workerUrl).host;
    await tun.startTun({ socksPort: state.socksPort, serverHost: host, onLog: (m) => { state.busyText = m; draw(); } });
    state.tunActive = true; state.busy = false;
    setMsg(A.green + "Full tunnel ON — every app's TCP now routes through the server." + A.reset + `  ${A.dim}(press f to turn off)${A.reset}`);
  } catch (e) {
    state.tunActive = false; state.busy = false;
    setMsg(A.red + `Full tunnel failed: ${e.message || e}` + A.reset);
  }
}

async function toggleSystemProxy() {
  if (!sysproxySupported()) return setMsg(A.red + "Device-wide is macOS-only here — set your OS proxy manually (press p)." + A.reset);
  if (!state.netService) state.netService = await primaryService();
  if (!state.netService) return setMsg(A.red + "Couldn't find your network service." + A.reset);
  const turnOn = !state.systemProxy;
  if (turnOn && !state.connected) return setMsg(A.red + "Connect first — device-wide routes every app through the tunnel." + A.reset);
  if (turnOn && state.tunActive) { try { await tun.stopTun(); } catch {} state.tunActive = false; } // exclusive with full tunnel
  state.busy = true; state.busyText = turnOn ? "enabling system proxy (may ask for your password)…" : "disabling system proxy…"; draw();
  const ok = await setSocks(state.netService, turnOn, "127.0.0.1", state.socksPort || 1080);
  state.busy = false;
  if (!ok) return setMsg(A.red + "Couldn't change the system proxy (cancelled or failed)." + A.reset);
  state.systemProxy = turnOn;
  setMsg(turnOn
    ? A.green + "Device-wide ON — every app now routes through the tunnel." + A.reset + `  ${A.dim}(press d to turn off before quitting)${A.reset}`
    : "Device-wide off — apps use your normal connection again.");
}

async function test() {
  if (!state.connected) return setMsg(A.red + "Connect first — press c." + A.reset);
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
// you redeploy. That's easy to trigger by accident and locks you out, so require a confirm.
async function regenKey() {
  const ok = await confirmWord([
    `${A.amber}${A.bold}Generate a new access key?${A.reset}`,
    ``,
    `current key  ${A.dim}${state.uuid ? ellip(state.uuid, 40) : "(none)"}${A.reset}`,
    ``,
    `This ${A.bold}replaces${A.reset} your key. Your server still expects the current one, so you'll`,
    `${A.bold}lose access until you redeploy${A.reset} (press ${A.amber}s${A.reset}) — which now uploads the new key.`,
    ``,
    `Type ${A.amber}yes${A.reset} to generate a new key, or press enter to cancel.`,
  ], "yes");
  if (!ok) { draw(); return setMsg("Kept your current key."); }
  state.uuid = crypto.randomUUID(); saveConfig({ uuid: state.uuid });
  setMsg(A.green + "New key generated." + A.reset + ` ${A.dim}Press s → redeploy to upload it to your server.${A.reset}`);
}

function openUrl(u) {
  const cmd = process.platform === "darwin" ? `open "${u}"` : process.platform === "win32" ? `start "" "${u}"` : `xdg-open "${u}"`;
  exec(cmd, () => {});
}

// In-box prompt: renders as a centered box view (state.view = "prompt") and reads input in
// raw mode — no jump to a bare top-left fullscreen readline. Returns the entered text.
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
function askLines(lines) { return promptStart(lines, ""); }
async function confirmWord(lines, word) { return (await promptStart(lines, "")).toLowerCase() === word; }

// The `s` key: pick where the server lives. VPS is the real path; Cloudflare is the demo.
async function chooseSetup() {
  const c = await askLines([
    `${A.amber}${A.bold}First-time setup${A.reset} — where should your server run?`,
    ``,
    `  ${A.amber}1${A.reset}  ${A.bold}Your own VM${A.reset} (Oracle Cloud free tier) — recommended`,
    `     ${A.dim}reaches every site, no connection cap, no ToS problems${A.reset}`,
    ``,
    `  ${A.amber}2${A.reset}  Cloudflare Workers`,
    `     ${A.dim}quick demo, but can't reach Cloudflare sites, no UDP, ToS-risky${A.reset}`,
    ``,
    `Type ${A.amber}1${A.reset} or ${A.amber}2${A.reset} (or enter to cancel).`,
  ]);
  if (c === "1") return setupVps();
  if (c === "2") return setup();
  draw(); return setMsg("Setup cancelled.");
}

async function setupVps() {
  const ok = await confirmWord([
    `${A.amber}${A.bold}Set up your own server${A.reset}`,
    ``,
    `You need a Linux VM with SSH access. An ${A.bold}Oracle Cloud Always-Free${A.reset}`,
    `${A.bold}Ubuntu${A.reset} instance is ideal (free forever). Before continuing, open`,
    `${A.bold}ports 80 and 443${A.reset} in its cloud console security list (one-time).`,
    ``,
    `This app will SSH in and install everything — server, HTTPS, firewall,`,
    `and a background service. Nothing to type on the VM.`,
    ``,
    `Type ${A.amber}yes${A.reset} to continue, or enter to cancel.`,
  ], "yes");
  if (!ok) { draw(); return setMsg("Setup cancelled."); }

  const host = await promptLine("VM public IP address", state.vpsHost || "");
  if (!host) { draw(); return setMsg("Cancelled — no IP entered."); }
  const user = await promptLine("SSH username (ubuntu for Ubuntu, opc for Oracle Linux)", state.vpsUser || "ubuntu");
  const keyRaw = await promptLine("Path to your SSH private key", state.vpsKey || `${os.homedir()}/.ssh/id_rsa`);
  const keyPath = keyRaw.replace(/^~(?=$|\/)/, os.homedir());
  saveConfig({ vpsHost: host, vpsUser: user, vpsKey: keyRaw });
  Object.assign(state, { vpsHost: host, vpsUser: user, vpsKey: keyRaw });

  state.view = "setup";
  state.steps = VPS_STEPS.map(([name, label]) => ({ name, label, status: "pending" }));
  state.busy = true; draw();
  const logFile = `${os.homedir()}/.collateral-setup.log`;
  try { fs.writeFileSync(logFile, ""); } catch {}
  try {
    const res = await provisionVps({
      host, user, keyPath,
      uuid: isUuid(state.uuid) ? state.uuid : undefined, // keep the client key as source of truth — upload it
      log: (m) => { try { fs.appendFileSync(logFile, m); } catch {} },
      onStep: (name, status, note) => {
        const st = state.steps.find((x) => x.name === name);
        if (st) { st.status = status; if (note) st.note = note; }
        draw();
      },
    });
    state.busy = false;
    state.workerUrl = res.workerUrl; state.uuid = res.uuid;
    saveConfig({ workerUrl: res.workerUrl, uuid: res.uuid });
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

async function setup() {
  const ok = await confirmWord([
    `${A.amber}${A.bold}First-time setup${A.reset} — deploy your own private endpoint.`,
    ``,
    `This deploys a proxy Worker to ${A.bold}your own${A.reset} Cloudflare account.`,
    ``,
    `${A.red}⚠  Cloudflare's Terms (§2.2.1(j)) prohibit running a proxy and can`,
    `   ban the account — including any other sites/domains on it.${A.reset}`,
    ``,
    `${A.bold}Use a throwaway Cloudflare account that hosts nothing else.${A.reset}`,
    `You'll paste one scoped API token (opened in your browser next).`,
    ``,
    `Type ${A.amber}yes${A.reset} to continue, or press enter to cancel.`,
  ], "yes");
  if (!ok) { draw(); return setMsg("Setup cancelled."); }

  openUrl(buildTokenDeepLink());
  const token = await promptLine("Paste your Cloudflare API token (the page just opened in your browser)", "");
  if (!token) { draw(); return setMsg("Setup cancelled — no token entered."); }

  state.view = "setup";
  state.steps = SETUP_STEPS.map(([name, label]) => ({ name, label, status: "pending" }));
  state.busy = true; draw();
  try {
    const res = await deployToAccount({
      token,
      existingUuid: state.uuid,
      onStep: (name, status, note) => {
        const st = state.steps.find((x) => x.name === name);
        if (st) { st.status = status; if (note) st.note = note; }
        draw();
      },
    });
    state.busy = false;
    state.workerUrl = res.workerUrl; state.uuid = res.uuid;
    saveConfig({ workerUrl: res.workerUrl, uuid: res.uuid });
    state.view = "main";
    setMsg(A.green + `Deployed to ${res.account}. Connecting…` + A.reset);
    await connect();
  } catch (e) {
    state.busy = false;
    const running = (state.steps || []).find((x) => x.status === "run");
    if (running) running.status = "fail";
    const msg = String(e.message || e);
    const hint = /1101|blocked|proxy|10202/i.test(msg)
      ? " — Cloudflare may be blocking proxy code (the ToS risk). Try a fresh account, or the self-host path."
      : /verify|active|9109|1000/i.test(msg)
      ? " — check the token was created from the link with Workers Scripts:Edit + Account Settings:Read."
      : "";
    state.view = "main";
    setMsg(A.red + `Setup failed: ${msg}${hint}` + A.reset);
  }
}

async function handleKey(k) {
  switch (k) {
    case "q": return quit();
    case "s": return chooseSetup();
    case "d": return toggleSystemProxy();
    case "f": return toggleTun();
    case "c": return state.connected ? disconnect() : connect();
    case "t": return test();
    case "g": return regenKey();
    case "k":
      openUrl(buildTokenDeepLink());
      return setMsg("Opened the Cloudflare token page in your browser.");
    case "p": state.view = "help"; return draw();
    case "w": {
      const v = await promptLine("Worker address (wss://your-worker.workers.dev)", state.workerUrl);
      state.workerUrl = v || ""; saveConfig({ workerUrl: state.workerUrl });
      return setMsg(state.workerUrl ? "Saved worker address." : "Cleared worker address.");
    }
    case "u": {
      const v = await promptLine("Access key (UUID) — paste it", state.uuid);
      state.uuid = v || ""; saveConfig({ uuid: state.uuid });
      return setMsg(state.uuid ? "Saved access key." : "Cleared access key.");
    }
    default: return;
  }
}

function keyHandler(str) {
  if (str === "\x03") return quit(); // Ctrl-C
  if (state.view === "prompt") return promptKey(str);
  // SGR mouse event: \x1b[<button;x;yM (press) / m (release). Act on left press only;
  // ignore release, drag, and wheel (64/65) — the wheel is swallowed so scroll stays locked.
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
  const k = str.length === 1 ? str.toLowerCase() : "";
  if (k === "q") return quit();                 // quit works even mid-connect/deploy
  if (!k) { if (events.length) return; return draw(); } // no key: mouse-only chunk, or re-sync
  if (state.view === "help") { state.view = "main"; return draw(); }
  if (state.busy) return;
  handleKey(k);
}

function hitAt(X, Y) {
  return hitTest(lastBuilt || buildBox(state), process.stdout.columns || 80, process.stdout.rows || 24, X, Y);
}

function onClick(X, Y) {
  if (state.view === "help") { state.view = "main"; return draw(); }
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

let cleaned = false;
function cleanup() {
  if (cleaned) return; cleaned = true;
  if (renderTimer) clearInterval(renderTimer);
  // Signal the root TUN session to tear down (restores routing). Synchronous file touch, safe
  // here; the session also self-heals via its owner-PID watchdog if this never runs.
  if (state.tunActive) tun.requestStopSync();
  if (socks) { try { socks.close(); } catch {} }
  try { process.stdin.setRawMode(false); } catch {}
  // Synchronous write so the terminal is restored even though process.exit() follows —
  // an async write would be truncated and leave the terminal stuck in the alt buffer.
  try { fs.writeSync(process.stdout.fd, SHOW + WRAP + SCREEN_OFF); }
  catch { w(SHOW + WRAP + SCREEN_OFF); }
}
async function quit() {
  if (quitting) return;
  quitting = true;
  // Best-effort: don't leave the user's traffic pointed at a dead proxy/TUN on exit.
  if (state.tunActive) {
    state.busy = true; state.busyText = "restoring network…"; draw();
    try { await tun.stopTun(); } catch {}
    state.tunActive = false;
  }
  if (state.systemProxy && state.netService) {
    state.busy = true; state.busyText = "restoring network…"; draw();
    try { await setSocks(state.netService, false); } catch {}
  }
  cleanup();
  process.exit(0);
}

function main() {
  if (!process.stdin.isTTY) {
    process.stdout.write(renderFrame(state) + "\n\n  (interactive controls need a real terminal — run: node tui.js)\n");
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
  // session left it on while we're not connected — that would strand the user's traffic.
  if (sysproxySupported()) (async () => {
    state.netService = await primaryService();
    state.systemProxy = await socksEnabled(state.netService);
    if (state.systemProxy && !state.connected) {
      state.msg = A.red + "Device-wide proxy is ON but not connected — press c to connect, or d to turn it off." + A.reset;
    }
    // A leftover TUN session from a crashed run would strand traffic — surface it so f turns it off.
    if (tun.supported() && await tun.isActive().catch(() => false)) {
      state.tunActive = true;
      state.msg = A.red + "A full tunnel from a previous run is still active — press f to turn it off." + A.reset;
    }
    draw();
  })();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
