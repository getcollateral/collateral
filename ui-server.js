// Collateral control panel — a local web GUI so non-technical users never touch a
// terminal. This Node process runs the SOCKS tunnel AND serves a dashboard at
// 127.0.0.1 that it auto-opens in the browser. Zero dependencies; no native toolchain.
//
//   npm run ui
//
// Security: bound to loopback only, plus a per-run token + Host check so no other
// web page (DNS-rebinding / CSRF) can drive the tunnel.

import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { exec } from "node:child_process";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { startClient } from "./client.js";
import { buildTokenDeepLink, FALLBACK_URL } from "./provision/deeplink.js";

// Store config in the user's home dir, not next to the script — a packaged .app
// bundle is read-only.
const CONFIG_PATH = path.join(os.homedir(), ".collateral-config.json");
const TOKEN = crypto.randomUUID();
const UI_PORT = Number(process.env.UI_PORT || 8799);

let config = loadConfig(); // { workerUrl, uuid }
let socks = null; // running SOCKS client server
let socksPort = null;

function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); } catch { return { workerUrl: "", uuid: "" }; }
}
function saveConfig(patch) {
  config = { ...config, ...patch };
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2)); } catch {}
}

const isWsUrl = (s) => /^wss?:\/\/[^\s]+$/i.test(s || "");
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");

function statusPayload() {
  return { connected: !!socks, socksPort, workerUrl: config.workerUrl || "", uuid: config.uuid || "" };
}

function startSocks(workerUrl, uuid, port) {
  return new Promise((resolve, reject) => {
    const srv = startClient({ socksPort: port, workerUrl, uuid, quiet: true });
    srv.once("listening", () => resolve(srv));
    srv.once("error", reject);
  });
}

async function connect() {
  if (socks) return statusPayload();
  if (!isWsUrl(config.workerUrl)) throw new Error("Enter a valid worker address starting with wss:// (or ws://).");
  if (!isUuid(config.uuid)) throw new Error("Enter a valid UUID (or click Generate).");
  try {
    socks = await startSocks(config.workerUrl, config.uuid, 1080);
  } catch (e) {
    if (e && e.code === "EADDRINUSE") socks = await startSocks(config.workerUrl, config.uuid, 0);
    else throw e;
  }
  socksPort = socks.address().port;
  return statusPayload();
}

function disconnect() {
  if (socks) { try { socks.close(); } catch {} }
  socks = null; socksPort = null;
  return statusPayload();
}

// Dial through the running SOCKS proxy to a non-Cloudflare echo service and read the
// exit IP, proving traffic really leaves via the worker.
function getExitIP() {
  return new Promise((resolve, reject) => {
    if (!socks) return reject(new Error("Not connected."));
    const timer = setTimeout(() => { try { s.destroy(); } catch {} reject(new Error("Test timed out.")); }, 9000);
    const s = net.connect(socksPort, "127.0.0.1");
    s.once("error", (e) => { clearTimeout(timer); reject(e); });
    s.once("connect", () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    s.once("data", () => {
      const host = Buffer.from("checkip.amazonaws.com");
      const p = Buffer.alloc(2); p.writeUInt16BE(443, 0);
      s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host, p]));
      s.once("data", (reply) => {
        if (reply[1] !== 0x00) { clearTimeout(timer); return reject(new Error("Proxy could not reach the test site.")); }
        const secure = tls.connect({ socket: s, servername: "checkip.amazonaws.com", ALPNProtocols: ["http/1.1"] });
        secure.once("secureConnect", () => secure.write("GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n"));
        let buf = "";
        secure.on("data", (d) => (buf += d));
        secure.on("close", () => {
          clearTimeout(timer);
          const body = buf.split("\r\n\r\n").slice(1).join("\r\n\r\n").trim();
          const ip = (body.match(/\d{1,3}(\.\d{1,3}){3}/) || [])[0];
          ip ? resolve(ip) : reject(new Error("Couldn't read the exit IP."));
        });
        secure.on("error", (e) => { clearTimeout(timer); reject(e); });
      });
    });
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => { try { resolve(d ? JSON.parse(d) : {}); } catch { resolve({}); } });
  });
}
function sendJSON(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(obj));
}

async function handleApi(req, res, url) {
  const m = req.method;
  if (m === "GET" && url.pathname === "/api/status") return sendJSON(res, 200, statusPayload());
  if (m === "POST" && url.pathname === "/api/generate-uuid") return sendJSON(res, 200, { uuid: crypto.randomUUID() });
  if (m === "GET" && url.pathname === "/api/deeplink") return sendJSON(res, 200, { url: buildTokenDeepLink(), fallback: FALLBACK_URL });
  if (m === "POST" && url.pathname === "/api/config") {
    const b = await readBody(req);
    saveConfig({ workerUrl: (b.workerUrl || "").trim(), uuid: (b.uuid || "").trim() });
    return sendJSON(res, 200, statusPayload());
  }
  if (m === "POST" && url.pathname === "/api/connect") {
    const b = await readBody(req);
    saveConfig({ workerUrl: (b.workerUrl || "").trim(), uuid: (b.uuid || "").trim() });
    try { return sendJSON(res, 200, await connect()); }
    catch (e) { return sendJSON(res, 400, { error: String(e.message || e) }); }
  }
  if (m === "POST" && url.pathname === "/api/disconnect") return sendJSON(res, 200, disconnect());
  if (m === "POST" && url.pathname === "/api/quit") {
    sendJSON(res, 200, { ok: true });
    disconnect();
    setTimeout(() => process.exit(0), 150);
    return;
  }
  if (m === "POST" && url.pathname === "/api/test") {
    try { return sendJSON(res, 200, { exitIP: await getExitIP() }); }
    catch (e) { return sendJSON(res, 400, { error: String(e.message || e) }); }
  }
  return sendJSON(res, 404, { error: "not found" });
}

const server = http.createServer(async (req, res) => {
  const host = (req.headers.host || "").split(":")[0];
  if (host !== "127.0.0.1" && host !== "localhost") { res.writeHead(403); return res.end("forbidden"); }
  const url = new URL(req.url, "http://127.0.0.1");
  if (req.method === "GET" && url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    return res.end(page());
  }
  if (url.pathname.startsWith("/api/")) {
    if (req.headers["x-collateral-token"] !== TOKEN) { res.writeHead(403); return res.end("bad token"); }
    try { return await handleApi(req, res, url); } catch (e) { return sendJSON(res, 500, { error: String(e.message || e) }); }
  }
  res.writeHead(404); res.end("not found");
});

server.listen(UI_PORT, "127.0.0.1", () => {
  const url = `http://127.0.0.1:${server.address().port}/`;
  console.log(`\n  Collateral control panel:  ${url}\n  (leave this window running; close it to stop the tunnel)\n`);
  if (!process.env.COLLATERAL_NO_OPEN) exec(`open "${url}"`, () => {});
});
server.on("error", (e) => {
  if (e.code === "EADDRINUSE") { console.error(`Port ${UI_PORT} is busy. Try:  UI_PORT=8800 npm run ui`); process.exit(1); }
  throw e;
});

for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { disconnect(); process.exit(0); });

function page() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Collateral</title>
<style>
  :root{
    --bg:#f1f4f8; --surface:#fff; --surface-2:#e9eef4; --ink:#111922; --muted:#51606f; --faint:#8492a0;
    --border:#d7e0ea; --signal:#c9781f; --teal:#1b6a6e; --good:#2c8b57; --bad:#bc3f38;
    --font-mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --font:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  @media (prefers-color-scheme:dark){:root{
    --bg:#0c1218; --surface:#131c25; --surface-2:#182430; --ink:#e7eef6; --muted:#9daab8; --faint:#6c7a88;
    --border:#25333f; --signal:#f0a63d; --teal:#54c8cd; --good:#5bc38c; --bad:#eb7c73;
  }}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);line-height:1.5;
    display:flex;justify-content:center;padding:32px 18px 64px}
  .app{width:100%;max-width:540px}
  header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
  .brand{font-family:var(--font-mono);font-weight:700;font-size:1.3rem;letter-spacing:-.02em}
  .brand::before{content:"";display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--signal);margin-right:9px;vertical-align:middle}
  .pill{font-family:var(--font-mono);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;font-weight:700;
    padding:5px 11px;border-radius:999px;border:1px solid var(--border);color:var(--faint);display:flex;align-items:center;gap:7px}
  .pill .dot{width:8px;height:8px;border-radius:50%;background:var(--faint)}
  .pill.on{color:var(--good);border-color:color-mix(in srgb,var(--good) 40%,transparent)} .pill.on .dot{background:var(--good)}
  .pill.busy{color:var(--signal)} .pill.busy .dot{background:var(--signal)}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:16px}
  h2{font-family:var(--font-mono);font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);margin:0 0 14px;font-weight:600}
  label{display:block;font-size:.82rem;color:var(--muted);margin:0 0 5px}
  .row{display:flex;gap:8px;margin-bottom:14px}
  .row:last-child{margin-bottom:0}
  input{width:100%;font-family:var(--font-mono);font-size:.86rem;padding:10px 12px;border-radius:9px;
    border:1px solid var(--border);background:var(--bg);color:var(--ink)}
  input:focus{outline:2px solid var(--signal);outline-offset:1px;border-color:transparent}
  button{font-family:var(--font);font-weight:600;font-size:.86rem;padding:10px 14px;border-radius:9px;
    border:1px solid var(--border);background:var(--surface-2);color:var(--ink);cursor:pointer;white-space:nowrap}
  button:hover{border-color:var(--signal)} button:disabled{opacity:.5;cursor:default}
  button.ghost{background:transparent}
  .connect{width:100%;font-size:1rem;padding:15px;border:0;color:#fff;background:var(--good);margin-top:2px}
  .connect.on{background:var(--bad)}
  .connect:disabled{background:var(--faint)}
  .kv{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:9px 0;border-top:1px solid var(--border);font-size:.9rem}
  .kv:first-of-type{border-top:0}
  .kv .k{color:var(--muted)} .kv .v{font-family:var(--font-mono);font-size:.84rem;text-align:right;word-break:break-all}
  .hintbox{font-size:.82rem;color:var(--muted);background:var(--surface-2);border:1px solid var(--border);border-radius:9px;padding:12px 14px}
  .hintbox code{font-family:var(--font-mono);background:var(--bg);padding:.1em .4em;border-radius:5px;color:var(--ink)}
  .steps{margin:0;padding-left:1.2em;font-size:.84rem;color:var(--muted)} .steps li{margin-bottom:6px}
  #toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(120%);transition:transform .25s;
    background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:9px;font-size:.85rem;max-width:90vw;box-shadow:0 8px 30px rgba(0,0,0,.25)}
  #toast.show{transform:translateX(-50%) translateY(0)} #toast.err{background:var(--bad);color:#fff}
  .foot{font-size:.75rem;color:var(--faint);text-align:center;margin-top:8px}
  .foot b{color:var(--signal)}
</style>
</head>
<body>
<div class="app">
  <header>
    <div class="brand">Collateral</div>
    <div id="pill" class="pill"><span class="dot"></span><span id="pillText">Disconnected</span></div>
  </header>

  <div class="card">
    <h2>Your endpoint</h2>
    <label for="workerUrl">Worker address</label>
    <div class="row"><input id="workerUrl" placeholder="wss://collateral-reflector.you.workers.dev" autocomplete="off" spellcheck="false"></div>
    <label for="uuid">Access key (UUID)</label>
    <div class="row">
      <input id="uuid" placeholder="paste, or generate" autocomplete="off" spellcheck="false">
      <button id="gen" class="ghost">Generate</button>
    </div>
    <div class="row"><button id="token" class="ghost" style="width:100%">Open Cloudflare token page…</button></div>
    <button id="connect" class="connect">Connect</button>
  </div>

  <div class="card">
    <h2>Status</h2>
    <div class="kv"><span class="k">State</span><span class="v" id="sState">—</span></div>
    <div class="kv"><span class="k">Local proxy</span><span class="v" id="sProxy">—</span></div>
    <div class="kv"><span class="k">Exit IP</span><span class="v" id="sExit">—</span></div>
    <div class="row" style="margin-top:14px"><button id="test" style="width:100%">Test connection</button></div>
  </div>

  <div class="card">
    <h2>Point your browser at it</h2>
    <ol class="steps">
      <li><b>Firefox:</b> Settings → Network Settings → Manual proxy → SOCKS v5 host <code id="ph1">127.0.0.1</code>, port <code id="pp1">1080</code>, and tick “Proxy DNS when using SOCKS v5”.</li>
      <li><b>macOS (all apps):</b> System Settings → Network → your Wi‑Fi → Details → Proxies → SOCKS, host <code>127.0.0.1</code> port <code id="pp2">1080</code>.</li>
    </ol>
    <div class="hintbox" style="margin-top:12px">Most big sites (Google, YouTube, Instagram, Reddit) work now. Cloudflare‑hosted sites (Discord, ChatGPT) need a relay you control — see the README.</div>
  </div>

  <div class="foot">Running locally on your machine · <b>throwaway Cloudflare account only</b></div>
  <div style="text-align:center;margin-top:10px"><button id="quit" class="ghost">Quit Collateral</button></div>
</div>
<div id="toast"></div>

<script>
const TOKEN = ${JSON.stringify(TOKEN)};
const $ = (id) => document.getElementById(id);
async function api(path, method="GET", body){
  const r = await fetch(path, { method, headers: { "x-collateral-token": TOKEN, "content-type":"application/json" }, body: body?JSON.stringify(body):undefined });
  const j = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(j.error || ("HTTP "+r.status));
  return j;
}
let toastTimer;
function toast(msg, err){ const t=$("toast"); t.textContent=msg; t.className="show"+(err?" err":""); clearTimeout(toastTimer); toastTimer=setTimeout(()=>t.className="",3200); }

function render(s){
  const on = s.connected;
  $("pill").className = "pill" + (on?" on":"");
  $("pillText").textContent = on ? "Connected" : "Disconnected";
  $("sState").textContent = on ? "Connected" : "Not connected";
  const port = s.socksPort || 1080;
  $("sProxy").textContent = on ? ("127.0.0.1:" + port) : "—";
  $("pp1").textContent = port; $("pp2").textContent = port;
  const btn = $("connect"); btn.textContent = on ? "Disconnect" : "Connect"; btn.className = "connect" + (on?" on":"");
  $("test").disabled = !on;
  if (!on) $("sExit").textContent = "—";
  if (s.workerUrl && !document.activeElement.matches("#workerUrl")) $("workerUrl").value = s.workerUrl;
  if (s.uuid && !document.activeElement.matches("#uuid")) $("uuid").value = s.uuid;
}

$("gen").onclick = async () => { const {uuid} = await api("/api/generate-uuid","POST"); $("uuid").value = uuid; toast("New access key generated — deploy it as USER_UUID on the worker."); };
$("token").onclick = async () => { const {url} = await api("/api/deeplink"); window.open(url, "_blank"); };
$("connect").onclick = async () => {
  const btn=$("connect"); const wasOn = btn.classList.contains("on");
  btn.disabled = true; $("pill").className="pill busy"; $("pillText").textContent = wasOn?"Disconnecting…":"Connecting…";
  try {
    if (wasOn) render(await api("/api/disconnect","POST"));
    else { render(await api("/api/connect","POST",{ workerUrl:$("workerUrl").value.trim(), uuid:$("uuid").value.trim() })); toast("Connected. Point your browser at the proxy below."); }
  } catch(e){ toast(e.message, true); render(await api("/api/status")); }
  finally { btn.disabled=false; }
};
$("test").onclick = async () => {
  $("sExit").textContent = "testing…"; $("test").disabled=true;
  try { const {exitIP} = await api("/api/test","POST"); $("sExit").textContent = exitIP; toast("Traffic is exiting via "+exitIP); }
  catch(e){ $("sExit").textContent = "failed"; toast(e.message, true); }
  finally { $("test").disabled=false; }
};
$("quit").onclick = async () => {
  try { await api("/api/quit","POST"); } catch {}
  document.body.innerHTML = '<div style="max-width:540px;margin:20vh auto;text-align:center;font-family:system-ui;color:var(--muted)"><h2 style="color:var(--ink);letter-spacing:.1em">COLLATERAL STOPPED</h2><p>The tunnel is off. You can close this tab.</p></div>';
};
api("/api/status").then(render).catch(()=>{});
</script>
</body>
</html>`;
}
