// End-to-end demo: spins up a local origin, the worker-shim, and the client, then
// drives real traffic through the whole VLESS-over-WebSocket tunnel and checks it.
// Everything is on 127.0.0.1 with an ephemeral UUID — no cloud account, no ToS risk.
//
//   run:  npm run demo   (or: node run-demo.js)

import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";
import { once } from "node:events";
import { startWorker } from "./worker-shim.js";
import { startClient } from "./client.js";
import { buildVlessUri } from "./common/config.js";
import { encodeVlessHeader, uuidToBytes } from "./common/vless.js";

const C = { grn: "\x1b[32m", red: "\x1b[31m", dim: "\x1b[2m", cyan: "\x1b[36m", rst: "\x1b[0m", b: "\x1b[1m" };
const results = [];
function record(name, ok, detail) {
  results.push({ name, ok });
  const tag = ok ? `${C.grn}PASS${C.rst}` : `${C.red}FAIL${C.rst}`;
  console.log(`  ${tag}  ${name}${detail ? `  ${C.dim}${detail}${C.rst}` : ""}`);
}

// Dial through the SOCKS5 proxy and return the connected socket.
function socksConnect(proxyPort, destHost, destPort) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1");
    s.once("error", reject);
    s.once("connect", () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    s.once("data", () => {
      const h = Buffer.from(destHost, "utf8");
      const p = Buffer.alloc(2);
      p.writeUInt16BE(destPort, 0);
      s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h, p]));
      s.once("data", (reply) => {
        if (reply[1] !== 0x00) return reject(new Error("SOCKS connect failed, code " + reply[1]));
        resolve(s);
      });
    });
  });
}

function httpGetOverSocket(sock, hostHeader, path = "/") {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    sock.on("data", (d) => (data = Buffer.concat([data, d])));
    sock.on("close", () => resolve(data.toString("utf8")));
    sock.on("error", reject);
    sock.write(`GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`);
  });
}

async function main() {
  const uuid = crypto.randomUUID();
  const nonce = crypto.randomBytes(8).toString("hex");

  console.log(`\n${C.b}Collateral prototype — end-to-end tunnel demo${C.rst}`);
  console.log(`${C.dim}ephemeral uuid ${uuid}${C.rst}\n`);

  // 1. Local origin server (stands in for "the open internet").
  const origin = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`COLLATERAL-ORIGIN-OK ${nonce}`);
  });
  origin.listen(0, "127.0.0.1");
  await once(origin, "listening");
  const originPort = origin.address().port;

  // 2. Worker data plane + 3. client, both on ephemeral ports.
  const worker = startWorker({ port: 0, uuid, quiet: true });
  await once(worker, "listening");
  const workerPort = worker.address().port;

  const client = startClient({ socksPort: 0, workerUrl: `ws://127.0.0.1:${workerPort}`, uuid, quiet: true });
  await once(client, "listening");
  const socksPort = client.address().port;

  console.log(`${C.cyan}topology${C.rst}  curl -> SOCKS5(:${socksPort}) -> VLESS/ws -> worker(:${workerPort}) -> origin(:${originPort})\n`);
  console.log(`${C.b}checks${C.rst}`);

  // --- Check 1: full tunnel to the origin ---
  try {
    const s = await socksConnect(socksPort, "127.0.0.1", originPort);
    const resp = await httpGetOverSocket(s, `127.0.0.1:${originPort}`);
    record("tunnel: HTTP request reaches origin through VLESS/ws", resp.includes(nonce), resp.includes(nonce) ? `echoed nonce ${nonce}` : "nonce missing");
  } catch (e) {
    record("tunnel: HTTP request reaches origin through VLESS/ws", false, e.message);
  }

  // --- Check 2: active-probing resistance (non-WS request => decoy) ---
  try {
    const page = await new Promise((res, rej) => {
      http.get({ host: "127.0.0.1", port: workerPort, path: "/" }, (r) => {
        let d = "";
        r.on("data", (c) => (d += c));
        r.on("end", () => res(d));
      }).on("error", rej);
    });
    const looksLikeDecoy = page.includes("Service status") && !page.toLowerCase().includes("vless");
    record("probe resistance: plain GET returns an innocuous decoy page", looksLikeDecoy);
  } catch (e) {
    record("probe resistance: plain GET returns an innocuous decoy page", false, e.message);
  }

  // --- Check 3: UUID auth gate (wrong UUID => dropped, no data) ---
  try {
    const dropped = await new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${workerPort}`);
      ws.binaryType = "arraybuffer";
      let gotData = false;
      const timer = setTimeout(() => resolve(!gotData), 800);
      ws.onopen = () => {
        const badUuid = uuidToBytes(crypto.randomUUID());
        ws.send(encodeVlessHeader({ uuid: badUuid, host: "127.0.0.1", port: originPort }));
        ws.send(Buffer.from(`GET / HTTP/1.1\r\nHost: x\r\n\r\n`));
      };
      ws.onmessage = () => { gotData = true; clearTimeout(timer); resolve(false); };
      ws.onclose = () => { clearTimeout(timer); resolve(!gotData); };
      ws.onerror = () => {};
    });
    record("auth gate: forged UUID is rejected with no proxying", dropped);
  } catch (e) {
    record("auth gate: forged UUID is rejected with no proxying", false, e.message);
  }

  // --- Check 4 (optional): real HTTPS to the open internet through the tunnel ---
  try {
    const raw = await socksConnect(socksPort, "example.com", 443);
    const secure = tls.connect({ socket: raw, servername: "example.com", ALPNProtocols: ["http/1.1"] });
    const status = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("timeout")), 6000);
      secure.once("secureConnect", () => secure.write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"));
      let buf = "";
      secure.on("data", (d) => {
        buf += d;
        const line = buf.split("\r\n")[0];
        if (line.startsWith("HTTP/")) { clearTimeout(t); resolve(line); secure.destroy(); }
      });
      secure.on("error", reject);
    });
    record(`live exit: HTTPS to example.com over the tunnel  ${C.dim}(${status.trim()})${C.rst}`, /200|30\d/.test(status), "optional");
  } catch (e) {
    console.log(`  ${C.dim}SKIP  live exit: no/blocked egress (${e.message}) — the localhost checks above still prove the mechanism${C.rst}`);
  }

  // --- Show the generated client config (what onboarding hands the user) ---
  const uri = buildVlessUri({ uuid, host: "your-domain.example", port: 443, path: "/" + nonce.slice(0, 8), sni: "your-domain.example", name: "Collateral-demo" });
  console.log(`\n${C.b}generated client config${C.rst} ${C.dim}(importable into sing-box/Xray for interop)${C.rst}\n  ${uri}\n`);

  worker.close();
  client.close();
  origin.close();

  const passed = results.filter((r) => r.ok).length;
  const required = results.length;
  console.log(`${C.b}result${C.rst}  ${passed}/${required} checks passed\n`);
  process.exit(passed === required ? 0 : 1);
}

main().catch((e) => {
  console.error("demo crashed:", e);
  process.exit(1);
});
