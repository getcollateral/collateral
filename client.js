// Client: a local SOCKS5 inbound that wraps each connection in VLESS and tunnels
// it over WebSocket-in-TLS to the worker. In product mode this would be a
// system-wide TUN (sing-box/libbox); a SOCKS5 inbound exercises the identical
// data path with no privileges. Point any app at socks5h://127.0.0.1:1080.
//
//   app -> SOCKS5 -> [VLESS header + stream] -> WebSocket -> worker -> destination
//
// Uses Node's built-in global WebSocket (no dependencies).

import net from "node:net";
import { fileURLToPath } from "node:url";
import { encodeVlessHeader, uuidToBytes } from "./common/vless.js";

export function startClient({ socksPort = 1080, host = "127.0.0.1", workerUrl, uuid, quiet = false } = {}) {
  if (!workerUrl) throw new Error("startClient: workerUrl is required");
  if (!uuid) throw new Error("startClient: uuid is required");
  const uuidBytes = uuidToBytes(uuid);

  const server = net.createServer((sock) => {
    sock.on("error", () => {});
    // Dispatch on the SOCKS version byte. macOS "use system proxy" mode makes Firefox/Zen
    // send SOCKS4 (it can't record the version), so we must speak both, not just SOCKS5.
    sock.once("data", (chunk) => {
      try {
        if (chunk[0] === 0x05) return socks5(sock, chunk);
        if (chunk[0] === 0x04) return socks4(sock, chunk);
      } catch { /* fall through */ }
      sock.destroy();
    });
  });

  // SOCKS5: negotiate no-auth, then read the CONNECT request.
  function socks5(sock, greeting) {
    sock.write(Buffer.from([0x05, 0x00])); // version 5, no auth
    sock.once("data", (req) => {
      if (req[0] !== 0x05 || req[1] !== 0x01) {
        sock.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return sock.destroy();
      }
      const atyp = req[3];
      let target, portOff;
      if (atyp === 0x01) { target = `${req[4]}.${req[5]}.${req[6]}.${req[7]}`; portOff = 8; }
      else if (atyp === 0x03) { const len = req[4]; target = req.subarray(5, 5 + len).toString("utf8"); portOff = 5 + len; }
      else if (atyp === 0x04) { const p = []; for (let i = 0; i < 8; i++) p.push(req.readUInt16BE(4 + i * 2).toString(16)); target = p.join(":"); portOff = 20; }
      else { sock.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return sock.destroy(); }
      const port = req.readUInt16BE(portOff);
      const extra = req.subarray(portOff + 2);
      sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); // succeeded
      openTunnel(sock, target, port, extra);
    });
  }

  // SOCKS4 / SOCKS4a: [4, cmd, port(2), ip(4), userid\0, (4a: host\0)]. The macOS system
  // proxy resolves DNS locally and sends SOCKS4 with an IP; SOCKS4a carries a hostname.
  function socks4(sock, req) {
    if (req[1] !== 0x01) { sock.write(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0])); return sock.destroy(); } // CONNECT only
    const port = req.readUInt16BE(2);
    const ip = [req[4], req[5], req[6], req[7]];
    let i = 8;
    while (i < req.length && req[i] !== 0x00) i++; // skip userid to its null terminator
    let target;
    if (ip[0] === 0 && ip[1] === 0 && ip[2] === 0 && ip[3] !== 0) {
      let d = i + 1, e = d;                          // SOCKS4a: hostname follows the userid null
      while (e < req.length && req[e] !== 0x00) e++;
      target = req.subarray(d, e).toString("utf8");
      i = e;
    } else {
      target = ip.join(".");
    }
    const extra = req.subarray(i + 1);
    sock.write(Buffer.concat([Buffer.from([0x00, 0x5a]), req.subarray(2, 8)])); // request granted
    openTunnel(sock, target, port, extra);
  }

  function openTunnel(sock, target, port, extra) {
    const ws = new WebSocket(workerUrl);
    ws.binaryType = "arraybuffer";
    let wsOpen = false;
    let respParsed = false;
    const buffered = [];
    if (extra && extra.length) buffered.push(extra);

    // Buffer app bytes until the WebSocket is open so nothing is lost in the race
    // between the SOCKS success reply and the ws handshake.
    sock.on("data", (d) => {
      if (wsOpen && ws.readyState === 1) ws.send(d);
      else buffered.push(d);
    });

    ws.onopen = () => {
      ws.send(encodeVlessHeader({ uuid: uuidBytes, host: target, port, command: 1 }));
      wsOpen = true;
      for (const d of buffered) ws.send(d);
      buffered.length = 0;
    };
    ws.onmessage = (ev) => {
      let buf = Buffer.from(ev.data);
      if (!respParsed) {
        // Strip the VLESS response header: [ver:1][addonLen:1][addons].
        if (buf.length < 2) return;
        const addonLen = buf[1];
        buf = buf.subarray(2 + addonLen);
        respParsed = true;
      }
      if (buf.length) sock.write(buf);
    };
    ws.onclose = (ev) => {
      const code = ev && ev.code;
      if (!quiet && code && code !== 1000) {
        let hint = "";
        if (code === 1008) hint = " — UUID rejected: the client USER_UUID must equal the worker's USER_UUID secret";
        else if (code === 1003) hint = " — worker refused a non-TCP command";
        else if (code === 1006 || !wsOpen) hint = ` — couldn't reach/keep the tunnel to ${workerUrl} (deployed? correct URL? Error 1101/banned?)`;
        console.error(`[client] tunnel closed (code ${code}${ev.reason ? " " + ev.reason : ""})${hint}`);
      }
      try { sock.end(); } catch {}
    };
    ws.onerror = () => { try { sock.destroy(); } catch {} };
    sock.on("close", () => { try { ws.close(); } catch {} });
  }

  server.listen(socksPort, host, () => {
    if (!quiet) console.log(`[client] SOCKS5 on ${host}:${server.address().port} -> ${workerUrl}`);
  });
  return server;
}

// Run standalone: `WORKER_URL=ws://127.0.0.1:8787 USER_UUID=... node client.js`
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const uuid = process.env.USER_UUID;
  const workerUrl = process.env.WORKER_URL || "ws://127.0.0.1:8787";
  if (!uuid) {
    console.error("Set USER_UUID (matching the worker) to run the client standalone, or use `npm run demo`.");
    process.exit(1);
  }
  startClient({ socksPort: Number(process.env.SOCKS_PORT || 1080), workerUrl, uuid });
}
