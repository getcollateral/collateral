// Worker-shim: a local Node stand-in for the Cloudflare Worker data plane.
// It runs the SAME VLESS logic (common/vless.js) the deployable worker/_worker.js
// uses, but against Node's net.connect() instead of cloudflare:sockets connect().
// This lets you exercise the full packet lifecycle on localhost, no cloud account,
// no ToS risk.
//
//   [ non-WebSocket request ]  -> decoy page          (active-probing resistance)
//   [ WebSocket + valid UUID ] -> parse VLESS, connect() outbound, bidirectional pipe
//   [ WebSocket + bad UUID ]   -> drop the connection

import http from "node:http";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { FrameParser, encodeFrame, computeAcceptKey, OPCODES } from "./common/ws-frame.js";
import { parseVlessHeader, buildVlessResponse, uuidToBytes, uuidEquals, bytesToUuid } from "./common/vless.js";
import { decoyPage, DECOY_HEADERS } from "./common/decoy.js";

export function startWorker({ port = 8787, host = "127.0.0.1", uuid, quiet = false } = {}) {
  if (!uuid) throw new Error("startWorker: uuid is required");
  const expected = uuidToBytes(uuid);

  const server = http.createServer((req, res) => {
    // Anything that is not a WebSocket upgrade gets the decoy.
    res.writeHead(200, DECOY_HEADERS);
    res.end(decoyPage());
  });

  server.on("upgrade", (req, socket, head) => {
    if ((req.headers["upgrade"] || "").toLowerCase() !== "websocket" || !req.headers["sec-websocket-key"]) {
      socket.destroy();
      return;
    }
    const accept = computeAcceptKey(req.headers["sec-websocket-key"]);
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );
    handleSession(socket, head, expected, quiet);
  });

  server.listen(port, host, () => {
    if (!quiet) console.log(`[worker-shim] listening on ${host}:${server.address().port}  uuid=${bytesToUuid(expected)}`);
  });
  return server;
}

function handleSession(socket, head, expected, quiet) {
  const parser = new FrameParser();
  let upstream = null;
  let headerParsed = false;
  let closed = false;

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { socket.write(encodeFrame(OPCODES.CLOSE, Buffer.alloc(0))); } catch {}
    try { socket.destroy(); } catch {}
    if (upstream) try { upstream.destroy(); } catch {}
  };

  const handle = (messages) => {
    for (const m of messages) {
      if (m.opcode === OPCODES.CLOSE) return closeAll();
      if (m.opcode === OPCODES.PING) {
        try { socket.write(encodeFrame(OPCODES.PONG, m.payload)); } catch {}
        continue;
      }
      if (m.opcode !== OPCODES.BIN && m.opcode !== OPCODES.TEXT) continue;

      if (!headerParsed) {
        headerParsed = true;
        let hdr;
        try {
          hdr = parseVlessHeader(m.payload);
        } catch {
          return closeAll();
        }
        if (!uuidEquals(hdr.uuid, expected)) return closeAll(); // bad auth -> drop
        if (hdr.command !== 1) return closeAll();                // TCP only; connect() has no UDP

        upstream = net.connect({ host: hdr.host, port: hdr.port });
        // Writes before 'connect' are buffered by Node, preserving order.
        try { socket.write(encodeFrame(OPCODES.BIN, Buffer.from(buildVlessResponse()))); } catch {}
        if (hdr.payload.length) upstream.write(Buffer.from(hdr.payload));
        upstream.on("data", (d) => { try { socket.write(encodeFrame(OPCODES.BIN, d)); } catch {} });
        upstream.on("close", closeAll);
        upstream.on("error", (e) => { if (!quiet) console.error("[worker-shim] upstream error:", e.code || e.message); closeAll(); });
      } else if (upstream && !upstream.destroyed) {
        upstream.write(Buffer.from(m.payload));
      }
    }
  };

  if (head && head.length) handle(parser.push(head));
  socket.on("data", (d) => handle(parser.push(d)));
  socket.on("close", closeAll);
  socket.on("error", closeAll);
}

// Run standalone: `USER_UUID=... node worker-shim.js`
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const uuid = process.env.USER_UUID;
  if (!uuid) {
    console.error("Set USER_UUID (a v4 UUID) to run the shim standalone, or use `npm run demo`.");
    process.exit(1);
  }
  startWorker({ port: Number(process.env.WORKER_PORT || 8787), uuid });
}
