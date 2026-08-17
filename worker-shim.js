// The server data plane: a small Node server that terminates the WebSocket-in-TLS
// tunnel, speaks VLESS (common/vless.js), and reflects traffic out via net.connect()
// / dgram. This same file is bundled onto your VM (see provision/vps.js) to run the
// real endpoint, and is also started locally by run-demo.js to exercise the whole
// packet lifecycle on localhost.
//
//   [ non-WebSocket request ]  -> decoy page          (active-probing resistance)
//   [ WebSocket + valid UUID ] -> parse VLESS, connect() outbound, bidirectional pipe
//   [ WebSocket + bad UUID ]   -> drop the connection

import http from "node:http";
import net from "node:net";
import dgram from "node:dgram";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { FrameParser, encodeFrame, computeAcceptKey, OPCODES } from "./common/ws-frame.js";
import { parseVlessHeader, buildVlessResponse, uuidToBytes } from "./common/vless.js";
import { decoyPage, DECOY_HEADERS } from "./common/decoy.js";

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const hexOf = (u) => Buffer.from(u).toString("hex"); // normalize 16 UUID bytes -> hex for set membership

// Build the set of allowed keys (as hex) from arbitrary lines: bare UUIDs, or `# label` comments
// and blank lines that are ignored. Multiple users share one server by each holding their own key.
export function parseKeys(lines) {
  const set = new Set();
  for (const line of lines || []) { const m = UUID_RE.exec(line || ""); if (m) set.add(hexOf(uuidToBytes(m[0]))); }
  return set;
}

// Accepts a single `uuid`, an array `uuids`, and/or a `keysFile` (one UUID per line, `#` comments).
// The keys file is re-read on change, so adding or revoking a key takes effect immediately, with
// no restart.
//
// When a keysFile is configured it is the SOLE source of truth. `uuid`/`uuids` are seeds: what a
// local run with no file uses, and the fallback for a box whose file is missing or empty. They
// are deliberately not unioned into the allowed set on every reload.
//
// Unioning them was a hole with no floor. provision/vps.js writes the owner's key into the keys
// file AND into USER_UUID in /opt/collateral/env, and every load put USER_UUID straight back.
// Nothing that edits the keys file can reach an env var - not removeKey in vps.js, not the Mac
// app's ServerKeys.remove, not its key rotation - so the provision-time key stayed valid forever:
// absent from the owner's own config, invisible in the friends list, unrevokable from either
// client. Rotation reported success while the key it had just removed still opened the tunnel.
// Three live servers were found in exactly that state, two of them sharing one such key.
export function startWorker({ port = 8787, host = "127.0.0.1", uuid, uuids, keysFile, wsPath, quiet = false } = {}) {
  const seeds = [];
  if (Array.isArray(uuids)) seeds.push(...uuids);
  if (uuid) seeds.push(uuid);

  let allowed = new Set();
  const sessions = new Set();

  // Revoking a key has to disconnect whoever holds it, not merely refuse their next connection.
  //
  // isAllowed is consulted once per session, when the VLESS header arrives, so a revoked key
  // kept working for as long as the socket stayed open - and a tunnel socket stays open for
  // days. A live server was found still carrying 38 sockets authorised under a key rotated away
  // half an hour earlier, which is exactly what "I revoked them and they are still connected"
  // looks like from the outside. 1008 is the code a key rejected at handshake already gets, so
  // the client sees one consistent signal whichever way it is turned away.
  const evictRevoked = () => {
    let n = 0;
    for (const s of [...sessions]) {
      if (s.keyHex !== null && !allowed.has(s.keyHex)) { s.close(1008); n += 1; }
    }
    if (n && !quiet) console.log(`[server] closed ${n} session(s) on revoked key(s)`);
    return n;
  };

  const loadKeys = () => {
    let fromFile = null;
    if (keysFile) { try { fromFile = parseKeys(fs.readFileSync(keysFile, "utf8").split("\n")); } catch {} }
    // Empty or unreadable falls back to the seeds rather than locking everyone out, and says so.
    // A server that answers nobody is a worse failure than one still accepting the key it was
    // built with, and an empty file is what a half-finished setup leaves behind.
    if (fromFile && fromFile.size) {
      allowed = fromFile;
    } else {
      if (keysFile && !quiet) console.warn(`[server] ${keysFile} is empty or unreadable; falling back to the provisioning key`);
      allowed = parseKeys(seeds);
    }
    if (!quiet) console.log(`[server] ${allowed.size} key(s) loaded`);
    return evictRevoked();
  };

  loadKeys();
  if (!allowed.size) throw new Error("startWorker: at least one key (uuid / uuids / keysFile) is required");
  if (keysFile) {
    // Re-armed after every event on purpose. Both clients revoke by writing a temp file and
    // mv-ing it over this one, which replaces the inode, and a watch on the old inode never
    // fires again. Left as a one-shot, the documented "re-read on change" quietly stopped
    // working after the very first revoke and everything afterwards leaned on SIGHUP alone.
    const arm = () => {
      try {
        const w = fs.watch(keysFile, { persistent: false }, () => {
          try { w.close(); } catch {}
          loadKeys();
          arm();
        });
      } catch {}
    };
    arm();
    process.on("SIGHUP", loadKeys); // explicit reload signal - belt-and-suspenders with the file watch
  }
  const isAllowed = (u) => allowed.has(hexOf(u));

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
    // The endpoint path is part of the secret, so it has to be checked before we admit to
    // speaking WebSocket at all.
    //
    // provision/vps.js mints a random path and puts it in the URL every client is given, but
    // the server was never told what it was, so every path answered 101. That made the random
    // path decorative and defeated the decoy in a single probe: a host that serves static
    // content does not complete a WebSocket handshake on an arbitrary URL, so one upgrade
    // request to /anything distinguished this box from the site it claims to be.
    //
    // A mismatch gets exactly what a plain GET for that path gets, because any other answer is
    // itself a signal.
    //
    // Unset means no check, which is what keeps servers provisioned before this shipped
    // working; they pick the check up when setup is next run.
    if (wsPath && (req.url || "").split("?")[0] !== wsPath) {
      const body = decoyPage();
      const head = Object.entries(DECOY_HEADERS).map(([k, v]) => `${k}: ${v}\r\n`).join("");
      try {
        socket.write(`HTTP/1.1 200 OK\r\n${head}content-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`);
      } catch {}
      socket.end();
      return;
    }
    const accept = computeAcceptKey(req.headers["sec-websocket-key"]);
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );
    handleSession(socket, head, isAllowed, quiet, sessions);
  });

  server.listen(port, host, () => {
    if (!quiet) console.log(`[server] listening on ${host}:${server.address().port}  keys=${allowed.size}`);
  });
  return server;
}

const UDP_IDLE_MS = 60000; // close an idle UDP association after this long (no close signal in UDP)

function handleSession(socket, head, isAllowed, quiet, sessions) {
  const parser = new FrameParser();
  let mode = null;         // "tcp" | "udp"
  let upstream = null;     // TCP: net.Socket
  let udp = null;          // UDP: { sock, host, port, bump }
  let headerParsed = false;
  let closed = false;
  let idleTimer = null;

  // Registered for the whole life of the connection, including before a header arrives, so the
  // entry is removed on exactly one path. `keyHex` stays null until a key is accepted, and a
  // null-keyed session is never evicted: it has not been let in yet, so there is nothing to
  // revoke, and it is already bounded by the handshake completing or the socket closing.
  const session = { keyHex: null, close: (code) => closeAll(code) };
  sessions.add(session);

  const closeAll = (code) => {
    if (closed) return;
    closed = true;
    sessions.delete(session);
    if (idleTimer) clearTimeout(idleTimer);
    const payload = code ? Buffer.from([(code >> 8) & 0xff, code & 0xff]) : Buffer.alloc(0);
    try { socket.write(encodeFrame(OPCODES.CLOSE, payload)); } catch {}
    try { socket.destroy(); } catch {}
    if (upstream) try { upstream.destroy(); } catch {}
    if (udp) try { udp.sock.close(); } catch {}
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
        if (!isAllowed(hdr.uuid)) return closeAll(1008); // 1008 (policy violation) = "key rejected/revoked"
        // Recorded so a later revoke can find this session and close it. Set only after the
        // key has been accepted, which is what makes it the right thing to re-check on reload.
        session.keyHex = hexOf(hdr.uuid);

        if (hdr.command === 1) {
          mode = "tcp";
          upstream = net.connect({ host: hdr.host, port: hdr.port });
          // Writes before 'connect' are buffered by Node, preserving order.
          try { socket.write(encodeFrame(OPCODES.BIN, Buffer.from(buildVlessResponse()))); } catch {}
          if (hdr.payload.length) upstream.write(Buffer.from(hdr.payload));
          upstream.on("data", (d) => { try { socket.write(encodeFrame(OPCODES.BIN, d)); } catch {} });
          upstream.on("close", closeAll);
          upstream.on("error", (e) => { if (!quiet) console.error("[worker-shim] upstream error:", e.code || e.message); closeAll(); });
        } else if (hdr.command === 2) {
          // UDP relay. One WebSocket carries one destination (host:port). Each subsequent WS
          // message is a datagram to send; each datagram received comes back as a WS message
          // (no length prefix / no response header - WebSocket already preserves boundaries).
          mode = "udp";
          const sock = dgram.createSocket(hdr.atype === 3 ? "udp6" : "udp4");
          const bump = () => { if (idleTimer) clearTimeout(idleTimer); idleTimer = setTimeout(closeAll, UDP_IDLE_MS); };
          udp = { sock, host: hdr.host, port: hdr.port, bump };
          sock.on("message", (msg) => { try { socket.write(encodeFrame(OPCODES.BIN, msg)); } catch {} bump(); });
          sock.on("error", (e) => { if (!quiet) console.error("[worker-shim] udp error:", e.code || e.message); closeAll(); });
          if (hdr.payload.length) { try { sock.send(Buffer.from(hdr.payload), hdr.port, hdr.host); } catch {} }
          bump();
        } else {
          return closeAll(); // MUX / unknown command unsupported
        }
      } else if (mode === "tcp" && upstream && !upstream.destroyed) {
        upstream.write(Buffer.from(m.payload));
      } else if (mode === "udp" && udp) {
        try { udp.sock.send(Buffer.from(m.payload), udp.port, udp.host); } catch {}
        udp.bump();
      }
    }
  };

  // A framing error closes this one connection and must never reach the event loop.
  //
  // parser.push throws for what a conforming peer cannot send: an over-large declared length,
  // a fragmented control frame, a continuation with nothing to continue. Both call sites below
  // run inside socket handlers, so an uncaught throw would end the process, take every other
  // user's tunnel down with it, and hand a stranger a one-packet outage.
  const feed = (chunk) => {
    let messages;
    try {
      messages = parser.push(chunk);
    } catch (e) {
      if (!quiet) console.error("[worker-shim] framing error:", e.message);
      return closeAll(e.code || 1002);
    }
    handle(messages);
  };

  if (head && head.length) feed(head);
  socket.on("data", feed);
  // A client that leaves cleanly sends a WebSocket CLOSE frame, handled in handle() above, and
  // one that is reset arrives as "error". The gap was the middle case: a client that simply
  // drops - laptop asleep, process killed, network handoff - delivers only a TCP FIN.
  //
  // The socket from the "upgrade" event is the one http.Server accepted, and http.Server sets
  // allowHalfOpen so a response can outlive its request's FIN. So on FIN Node emits "end" and
  // then stops: it does not close the writable half, "close" never fires, and closeAll never
  // runs. Nothing listened for "end", so the fd sat in CLOSE-WAIT indefinitely, holding its
  // parser, its dgram socket, and an upstream still ESTABLISHED and still pumping bytes into a
  // write queue with nobody left to drain it. Measured on a live server after 4.7 days: 53
  // sockets in CLOSE-WAIT and 537 MB resident.
  //
  // `upstream` needs no equivalent - a plain net.connect socket defaults to allowHalfOpen
  // false, so it ends its own writable half on FIN and reaches "close" by itself.
  socket.on("end", closeAll);
  socket.on("close", closeAll);
  socket.on("error", closeAll);
}

// Run standalone: `USER_UUID=... node worker-shim.js` or `KEYS_FILE=/opt/collateral/keys node worker-shim.js`
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const keysFile = process.env.KEYS_FILE;
  const uuid = process.env.USER_UUID;
  if (!keysFile && !uuid) {
    console.error("Set USER_UUID or KEYS_FILE to run the server standalone, or use `npm run demo`.");
    process.exit(1);
  }
  startWorker({ port: Number(process.env.WORKER_PORT || 8787), uuid, keysFile });
}
