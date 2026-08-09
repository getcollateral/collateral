// Client: a local SOCKS5 inbound that wraps each connection in VLESS and tunnels
// it over WebSocket-in-TLS to the worker. In product mode this would be a
// system-wide TUN (sing-box/libbox); a SOCKS5 inbound exercises the identical
// data path with no privileges. Point any app at socks5h://127.0.0.1:1080.
//
//   app -> SOCKS5 -> [VLESS header + stream] -> WebSocket -> worker -> destination
//
// Uses Node's built-in global WebSocket (no dependencies).

import net from "node:net";
import dgram from "node:dgram";
import { fileURLToPath } from "node:url";
import { encodeVlessHeader, uuidToBytes } from "./common/vless.js";

// Parse a SOCKS5 UDP request datagram: [RSV(2)][FRAG(1)][ATYP][ADDR][PORT(2)][DATA].
// Returns { atyp, host, port, hdrPrefix, data } or null. hdrPrefix is the [RSV FRAG ATYP ADDR
// PORT] bytes echoed verbatim on reply datagrams (same destination). FRAG != 0 is unsupported.
export function parseSocksUdp(buf) {
  if (buf.length < 5 || buf[2] !== 0x00) return null;
  const atyp = buf[3];
  let portOff, host;
  // Each address family needs its own length check before its address is read. The shared
  // `buf.length < 5` above is enough to reach ATYP and no further: an IPv6-typed datagram
  // truncated after it sent readUInt16BE past the end of the buffer, and a RangeError raised
  // inside the relay's 'message' handler is uncaught, so one short datagram from anywhere on
  // the network ended the process. A datagram we cannot parse is simply not ours.
  if (atyp === 0x01) {
    if (buf.length < 10) return null;                  // 4 header + 4 address + 2 port
    host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`; portOff = 8;
  } else if (atyp === 0x03) {
    const len = buf[4];
    if (buf.length < 5 + len + 2) return null;         // 5 header + name + 2 port
    host = buf.subarray(5, 5 + len).toString("utf8"); portOff = 5 + len;
  } else if (atyp === 0x04) {
    if (buf.length < 22) return null;                  // 4 header + 16 address + 2 port
    const p = []; for (let i = 0; i < 8; i++) p.push(buf.readUInt16BE(4 + i * 2).toString(16));
    host = p.join(":"); portOff = 20;
  } else return null;
  if (buf.length < portOff + 2) return null;
  const port = buf.readUInt16BE(portOff);
  const dataOff = portOff + 2;
  return { atyp, host, port, hdrPrefix: Buffer.concat([Buffer.from([0, 0, 0]), buf.subarray(3, dataOff)]), data: buf.subarray(dataOff) };
}

// Refuse one SOCKS5 request without taking the process with it. `rep` is the SOCKS5 reply code
// (0x01 general failure, 0x08 address type not supported).
function failRequest(sock, rep) {
  try { sock.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch {}
  sock.destroy();
}

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

  server.bytesUp = 0; server.bytesDown = 0; // live throughput counters, read by the TUI

  // SOCKS5: negotiate no-auth, then read the request (CONNECT=1 for TCP, UDP ASSOCIATE=3).
  function socks5(sock, greeting) {
    sock.write(Buffer.from([0x05, 0x00])); // version 5, no auth
    sock.once("data", (req) => {
      if (req[0] !== 0x05) { sock.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return sock.destroy(); }
      if (req[1] === 0x03) return socks5Udp(sock);   // UDP ASSOCIATE
      if (req[1] !== 0x01) {                          // only CONNECT + UDP ASSOCIATE
        sock.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return sock.destroy();
      }
      const atyp = req[3];
      let target, portOff;
      // Same bounds discipline as parseSocksUdp, and for the same reason: this runs in a
      // 'data' handler, so reading past the end throws RangeError with nobody to catch it and
      // the process dies. A short request is not necessarily hostile either - the whole
      // request is assumed to arrive in one segment, and TCP does not promise that.
      if (atyp === 0x01) {
        if (req.length < 10) return failRequest(sock, 0x01);
        target = `${req[4]}.${req[5]}.${req[6]}.${req[7]}`; portOff = 8;
      } else if (atyp === 0x03) {
        const len = req[4];
        if (req.length < 5 + len + 2) return failRequest(sock, 0x01);
        target = req.subarray(5, 5 + len).toString("utf8"); portOff = 5 + len;
      } else if (atyp === 0x04) {
        if (req.length < 22) return failRequest(sock, 0x01);
        const p = []; for (let i = 0; i < 8; i++) p.push(req.readUInt16BE(4 + i * 2).toString(16));
        target = p.join(":"); portOff = 20;
      } else { return failRequest(sock, 0x08); }        // 0x08 = address type not supported
      const port = req.readUInt16BE(portOff);
      const extra = req.subarray(portOff + 2);
      sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); // succeeded
      openTunnel(sock, target, port, extra);
    });
  }

  // SOCKS4 / SOCKS4a: [4, cmd, port(2), ip(4), userid\0, (4a: host\0)]. The macOS system
  // proxy resolves DNS locally and sends SOCKS4 with an IP; SOCKS4a carries a hostname.
  function socks4(sock, req) {
    // [VN, CD, port(2), ip(4)] is 8 bytes before the userid; short of that, readUInt16BE(2)
    // and the ip reads below run off the end and throw out of a 'data' handler.
    if (req.length < 8) { sock.write(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0])); return sock.destroy(); }
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
    if (extra && extra.length) { server.bytesUp += extra.length; buffered.push(extra); }

    // Buffer app bytes until the WebSocket is open so nothing is lost in the race
    // between the SOCKS success reply and the ws handshake.
    sock.on("data", (d) => {
      server.bytesUp += d.length;
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
        server.authRejected = false; // got a VLESS response -> the key is accepted
      }
      if (buf.length) { server.bytesDown += buf.length; sock.write(buf); }
    };
    ws.onclose = (ev) => {
      const code = ev && ev.code;
      if (code === 1008) server.authRejected = true; // 1008 = server rejected the key (wrong or revoked)
      if (!quiet && code && code !== 1000) {
        let hint = "";
        if (code === 1008) hint = ", UUID rejected: the client USER_UUID must equal the server's USER_UUID";
        else if (code === 1003) hint = ", server refused a non-TCP command";
        else if (code === 1006 || !wsOpen) hint = `, couldn't reach/keep the tunnel to ${workerUrl} (is the server set up? correct URL?)`;
        console.error(`[client] tunnel closed (code ${code}${ev.reason ? " " + ev.reason : ""})${hint}`);
      }
      try { sock.end(); } catch {}
    };
    ws.onerror = () => { try { sock.destroy(); } catch {} };
    sock.on("close", () => { try { ws.close(); } catch {} });
  }

  // A VLESS-UDP tunnel to ONE destination. Each ws.send is one datagram; each ws message
  // received is one return datagram (WebSocket preserves boundaries, so no length framing).
  function openUdpSession(destHost, destPort, onDatagram, onClose = () => {}) {
    const ws = new WebSocket(workerUrl);
    ws.binaryType = "arraybuffer";
    let wsOpen = false;
    const buffered = [];
    const MAX_BUFFERED = 64; // only queue while still connecting; never let a dead session buffer forever
    ws.onopen = () => {
      ws.send(encodeVlessHeader({ uuid: uuidBytes, host: destHost, port: destPort, command: 2 }));
      wsOpen = true;
      for (const d of buffered) ws.send(d);
      buffered.length = 0;
    };
    ws.onmessage = (ev) => { onDatagram(Buffer.from(ev.data)); };
    ws.onerror = () => { try { ws.close(); } catch {} };
    // A server-side close (60s idle, dgram error) must evict this session so the NEXT datagram opens
    // a fresh tunnel - otherwise it becomes a zombie that silently black-holes that destination.
    ws.onclose = () => { wsOpen = false; buffered.length = 0; onClose(); };
    return {
      send(payload) {
        if (wsOpen && ws.readyState === 1) ws.send(payload);
        else if (ws.readyState === 0 && buffered.length < MAX_BUFFERED) buffered.push(payload); // still connecting
        // closing/closed or over budget -> drop; the relay has evicted us and will re-establish
      },
      close() { try { ws.close(); } catch {} },
    };
  }

  // SOCKS5 UDP ASSOCIATE: bind a loopback UDP relay, tell the client its address, then bridge
  // each datagram to a per-destination VLESS-UDP tunnel. The association lives as long as the
  // TCP control socket stays open (RFC 1928). This is what lets tun2socks carry UDP/QUIC/games.
  function socks5Udp(ctrl) {
    const relay = dgram.createSocket("udp4");
    const sessions = new Map(); // "host:port" -> { session, hdrPrefix, app, idle, bump }
    const MAX_SESSIONS = 512;   // ceiling so a churn storm (games open many destinations) can't grow unbounded
    let closed = false;
    const drop = (key) => { const s = sessions.get(key); if (!s) return; clearTimeout(s.idle); try { s.session.close(); } catch {} sessions.delete(key); };
    const closeAll = () => {
      if (closed) return; closed = true;
      try { relay.close(); } catch {}
      for (const s of sessions.values()) { clearTimeout(s.idle); try { s.session.close(); } catch {} }
      sessions.clear();
      try { ctrl.destroy(); } catch {} // drop the control socket so tun2socks re-issues UDP ASSOCIATE (avoids a permanent blackhole)
    };
    relay.on("error", closeAll);
    relay.on("message", (msg, rinfo) => {
      const p = parseSocksUdp(msg);
      if (!p) return;
      const key = `${p.host}:${p.port}`;
      let s = sessions.get(key);
      if (!s) {
        if (sessions.size >= MAX_SESSIONS) drop(sessions.keys().next().value); // evict the oldest
        s = { hdrPrefix: p.hdrPrefix, app: rinfo, idle: null };
        s.bump = () => { clearTimeout(s.idle); s.idle = setTimeout(() => drop(key), 60000); };
        s.session = openUdpSession(p.host, p.port, (datagram) => {
          server.bytesDown += datagram.length;
          try { relay.send(Buffer.concat([s.hdrPrefix, datagram]), s.app.port, s.app.address, () => {}); } catch {} // per-send cb: a transient ENOBUFS can't nuke the association
          s.bump();
        }, () => { if (sessions.get(key) === s) { clearTimeout(s.idle); sessions.delete(key); } }); // ws closed -> evict so the next datagram re-establishes
        sessions.set(key, s);
      }
      s.app = rinfo;      // reply to wherever the app last sent from
      s.bump();
      server.bytesUp += p.data.length;
      s.session.send(p.data);
    });
    relay.bind(0, "127.0.0.1", () => {
      const { port } = relay.address();
      // reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR=127.0.0.1 BND.PORT
      try { ctrl.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (port >> 8) & 0xff, port & 0xff])); } catch {}
    });
    ctrl.on("close", closeAll);
    ctrl.on("error", closeAll);
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
