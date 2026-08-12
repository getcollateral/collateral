// A tiny DNS forwarder that tunnels queries. It listens on a local UDP socket and relays every
// query to an upstream resolver (e.g. 1.1.1.1) THROUGH our SOCKS5 proxy's UDP path - so DNS rides
// the same VLESS/WS/TLS tunnel as everything else and exits at the VM, closing the plaintext-DNS
// leak. The forwarder->proxy hop uses the SOCKS port (not :53), so it can never loop through a
// :53 redirect rule.
//
// It speaks the client side of SOCKS5 UDP ASSOCIATE against our own client.js: open a TCP control
// connection, ask for a UDP relay, then send each query as a SOCKS-UDP datagram to that relay.
// Responses arrive on the relay socket; we match them back to the waiting client by DNS txid.

import dgram from "node:dgram";
import net from "node:net";
import crypto from "node:crypto";

// Wrap a payload in a SOCKS5 UDP request header: [RSV(2)=0][FRAG(1)=0][ATYP][ADDR][PORT(2)][DATA].
export function socksUdpWrap(host, port, data) {
  const p = host.split(".").map(Number);
  const isV4 = p.length === 4 && p.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
  const head = isV4
    ? Buffer.from([0, 0, 0, 0x01, p[0], p[1], p[2], p[3]])
    : Buffer.concat([Buffer.from([0, 0, 0, 0x03, host.length]), Buffer.from(host)]);
  const pb = Buffer.alloc(2); pb.writeUInt16BE(port, 0);
  return Buffer.concat([head, pb, data]);
}

// Strip the SOCKS5 UDP header, returning just the payload (the DNS response), or null if malformed.
export function socksUdpUnwrap(buf) {
  if (buf.length < 4 || buf[2] !== 0x00) return null;
  const atyp = buf[3];
  let off;
  if (atyp === 0x01) off = 4 + 4 + 2;
  else if (atyp === 0x04) off = 4 + 16 + 2;
  else if (atyp === 0x03) off = 4 + 1 + buf[4] + 2;
  else return null;
  return buf.length >= off ? buf.subarray(off) : null;
}

export function startDnsForwarder({ host = "127.0.0.1", port = 5353, upstream = "1.1.1.1", upstreamPort = 53, socksHost = "127.0.0.1", socksPort = 1080, quiet = false } = {}) {
  const server = dgram.createSocket("udp4"); // where the OS / dig sends its DNS queries
  const relay = dgram.createSocket("udp4");  // our datagrams to the SOCKS UDP relay
  const pending = new Map();                 // OUR txid -> { rinfo, clientTxid, timer }
  let relayAddr = null, ctrl = null, ready = false, closed = false;
  const buffered = [];

  // Open the SOCKS5 UDP association: greet, request UDP ASSOCIATE, learn the relay's address. The
  // association lives as long as this TCP control connection stays open (RFC 1928).
  function associate() {
    if (closed) return;
    ready = false; relayAddr = null;
    ctrl = net.connect(socksPort, socksHost);
    let step = 0;
    ctrl.on("error", () => {});
    ctrl.once("connect", () => ctrl.write(Buffer.from([0x05, 0x01, 0x00]))); // version 5, no-auth
    ctrl.on("data", (d) => {
      if (step === 0) { ctrl.write(Buffer.from([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); step = 1; } // UDP ASSOCIATE
      else if (step === 1) {
        if (d[1] !== 0x00) return;                                          // associate failed
        relayAddr = { host: `${d[4]}.${d[5]}.${d[6]}.${d[7]}`, port: d.readUInt16BE(8) };
        ready = true; step = 2;
        for (const b of buffered.splice(0)) sendUp(b.msg, b.rinfo);
      }
    });
    ctrl.on("close", () => { ready = false; relayAddr = null; ctrl = null; });
  }

  // A transaction id we are not already waiting on. Random rather than sequential: a
  // predictable id is one an off-path attacker can guess.
  function allocTxid() {
    for (let i = 0; i < 64; i++) {
      const t = crypto.randomInt(0x10000);
      if (!pending.has(t)) return t;
    }
    return null;
  }

  function sendUp(msg, rinfo) {
    if (closed) return;
    if (!ready || !relayAddr) { buffered.push({ msg, rinfo }); if (!ctrl) associate(); return; }
    // Rewrite the transaction ID on the way out, and restore it on the way back.
    //
    // Keying `pending` on the CLIENT's txid meant two clients that happened to pick the same
    // 16-bit value collided, and the map simply overwrote the first. Its reply was then sent to
    // the second client, carrying an answer to a question it never asked but with a txid that
    // matched, while the first query vanished until it timed out. This is not exotic: the
    // resolver picks txids at random, so it is a birthday problem, and around fifty queries in
    // flight is enough for a percent-level chance. mDNSResponder on a busy machine gets there.
    //
    // Choosing our own id fixes it by construction, because we can guarantee uniqueness where
    // we cannot govern what a client picks. It also raises the bar for off-path injection: a
    // forged reply now has to guess a value we chose at random rather than one it watched the
    // client send.
    const clientTxid = msg.readUInt16BE(0);
    const ourTxid = allocTxid();
    if (ourTxid === null) return;   // table full; the 5s timers will drain it
    const out = Buffer.from(msg);   // copy: never mutate the caller's buffer
    out.writeUInt16BE(ourTxid, 0);
    pending.set(ourTxid, { rinfo, clientTxid, timer: setTimeout(() => pending.delete(ourTxid), 5000) });
    try { relay.send(socksUdpWrap(upstream, upstreamPort, out), relayAddr.port, relayAddr.host); } catch {}
  }

  server.on("error", () => {});
  relay.on("error", () => {});
  server.on("message", (msg, rinfo) => { if (msg.length >= 12) sendUp(msg, rinfo); }); // >= a DNS header
  relay.on("message", (buf) => {
    const dns = socksUdpUnwrap(buf);
    if (!dns || dns.length < 2) return;
    const ourTxid = dns.readUInt16BE(0);
    const w = pending.get(ourTxid);
    if (!w) return;
    clearTimeout(w.timer); pending.delete(ourTxid);
    // Put the client's own id back, or its resolver discards a reply it cannot match.
    const out = Buffer.from(dns);
    out.writeUInt16BE(w.clientTxid, 0);
    try { server.send(out, w.rinfo.port, w.rinfo.address); } catch {}
  });

  // DNS over TCP, on the same port.
  //
  // The Linux session script redirects BOTH udp/53 and tcp/53 to this forwarder, and until now
  // only UDP was ever listened on, so every TCP lookup got connection-refused. Resolvers fall
  // back to TCP whenever an answer does not fit in a datagram - a truncated reply with TC=1,
  // large TXT records, most DNSSEC - so those names failed outright rather than being slow. The
  // UDP path hid it, which is why it only ever showed up on the handful of domains that need
  // TCP at all.
  //
  // Not redirecting tcp/53 instead would be worse: with the kill switch off those queries would
  // go straight out in plaintext, which is the leak this whole forwarder exists to close.
  //
  // TCP DNS is length-prefixed and a client may pipeline several queries down one connection,
  // so there is nothing to demultiplex here: open one tunnelled connection per client
  // connection and let the bytes flow both ways. No txid bookkeeping, because TCP already
  // keeps the pairing.
  const tcpServer = net.createServer((sock) => {
    sock.on("error", () => {});
    if (closed) { sock.destroy(); return; }
    const up = net.connect(socksPort, socksHost);
    let step = 0;
    up.on("error", () => { try { sock.destroy(); } catch {} });
    sock.on("close", () => { try { up.destroy(); } catch {} });
    up.once("connect", () => up.write(Buffer.from([0x05, 0x01, 0x00])));   // v5, no auth
    up.on("data", function handshake(d) {
      if (step === 0) {
        if (d[0] !== 0x05 || d[1] !== 0x00) { up.destroy(); sock.destroy(); return; }
        // CONNECT to the upstream resolver, addressed the same way socksUdpWrap does.
        const parts = upstream.split(".").map(Number);
        const isV4 = parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
        const addr = isV4
          ? Buffer.from([0x01, ...parts])
          : Buffer.concat([Buffer.from([0x03, upstream.length]), Buffer.from(upstream)]);
        const pb = Buffer.alloc(2); pb.writeUInt16BE(upstreamPort, 0);
        up.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, pb]));
        step = 1;
        return;
      }
      // CONNECT reply. Hand the socket over to a plain pipe from here on.
      if (d[1] !== 0x00) { up.destroy(); sock.destroy(); return; }
      up.removeListener("data", handshake);
      up.pipe(sock);
      sock.pipe(up);
    });
  });
  tcpServer.on("error", () => {});

  relay.bind(0, "127.0.0.1");
  server.bind(port, host, () => {
    // Bind TCP to whatever port UDP actually got, so a `port: 0` caller (the tests) still ends
    // up with both on one port, the way the redirect rules assume.
    try { tcpServer.listen(server.address().port, host); } catch {}
    if (!quiet) console.log(`[dns] on ${host}:${server.address().port} (udp+tcp) -> tunnel -> ${upstream}:${upstreamPort}`);
  });
  associate();

  return {
    address: () => server.address(),
    close() {
      closed = true;
      for (const p of pending.values()) clearTimeout(p.timer);
      pending.clear();
      try { ctrl && ctrl.destroy(); } catch {}
      try { relay.close(); } catch {}
      try { server.close(); } catch {}
      try { tcpServer.close(); } catch {}
    },
  };
}

// Run standalone:  SOCKS_PORT=1080 DNS_PORT=5353 node common/dns.js
if (process.argv[1] && /dns\.js$/.test(process.argv[1])) {
  startDnsForwarder({
    port: Number(process.env.DNS_PORT || 5353),
    upstream: process.env.DNS_UPSTREAM || "1.1.1.1",
    socksPort: Number(process.env.SOCKS_PORT || 1080),
  });
}
