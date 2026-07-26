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
  const pending = new Map();                 // dns txid -> { rinfo, timer }
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

  function sendUp(msg, rinfo) {
    if (closed) return;
    if (!ready || !relayAddr) { buffered.push({ msg, rinfo }); if (!ctrl) associate(); return; }
    const txid = msg.readUInt16BE(0);
    const prev = pending.get(txid); if (prev) clearTimeout(prev.timer);
    pending.set(txid, { rinfo, timer: setTimeout(() => pending.delete(txid), 5000) });
    try { relay.send(socksUdpWrap(upstream, upstreamPort, msg), relayAddr.port, relayAddr.host); } catch {}
  }

  server.on("error", () => {});
  relay.on("error", () => {});
  server.on("message", (msg, rinfo) => { if (msg.length >= 12) sendUp(msg, rinfo); }); // >= a DNS header
  relay.on("message", (buf) => {
    const dns = socksUdpUnwrap(buf);
    if (!dns || dns.length < 2) return;
    const txid = dns.readUInt16BE(0);
    const w = pending.get(txid);
    if (!w) return;
    clearTimeout(w.timer); pending.delete(txid);
    try { server.send(dns, w.rinfo.port, w.rinfo.address); } catch {}
  });

  relay.bind(0, "127.0.0.1");
  server.bind(port, host, () => { if (!quiet) console.log(`[dns] on ${host}:${server.address().port} -> tunnel -> ${upstream}:${upstreamPort}`); });
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
