// VLESS protocol: a faithful subset, pure (Uint8Array only). VLESS carries no
// crypto of its own — confidentiality comes entirely from the outer TLS that
// the server (behind Caddy) terminates.
//
// Request header (client -> server):
//   [ver:1][uuid:16][addonLen:1][addons:addonLen][cmd:1][port:2][atype:1][addr:var][payload...]
//   cmd  1=TCP 2=UDP 3=MUX     atype 1=IPv4 2=domain 3=IPv6
// Response header (server -> client): [ver:1][addonLen:1] then the raw stream.

const td = new TextDecoder();
const te = new TextEncoder();

export function uuidToBytes(str) {
  const hex = String(str).replace(/-/g, "");
  if (hex.length !== 32 || /[^0-9a-fA-F]/.test(hex)) throw new Error("invalid UUID");
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}

export function bytesToUuid(b) {
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Constant-time-ish compare so a bad UUID can't be timing-probed.
export function uuidEquals(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// Parse an IPv6 literal (incl. "::" compression, optional %zone) to 16 bytes. Pure, no deps.
export function ipv6ToBytes(host) {
  host = String(host).split("%")[0];
  let head, tail;
  if (host.includes("::")) {
    const [h, t] = host.split("::");
    if (host.indexOf("::") !== host.lastIndexOf("::")) throw new Error("invalid IPv6");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = host.split(":"); tail = [];
  }
  const total = head.length + tail.length;
  if (total > 8 || (!host.includes("::") && total !== 8)) throw new Error("invalid IPv6");
  const groups = [...head, ...Array(8 - total).fill("0"), ...tail];
  const b = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const v = parseInt(groups[i] || "0", 16);
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i] || "0") || v > 0xffff) throw new Error("invalid IPv6");
    b[i * 2] = v >> 8; b[i * 2 + 1] = v & 0xff;
  }
  return b;
}

export function encodeVlessHeader({ uuid, host, port, command = 1 }) {
  if (!(uuid instanceof Uint8Array) || uuid.length !== 16) throw new Error("uuid must be 16 bytes");
  let atype, addr;
  const m = IPV4.exec(host);
  if (m) {
    atype = 1;
    addr = Uint8Array.from([+m[1], +m[2], +m[3], +m[4]]);
  } else if (host.includes(":")) {
    atype = 3; // IPv6
    addr = ipv6ToBytes(host);
  } else {
    atype = 2; // domain
    const h = te.encode(host);
    if (h.length > 255) throw new Error("hostname too long");
    addr = Uint8Array.from([h.length, ...h]);
  }
  const out = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + addr.length);
  let o = 0;
  out[o++] = 0; // version
  out.set(uuid, o); o += 16;
  out[o++] = 0; // addon length
  out[o++] = command;
  out[o++] = (port >> 8) & 0xff;
  out[o++] = port & 0xff;
  out[o++] = atype;
  out.set(addr, o);
  return out;
}

export function parseVlessHeader(data) {
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
  if (data.length < 24) throw new Error("header too short");
  let o = 0;
  const version = data[o++];
  const uuid = data.slice(o, o + 16); o += 16;
  const addonLen = data[o++]; o += addonLen;
  if (o + 4 > data.length) throw new Error("truncated header");
  const command = data[o++];
  const port = (data[o] << 8) | data[o + 1]; o += 2;
  const atype = data[o++];
  let host;
  if (atype === 1) {
    if (o + 4 > data.length) throw new Error("truncated ipv4");
    host = `${data[o]}.${data[o + 1]}.${data[o + 2]}.${data[o + 3]}`; o += 4;
  } else if (atype === 2) {
    const len = data[o++];
    if (o + len > data.length) throw new Error("truncated domain");
    host = td.decode(data.slice(o, o + len)); o += len;
  } else if (atype === 3) {
    if (o + 16 > data.length) throw new Error("truncated ipv6");
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((data[o + i * 2] << 8) | data[o + i * 2 + 1]).toString(16));
    host = parts.join(":"); o += 16;
  } else {
    throw new Error("unknown address type " + atype);
  }
  return { version, uuid, command, port, atype, host, payload: data.slice(o), headerLength: o };
}

export function buildVlessResponse() {
  return new Uint8Array([0, 0]); // version 0, no addons
}
