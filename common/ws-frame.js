// Minimal RFC 6455 WebSocket framing for the server (Worker-shim) side.
// The Cloudflare Worker uses the runtime's native WebSocket; this exists only so
// the local Node shim can speak WebSocket with zero dependencies. Node-only
// (uses Buffer + node:crypto). Handles binary/text/close/ping and fragmentation.

import crypto from "node:crypto";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export const OPCODES = { CONT: 0x0, TEXT: 0x1, BIN: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };

export function computeAcceptKey(secWebSocketKey) {
  return crypto.createHash("sha1").update(secWebSocketKey + GUID).digest("base64");
}

export class FrameParser {
  constructor() {
    this.buf = Buffer.alloc(0);
    this.fragOp = null;
    this.fragChunks = [];
  }

  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : Buffer.from(chunk);
    const out = [];
    for (;;) {
      const f = this._readFrame();
      if (!f) break;
      if (f.opcode === OPCODES.CLOSE || f.opcode === OPCODES.PING || f.opcode === OPCODES.PONG) {
        out.push({ opcode: f.opcode, payload: f.payload });
        continue;
      }
      if (f.opcode === OPCODES.CONT) {
        this.fragChunks.push(f.payload);
        if (f.fin) {
          out.push({ opcode: this.fragOp ?? OPCODES.BIN, payload: Buffer.concat(this.fragChunks) });
          this.fragOp = null;
          this.fragChunks = [];
        }
      } else if (f.fin) {
        out.push({ opcode: f.opcode, payload: f.payload });
      } else {
        this.fragOp = f.opcode;
        this.fragChunks = [f.payload];
      }
    }
    return out;
  }

  _readFrame() {
    const b = this.buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      const hi = b.readUInt32BE(2);
      const lo = b.readUInt32BE(6);
      len = hi * 2 ** 32 + lo;
      off = 10;
    }
    let mask = null;
    if (masked) {
      if (b.length < off + 4) return null;
      mask = b.subarray(off, off + 4);
      off += 4;
    }
    if (b.length < off + len) return null;
    let payload = b.subarray(off, off + len);
    if (masked) {
      const p = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) p[i] = payload[i] ^ mask[i & 3];
      payload = p;
    } else {
      payload = Buffer.from(payload); // detach from the rolling buffer
    }
    this.buf = b.subarray(off + len);
    return { fin, opcode, payload };
  }
}

// Server frames are never masked (RFC 6455 §5.1).
export function encodeFrame(opcode, payload) {
  payload = payload ? Buffer.from(payload) : Buffer.alloc(0);
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeUInt32BE(Math.floor(len / 2 ** 32), 2);
    header.writeUInt32BE(len >>> 0, 6);
  }
  return Buffer.concat([header, payload]);
}
