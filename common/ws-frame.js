// Minimal RFC 6455 WebSocket framing for the server side. Exists so the Node
// server can speak WebSocket with zero dependencies. Node-only (uses Buffer +
// node:crypto). Handles binary/text/close/ping and fragmentation.

import crypto from "node:crypto";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export const OPCODES = { CONT: 0x0, TEXT: 0x1, BIN: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };

export function computeAcceptKey(secWebSocketKey) {
  return crypto.createHash("sha1").update(secWebSocketKey + GUID).digest("base64");
}

// Refuse a frame, or a reassembled message, larger than this. 16 MiB is far above anything the
// tunnel carries in one frame (app writes arrive in tens of kilobytes) and far below anything
// that troubles the box.
//
// Without a ceiling the length field is a promise the parser keeps at its own expense: declare
// a 100 GB frame, then trickle bytes, and _readFrame returns null every time while `buf` grows
// to hold a payload that never arrives. No key, no VLESS header, not even a complete frame is
// needed - the declaration alone does it, and it costs the sender nothing. Fragmentation is a
// second route to the same place with every individual frame a legal size.
//
// Rejecting at the header, before any payload is buffered, is what keeps `buf` bounded: a frame
// is only accumulated once its declared length is known to be acceptable, so the buffer cannot
// exceed one frame plus a 14-byte header. That also disposes of the 64-bit length's precision
// problem (past 2^53, `hi * 2**32 + lo` stops being exact), because such a length is refused
// long before the value is trusted for anything.
export const MAX_FRAME_BYTES = 16 * 1024 * 1024;
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

// Thrown for what a conforming peer cannot legitimately send. Callers must catch it and close
// the connection: these surface inside a socket 'data' handler, where an uncaught throw ends
// the process and every other user's tunnel with it.
export class FrameError extends Error {
  /// `code` is the RFC 6455 close code to send back: 1009 for something too big, 1002 for a
  /// framing rule broken.
  constructor(message, code = 1002) {
    super(message);
    this.name = "FrameError";
    this.code = code;
  }
}

export class FrameParser {
  constructor({ maxFrameBytes = MAX_FRAME_BYTES, maxMessageBytes = MAX_MESSAGE_BYTES } = {}) {
    this.buf = Buffer.alloc(0);
    this.fragOp = null;
    this.fragChunks = [];
    this.fragBytes = 0;
    this.maxFrameBytes = maxFrameBytes;
    this.maxMessageBytes = maxMessageBytes;
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
        // A continuation with nothing to continue. Accepting it silently started a message
        // whose fragOp was never set, which then surfaced as a BIN frame nobody sent.
        if (this.fragOp === null && !this.fragChunks.length) {
          throw new FrameError("continuation frame with no message in progress");
        }
        this.fragBytes += f.payload.length;
        if (this.fragBytes > this.maxMessageBytes) {
          throw new FrameError(`fragmented message exceeds ${this.maxMessageBytes} bytes`, 1009);
        }
        this.fragChunks.push(f.payload);
        if (f.fin) {
          out.push({ opcode: this.fragOp ?? OPCODES.BIN, payload: Buffer.concat(this.fragChunks) });
          this.fragOp = null;
          this.fragChunks = [];
          this.fragBytes = 0;
        }
      } else if (f.fin) {
        out.push({ opcode: f.opcode, payload: f.payload });
      } else {
        // A second opening frame while one is already in progress is not fragmentation, it is
        // a peer that has lost the plot; the old chunks would otherwise be silently discarded.
        if (this.fragOp !== null || this.fragChunks.length) {
          throw new FrameError("new message started while a fragmented one was in progress");
        }
        this.fragOp = f.opcode;
        this.fragChunks = [f.payload];
        this.fragBytes = f.payload.length;
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
    // Control frames (>= 0x8) must be short and unfragmented (RFC 6455 5.5). Checked before the
    // length is read, because a fragmented control frame is a framing error however long it is.
    const isControl = (opcode & 0x8) !== 0;
    if (isControl && !fin) throw new FrameError("fragmented control frame");
    // No extensions are negotiated, so a reserved bit set means the peer is speaking a protocol
    // this parser does not implement, and the payload cannot be interpreted (RFC 6455 5.2).
    if ((b[0] & 0x70) !== 0) throw new FrameError("reserved bits set with no extension negotiated");

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
    if (isControl && len > 125) throw new FrameError("control frame payload over 125 bytes");
    // The load-bearing line. Refusing here, rather than after buffering, is what stops a
    // declared length from being a memory-allocation instruction.
    if (len > this.maxFrameBytes) {
      throw new FrameError(`frame declares ${len} bytes, over the ${this.maxFrameBytes} limit`, 1009);
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
