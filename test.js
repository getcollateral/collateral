// Unit tests for the pure protocol modules.  Run: npm test  (node --test)

import test from "node:test";
import assert from "node:assert/strict";
import {
  encodeVlessHeader,
  parseVlessHeader,
  uuidToBytes,
  bytesToUuid,
  uuidEquals,
  buildVlessResponse,
  ipv6ToBytes,
} from "./common/vless.js";
import { parseSocksUdp } from "./client.js";
import { qrMatrix } from "./common/qr.js";
import { vlessUriFromConfig, parseVlessUri } from "./common/config.js";
import { FrameParser, encodeFrame, OPCODES } from "./common/ws-frame.js";
import { isIPv4Literal, isCloudflareV4, nat64Address, normalizeNat64Prefix } from "./common/nat64.js";
import { renderFrame, hitTest } from "./tui.js";
import { platArch, assetUrl, isPrivateIp, parseDefaultRoute, parsePublicDns, firstFreeUtun } from "./common/tun.js";

const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

const UUID = "8f1b6a2e-0c3d-4e5f-8a9b-1c2d3e4f5a6b";

test("uuid round-trips through bytes", () => {
  assert.equal(bytesToUuid(uuidToBytes(UUID)), UUID);
});

test("uuidEquals is true for equal, false for different", () => {
  assert.ok(uuidEquals(uuidToBytes(UUID), uuidToBytes(UUID)));
  assert.ok(!uuidEquals(uuidToBytes(UUID), uuidToBytes("00000000-0000-4000-8000-000000000000")));
});

test("VLESS header round-trips (domain + port)", () => {
  const uuid = uuidToBytes(UUID);
  const h = encodeVlessHeader({ uuid, host: "example.com", port: 443 });
  const p = parseVlessHeader(h);
  assert.equal(p.host, "example.com");
  assert.equal(p.port, 443);
  assert.equal(p.command, 1);
  assert.equal(p.atype, 2);
  assert.ok(uuidEquals(p.uuid, uuid));
  assert.equal(p.payload.length, 0);
});

test("VLESS header round-trips (ipv4) and preserves trailing payload", () => {
  const uuid = uuidToBytes(UUID);
  const head = encodeVlessHeader({ uuid, host: "127.0.0.1", port: 8080 });
  const body = new TextEncoder().encode("hello-payload");
  const frame = new Uint8Array(head.length + body.length);
  frame.set(head, 0);
  frame.set(body, head.length);
  const p = parseVlessHeader(frame);
  assert.equal(p.host, "127.0.0.1");
  assert.equal(p.port, 8080);
  assert.equal(p.atype, 1);
  assert.equal(new TextDecoder().decode(p.payload), "hello-payload");
});

test("VLESS response header is [0,0]", () => {
  assert.deepEqual(Array.from(buildVlessResponse()), [0, 0]);
});

test("VLESS header round-trips a UDP command with an IPv6 destination", () => {
  const uuid = uuidToBytes(UUID);
  const h = encodeVlessHeader({ uuid, host: "2606:4700:4700::1111", port: 53, command: 2 });
  const p = parseVlessHeader(h);
  assert.equal(p.command, 2);     // UDP
  assert.equal(p.atype, 3);       // IPv6
  assert.equal(p.port, 53);
  assert.equal(p.host, "2606:4700:4700:0:0:0:0:1111");
});

test("ipv6ToBytes handles :: compression and rejects junk", () => {
  assert.deepEqual(Array.from(ipv6ToBytes("::1")), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(Array.from(ipv6ToBytes("2606:4700:4700::1111")).slice(0, 4), [0x26, 0x06, 0x47, 0x00]);
  assert.throws(() => ipv6ToBytes("1:2:3"));   // too short without ::
  assert.throws(() => ipv6ToBytes("gg::1"));   // invalid hex
});

test("SOCKS5 UDP request parses the destination and preserves the reply header prefix", () => {
  const dport = Buffer.alloc(2); dport.writeUInt16BE(53);
  const req = Buffer.concat([Buffer.from([0, 0, 0, 1, 8, 8, 8, 8]), dport, Buffer.from("query")]);
  const p = parseSocksUdp(req);
  assert.equal(p.host, "8.8.8.8");
  assert.equal(p.port, 53);
  assert.equal(p.data.toString(), "query");
  assert.deepEqual(Array.from(p.hdrPrefix), [0, 0, 0, 1, 8, 8, 8, 8, 0, 53]); // echoed verbatim on replies
  assert.equal(parseSocksUdp(Buffer.from([0, 0, 1, 1])), null);               // FRAG != 0 unsupported
});

test("parseVlessHeader rejects a truncated buffer", () => {
  assert.throws(() => parseVlessHeader(new Uint8Array(10)));
});

test("WebSocket frame: masked client frame parses back to the original", () => {
  const payload = Buffer.from("the quick brown fox jumps");
  const mask = Buffer.from([0x11, 0x22, 0x33, 0x44]);
  const masked = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i & 3];
  const frame = Buffer.concat([Buffer.from([0x80 | OPCODES.BIN, 0x80 | payload.length]), mask, masked]);
  const msgs = new FrameParser().push(frame);
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0].opcode, OPCODES.BIN);
  assert.ok(msgs[0].payload.equals(payload));
});

test("WebSocket frame: encodeFrame output parses back (server->client, unmasked)", () => {
  const payload = Buffer.from("x".repeat(500)); // exercises the 16-bit length path
  const msgs = new FrameParser().push(encodeFrame(OPCODES.BIN, payload));
  assert.equal(msgs.length, 1);
  assert.ok(msgs[0].payload.equals(payload));
});

test("WebSocket frame: a message split across two pushes is reassembled", () => {
  const payload = Buffer.from("split-across-tcp-segments");
  const frame = encodeFrame(OPCODES.BIN, payload);
  const parser = new FrameParser();
  assert.equal(parser.push(frame.subarray(0, 3)).length, 0);
  const msgs = parser.push(frame.subarray(3));
  assert.equal(msgs.length, 1);
  assert.ok(msgs[0].payload.equals(payload));
});

test("NAT64: address embeds the IPv4 in the last 32 bits (RFC 6052 /96)", () => {
  assert.equal(nat64Address("1.2.3.4", "2602:fc59:b0:64::"), "2602:fc59:b0:64::0102:0304");
  assert.equal(nat64Address("104.26.12.205", "2602:fc59:b0:64::"), "2602:fc59:b0:64::681a:0ccd");
  // callers must NOT get brackets (those are added only for the connect() string form)
  assert.ok(!nat64Address("1.2.3.4", "2602:fc59:b0:64::").includes("["));
});

test("NAT64: Cloudflare-fronted destination IPs are detected, others are not", () => {
  assert.ok(isCloudflareV4("104.26.12.205")); // ipify (104.24.0.0/14)
  assert.ok(isCloudflareV4("172.67.74.152")); // ipify (172.64.0.0/13)
  assert.ok(isCloudflareV4("162.159.0.1"));   // 162.158.0.0/15
  assert.ok(!isCloudflareV4("8.8.8.8"));       // Google
  assert.ok(!isCloudflareV4("54.239.28.85"));  // AWS
  assert.ok(!isCloudflareV4("999.1.1.1"));     // invalid
});

test("NAT64: IPv4 literal validation rejects out-of-range octets", () => {
  assert.ok(isIPv4Literal("127.0.0.1"));
  assert.ok(!isIPv4Literal("256.0.0.1"));
  assert.ok(!isIPv4Literal("1.2.3"));
  assert.ok(!isIPv4Literal("example.com"));
});

test("NAT64: only /96 prefixes ending in :: are accepted", () => {
  assert.equal(normalizeNat64Prefix("2602:fc59:b0:64::"), "2602:fc59:b0:64::");
  assert.equal(normalizeNat64Prefix("2602:fc59:b0:64"), null);
  assert.equal(normalizeNat64Prefix(12345), null);
});

test("TUI: renders a disconnected frame with the menu", () => {
  const f = strip(renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "hi" }));
  assert.match(f, /collateral/);
  assert.match(f, /disconnected/);
  assert.match(f, /c {2}connect/);       // key, then label (no brackets)
  assert.match(f, /q {2}quit/);
  assert.match(f, /\(not set — press w\)/);
});

test("TUI: the [•] mark reflects connection state", () => {
  const on = strip(renderFrame({ view: "main", connected: true, socksPort: 1080, workerUrl: "", uuid: "", msg: "" }));
  const off = strip(renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "" }));
  assert.match(on, /\[•\]/);  // filled dot = connected
  assert.match(off, /\[ \]/); // empty = idle
});

test("TUI: click hit-testing maps terminal coordinates to a key", () => {
  const built = { lines: ["##########", "##########", "##########"], zones: [{ line: 1, x0: 0, x1: 5, key: "c" }] };
  // cols=20 => leftPad 5; rows=10 => topPad 3; zone line 1 => row 5; content x in [8,13)
  assert.equal(hitTest(built, 20, 10, 8, 5), "c");
  assert.equal(hitTest(built, 20, 10, 12, 5), "c");
  assert.equal(hitTest(built, 20, 10, 13, 5), null); // x1 is exclusive
  assert.equal(hitTest(built, 20, 10, 8, 4), null);  // wrong row
});

test("TUI: hovering an item renders a reverse-video highlight bar", () => {
  const hovered = renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "", hover: "t" });
  assert.match(hovered, /\x1b\[7m/);  // highlight present for the hovered item
  const idle = renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "", hover: null });
  assert.ok(!/\x1b\[7m/.test(idle));  // no highlight when nothing is hovered
});

test("TUI: prompt view renders in-box with the typed value", () => {
  const f = strip(renderFrame({ view: "prompt", prompt: { lines: ["Worker address"], current: "", value: "wss://ex" } }));
  assert.match(f, /collateral/);      // brand header, so it stays in the box
  assert.match(f, /Worker address/);  // the label
  assert.match(f, /wss:\/\/ex/);      // the typed value
  assert.match(f, /esc to cancel/);
});

test("TUI: connected frame shows the proxy address and worker", () => {
  const f = strip(renderFrame({ view: "main", connected: true, socksPort: 1080, workerUrl: "wss://x.workers.dev", uuid: "u", exitIP: "1.2.3.4", msg: "" }));
  assert.match(f, /socks5 {2}127\.0\.0\.1:1080/);
  assert.match(f, /c {2}disconnect/);
  assert.match(f, /wss:\/\/x\.workers\.dev/);
  assert.match(f, /1\.2\.3\.4/);
});

test("QR: correct size + valid finder patterns at all three corners", () => {
  const m = qrMatrix("HELLO WORLD", "M");
  assert.equal(m.length, 21);            // version 1
  assert.equal(m[0].length, 21);
  const finderOk = (ox, oy) => {
    for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) {
      const want = x === 0 || x === 6 || y === 0 || y === 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4);
      if (!!m[oy + y][ox + x] !== want) return false;
    }
    return true;
  };
  assert.ok(finderOk(0, 0));             // top-left
  assert.ok(finderOk(14, 0));            // top-right
  assert.ok(finderOk(0, 14));            // bottom-left
});

test("QR: scales version to the payload and stays square (multi-block)", () => {
  const m = qrMatrix("a".repeat(200), "L");
  assert.equal(m.length, 53);            // version 9
  assert.equal(m.length, m[0].length);
});

test("config: vlessUriFromConfig builds an importable vless:// link", () => {
  const uri = vlessUriFromConfig({ workerUrl: "wss://1.2.3.4.sslip.io/abc123", uuid: "745282aa-88d3-476d-87aa-9cecee72177c" });
  assert.match(uri, /^vless:\/\/745282aa-88d3-476d-87aa-9cecee72177c@1\.2\.3\.4\.sslip\.io:443\?/);
  assert.match(uri, /type=ws/);
  assert.match(uri, /security=tls/);
  assert.match(uri, /sni=1\.2\.3\.4\.sslip\.io/);
  assert.match(uri, /path=%2Fabc123/);
});

test("config: vless URI round-trips (share -> scan -> import)", () => {
  const workerUrl = "wss://161.33.237.170.sslip.io/fa7f13e7d4de";
  const uuid = "745282aa-88d3-476d-87aa-9cecee72177c";
  const back = parseVlessUri(vlessUriFromConfig({ workerUrl, uuid }));
  assert.equal(back.uuid, uuid);
  assert.equal(back.workerUrl, workerUrl);
  assert.equal(back.name, "Collateral");
});

test("config: parseVlessUri rejects a non-vless link", () => {
  assert.throws(() => parseVlessUri("https://example.com/x"));
});

test("TUI: help view renders proxy instructions", () => {
  const f = strip(renderFrame({ view: "help", socksPort: 1080 }));
  assert.match(f, /Firefox/);
  assert.match(f, /SOCKS/);
  assert.match(f, /go back/);
});

test("TUI: main menu offers first-time setup", () => {
  const f = strip(renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "" }));
  assert.match(f, /s {2}first-time setup/);
});

test("TUI: menu exposes both device-wide modes (system proxy + full tunnel)", () => {
  const f = strip(renderFrame({ view: "main", connected: true, socksPort: 1080, workerUrl: "wss://x", uuid: "u", msg: "", systemProxy: false, tunActive: true }));
  assert.match(f, /d {2}system proxy:/);
  assert.match(f, /f {2}full tunnel: on/);   // reflects tunActive
});

test("TUN: platform asset name + pinned download URL", () => {
  assert.match(platArch(), /^(darwin|linux|win32)-(amd64|arm64)$/);
  assert.match(assetUrl(), /tun2socks\/releases\/download\/v2\.7\.0\/tun2socks-\w+-\w+\.zip$/);
});

test("TUN: only public DNS resolvers get host-routed (LAN stays on the subnet route)", () => {
  assert.ok(isPrivateIp("192.168.1.1"));
  assert.ok(isPrivateIp("10.0.0.5"));
  assert.ok(isPrivateIp("172.20.9.9"));
  assert.ok(isPrivateIp("127.0.0.1"));
  assert.ok(!isPrivateIp("1.1.1.1"));
  assert.ok(!isPrivateIp("8.8.8.8"));
  assert.deepEqual(parsePublicDns("nameserver[0] : 192.168.1.1\nnameserver[0] : 1.1.1.1\nnameserver[1] : 8.8.8.8"), ["1.1.1.1", "8.8.8.8"]);
});

test("TUN: parses the default gateway/interface and picks a free utun", () => {
  const dr = parseDefaultRoute("   gateway: 10.0.0.1\n  interface: en0\n");
  assert.equal(dr.gateway, "10.0.0.1");
  assert.equal(dr.interface, "en0");
  assert.equal(firstFreeUtun("lo0 en0 utun0 utun1 utun2 utun3"), "utun123");
  assert.equal(firstFreeUtun("lo0 en0 utun123 utun124"), "utun125");
});

test("TUI: setup view lists deploy steps with state", () => {
  const f = strip(renderFrame({
    view: "setup",
    steps: [
      { name: "verify", label: "Verify token", status: "ok" },
      { name: "upload", label: "Deploy the worker", status: "run" },
      { name: "health", label: "Health check", status: "pending" },
    ],
  }));
  assert.match(f, /first-time setup/);
  assert.match(f, /Verify token/);
  assert.match(f, /Deploy the worker/);
});
