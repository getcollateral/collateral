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
import { FrameParser, FrameError, encodeFrame, OPCODES } from "./common/ws-frame.js";
import { renderFrame, hitTest, fmtBytes, latLevel, pickFastest, mergeBy, buildBackup, planImport, semverGt } from "./tui.js";
import { parseEndpoint } from "./common/doctor.js";
import { parseKeys } from "./worker-shim.js";
import { siteNames } from "./provision/vps.js";
import { platArch, assetUrl, isPrivateIp, parseDefaultRoute, parsePublicDns, firstFreeUtun, parseLinuxDefaultRoute, parseResolvConf, parseResolvectl, firstFreeTun, pfKillSwitchRules, iptablesKillSwitchSetup, iptablesKillSwitchTeardown, iptablesDnsRedirect, iptablesDnsRedirectTeardown } from "./common/tun.js";
import { aptHint } from "./provision/vps.js";
import { socksUdpWrap, socksUdpUnwrap } from "./common/dns.js";
import { normalizeDomain } from "./provision/vps.js";

const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

const lenBE = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
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

test("SOCKS5 UDP: a datagram truncated after ATYP returns null instead of throwing", () => {
  // The IPv6 case is the one that used to crash: only `length < 5` was checked, so ATYP 0x04
  // then read sixteen address bytes that were not there, and RangeError out of the relay's
  // 'message' handler is uncaught - one short datagram from anywhere took the process down.
  for (const atyp of [0x01, 0x03, 0x04]) {
    for (let n = 5; n < 22; n++) {
      const buf = Buffer.alloc(n);
      buf[3] = atyp;
      if (atyp === 0x03) buf[4] = 200;   // claims a 200-byte name the datagram does not carry
      assert.doesNotThrow(() => parseSocksUdp(buf), `atyp ${atyp}, length ${n}`);
    }
  }
  // A well-formed IPv6 datagram still parses, so the bounds checks did not cost us the feature.
  const port = Buffer.alloc(2); port.writeUInt16BE(443);
  const v6 = Buffer.concat([Buffer.from([0, 0, 0, 4]), Buffer.alloc(15), Buffer.from([1]), port, Buffer.from("hi")]);
  const p = parseSocksUdp(v6);
  assert.equal(p.host, "0:0:0:0:0:0:0:1");
  assert.equal(p.port, 443);
  assert.equal(p.data.toString(), "hi");
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

test("WebSocket frame: a huge declared length is refused before any of it is buffered", () => {
  // The DoS the cap exists for. A 64-bit length header is 10 bytes and costs the sender
  // nothing; before the cap, the parser would wait for the payload and let `buf` grow to meet
  // it. No key and no complete frame are needed, so any stranger could do this to a server.
  const p = new FrameParser();
  const head = Buffer.alloc(10);
  head[0] = 0x80 | OPCODES.BIN;
  head[1] = 127;
  head.writeUInt32BE(0x00000020, 2); // 128 GiB, and far past 2**53 when combined below
  head.writeUInt32BE(0x00000000, 6);
  assert.throws(() => p.push(head), (e) => e instanceof FrameError && e.code === 1009);
  // The point is not just the throw: nothing was retained on the way to it.
  assert.ok(p.buf.length <= 14, `buffer grew to ${p.buf.length}`);
});

test("WebSocket frame: fragments are capped on the reassembled total, not per frame", () => {
  // Every individual frame here is legal and well under the frame cap; only the running total
  // is abusive, so a per-frame check alone would miss it.
  const p = new FrameParser({ maxMessageBytes: 4096 });
  const chunk = Buffer.alloc(1024, 0x41);
  p.push(Buffer.concat([Buffer.from([OPCODES.BIN, 126]), lenBE(chunk.length), chunk])); // fin=0, opens
  // Three more brings the running total to exactly 4096: at the cap, still allowed.
  for (let i = 0; i < 3; i++) {
    p.push(Buffer.concat([Buffer.from([OPCODES.CONT, 126]), lenBE(chunk.length), chunk]));
  }
  // The fragment that crosses it is refused.
  assert.throws(
    () => p.push(Buffer.concat([Buffer.from([OPCODES.CONT, 126]), lenBE(chunk.length), chunk])),
    (e) => e instanceof FrameError && e.code === 1009
  );
});

test("WebSocket frame: framing rules a conforming peer cannot break are rejected", () => {
  const err = (e) => e instanceof FrameError && e.code === 1002;
  // Continuation with nothing to continue: used to silently emit a BIN frame nobody sent.
  assert.throws(() => new FrameParser().push(Buffer.from([0x80 | OPCODES.CONT, 0])), err);
  // Control frames must not be fragmented, and must stay under 126 bytes (RFC 6455 5.5).
  assert.throws(() => new FrameParser().push(Buffer.from([OPCODES.PING, 0])), err);
  assert.throws(() => new FrameParser().push(Buffer.from([0x80 | OPCODES.PING, 126, 0x01, 0x00])), err);
  // A reserved bit set means an extension nobody negotiated (RFC 6455 5.2).
  assert.throws(() => new FrameParser().push(Buffer.from([0x80 | 0x40 | OPCODES.BIN, 0])), err);
});

test("WebSocket frame: a legal fragmented message still reassembles", () => {
  // The regression guard for the checks above: none of them may cost us ordinary fragmentation.
  const p = new FrameParser();
  const out = [
    ...p.push(Buffer.from([OPCODES.BIN, 3, 0x61, 0x62, 0x63])),
    ...p.push(Buffer.from([OPCODES.CONT, 2, 0x64, 0x65])),
    ...p.push(Buffer.from([0x80 | OPCODES.CONT, 1, 0x66])),
  ];
  assert.equal(out.length, 1);
  assert.equal(out[0].opcode, OPCODES.BIN);
  assert.equal(out[0].payload.toString(), "abcdef");
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

test("TUI: renders a disconnected frame with the menu", () => {
  const f = strip(renderFrame({ view: "main", connected: false, workerUrl: "", uuid: "", msg: "hi" }));
  assert.match(f, /collateral/);
  assert.match(f, /disconnected/);
  assert.match(f, /c {2}connect/);       // key, then label (no brackets)
  assert.match(f, /q {2}quit/);
  assert.match(f, /\(not set, press e\)/);
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
  const f = strip(renderFrame({ view: "prompt", prompt: { lines: ["Server address"], current: "", value: "wss://ex" } }));
  assert.match(f, /collateral/);      // brand header, so it stays in the box
  assert.match(f, /Server address/);  // the label
  assert.match(f, /wss:\/\/ex/);      // the typed value
  assert.match(f, /esc to cancel/);
});

test("TUI: connected frame shows the proxy address and endpoint", () => {
  const f = strip(renderFrame({ view: "main", connected: true, socksPort: 1080, workerUrl: "wss://1.2.3.4.sslip.io/abc", uuid: "u", exitIP: "1.2.3.4", msg: "" }));
  assert.match(f, /socks5 {2}127\.0\.0\.1:1080/);
  assert.match(f, /c {2}disconnect/);
  assert.match(f, /wss:\/\/1\.2\.3\.4\.sslip\.io/);
  assert.match(f, /1\.2\.3\.4/);
});

test("TUI: fmtBytes scales units and rounds sensibly", () => {
  assert.equal(fmtBytes(0), "0 B");
  assert.equal(fmtBytes(512), "512 B");
  assert.equal(fmtBytes(1024), "1.0 KB");
  assert.equal(fmtBytes(1536), "1.5 KB");
  assert.equal(fmtBytes(1024 * 1024), "1.0 MB");
  assert.equal(fmtBytes(20 * 1024 * 1024), "20 MB");   // >= 10 drops the decimal
  assert.equal(fmtBytes(undefined), "0 B");            // no traffic yet
});

test("TUI: semverGt compares dotted versions for the update nudge", () => {
  assert.equal(semverGt("0.8.0", "0.7.0"), true);
  assert.equal(semverGt("0.7.1", "0.7.0"), true);
  assert.equal(semverGt("1.0.0", "0.9.9"), true);
  assert.equal(semverGt("0.7.0", "0.7.0"), false);   // equal is not newer
  assert.equal(semverGt("0.6.9", "0.7.0"), false);
});

test("TUI: mergeBy folds in new items and skips existing keys (backup import)", () => {
  const cur = [{ workerUrl: "wss://a", uuid: "1" }, { workerUrl: "wss://b", uuid: "2" }];
  const inc = [{ workerUrl: "wss://b", uuid: "2" }, { workerUrl: "wss://c", uuid: "3" }, null];
  const r = mergeBy(cur, inc, (x) => `${x.workerUrl}|${x.uuid}`);
  assert.equal(r.added, 1);                 // only wss://c is new (b already present, null skipped)
  assert.equal(r.list.length, 3);
  assert.equal(r.list[2].workerUrl, "wss://c");
  assert.deepEqual(mergeBy(undefined, [{ uuid: "x" }], (x) => x.uuid), { list: [{ uuid: "x" }], added: 1 });
});

test("TUI: backup round-trip - export captures the active server, import merges onto a fresh box", () => {
  const cfg = { workerUrl: "wss://home/x", uuid: "3d9a7f2e-1c84-4b6d-a05f-8e21c9b4d7f0", machines: [{ desc: "vm", workerUrl: "wss://vm/y", uuid: "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d" }], friends: [{ label: "sam", uuid: "ffffffff-ffff-ffff-ffff-ffffffffffff" }] };
  const backup = buildBackup(cfg, "2026-01-01T00:00:00Z");
  assert.equal(backup._collateral, "backup");
  assert.equal(backup.config.machines.length, 2);                         // the vm + the active server, captured
  assert.ok(backup.config.machines.some((m) => m.workerUrl === "wss://home/x"));
  // fresh machine (no server set): import merges everything and adopts the active server/key
  const fresh = { machines: [], friends: [], workerUrl: "", uuid: "" };
  const r = planImport(fresh, backup.config);
  assert.equal(r.addedMachines, 2);
  assert.equal(r.addedFriends, 1);
  assert.equal(r.patch.workerUrl, "wss://home/x");                        // adopted (was unset)
  // already-configured machine: don't hijack the active server, still merge new machines
  const configured = { machines: [], friends: [], workerUrl: "wss://mine/z", uuid: "0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a" };
  const r2 = planImport(configured, backup.config);
  assert.equal(r2.patch.workerUrl, undefined);                           // left alone
  assert.equal(r2.addedMachines, 2);
});

test("TUI: pickFastest returns the lowest-latency reachable machine", () => {
  const a = { m: { desc: "a" }, ms: 80 };
  const b = { m: { desc: "b" }, ms: 20 };
  const c = { m: { desc: "c" }, ms: null };   // unreachable
  assert.equal(pickFastest([a, b, c]), b);    // lowest ms wins
  assert.equal(pickFastest([c]), null);       // none reachable
  assert.equal(pickFastest([]), null);
});

test("TUI: latLevel maps latency to signal-bar levels (null = none)", () => {
  assert.equal(latLevel(null), 0);
  assert.equal(latLevel(20), 4);
  assert.equal(latLevel(60), 3);
  assert.equal(latLevel(120), 2);
  assert.equal(latLevel(300), 1);
});

test("TUI: connected frame shows the live traffic + ping rows", () => {
  const f = strip(renderFrame({ view: "main", connected: true, socksPort: 1080, workerUrl: "wss://x/y", uuid: "u", exitIP: "1.2.3.4", downRate: 1024 * 1024, upRate: 2048, totalBytes: 5 * 1024 * 1024, latency: 24, msg: "" }));
  assert.match(f, /traffic/);
  assert.match(f, /1\.0 MB\/s/);   // down rate formatted
  assert.match(f, /ping/);
  assert.match(f, /24 ms/);
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

test("provision: normalizeDomain strips scheme/path/case/whitespace", () => {
  assert.equal(normalizeDomain("  https://Proxy.Will-Notes.NET/foo?a=1 "), "proxy.will-notes.net");
  assert.equal(normalizeDomain("will-notes.net"), "will-notes.net");
  assert.equal(normalizeDomain("HTTP://a.b.c"), "a.b.c");
  assert.equal(normalizeDomain(""), "");
  assert.equal(normalizeDomain(null), "");
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

test("TUN(linux): parses `ip route show default` for gateway + interface", () => {
  const r = parseLinuxDefaultRoute("default via 192.168.1.1 dev wlan0 proto dhcp metric 600");
  assert.equal(r.gateway, "192.168.1.1");
  assert.equal(r.interface, "wlan0");
});

test("TUN(linux): resolv.conf public resolvers, skipping the systemd-resolved stub", () => {
  assert.deepEqual(parseResolvConf("nameserver 127.0.0.53\noptions edns0\nnameserver 8.8.8.8\n"), ["8.8.8.8"]);
  // resolvectl fallback only takes IPs off DNS-Server lines, and drops private ones
  assert.deepEqual(parseResolvectl("Link 2 (wlan0)\n  Current DNS Server: 1.1.1.1\n  DNS Servers: 1.1.1.1 192.168.1.1\n"), ["1.1.1.1"]);
});

test("TUN(linux): firstFreeTun picks the first unused collateralN", () => {
  assert.equal(firstFreeTun("lo eth0 collateral0 collateral1"), "collateral2");
  assert.equal(firstFreeTun("lo eth0 wlan0"), "collateral0");
});

test("kill switch (macOS pf): blocks all egress but loopback, tun, server, DNS", () => {
  const rules = pfKillSwitchRules("203.0.113.9", ["1.1.1.1", "8.8.8.8"], "utun123");
  assert.match(rules, /pass quick on lo0 all/);
  assert.match(rules, /pass quick on utun123 all/);
  assert.match(rules, /pass out quick inet proto tcp to 203\.0\.113\.9/);        // server reachable
  assert.match(rules, /to \{ 1\.1\.1\.1 8\.8\.8\.8 \} port 53/);                 // DNS reachable
  assert.match(rules, /block drop out inet all/);                               // everything else blocked
  // the block must come LAST so the quick passes win first
  assert.ok(rules.trim().endsWith("block drop out inet all"));
  // no DNS servers -> no DNS pass line at all
  assert.ok(!/port 53/.test(pfKillSwitchRules("203.0.113.9", [], "utun9")));
});

test("kill switch (Linux iptables): dedicated chain hooked into OUTPUT, cleanly removed", () => {
  const setup = iptablesKillSwitchSetup("203.0.113.9", ["1.1.1.1"], "collateral0");
  assert.match(setup, /-A COLLATERAL_KS -o lo -j ACCEPT/);
  assert.match(setup, /-A COLLATERAL_KS -o collateral0 -j ACCEPT/);
  assert.match(setup, /-A COLLATERAL_KS -d 203\.0\.113\.9 -j ACCEPT/);
  assert.match(setup, /-A COLLATERAL_KS -d 1\.1\.1\.1 -j ACCEPT/);
  assert.match(setup, /-A COLLATERAL_KS -j DROP/);
  assert.match(setup, /-I OUTPUT 1 -j COLLATERAL_KS/);
  // DROP must be appended before the chain is hooked, so it's the chain's last rule
  assert.ok(setup.indexOf("-j DROP") < setup.indexOf("-I OUTPUT"));
  const down = iptablesKillSwitchTeardown();
  assert.match(down, /-D OUTPUT -j COLLATERAL_KS/);
  assert.match(down, /-X COLLATERAL_KS/);
});

test("dns-through-tunnel (Linux): redirect rules point :53 at the local forwarder", () => {
  const s = iptablesDnsRedirect(5353);
  assert.match(s, /-t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353/);
  assert.match(s, /-p tcp --dport 53 -j REDIRECT --to-ports 5353/);
  assert.match(iptablesDnsRedirectTeardown(5353), /-t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353/);
});

test("dns: socks-udp wrap/unwrap round-trips the DNS payload", () => {
  const payload = Buffer.from("a-dns-message");
  const wrapped = socksUdpWrap("1.1.1.1", 53, payload);
  assert.equal(wrapped[2], 0);                       // FRAG = 0
  assert.equal(wrapped[3], 1);                       // ATYP = IPv4
  assert.equal(wrapped.readUInt16BE(8), 53);         // dest port
  assert.deepEqual(socksUdpUnwrap(wrapped), payload); // strips the header cleanly
  assert.equal(socksUdpUnwrap(Buffer.from([1, 2])), null);       // too short
  assert.equal(socksUdpUnwrap(Buffer.from([0, 0, 1, 1])), null); // FRAG != 0 rejected
});

test("provision: aptHint gives guided advice for the common Oracle first-boot failures", () => {
  assert.match(aptHint("E: Could not get lock /var/lib/dpkg/lock-frontend"), /first-boot/);
  assert.match(aptHint("unified-monitoring-agent needs to be reinstalled, but I can't find an archive"), /wedged/);
  assert.match(aptHint("Temporary failure resolving 'deb.nodesource.com'"), /mirrors/);
  assert.equal(aptHint("something unrelated"), "");
});

test("server: parseKeys builds the allowed set (labels/blank/garbage ignored, deduped)", () => {
  const A = "3d9a7f2e-1c84-4b6d-a05f-8e21c9b4d7f0", B = "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
  const set = parseKeys(["# owner", A, "", "# alice", B, "  " + A + "  ", "not-a-uuid"]);
  assert.equal(set.size, 2);        // A + B; A deduped; comment / blank / garbage dropped
  assert.equal(parseKeys([]).size, 0);
});

test("doctor: parseEndpoint splits host / port / scheme", () => {
  const a = parseEndpoint("wss://example.com/abc");
  assert.equal(a.host, "example.com"); assert.equal(a.port, 443); assert.equal(a.secure, true);
  const b = parseEndpoint("ws://1.2.3.4:8787/x");
  assert.equal(b.host, "1.2.3.4"); assert.equal(b.port, 8787); assert.equal(b.secure, false);
  assert.equal(parseEndpoint("wss://host.tld:8443/p").port, 8443);
});

test("TUI: setup view lists provisioning steps with state", () => {
  const f = strip(renderFrame({
    view: "setup",
    steps: [
      { name: "ssh", label: "Connect over SSH", status: "ok" },
      { name: "upload", label: "Upload the server", status: "run" },
      { name: "health", label: "Health check", status: "pending" },
    ],
  }));
  assert.match(f, /first-time setup/);
  assert.match(f, /Connect over SSH/);
  assert.match(f, /Upload the server/);
});

// Reading which names a Caddyfile serves. This is what stops setup silently re-homing a
// working server: get it wrong and every link already shared dies without a word.
test("siteNames reads the domains a Caddyfile serves", () => {
  const global = "{\n  auto_https disable_redirects\n}\n";

  // One name, which is what setup writes for a fresh VM.
  assert.deepEqual(
    siteNames(global + "137.23.22.36.sslip.io {\n  reverse_proxy localhost:8787\n}\n"),
    ["137.23.22.36.sslip.io"],
  );

  // Several, which is what it writes when keeping an existing name alongside a new one.
  assert.deepEqual(
    siteNames(global + "reflector1.example.com, 1.2.3.4.sslip.io {\n  reverse_proxy localhost:8787\n}\n"),
    ["reflector1.example.com", "1.2.3.4.sslip.io"],
  );

  // The global options block is also a line ending in "{" and must not be read as a site.
  assert.deepEqual(siteNames(global), []);

  // No Caddy at all: a fresh VM, which must look different from a configured one.
  assert.deepEqual(siteNames(""), []);
  assert.deepEqual(siteNames(null), []);

  // Directives inside a block have no dot and are not site names.
  assert.deepEqual(
    siteNames(global + "example.com {\n  handle_path /x/* {\n    respond 200\n  }\n}\n"),
    ["example.com"],
  );
});
