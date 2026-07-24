// Dial through the running SOCKS proxy to an echo service and read the exit IP
// back - proves traffic really leaves via your server. Shared by the TUI and
// the web UI.
import net from "node:net";
import tls from "node:tls";

export function getExitIP(socksPort, timeoutMs = 9000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(socksPort, "127.0.0.1");
    const timer = setTimeout(() => { try { s.destroy(); } catch {} reject(new Error("timed out")); }, timeoutMs);
    const fail = (e) => { clearTimeout(timer); reject(e instanceof Error ? e : new Error(String(e))); };
    s.once("error", fail);
    s.once("connect", () => s.write(Buffer.from([0x05, 0x01, 0x00]))); // SOCKS5 greeting, no auth
    s.once("data", () => {
      const host = Buffer.from("checkip.amazonaws.com");
      const p = Buffer.alloc(2); p.writeUInt16BE(443, 0);
      s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host, p]));
      s.once("data", (reply) => {
        if (reply[1] !== 0x00) return fail(new Error("proxy could not reach the test site"));
        const sec = tls.connect({ socket: s, servername: "checkip.amazonaws.com", ALPNProtocols: ["http/1.1"] });
        sec.once("secureConnect", () => sec.write("GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n"));
        let buf = "";
        sec.on("data", (d) => (buf += d));
        sec.on("close", () => {
          clearTimeout(timer);
          const body = buf.split("\r\n\r\n").slice(1).join("\r\n\r\n").trim();
          const ip = (body.match(/\d{1,3}(\.\d{1,3}){3}/) || [])[0];
          ip ? resolve(ip) : reject(new Error("couldn't read the exit IP"));
        });
        sec.on("error", fail);
      });
    });
  });
}
