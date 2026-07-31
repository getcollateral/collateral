// `collateral doctor` - a one-shot health check. Runs a sequence of checks against the configured
// server + tunnel and yields a pass / warn / fail / skip result for each, so a broken setup reads
// like a checklist instead of a guess. Pure Node built-ins; reuses the SOCKS/VLESS client and the
// exit-IP probe, so a green "tunnel" line means the whole path (VLESS - WebSocket - TLS - server)
// actually works end to end.
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";
import { once } from "node:events";
import { startClient } from "../client.js";
import { getExitIP } from "./probe.js";

const isWsUrl = (s) => /^wss?:\/\/[^\s]+$/i.test(s || "");
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");
const isIpv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s || "");

// wss://host[:port]/path -> { host, port, secure }
export function parseEndpoint(workerUrl) {
  const u = new URL(workerUrl);
  const secure = u.protocol === "wss:";
  return { host: u.hostname, port: Number(u.port) || (secure ? 443 : 80), secure };
}

// TCP connect test with a timeout. Resolves { ok, err }.
function tcp(host, port, timeout = 6000) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    let done = false;
    const end = (ok, err) => { if (done) return; done = true; try { s.destroy(); } catch {} resolve({ ok, err }); };
    s.setTimeout(timeout);
    s.once("connect", () => end(true));
    s.once("timeout", () => end(false, "timed out"));
    s.once("error", (e) => end(false, e.code || e.message));
  });
}

// TLS handshake without failing on an untrusted cert, so we can always report WHY it's bad and
// read the expiry/issuer. Resolves { ok, err, daysLeft, issuer }.
function tlsCert(host, port, servername, timeout = 8000) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, servername, rejectUnauthorized: false });
    let done = false;
    const end = (r) => { if (done) return; done = true; try { s.destroy(); } catch {} resolve(r); };
    s.setTimeout(timeout);
    s.once("secureConnect", () => {
      const c = s.getPeerCertificate() || {};
      const to = c.valid_to ? new Date(c.valid_to) : null;
      const daysLeft = to && !isNaN(to) ? Math.round((to - Date.now()) / 86400000) : null;
      const issuer = c.issuer ? (c.issuer.O || c.issuer.CN || "") : "";
      end({ ok: s.authorized, err: s.authorizationError, daysLeft, issuer });
    });
    s.once("timeout", () => end({ ok: false, err: "timed out" }));
    s.once("error", (e) => end({ ok: false, err: e.code || e.message }));
  });
}

// Async generator: yields { name, status: "ok"|"warn"|"fail"|"skip", detail } per check, in order.
export async function* diagnose(cfg = {}) {
  const { workerUrl, uuid, vpsHost } = cfg;
  const haveUrl = isWsUrl(workerUrl), haveKey = isUuid(uuid);

  yield haveUrl && haveKey
    ? { name: "config", status: "ok", detail: "server address + access key set" }
    : { name: "config", status: "fail", detail: `missing ${[!haveUrl && "server address (e)", !haveKey && "access key (e/g)"].filter(Boolean).join(" and ")}` };

  try { await dns.lookup("example.com"); yield { name: "local dns", status: "ok", detail: "your machine can resolve names" }; }
  catch { yield { name: "local dns", status: "fail", detail: "can't resolve names - are you online?" }; }

  if (!haveUrl) { yield { name: "server", status: "skip", detail: "no server configured (press s to set up)" }; return; }
  const { host, port, secure } = parseEndpoint(workerUrl);

  // resolve the server's domain
  if (isIpv4(host)) {
    yield { name: "server dns", status: "ok", detail: `${host} (IP literal)` };
  } else {
    try { const { address } = await dns.lookup(host, { family: 4 }); yield { name: "server dns", status: "ok", detail: `${host} -> ${address}` }; }
    catch { yield { name: "server dns", status: "fail", detail: `${host} doesn't resolve - is the A record set?` }; }
  }

  const p = await tcp(host, port);
  yield p.ok ? { name: `port ${port}`, status: "ok", detail: "reachable" }
             : { name: `port ${port}`, status: "fail", detail: `unreachable (${p.err}) - open it in the VM's firewall / security list` };

  // NB: we deliberately don't check port 80. Caddy fronts everything on 443 and renews its cert via
  // the TLS-ALPN-01 challenge, so port 80 is usually closed on a perfectly healthy server. The TLS
  // cert check below is the real signal for HTTPS health.
  if (secure && p.ok && !isIpv4(host)) {
    const t = await tlsCert(host, port, host);
    if (t.ok) {
      const exp = t.daysLeft != null ? `, ${t.daysLeft} days left` : "";
      yield (t.daysLeft != null && t.daysLeft < 10)
        ? { name: "tls cert", status: "warn", detail: `valid but expiring soon (${t.daysLeft} days)` }
        : { name: "tls cert", status: "ok", detail: `valid${t.issuer ? ` - ${t.issuer}` : ""}${exp}` };
    } else {
      yield { name: "tls cert", status: "fail", detail: `not trusted: ${t.err || "handshake failed"}` };
    }
  }

  if (vpsHost) {
    const ssh = await tcp(vpsHost, 22);
    yield ssh.ok ? { name: "ssh :22", status: "ok", detail: `${vpsHost} reachable` }
                 : { name: "ssh :22", status: "warn", detail: `${vpsHost}:22 unreachable (${ssh.err})` };
  }

  // the whole tunnel, end to end
  if (!haveKey) { yield { name: "tunnel", status: "skip", detail: "no access key set" }; return; }
  let srv;
  try {
    srv = startClient({ socksPort: 0, workerUrl, uuid, quiet: true });
    await once(srv, "listening");
    const ip = await getExitIP(srv.address().port);
    yield { name: "tunnel", status: "ok", detail: `working - traffic exits via ${ip}` };
  } catch (e) {
    yield { name: "tunnel", status: "fail", detail: `couldn't establish: ${e.message || e} (server up? key match?)` };
  } finally {
    if (srv) { try { srv.close(); } catch {} }
  }
}
