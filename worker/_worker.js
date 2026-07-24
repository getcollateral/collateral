// Deployable Cloudflare Worker — the real data plane.
// This is the artifact you deploy (via wrangler) onto a THROWAWAY Cloudflare
// account. It shares common/vless.js and common/decoy.js with the local prototype;
// wrangler's bundler inlines those relative imports at deploy time.
//
// ⚠️  Running a proxy on Cloudflare Workers violates Cloudflare's Self-Serve
//     Subscription Agreement §2.2.1(j) and is fingerprinted/blocked. Treat this
//     as a disposable BOOTSTRAP transport on an account that hosts nothing else.
//     See the project README and the blueprint's risk register.
//
// Config: set a per-user secret  ->  npx wrangler secret put USER_UUID

import { connect } from "cloudflare:sockets";
import { parseVlessHeader, buildVlessResponse, uuidToBytes, uuidEquals } from "../common/vless.js";
import { decoyPage, DECOY_HEADERS } from "../common/decoy.js";
import { planRoute } from "../common/nat64.js";

export default {
  async fetch(request, env) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response(decoyPage(), { status: 200, headers: DECOY_HEADERS });
    }
    if (!env.USER_UUID) return new Response("misconfigured", { status: 500 });

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    handleSession(server, env).catch(() => {
      try { server.close(1011); } catch {}
    });
    return new Response(null, { status: 101, webSocket: client });
  },
};

async function handleSession(ws, env) {
  const expected = uuidToBytes(env.USER_UUID);

  // Attach the message pump synchronously (before any await) so no frame that
  // arrives right after accept() is lost.
  const queue = [];
  let waiter = null;
  let closed = false;
  ws.addEventListener("message", (ev) => {
    const d = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data)
      : typeof ev.data === "string" ? new TextEncoder().encode(ev.data)
      : new Uint8Array(ev.data);
    if (waiter) { const w = waiter; waiter = null; w(d); }
    else queue.push(d);
  });
  ws.addEventListener("close", () => {
    closed = true;
    if (waiter) { const w = waiter; waiter = null; w(null); }
  });
  const next = () =>
    queue.length ? Promise.resolve(queue.shift())
    : closed ? Promise.resolve(null)
    : new Promise((r) => (waiter = r));

  const first = await next();
  if (!first) return;

  const hdr = parseVlessHeader(first);
  if (!uuidEquals(hdr.uuid, expected)) return ws.close(1008); // bad auth
  if (hdr.command !== 1) return ws.close(1003);               // TCP only (connect() has no UDP)

  let socket;
  try {
    socket = await openUpstream(hdr.host, hdr.port, env);
  } catch {
    return ws.close(1011); // couldn't reach the destination directly or via NAT64
  }
  const writer = socket.writable.getWriter();

  ws.send(buildVlessResponse());
  if (hdr.payload.length) await writer.write(hdr.payload);

  // client -> upstream
  (async () => {
    try {
      for (;;) {
        const m = await next();
        if (m === null) break;
        await writer.write(m);
      }
    } catch {}
    try { await writer.close(); } catch {}
    try { socket.close(); } catch {}
  })();

  // upstream -> client
  const reader = socket.readable.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      ws.send(value);
    }
  } catch {}
  try { ws.close(); } catch {}
}

// Reach the destination, routing Cloudflare-fronted hosts through NAT64 (see
// common/nat64.js). Non-Cloudflare traffic goes direct and never touches the gateway.
async function openUpstream(host, port, env) {
  const { nat64Target, preferNat64 } = await planRoute(host, port, env);
  if (preferNat64) return dial(nat64Target, 4000);
  try {
    return await dial({ hostname: host, port }, 1500);
  } catch (e) {
    if (nat64Target) return dial(nat64Target, 4000); // last resort if a direct dial fails
    throw e;
  }
}

// Open a socket and confirm it established, cleaning up on failure so a blocked or
// slow attempt can't leak a half-open socket or an unhandled rejection.
async function dial(target, ms) {
  const s = connect(target);
  try {
    await withTimeout(s.opened, ms);
    return s;
  } catch (e) {
    try { s.close(); } catch {}
    if (s.opened && typeof s.opened.catch === "function") s.opened.catch(() => {});
    throw e;
  }
}

function withTimeout(promise, ms) {
  let t;
  const timer = new Promise((_, reject) => { t = setTimeout(() => reject(new Error("connect timeout")), ms); });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}
