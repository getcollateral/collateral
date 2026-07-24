// Build the client-facing config the onboarding wizard hands the user: a vless://
// URI (and a base64 subscription blob). Format matches Xray/sing-box so a config
// generated here can be imported into a real client for interop testing.

export function buildVlessUri({ uuid, host, port = 443, path = "/", sni, wsHost, tls = true, name = "Collateral" }) {
  const q = new URLSearchParams();
  q.set("encryption", "none");
  q.set("type", "ws");
  q.set("security", tls ? "tls" : "none");
  if (tls && sni) q.set("sni", sni);
  q.set("host", wsHost || host);
  q.set("path", path);
  return `vless://${uuid}@${host}:${port}?${q.toString()}#${encodeURIComponent(name)}`;
}

// Turn the app's stored endpoint (a wss:// worker URL + uuid) into a shareable vless:// URI,
// so a new user can import the whole config in one scan/paste - no SSH, no first-time setup.
// Built directly (not via buildVlessUri) so it can omit the WS "host" header param: our server
// routes by TLS SNI and ignores the Host header, and clients default it to the address - so
// dropping it keeps the QR smaller without breaking compatibility.
export function vlessUriFromConfig({ workerUrl, uuid, name = "Collateral" }) {
  const u = new URL(workerUrl);
  const tls = u.protocol === "wss:";
  const port = Number(u.port) || (tls ? 443 : 80);
  const q = new URLSearchParams();
  q.set("encryption", "none");
  q.set("type", "ws");
  q.set("security", tls ? "tls" : "none");
  if (tls) q.set("sni", u.hostname);            // load-bearing: Caddy/TLS routes by this
  q.set("path", (u.pathname || "/") + (u.search || ""));
  return `vless://${uuid}@${u.hostname}:${port}?${q.toString()}#${encodeURIComponent(name)}`;
}

// Inverse of vlessUriFromConfig: parse a scanned/pasted vless:// URI back into the app's
// { workerUrl, uuid } so another instance can import it. Throws on a non-vless link.
export function parseVlessUri(uri) {
  const u = new URL(String(uri).trim());
  if (u.protocol !== "vless:") throw new Error("not a vless:// link");
  const uuid = decodeURIComponent(u.username);
  const tls = (u.searchParams.get("security") || "tls") !== "none";
  const scheme = tls ? "wss" : "ws";
  const port = u.port || (tls ? "443" : "80");
  const isDefaultPort = (tls && port === "443") || (!tls && port === "80");
  const path = u.searchParams.get("path") || "/";
  const workerUrl = `${scheme}://${u.hostname}${isDefaultPort ? "" : ":" + port}${path}`;
  const name = u.hash ? decodeURIComponent(u.hash.slice(1)) : "";
  return { workerUrl, uuid, name };
}

// A subscription is just base64 of newline-joined URIs - what the app refreshes
// to rotate a burned endpoint without shipping an app update.
export function buildSubscription(uris) {
  const blob = uris.join("\n");
  return Buffer.from(blob, "utf8").toString("base64");
}
