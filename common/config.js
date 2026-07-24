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

// A subscription is just base64 of newline-joined URIs — what the app refreshes
// to rotate a burned endpoint without shipping an app update.
export function buildSubscription(uris) {
  const blob = uris.join("\n");
  return Buffer.from(blob, "utf8").toString("base64");
}
