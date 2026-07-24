// NAT64 routing helpers — portable (fetch + math only, no cloudflare:sockets), so
// they run in the Worker and are unit-testable in Node.
//
// Why: a Cloudflare Worker's connect() is blocked from dialing Cloudflare's OWN IPs
// (anti-loop), and much of the web is Cloudflare-fronted. We resolve the host, and
// if it's a Cloudflare IP we route it through a NAT64 gateway (an IPv6 that embeds
// the IPv4, which isn't caught by the anti-loop block). Everything else goes direct,
// so non-Cloudflare traffic never touches the third-party gateway.
//
// ⚠️  NAT64 is OFF by default. Reaching CF-fronted sites this way requires routing
//     through a NAT64 gateway, and public gateways are unreliable (they die often)
//     and are a third-party on-path hop — the exact "infra you don't control" risk a
//     privacy tool should avoid. Opt in by setting env.NAT64_PREFIX to a gateway you
//     trust (ideally your own / a ProxyIP you run). Only /96 prefixes ending in "::".
//     A known public example (verify it's live before trusting it): 2602:fc59:b0:64::

// Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4). Shipped statically so
// routing stays self-contained.
export const CF_V4_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
];

export function isIPv4Literal(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s || "");
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}

export function v4ToInt(ip) {
  if (!isIPv4Literal(ip)) return null;
  const o = ip.split(".").map(Number);
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

export function isCloudflareV4(ip) {
  const n = v4ToInt(ip);
  if (n === null) return false;
  return CF_V4_CIDRS.some((cidr) => {
    const [base, bitsStr] = cidr.split("/");
    const bits = Number(bitsStr);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (v4ToInt(base) & mask) === (n & mask);
  });
}

// Only /96 prefixes written to end in "::" are supported (RFC 6052 v4-in-96..127).
export function normalizeNat64Prefix(p) {
  return typeof p === "string" && p.endsWith("::") ? p : null;
}

// Returns the BARE IPv6 (no brackets); callers wrap it as "[addr]:port" for connect().
export function nat64Address(ipv4, prefix) {
  if (!isIPv4Literal(ipv4)) throw new Error("nat64Address: bad IPv4");
  const hex = ipv4.split(".").map((n) => (Number(n) & 0xff).toString(16).padStart(2, "0"));
  return `${prefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

// Resolve an A record over DoH, self-contained with an abortable timeout.
// Returns an IPv4 string, or null (unresolvable / AAAA-only / error) => caller goes direct.
export async function resolveA(host, timeoutMs = 2500) {
  if (isIPv4Literal(host)) return host;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      { headers: { accept: "application/dns-json" }, signal: ac.signal }
    );
    if (!r.ok) return null;
    const j = await r.json();
    if (j.Status !== 0) return null;
    const ans = (j.Answer || []).find((a) => a.type === 1); // 1 = A record
    return ans && isIPv4Literal(ans.data) ? ans.data : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Decide how to reach host:port. NAT64 is opt-in: with no NAT64_PREFIX we skip the
// DoH lookup entirely and go direct (fast for everything; CF-fronted sites fail fast
// rather than hanging on a dead relay). With a prefix set, CF-fronted IPs use NAT64.
export async function planRoute(host, port, env) {
  const prefix = normalizeNat64Prefix(env && env.NAT64_PREFIX);
  if (!prefix) return { ipv4: null, nat64Target: null, preferNat64: false };
  const ipv4 = await resolveA(host);
  const nat64Target = ipv4 ? `[${nat64Address(ipv4, prefix)}]:${port}` : null;
  const preferNat64 = !!(nat64Target && isCloudflareV4(ipv4));
  return { ipv4, nat64Target, preferNat64 };
}
