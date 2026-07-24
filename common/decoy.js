// Active-probing resistance: any request that isn't an authenticated WebSocket
// upgrade gets a plausible, boring web page instead of a proxy-shaped reply.
// A censor probing the endpoint sees an ordinary site and has nothing to blacklist.
// Pure (no runtime deps).

export function decoyPage() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Status</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:40rem;
    margin:6rem auto;padding:0 1.25rem;color:#1f2937;line-height:1.6}
  h1{font-size:1.5rem;margin:0 0 .25rem} .ok{color:#16a34a;font-weight:600}
  code{background:#f3f4f6;padding:.1rem .35rem;border-radius:4px}
  footer{margin-top:3rem;color:#9ca3af;font-size:.85rem}
</style>
</head>
<body>
  <h1>Service status</h1>
  <p><span class="ok">&#9679; All systems operational.</span></p>
  <p>This host serves static content. See <code>/health</code> for uptime checks.</p>
  <footer>Last updated automatically.</footer>
</body>
</html>`;
}

export const DECOY_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
};
