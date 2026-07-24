# Collateral — prototype

A **runnable** prototype of the core mechanism from the blueprint: a
bring-your-own-infrastructure censorship-circumvention tunnel. Traffic is wrapped
in **VLESS**, carried over **WebSocket-inside-TLS**, and reflected out to the open
internet by an edge worker that opens a plain outbound TCP socket to the
destination.

It runs entirely on `127.0.0.1` with **zero dependencies** and **no cloud account**,
so you can see the whole packet lifecycle end-to-end without any Terms-of-Service or
legal risk. The same protocol code also compiles into a **real deployable Cloudflare
Worker** (`worker/_worker.js`).

```
npm run tui      # ⭐ terminal control panel (no browser, any OS)
npm run ui       # same thing as a local web GUI, if you prefer a browser
npm run demo     # end-to-end tunnel + self-checks (proves the mechanism)
npm test         # unit tests for the protocol + framing
npm run provision   # onboarding wizard logic (safe / read-only)
```

## The terminal app (`npm run tui`)

A full-screen TUI — centered, scroll-locked (like vim/htop), **clickable**, live status,
zero dependencies, runs in any terminal on macOS / Linux / Windows. Ships as a one-liner
(`npx`), so there's no app to sign or install. The brand mark `[•]` **is** the status
light: filled = connected, empty `[ ]` = idle, spinner = busy.

```
  ╭──────────────────────────────────────────────────╮
  │ [•] collateral                         connected  │
  │ your own private proxy                            │
  ├──────────────────────────────────────────────────┤
  │ proxy      socks5  127.0.0.1:1080                 │
  │ endpoint   wss://161.33.237.170.sslip.io/coll…    │
  │ key        dc592984-437f-4d0f-9c28-9f0fe354f260   │
  │ exit ip    161.33.237.170                         │
  │ transport  VLESS · WebSocket · TLS · :443         │
  ├──────────────────────────────────────────────────┤
  │ s  first-time setup      c  disconnect            │
  │ t  test connection       w  set worker address    │
  │ u  set access key        g  generate new key      │
  │ k  cloudflare token link p  proxy setup help      │
  │ d  system proxy: off     f  full tunnel: off      │
  │ q  quit                                           │
  ├──────────────────────────────────────────────────┤
  │ › Connected — traffic exits via 161.33.237.170.   │
  ╰──────────────────────────────────────────────────╯
```

**Click** any menu item — the whole row is the hit target and highlights under the cursor on
hover, so it's obvious what's clickable — or use the keys: **s** first-time setup · **c**
connect/disconnect · **t** test (shows the live exit IP) · **w**/**u** set worker + key · **g**
generate a key · **k** Cloudflare token page · **d** system proxy on/off · **f** full tunnel
(TUN) on/off · **p** proxy help · **q** quit (works even mid-connect). Config persists in
`~/.collateral-config.json`. Mouse tracking hard-locks the frame against scrolling; hold Option
to select text.

There are **two** device-wide modes; both only turn on while connected and turn **off
automatically on disconnect, on quit, and on crash**, so a dead tunnel can never strand your
traffic. They're mutually exclusive.

### `d` — system SOCKS proxy (macOS, best-effort)

**d** flips the macOS **system SOCKS proxy** to point at the tunnel, so *every* app that
honors it is routed. Changing network settings needs admin (password prompt). The client
speaks **both SOCKS5 and SOCKS4/4a** — required because macOS "use system proxy" mode makes
Firefox/Zen send **SOCKS4** (macOS records no version, Mozilla bug 1700857), which a SOCKS5-only
proxy would reject. But Apple treats the system SOCKS proxy as **best-effort** (apps may bypass
it), which is why the real device-wide option is the full tunnel below.

### `f` — full tunnel / TUN (macOS, real device-wide)

**f** brings up a real **VPN-style TUN interface** that captures *all* of the machine's TCP at
the IP layer — no per-app cooperation, nothing to bypass. It reuses the exact same tunnel
(VLESS · WebSocket · TLS · server); we just add a new front door:

- A tiny, **pinned + SHA-256-verified** helper (`tun2socks`, ~4 MB, downloaded once to
  `~/.collateral/bin/`, never committed) creates a `utun` and forwards every flow into our
  existing SOCKS5 client on loopback. So the server and protocol are unchanged.
- **Crash-safe routing:** we never edit your real default route. We add two `/1` routes bound
  to the `utun` (they out-specific the default, and the kernel deletes them the instant the
  interface disappears), a host route for the **server's own IP** via your real gateway (so the
  tunnel's own packets don't loop), and host routes for any **public DNS** servers (so name
  resolution keeps working). If the helper dies for *any* reason, networking self-heals.
- **One admin prompt** (a macOS GUI dialog) starts a small root session that owns the helper and
  **watches this app's PID** — if the app exits or crashes, it tears everything down. Turning it
  off just touches a file (no second prompt).

**TCP + UDP both work** through the tunnel (VLESS UDP over the same WebSocket), so QUIC/HTTP-3,
games (Roblox etc.), and DNS route through your VM — not just TCP. **Limits (v1):** macOS +
IPv4 only, and UDP works on the **self-hosted VM** path but not on Cloudflare Workers (their
`connect()` is TCP-only). **Recovery:** if something ever gets stuck, `node common/tun.js down`
requests teardown and `node common/tun.js status` shows the current state.

### First-time setup (`s`) — the app provisions your server

Press **s** and pick where the server runs:

**1. Your own VM (recommended).** Point it at a Linux VM — an **Oracle Cloud Always-Free**
Ubuntu instance is ideal (free forever). Enter the VM's IP, SSH user, and key path, and the
app **SSHes in and sets everything up**: it bundles our server into one file, installs Node +
**Caddy** (automatic Let's Encrypt HTTPS on a `<ip>.sslip.io` domain — no domain to buy),
opens the firewall, runs it as a background service, and connects. One-time manual step: open
**ports 80 + 443** in the VM's cloud-console security list. This is the real path — a VM
reaches every site (incl. Cloudflare), has no connection cap, no ToS problems, and still
looks like HTTPS on 443 so filters pass it. It relays both **TCP and UDP** (QUIC/HTTP-3, games,
DNS), which Cloudflare Workers can't do.

**2. Cloudflare Workers.** The quick demo path (pre-filled token → auto-deploy), but limited:
can't reach Cloudflare-fronted sites, no UDP, and it violates Cloudflare's ToS.

> The server bundle and both wizard flows are verified locally; the live SSH provisioning and
> the live Cloudflare deploy each need your own VM / token to confirm end-to-end.

### A web GUI too (`npm run ui`)

Same features served as a local page at `http://127.0.0.1:8799` for people who'd rather
click — loopback-only, guarded by a per-run token + Host check.

## Package it as a double-clickable app (macOS)

```
./build-app.sh                # dist/Collateral.app — uses the Node on this Mac (~76 KB)
./build-app.sh --embed-node   # dist/Collateral.app — bundles official Node (~139 MB), runs
                              # on other same-arch Macs with no Node installed
```
Double-click `dist/Collateral.app`: it starts the tunnel service and opens the control
panel in the browser — no terminal. The launcher finds Node even under Finder's minimal
PATH, and config lives in `~/.collateral-config.json` (the bundle stays read-only).

### Shipping it to customers (the business steps)

`build-app.sh` produces an **unsigned** app, so another Mac's Gatekeeper blocks it until
the user right-clicks → Open. To sell it you need to:

- **Code-sign + notarize** (Apple Developer account, $99/yr): `codesign --deep --sign "Developer ID Application: …" dist/Collateral.app`, then `xcrun notarytool submit` + `stapler staple`. After that it opens with a normal double-click. Wrap it in a `.dmg` for distribution.
- **Windows:** build a separate package (e.g. a Node SEA or `pkg` binary + an installer, signed with an Authenticode cert). Same app code, different shell.
- Consider **Electron/Tauri** later only if you want a native window instead of the browser tab — the current architecture (local server + browser) is simpler and already works.

Requires Node ≥ 22 (built-in `WebSocket`, `fetch`, `node --test`). Developed on Node 26.

---

## What the demo proves

`npm run demo` starts a local origin, the worker-shim, and the client, then drives
real traffic through the tunnel and checks four things:

```
curl-equivalent ──SOCKS5──▶ client ──VLESS/ws──▶ worker-shim ──connect()──▶ origin
```

1. **Tunnel works** — an HTTP request reaches the origin through VLESS-over-WebSocket and the response comes back.
2. **Probe resistance** — a plain (non-WebSocket) request to the worker gets an innocuous **decoy page**, never a proxy-shaped reply.
3. **Auth gate** — a forged UUID is dropped with no proxying.
4. **Live exit (optional)** — a real HTTPS request to `example.com` through the tunnel, if outbound internet is available (skipped cleanly if not).

It also prints a generated `vless://` config — the artifact onboarding hands the
user, importable into sing-box/Xray for interop.

---

## Layout

| Path | Role |
|---|---|
| `common/vless.js` | VLESS framing — **pure**, shared by the shim and the real Worker |
| `common/ws-frame.js` | Minimal RFC 6455 WebSocket framing (Node shim side only) |
| `common/decoy.js` | The decoy page served to probes — shared by shim and Worker |
| `common/config.js` | `vless://` URI + subscription blob generation |
| `worker-shim.js` | Local Node stand-in for the Worker data plane |
| `client.js` | SOCKS5 inbound → VLESS → WebSocket client |
| `run-demo.js` | The self-verifying end-to-end demo |
| `test.js` | Unit tests |
| `worker/_worker.js` | **Deployable** Cloudflare Worker (same protocol code) |
| `worker/wrangler.toml` | Deploy config |
| `provision/*` | Onboarding wizard logic (deep link + safe read-only steps) |

---

## Mapping to the blueprint pillars

- **Pillar 1 (architecture):** the two-TLS model is real here. The worker/shim
  terminates the *outer* WebSocket TLS and forwards opaque bytes to the
  destination; for an HTTPS site those bytes are the user's *inner* TLS, which the
  worker never reads. The self-hosted shim relays **TCP (`net`) and UDP (`dgram`)**
  via VLESS command 1/2; a Cloudflare Worker's `connect()` is TCP-only.
- **Pillar 2 (onboarding):** `provision/` builds the pre-filled least-privilege
  token link and runs the read-only verify/enumerate steps. The deploy step is left
  to `wrangler` by design (see safety note).
- **Pillar 3 (obfuscation):** the decoy page gives active-probing resistance. Note
  the honest limits from the blueprint still hold — this is TLS-in-TLS on the wire,
  and blending is a *collateral-freedom* bet, not invisibility.
- **Pillar 4 / risk register:** the safety boundary below is exactly the top
  critical risk, enforced in code.

---

## Reaching Cloudflare-fronted sites (NAT64)

A Worker's `connect()` is blocked from dialing Cloudflare's own IPs (anti-loop), and
much of the web is Cloudflare-fronted — so a bare reflector can't reach those sites.
Reaching them requires a **NAT64 gateway** (or a ProxyIP), and that is a third party on
the path. So NAT64 is **off by default** and opt-in:

- **Default (no `NAT64_PREFIX`):** all traffic goes direct. The non-Cloudflare web works;
  Cloudflare-fronted sites fail fast (no hanging on a dead relay, no unvetted third party).
- **Opt in:** set `NAT64_PREFIX` (in `wrangler.toml` or the dashboard) to a gateway you
  trust — ideally your own or a ProxyIP you run. `common/nat64.js` then resolves each
  destination and routes only Cloudflare-fronted IPs through it; everything else stays direct.
- Public gateways (e.g. `2602:fc59:b0:64::`) exist but **die often and see your destination
  IPs** — verify liveness before trusting one, and prefer infrastructure you control.
- The IPv6 `connect()` path is the one part not runtime-tested here (Node can't run
  `cloudflare:sockets`); confirm it on deploy with a CF-fronted target.

## What this prototype does NOT do (on purpose)

- **It does not deploy a live proxy for you.** Running a proxy on Cloudflare Workers
  violates Cloudflare's Self-Serve Subscription Agreement §2.2.1(j) and is
  actively fingerprinted and account-banned. Deploying is a conscious act you take
  on a **throwaway account** that hosts nothing else — never automated here.
- **Device-wide TUN is macOS-only (v1).** Press **f** for a real `utun` that captures traffic
  device-wide (via a pinned `tun2socks` helper + our existing client — see above). Carries
  **TCP and UDP** (QUIC, games, DNS) on the self-hosted VM path. Linux/Windows routing and
  mobile builds are follow-ups. Production would additionally embed **libbox** + `uTLS`
  fingerprint mimicry.
- **No uTLS / ECH / REALITY.** Those are hardening layers (Phase 2+), not needed to
  prove the mechanism.

## Deploying the real Worker (only when you choose to)

```bash
cd worker
npx wrangler login                 # or set CLOUDFLARE_API_TOKEN=<scoped token>
npx wrangler secret put USER_UUID  # the per-user UUID the client will hold
npx wrangler deploy                # bundles ../common/*.js automatically
```

`*.workers.dev` is DNS-blocked in Iran/China, so it only proves the pipeline from an
uncensored network — bind a custom domain for real use.
