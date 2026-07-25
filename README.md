# Collateral

**A private tunnel you own end to end.** Collateral sets up a stealth proxy on your own
free cloud VM and drives it from a small terminal app. Your traffic is wrapped so it looks
like ordinary HTTPS on port 443 - the kind of connection a school or workplace filter can't
tell apart from normal web browsing - and it exits from a server that only you control.

No subscription, no shared VPN server, no account with a middleman who can see your traffic.
The exit IP is yours.

```
npx getcollateral
```

That's it - the command downloads and opens the control panel. Needs [Node](https://nodejs.org)
≥ 22.

- **Website:** https://getcollateral.xyz
- **Works on:** macOS, Linux, Windows (the terminal app). Device-wide "full tunnel" mode works
  on macOS and Linux (Windows is planned).

---

## What you need

1. **Node ≥ 22** on your computer - that's what runs the control panel.
2. **A Linux VM to be your exit server.** An [Oracle Cloud Always-Free](https://www.oracle.com/cloud/free/)
   Ubuntu instance is ideal: free forever, and enough for personal use. You provide the VM's IP
   and SSH key once; Collateral sets up everything on it for you.

You don't need to know anything about proxies, TLS, or server admin. The app does the setup.

---

## Quick start

1. Create a free Ubuntu VM (Oracle Cloud Always-Free works well) and note its **public IP**,
   **SSH username**, and **SSH key file**.
2. In your VM's cloud console, open **ports 80 and 443** in the security list / firewall rules.
   (One-time click in the web console - the app can't do this part for you.)
3. Run `npx getcollateral`.
4. Press **s** for first-time setup, choose **your own VM**, and enter the IP, user, and key
   path. The app SSHes in and configures the server, gets an HTTPS certificate automatically,
   and connects.
5. Press **t** any time to test - it shows the live exit IP (your VM's).

Your settings are saved to `~/.collateral-config.json`, so next time you just run the command
and press **c** to connect.

---

## The control panel

A full-screen terminal app - clickable, live status, zero dependencies. The brand mark `[•]`
**is** the status light: filled when connected, empty `[ ]` when idle, a spinner while it's
working.

![Collateral — the terminal control panel: connecting, testing the tunnel, and turning on the full device-wide tunnel](assets/demo.gif)

**Click** any row, or use the keys:

| Key | Does |
|---|---|
| **s** | First-time setup - provisions your server |
| **c** | Connect / disconnect |
| **t** | Test the connection (shows the live exit IP) |
| **d** | System-wide proxy on/off (macOS) |
| **f** | Full tunnel on/off - captures the whole device (macOS & Linux) |
| **x** | Share this config as a QR code |
| **i** | Import a config by scanning a QR (macOS camera) |
| **w** / **u** | Set the server address / access key manually |
| **g** | Generate a new access key |
| **p** | Proxy setup help |
| **q** | Quit (works even mid-connect) |

Once connected, point any app's SOCKS5 proxy at `127.0.0.1:1080`, or use the device-wide
options below.

While connected, a background health check keeps the status honest: if the server ever becomes
unreachable it shows **reconnecting…** and flips back to **connected** on its own when it
recovers - no manual reconnect needed.

---

## Route your whole device (macOS & Linux)

There are two device-wide modes. Both only run while you're connected, and both turn **off
automatically on disconnect, on quit, and even on a crash** - a dead tunnel can never strand
your traffic.

### `d` - system proxy (macOS)

Flips the macOS system SOCKS proxy to point at the tunnel, so every app that honors it is
routed. Needs your password (changing network settings requires admin). Apple treats this as
best-effort, though - some apps ignore it. For real coverage use the full tunnel.

### `f` - full tunnel (recommended for device-wide)

Brings up a VPN-style interface that captures **all** of your device's traffic at the network
level - nothing to configure per app, nothing that can bypass it. **Both TCP and UDP** go
through your VM, so video calls, games (Roblox, etc.), and QUIC/HTTP-3 sites all work, not just
web pages.

Works on **macOS and Linux** (Windows is planned). It asks for your password once to set up (a
system dialog on macOS, a polkit prompt on Linux), then runs safely in the background: it never
touches your normal network routes, and if anything goes wrong it heals itself automatically.

---

## Move your config to another Mac - no typing (`x` → `i`)

- On the Mac that's already set up, press **x**. It shows a **QR code** of your server + key.
- On the new Mac, press **i**. It opens the camera; point it at the first screen. It reads the
  config, imports it, and you press **c** to connect.

The same QR also imports into mobile VLESS apps (v2rayNG, sing-box, Shadowrocket) if you want
your phone on it too.

> **Anyone with your config can use your server.** Only share the QR with people you want on it.

---

## Use your own domain (optional, stronger)

During setup you can enter a domain **you own** with an A record already pointed at your VM.
Then your connection looks like an ordinary visit to *your* website - there's no shared pattern
for a filter to block. (The automatic default uses `sslip.io`, which works out of the box but,
like any shared suffix, could in principle be blocked wholesale.) Setup checks that the domain
points at your VM before continuing. Press enter to skip and use the automatic default.

---

## Honest limits

- **Full tunnel covers macOS and Linux (Windows is planned).** The terminal app and SOCKS proxy
  work everywhere; Windows device-wide capture and mobile apps are on the roadmap.
- **This isn't magic invisibility.** It looks like normal HTTPS, which defeats the common
  filters that block by domain or category. A sophisticated national firewall doing deep traffic
  analysis is a harder problem - using your own domain helps, but no tool is a guarantee.
- **You run the server.** That's the point - no third party sees your traffic - but it also
  means the exit is only as reliable as your VM.

Use it to protect your own privacy and access, on networks and in ways that are lawful where
you are.

---

## License

MIT. Contributions and issues welcome - https://getcollateral.xyz
