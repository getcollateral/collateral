# Security Policy

Collateral is a censorship-circumvention tool, so security reports are taken seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately** - not in a public issue.

Use GitHub's private vulnerability reporting: the repository's **Security** tab →
**Report a vulnerability**. (If it isn't enabled yet, turn on "Private vulnerability
reporting" under Settings → Code security.)

Include what you found, how to reproduce it, and the impact. You'll get an
acknowledgement within a few days and updates as a fix is worked on. Please allow
reasonable time to ship a fix before any public disclosure.

## Scope and honest limits

Collateral hides *what* you connect to by making traffic look like ordinary HTTPS on
port 443 (VLESS over WebSocket over TLS). This is a **collateral-freedom** bet, not
invisibility: it is TLS-in-TLS on the wire, and a sophisticated adversary doing deep
traffic analysis is outside the current design's threat model. Using your own domain
strengthens it, but no tool is a guarantee. See the README for the full picture.

In scope: auth/handshake flaws, config or key leakage, the provisioning path, the
device-wide routing (leaks around the tunnel), and anything that deanonymizes a user
or exposes traffic contents.

## Supported versions

The latest release on the default branch is the supported version.
