// macOS system SOCKS proxy control, so the tunnel can apply device-wide (to every app
// that honors the system proxy) — not just apps you point at 127.0.0.1 manually.
//
// Changing network settings needs admin rights, so writes try un-elevated first and fall
// back to an osascript GUI password prompt. Read-only queries never prompt. macOS only.

import { execFile } from "node:child_process";

const isMac = process.platform === "darwin";

function run(cmd, args, timeout = 4000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout }, (err, stdout) => resolve(err ? null : stdout || ""));
  });
}

export function supported() { return isMac; }

// The network service backing the default route (e.g. "Wi-Fi"), best-effort.
export async function primaryService() {
  if (!isMac) return null;
  const route = await run("route", ["-n", "get", "default"]);
  const dev = route && (route.match(/interface:\s*(\S+)/) || [])[1];
  const order = await run("networksetup", ["-listnetworkserviceorder"]);
  if (dev && order) {
    const re = /\(\d+\)\s*(.+?)\r?\n\(Hardware Port:[^,]*, Device:\s*([^)]+)\)/g;
    let m;
    while ((m = re.exec(order))) if (m[2].trim() === dev) return m[1].trim();
  }
  const list = await run("networksetup", ["-listallnetworkservices"]);
  if (list) {
    const svc = list.split("\n").slice(1).map((s) => s.trim()).filter((s) => s && !s.startsWith("*"));
    if (svc.length) return svc.includes("Wi-Fi") ? "Wi-Fi" : svc[0];
  }
  return "Wi-Fi";
}

export async function socksEnabled(service) {
  if (!isMac || !service) return false;
  const out = await run("networksetup", ["-getsocksfirewallproxy", service]);
  return !!(out && /^Enabled:\s*Yes/im.test(out));
}

// Turn the system SOCKS proxy on (pointed at host:port) or off. Returns true on success.
export async function setSocks(service, on, host = "127.0.0.1", port = 1080) {
  if (!isMac || !service) return false;
  // Try without elevation first (works for admin users on many macOS versions → no prompt).
  const direct = on
    ? (await run("networksetup", ["-setsocksfirewallproxy", service, host, String(port)])) !== null &&
      (await run("networksetup", ["-setsocksfirewallproxystate", service, "on"])) !== null
    : (await run("networksetup", ["-setsocksfirewallproxystate", service, "off"])) !== null;
  if (direct) return true;

  // Escalate via an admin GUI prompt.
  const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
  const cmd = on
    ? `networksetup -setsocksfirewallproxy ${q(service)} ${host} ${Number(port)} && networksetup -setsocksfirewallproxystate ${q(service)} on`
    : `networksetup -setsocksfirewallproxystate ${q(service)} off`;
  const script = `do shell script "${cmd.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}" with administrator privileges`;
  return (await run("osascript", ["-e", script], 120000)) !== null;
}
