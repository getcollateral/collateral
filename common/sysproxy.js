// macOS system SOCKS proxy control, so the tunnel can apply device-wide (to every app
// that honors the system proxy) - not just apps you point at 127.0.0.1 manually.
//
// Changing network settings needs admin rights, so writes try un-elevated first and fall
// back to an osascript GUI password prompt. Read-only queries never prompt. macOS only.

import { execFile, execFileSync } from "node:child_process";

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

// Turn the proxy off synchronously, for a process 'exit' handler.
//
// Nothing async can run there - the event loop is finished, so setSocks() below would be
// registered and never executed, which is exactly how a killed TUI left the whole machine
// pointed at a SOCKS port that no longer had anything listening on it. The user's browsing
// stops working and nothing on screen explains why.
//
// Un-elevated only, and deliberately so: the osascript escalation opens a GUI password prompt,
// and blocking a dying process on one would hang the terminal instead of restoring it. If the
// un-elevated call is refused there is nothing more to try from here, and the TUI's own startup
// check reports a proxy left on so the next run can offer to fix it.
export function setSocksOffSync(service) {
  if (!isMac || !service) return false;
  try {
    execFileSync("networksetup", ["-setsocksfirewallproxystate", service, "off"],
                 { timeout: 4000, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
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
