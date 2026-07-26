// First-time setup, VPS edition: SSH into the user's own VM (e.g. an Oracle Cloud
// Always-Free instance) and stand up the server automatically - no manual terminal work.
// This is the "app provisions your server" model (like Outline Manager).
//
// It bundles our server (worker-shim.js) into one file, puts Caddy in front for
// automatic Let's Encrypt HTTPS on a <ip>.sslip.io domain (no domain purchase needed),
// and runs it behind systemd. Uses the system `ssh` binary, so still zero npm deps.
//
// A real VM reaches every site, does TCP + UDP, and has no connection cap - while
// staying WebSocket-over-TLS on :443 (filter-friendly).

import { execFile } from "node:child_process";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Normalize a user-entered domain: strip scheme/path/whitespace, lowercase. "" if empty.
export function normalizeDomain(s) {
  return String(s || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"];

// Inline worker-shim.js + its shared modules into one runnable server.mjs.
export function bundleServer() {
  const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");
  const files = ["common/vless.js", "common/decoy.js", "common/ws-frame.js", "worker-shim.js"];
  const nodeImports = new Set();
  const bodies = [];
  for (const f of files) {
    let src = read(f);
    src = src.replace(/^\s*import\s.*from\s+["'](node:[^"']+)["'];?\s*$/gm, (m) => { nodeImports.add(m.trim()); return ""; });
    src = src.replace(/^\s*import\s.*from\s+["']\.{1,2}\/.*$/gm, ""); // drop local imports (inlined)
    src = src.replace(/^export\s+/gm, "");                            // strip export keyword
    if (f === "worker-shim.js") src = src.replace(/\/\/ Run standalone[\s\S]*$/m, ""); // drop the symlink-fragile guard
    bodies.push(src.trim());
  }
  // Dedicated server file → start unconditionally, bound to localhost (Caddy fronts it).
  const start = `\nstartWorker({ port: Number(process.env.WORKER_PORT || 8787), host: "127.0.0.1", keysFile: process.env.KEYS_FILE, uuid: process.env.USER_UUID });\n`;
  return [...nodeImports].join("\n") + "\n\n" + bodies.join("\n\n") + "\n" + start;
}

function ssh(host, user, keyPath, remoteCmd, input, timeout = 300000, onData) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "ssh",
      ["-i", keyPath, ...SSH_OPTS, `${user}@${host}`, remoteCmd],
      { timeout, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; err.stdout = stdout; return reject(err); }
        resolve({ stdout, stderr });
      }
    );
    if (onData) { child.stdout.on("data", (d) => onData(String(d))); child.stderr.on("data", (d) => onData(String(d))); }
    if (input != null) { child.stdin.write(input); child.stdin.end(); }
  });
}

// The remote install script (Ubuntu-focused; best-effort on Oracle Linux). Idempotent.
function setupScript({ uuid, domain }) {
  return `#!/usr/bin/env bash
set -eo pipefail
export DEBIAN_FRONTEND=noninteractive
have(){ command -v "$1" >/dev/null 2>&1; }
if ! sudo -n true 2>/dev/null; then echo COLLATERAL_NEED_NOPASSWD_SUDO; exit 1; fi
# Use a SYSTEM node (never a home-dir nvm node - systemd as root can't exec that).
sysnode(){ for c in /usr/bin/node /usr/local/bin/node; do if [ -x "$c" ] && [ "$("$c" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" -ge 18 ]; then echo "$c"; return; fi; done; }
NODE="$(sysnode)"
if [ -z "$NODE" ]; then
  if have apt-get; then curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs
  elif have dnf; then sudo dnf module reset -y nodejs || true; sudo dnf module install -y nodejs:20/common || sudo dnf install -y nodejs; fi
  NODE="$(sysnode)"; [ -z "$NODE" ] && NODE=/usr/bin/node
fi
if ! have caddy; then
  if have apt-get; then
    sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg ca-certificates
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -y && sudo apt-get install -y caddy
  elif have dnf; then
    sudo dnf install -y 'dnf-command(copr)' || true
    sudo dnf copr enable -y @caddy/caddy "epel-$(rpm -E %rhel)-$(uname -m)" 2>/dev/null || sudo dnf copr enable -y @caddy/caddy || true
    sudo dnf install -y caddy
  fi
fi
sudo mkdir -p /opt/collateral
[ -f /tmp/collateral-server.mjs ] && sudo cp /tmp/collateral-server.mjs /opt/collateral/server.mjs
# keys file: the server watches this. Ensure the owner's key is present WITHOUT clobbering any
# friend keys added since - a redeploy must never wipe them.
sudo touch /opt/collateral/keys && sudo chmod 600 /opt/collateral/keys
sudo grep -qxF '${uuid}' /opt/collateral/keys || echo '${uuid}' | sudo tee -a /opt/collateral/keys >/dev/null
printf 'KEYS_FILE=/opt/collateral/keys\\nUSER_UUID=%s\\nWORKER_PORT=8787\\n' '${uuid}' | sudo tee /opt/collateral/env >/dev/null
sudo chmod 600 /opt/collateral/env
sudo tee /etc/systemd/system/collateral.service >/dev/null <<UNIT
[Unit]
Description=Collateral server
After=network.target
[Service]
EnvironmentFile=/opt/collateral/env
ExecStart=$NODE /opt/collateral/server.mjs
Restart=always
User=root
[Install]
WantedBy=multi-user.target
UNIT
sudo mkdir -p /etc/caddy
echo '{
  auto_https disable_redirects
}
${domain} {
  reverse_proxy localhost:8787
}' | sudo tee /etc/caddy/Caddyfile >/dev/null
# open 80 (ACME challenge) + 443 on the instance's own firewall
if have firewall-cmd; then sudo firewall-cmd --add-port=80/tcp --add-port=443/tcp --permanent && sudo firewall-cmd --reload
else
  sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
  if have netfilter-persistent; then sudo netfilter-persistent save
  elif [ -d /etc/iptables ]; then sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
  else sudo sh -c 'iptables-save > /etc/sysconfig/iptables' 2>/dev/null || true; fi
fi
sudo systemctl daemon-reload
sudo systemctl enable collateral
# restart (not 'enable --now'): on a redeploy the service is already running, and --now would
# NOT reload it - leaving a stale process with the OLD USER_UUID/code. restart always reloads.
sudo systemctl restart collateral
sudo systemctl restart caddy || sudo systemctl start caddy
echo COLLATERAL_SETUP_OK
`;
}

function waitForHttps(domain, log = () => {}, tries = 40) {
  return new Promise(async (resolve, reject) => {
    for (let i = 0; i < tries; i++) {
      try {
        const r = await fetch(`https://${domain}/`, { redirect: "manual" });
        log(`  cert check ${i + 1}/${tries}: HTTP ${r.status}\n`);
        if (r.status === 200 || r.status === 426) return resolve(true); // decoy or WS-expected
      } catch (e) { log(`  cert check ${i + 1}/${tries}: ${(e.cause && e.cause.code) || e.message}\n`); }
      await new Promise((s) => setTimeout(s, 3000));
    }
    reject(new Error("HTTPS didn't come up after ~2min (Caddy couldn't get a cert)"));
  });
}

// Pull the state of the VM when something's wrong - this is what tells us WHY.
export async function diagnose(host, user, keyPath, domain) {
  const cmd = `set +e
echo "== services active? =="; sudo systemctl is-active caddy collateral
echo; echo "== caddy log (last 45) =="; sudo journalctl -u caddy --no-pager -n 45 2>&1 | tail -45
echo; echo "== collateral server log =="; sudo journalctl -u collateral --no-pager -n 15 2>&1 | tail -15
echo; echo "== local node server =="; curl -sS -m 5 -o /dev/null -w 'http %{http_code}\\n' http://localhost:8787/ 2>&1
echo "== listening 80/443/8787 =="; sudo ss -tlnp 2>/dev/null | grep -E ':80 |:443 |:8787 ' || echo "NOTHING on 80/443/8787!"
echo "== iptables INPUT =="; sudo iptables -S INPUT 2>/dev/null | head -8
echo "== dns ${domain} =="; getent hosts ${domain} 2>&1 || echo "getent failed"`;
  try { const { stdout } = await ssh(host, user, keyPath, "bash -s", cmd, 60000); return stdout; }
  catch (e) { return (e.stdout || "") + (e.stderr || "") + (e.message || ""); }
}

const KEYS_PATH = "/opt/collateral/keys";
const okUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");
// Nudge the server to re-read the keys file right away (fs.watch is best-effort on some kernels).
const RELOAD = "(sudo systemctl kill -s HUP collateral 2>/dev/null || sudo pkill -HUP -f /opt/collateral/server.mjs 2>/dev/null) || true";

// Friend keys: the VM's keys file is the source of truth, and the server re-reads it on change
// (fs.watch), so add/revoke take effect immediately - no redeploy. UUIDs are validated before they
// reach the shell, so there's nothing to inject.
export async function addKey({ host, user = "ubuntu", keyPath, uuid }) {
  if (!okUuid(uuid)) throw new Error("addKey: bad uuid");
  await ssh(host, user, keyPath, `sudo touch ${KEYS_PATH}; sudo grep -qxF '${uuid}' ${KEYS_PATH} || echo '${uuid}' | sudo tee -a ${KEYS_PATH} >/dev/null; ${RELOAD}`, null, 30000);
}
export async function removeKey({ host, user = "ubuntu", keyPath, uuid }) {
  if (!okUuid(uuid)) throw new Error("removeKey: bad uuid");
  await ssh(host, user, keyPath, `sudo sh -c 'grep -vxF "${uuid}" ${KEYS_PATH} > ${KEYS_PATH}.tmp 2>/dev/null; mv ${KEYS_PATH}.tmp ${KEYS_PATH}; chmod 600 ${KEYS_PATH}'; ${RELOAD}`, null, 30000);
}
export async function listKeys({ host, user = "ubuntu", keyPath }) {
  const { stdout } = await ssh(host, user, keyPath, `sudo cat ${KEYS_PATH} 2>/dev/null || true`, null, 30000);
  return stdout.split("\n").map((s) => s.trim().toLowerCase()).filter(okUuid);
}

// Provision the VM and return the client endpoint. onStep(name, status, note) drives the UI.
// Pass `uuid` to install a specific access key (the client key is the source of truth, so a
// redeploy uploads it and stays in sync); omit it for a brand-new setup to mint a fresh one.
export async function provisionVps({ host, user = "ubuntu", keyPath, uuid: keyArg, domain: customDomain, onStep = () => {}, log = () => {} }) {
  onStep("connect", "run");
  log(`[connect] ssh ${user}@${host}\n`);
  try { await ssh(host, user, keyPath, "true", null, 20000); }
  catch (e) { throw new Error(`can't SSH in as ${user}@${host} (${(e.stderr || e.message || "").trim().split("\n").pop()})`); }
  onStep("connect", "ok", `${user}@${host}`);

  // Domain: a custom one you own (stronger - no shared `*.sslip.io` pattern to block) or the
  // automatic `<ip>.sslip.io`. A custom domain must already point at the VM or Let's Encrypt
  // can't issue a cert, so verify its A record up front and fail early with clear guidance.
  const custom = normalizeDomain(customDomain);
  const domain = custom || `${host}.sslip.io`;
  if (custom) {
    onStep("dns", "run");
    log(`[dns] checking ${domain} → ${host}\n`);
    let ips = [];
    try { ips = await dns.resolve4(domain); } catch (e) { log(`[dns] lookup failed: ${e.code || e.message}\n`); }
    if (!ips.includes(host)) {
      onStep("dns", "fail");
      throw new Error(`${domain} doesn't point at ${host} yet (resolved: ${ips.join(", ") || "nothing"}). Add an A record “${domain} → ${host}”, wait a few minutes for DNS to propagate, then run setup again.`);
    }
    onStep("dns", "ok", `${domain} → ${host}`);
  }

  const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");
  const uuid = isUuid(keyArg) ? keyArg : crypto.randomUUID();
  log(isUuid(keyArg) ? "using your existing access key\n" : "minting a new access key\n");
  const wsPath = "/" + crypto.randomBytes(6).toString("hex");
  log(`domain: ${domain}\n`);

  onStep("upload", "run");
  log("\n[upload] sending server.mjs\n");
  await ssh(host, user, keyPath, "cat > /tmp/collateral-server.mjs", bundleServer());
  onStep("upload", "ok");

  onStep("install", "run");
  log("\n[install] running setup on the VM:\n");
  let out;
  try {
    out = await ssh(host, user, keyPath, "bash -s", setupScript({ uuid, domain }), 600000, log);
  } catch (e) {
    const blob = (e.stdout || "") + (e.stderr || "");
    if (/COLLATERAL_NEED_NOPASSWD_SUDO/.test(blob)) throw new Error(`${user}@${host} needs passwordless sudo (ubuntu/opc users have it).`);
    throw new Error("install failed: " + (e.stderr || e.stdout || e.message || "").trim().split("\n").slice(-3).join(" ").slice(-300));
  }
  if (!/COLLATERAL_SETUP_OK/.test(out.stdout)) throw new Error("install didn't complete: " + (out.stderr || out.stdout || "").trim().slice(-300));
  onStep("install", "ok");

  onStep("tls", "run");
  log("\n[tls] waiting for Caddy to issue the HTTPS certificate:\n");
  try {
    await waitForHttps(domain, log);
  } catch (e) {
    log("\n[tls] failed, pulling VM diagnostics (this is the real reason):\n");
    log("\n" + (await diagnose(host, user, keyPath, domain)) + "\n");
    throw new Error(e.message + ". See the Caddy log in the diagnostics (rate limit? port 80 unreachable? service down?)");
  }
  onStep("tls", "ok", domain);

  log(`\n✓ endpoint: wss://${domain}${wsPath}\n`);
  return { workerUrl: `wss://${domain}${wsPath}`, httpsUrl: `https://${domain}`, uuid, domain, wsPath, host };
}

// Verbose standalone runner:  node provision/vps.js <ip> [user] [ssh-key-path]
if (process.argv[1] && /vps\.js$/.test(process.argv[1]) && process.argv[2]) {
  const host = process.argv[2];
  const user = process.argv[3] || "ubuntu";
  const keyPath = (process.argv[4] || `${os.homedir()}/.ssh/id_rsa`).replace(/^~(?=$|\/)/, os.homedir());
  const domain = process.argv[5]; // optional: your own domain (A record → host)
  console.log(`Provisioning ${user}@${host}  (key: ${keyPath})${domain ? `  domain: ${domain}` : ""}`);
  provisionVps({
    host, user, keyPath, domain,
    onStep: (n, s, note) => process.stdout.write(`\n[${s.toUpperCase()}] ${n}${note ? ": " + note : ""}\n`),
    log: (m) => process.stdout.write(m),
  })
    .then((res) => {
      console.log(`\n✓ SUCCESS`);
      console.log(`  worker URL : ${res.workerUrl}`);
      console.log(`  access key : ${res.uuid}`);
      console.log(`\nOpen the TUI, press w then u to paste those, and connect.`);
      process.exit(0);
    })
    .catch((e) => { console.error(`\n✗ FAILED: ${e.message}`); process.exit(1); });
}
