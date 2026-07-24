// First-time setup: deploy the reflector Worker to the USER'S own Cloudflare account
// over the API — no wrangler, no terminal. Bundles the worker + its shared modules
// into one file, uploads it with the per-user UUID as a secret, enables the endpoint.
//
// ⚠️  Deploying a proxy violates Cloudflare ToS §2.2.1(j) and can ban the account.
//     The wizard that calls this MUST get explicit consent and steer users to a
//     throwaway account first (see tui.js setup()).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const API = "https://api.cloudflare.com/client/v4";
const isUuidStr = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || "");

// Inline the worker's local imports into a single ESM module (the API upload wants
// one self-contained file). The shared modules have no imports of their own, so a
// concatenate-and-strip is sufficient and stays in lockstep with the source.
export function bundleWorker() {
  const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");
  const stripImports = (s) => s.replace(/^\s*import\s.*$/gm, "");
  const stripExports = (s) => s.replace(/^export\s+/gm, "");
  const deps = ["common/vless.js", "common/decoy.js", "common/nat64.js"]
    .map((f) => stripExports(stripImports(read(f))).trim())
    .join("\n\n");
  const main = stripImports(read("worker/_worker.js")).trim(); // keeps `export default`
  return `import { connect } from "cloudflare:sockets";\n\n${deps}\n\n${main}\n`;
}

async function cf(token, method, pathname, opts = {}) {
  const r = await fetch(API + pathname, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(opts.headers || {}) },
    body: opts.body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    const err = new Error((j.errors && j.errors.map((e) => `${e.code} ${e.message}`).join("; ")) || `HTTP ${r.status}`);
    err.code = j.errors && j.errors[0] && j.errors[0].code;
    throw err;
  }
  return j.result;
}

async function ensureSubdomain(token, accountId) {
  try {
    const r = await cf(token, "GET", `/accounts/${accountId}/workers/subdomain`);
    if (r && r.subdomain) return { subdomain: r.subdomain, created: false };
  } catch { /* none yet */ }
  for (let i = 0; i < 4; i++) {
    const name = "cf-" + crypto.randomBytes(4).toString("hex");
    try {
      await cf(token, "PUT", `/accounts/${accountId}/workers/subdomain`, {
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ subdomain: name }),
      });
      return { subdomain: name, created: true };
    } catch (e) {
      if (e.code === 10036) { // already registered for this account — read it back
        const r = await cf(token, "GET", `/accounts/${accountId}/workers/subdomain`);
        if (r && r.subdomain) return { subdomain: r.subdomain, created: false };
      }
      // else: name taken globally — try another
    }
  }
  throw new Error("couldn't register a workers.dev subdomain (token may lack Workers permissions)");
}

// Does a script with this name already exist on the account? (idempotent re-runs)
async function scriptExists(token, accountId, scriptName) {
  try {
    const list = await cf(token, "GET", `/accounts/${accountId}/workers/scripts`);
    return Array.isArray(list) && list.some((s) => s && s.id === scriptName);
  } catch { return false; }
}

async function uploadWorker(token, accountId, scriptName, uuid) {
  const metadata = {
    main_module: "worker.js",
    compatibility_date: "2025-01-01",
    bindings: [{ type: "secret_text", name: "USER_UUID", text: uuid }],
  };
  const fd = new FormData();
  fd.set("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  fd.set("worker.js", new Blob([bundleWorker()], { type: "application/javascript+module" }), "worker.js");
  await cf(token, "PUT", `/accounts/${accountId}/workers/scripts/${scriptName}`, { body: fd });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function healthCheck(httpsUrl, tries = 8) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(httpsUrl, { redirect: "manual" });
      if (r.status === 200 || r.status === 426) return true; // decoy page or WS-expected
    } catch { /* propagating */ }
    await sleep(1500);
  }
  throw new Error("worker deployed but the endpoint isn't responding yet");
}

// Run the whole sequence, idempotently: re-runs reuse the existing key + subdomain and
// update the worker in place rather than recreating it. onStep(name, status, note)
// drives the wizard's progress UI. Pass existingUuid (from saved config) to keep the
// same access key across runs instead of rotating it.
export async function deployToAccount({ token, scriptName = "collateral-reflector", existingUuid, onStep = () => {} }) {
  onStep("verify", "run");
  const v = await cf(token, "GET", "/user/tokens/verify");
  if (v.status !== "active") throw new Error("token is not active");
  onStep("verify", "ok");

  onStep("account", "run");
  const accounts = await cf(token, "GET", "/accounts");
  if (!accounts.length) throw new Error("this token has no accounts");
  const account = accounts[0];
  onStep("account", "ok", account.name);

  // Subdomain: reused if the account already has one, only created when missing.
  onStep("subdomain", "run");
  const sub = await ensureSubdomain(token, account.id);
  onStep("subdomain", "ok", `${sub.subdomain}.workers.dev${sub.created ? "" : " · existing"}`);

  // Key: reuse the one from saved config so re-runs don't rotate it.
  onStep("key", "run");
  const reused = isUuidStr(existingUuid);
  const uuid = reused ? existingUuid : crypto.randomUUID();
  onStep("key", "ok", reused ? "reused existing" : "generated");

  // Worker: always upload (guarantees current code + correct secret — the deployed
  // secret can't be read back, so skipping would risk a stale/mismatched worker), but
  // report whether we updated an existing script or created a new one.
  onStep("upload", "run");
  const existed = await scriptExists(token, account.id, scriptName);
  await uploadWorker(token, account.id, scriptName, uuid);
  onStep("upload", "ok", existed ? "updated existing" : "created");

  onStep("enable", "run");
  await cf(token, "POST", `/accounts/${account.id}/workers/scripts/${scriptName}/subdomain`, {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ enabled: true }),
  });
  onStep("enable", "ok");

  const httpsUrl = `https://${scriptName}.${sub.subdomain}.workers.dev`;
  onStep("health", "run");
  await healthCheck(httpsUrl);
  onStep("health", "ok");

  return {
    workerUrl: `wss://${scriptName}.${sub.subdomain}.workers.dev`,
    httpsUrl, uuid, subdomain: sub.subdomain, account: account.name,
    reusedKey: reused, updatedExisting: existed,
  };
}
