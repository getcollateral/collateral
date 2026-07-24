// Onboarding wizard logic (slice 5), in a SAFE form.
//
//  - Always: print the pre-filled token deep link + the least-privilege scopes.
//  - If CF_API_TOKEN is set: run the READ-ONLY steps live (verify token, list
//    accounts, read the workers.dev subdomain). These do not deploy anything and
//    carry no ToS risk — they just prove the onboarding read path works.
//  - The WRITE steps (upload Worker, enable subdomain) are printed as a dry-run
//    plan only. Actually deploying a proxy is the ToS-violating, account-ban-risking
//    step, so this tool never performs it — use `wrangler deploy` on a throwaway
//    account when you consciously choose to.
//
//  run:  node provision/provision.js        (dry-run + deep link)
//        CF_API_TOKEN=xxxx node provision/provision.js   (also runs read-only live)

import crypto from "node:crypto";
import { buildTokenDeepLink, FALLBACK_URL, RECOMMENDED_SCOPES } from "./deeplink.js";

const API = "https://api.cloudflare.com/client/v4";
const C = { grn: "\x1b[32m", red: "\x1b[31m", dim: "\x1b[2m", cyan: "\x1b[36m", yel: "\x1b[33m", rst: "\x1b[0m", b: "\x1b[1m" };

async function cf(token, path) {
  const r = await fetch(API + path, { headers: { Authorization: `Bearer ${token}` } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    const msg = (j.errors && j.errors.map((e) => `${e.code} ${e.message}`).join("; ")) || `HTTP ${r.status}`;
    throw new Error(msg);
  }
  return j.result;
}

async function main() {
  console.log(`\n${C.b}Collateral — onboarding wizard (safe/read-only)${C.rst}\n`);

  console.log(`${C.b}Step 1 — user creates a scoped token${C.rst}`);
  console.log(`  least-privilege scopes: ${C.cyan}${RECOMMENDED_SCOPES.map((s) => s.key + ":" + s.type).join("  ")}${C.rst}`);
  console.log(`  pre-filled link the wizard opens:\n  ${C.cyan}${buildTokenDeepLink()}${C.rst}`);
  console.log(`  ${C.dim}fallback if the deep link breaks: ${FALLBACK_URL}${C.rst}\n`);

  const token = process.env.CF_API_TOKEN;
  if (!token) {
    console.log(`${C.yel}No CF_API_TOKEN set — skipping the live read-only steps.${C.rst}`);
    console.log(`${C.dim}Set CF_API_TOKEN=<a token created from the link above> to run steps 2–4 live.${C.rst}\n`);
  } else {
    try {
      console.log(`${C.b}Step 2 — verify token${C.rst}  ${C.dim}GET /user/tokens/verify${C.rst}`);
      const v = await cf(token, "/user/tokens/verify");
      console.log(`  ${C.grn}ok${C.rst}  status=${v.status}\n`);

      console.log(`${C.b}Step 3 — enumerate accounts${C.rst}  ${C.dim}GET /accounts${C.rst}`);
      const accounts = await cf(token, "/accounts");
      accounts.forEach((a) => console.log(`  ${C.grn}•${C.rst} ${a.name}  ${C.dim}${a.id}${C.rst}`));
      const account = accounts[0];
      if (accounts.length > 1) console.log(`  ${C.dim}(>1 account — the wizard would show a picker; using the first here)${C.rst}`);
      console.log("");

      console.log(`${C.b}Step 4 — read workers.dev subdomain${C.rst}  ${C.dim}GET /accounts/{id}/workers/subdomain${C.rst}`);
      try {
        const sub = await cf(token, `/accounts/${account.id}/workers/subdomain`);
        console.log(`  ${C.grn}ok${C.rst}  https://<script>.${sub.subdomain}.workers.dev\n`);
      } catch (e) {
        console.log(`  ${C.yel}none set${C.rst}  (${e.message}) — the wizard would register one\n`);
      }
    } catch (e) {
      console.log(`  ${C.red}live step failed:${C.rst} ${e.message}`);
      console.log(`  ${C.dim}(check the token was created with the scopes above)${C.rst}\n`);
    }
  }

  const uuid = crypto.randomUUID();
  console.log(`${C.b}Steps 5–8 — DRY RUN (not executed)${C.rst}  ${C.dim}the ToS-risky writes${C.rst}`);
  console.log(`  5. generate per-user UUID (CSPRNG)   -> ${C.cyan}${uuid}${C.rst}`);
  console.log(`  6. PUT /accounts/{id}/workers/scripts/collateral-reflector  ${C.dim}(multipart module + USER_UUID secret)${C.rst}`);
  console.log(`  7. POST /accounts/{id}/workers/scripts/collateral-reflector/subdomain  {"enabled":true}`);
  console.log(`  8. health check: GET https://<script>.<subdomain>.workers.dev -> expect ${C.cyan}426 Upgrade Required${C.rst}\n`);

  console.log(`${C.yel}${C.b}⚠  Deploying the Worker is deliberately NOT automated here.${C.rst}`);
  console.log(`   A proxy on Workers violates Cloudflare ToS §2.2.1(j) and is fingerprinted/blocked;`);
  console.log(`   a strike can take down the whole account. When you consciously choose to, deploy`);
  console.log(`   onto a THROWAWAY account:  ${C.cyan}cd worker && npx wrangler secret put USER_UUID && npx wrangler deploy${C.rst}\n`);
}

main().catch((e) => {
  console.error("provision error:", e);
  process.exit(1);
});
