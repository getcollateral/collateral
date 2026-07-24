// Builds the pre-filled Cloudflare API-token creation link the onboarding wizard
// opens, so a non-technical user goes Continue -> Create -> Copy instead of
// hunting through a ~15-checkbox permission builder.
//
// NOTE: this URL scheme and the permission-group key strings are UNDOCUMENTED and
// unsupported. Verify against the live dashboard before each release and always
// ship a fallback to the plain https://dash.cloudflare.com/profile/api-tokens page.

// Least privilege for a workers.dev reflector. Add workers_kv_storage:edit only
// if the Worker uses KV. Deliberately no zone/DNS/Routes scopes.
export const RECOMMENDED_SCOPES = [
  { key: "workers_scripts", type: "edit" }, // upload/replace script, enable its subdomain
  { key: "account_settings", type: "read" }, // enumerate accounts, read workers.dev subdomain
];

export function buildTokenDeepLink({ name = "Collateral-Worker-Deploy", scopes = RECOMMENDED_SCOPES } = {}) {
  const params = new URLSearchParams();
  params.set("permissionGroupKeys", JSON.stringify(scopes));
  params.set("name", name);
  params.set("accountId", "*");
  params.set("zoneId", "all");
  return "https://dash.cloudflare.com/profile/api-tokens?" + params.toString();
}

export const FALLBACK_URL = "https://dash.cloudflare.com/profile/api-tokens";
