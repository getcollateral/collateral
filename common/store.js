// Shared config store: remembers the worker address + access key between runs,
// in the user's home dir (works whether run as a script, npx, or a bundle).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CONFIG_PATH = path.join(os.homedir(), ".collateral-config.json");

export function loadConfig() {
  try { return { workerUrl: "", uuid: "", ...JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) }; }
  catch { return { workerUrl: "", uuid: "" }; }
}

export function saveConfig(patch) {
  const merged = { ...loadConfig(), ...patch };
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2)); } catch {}
  return merged;
}
