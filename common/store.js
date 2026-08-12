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
  // Read the base ourselves rather than through loadConfig(), because we need to tell "no file
  // yet" from "a file that will not parse". loadConfig() answers both with defaults, which is
  // right for a reader and catastrophic for a writer: merging a patch onto defaults and saving
  // it replaces every machine, friend and credential with the two keys the caller passed.
  let base;
  try {
    base = { workerUrl: "", uuid: "", ...JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) };
  } catch (e) {
    if (e && e.code === "ENOENT") {
      base = { workerUrl: "", uuid: "" };   // first run, nothing to preserve
    } else {
      // The file exists and we cannot read it. Its contents are unknown, not empty, so writing
      // now would turn a temporary problem into permanent data loss. Leave it alone; the user
      // can delete it, and a reader still gets usable defaults in the meantime.
      return loadConfig();
    }
  }

  const merged = { ...base, ...patch };
  try {
    // Temp file plus rename, because rename is atomic within a filesystem while writeFileSync
    // truncates first and then writes. That truncation window is not theoretical: the Mac app
    // shares this exact file, and a read landing inside it saw an empty or half-written config
    // and - before the guard above and its counterpart in ConfigStore.save - wrote the empty
    // result straight back.
    //
    // 0600 because this file holds the access key, which is the whole credential for the
    // tunnel, plus the ssh key path. The default 0644 left it readable by every other account
    // on the machine. ConfigStore.swift has always written 0600; the two halves of one shared
    // file simply disagreed.
    const tmp = `${CONFIG_PATH}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(merged, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, CONFIG_PATH);
    // rename preserves the temp file's mode, but an existing file replaced by rename keeps
    // nothing of its own, so make the intent explicit for a file created before this change.
    fs.chmodSync(CONFIG_PATH, 0o600);
  } catch {}
  return merged;
}
