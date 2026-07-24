// Bridge to the macOS camera QR scanner (mac/scan-qr.swift). Node can't open the camera, so we
// shell out to a tiny Swift helper that shows a preview window, decodes a QR with AVFoundation,
// and prints the decoded string. Returns the string, or null if the user cancelled; rejects if
// the camera is unavailable / permission was denied. macOS only, no dependencies (uses the
// system `swift`, which ships with the Xcode Command Line Tools).

import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "mac", "scan-qr.swift");

export function supported() { return process.platform === "darwin"; }

export function scanQrViaCamera() {
  return new Promise((resolve, reject) => {
    // `swift <file>` compiles + runs the helper (a few seconds); the 120s in-helper timeout is
    // the real bound, so allow generous headroom here.
    execFile("swift", [SCRIPT], { timeout: 135000, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      const out = (stdout || "").trim();
      if (out) return resolve(out);                      // a QR was decoded
      const e = (stderr || "").toString();
      if (/CAMERA_DENIED/.test(e)) return reject(new Error("camera access denied, enable it for your terminal in System Settings → Privacy & Security → Camera"));
      if (/NO_CAMERA/.test(e)) return reject(new Error("no camera available"));
      if (err && err.killed) return reject(new Error("timed out waiting for a QR"));
      if (err && /swift: command not found|ENOENT/.test(e + (err.message || ""))) return reject(new Error("`swift` not found. Install the Xcode Command Line Tools (xcode-select --install)"));
      return resolve(null);                              // exit 0, no output = cancelled (Esc/close)
    });
  });
}
