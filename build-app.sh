#!/bin/bash
# Package the control panel into a double-clickable macOS app: dist/Collateral.app
#
#   ./build-app.sh                # lightweight; uses the Node already on this Mac
#   ./build-app.sh --embed-node   # self-contained; downloads the official Node so it
#                                 # runs on other (same-arch) Macs with no Node installed
#
# Either result runs on YOUR Mac immediately. To sell it you still need to code-sign +
# notarize (Apple Developer account) so Gatekeeper opens it cleanly, and build a
# separate Windows version - see README "Shipping it".
set -euo pipefail
cd "$(dirname "$0")"

APP="dist/Collateral.app"
RES="$APP/Contents/Resources"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RES/app"

echo "• copying app files"
cp ui-server.js client.js package.json "$RES/app/"
cp -R common provision "$RES/app/"

if [ "${1:-}" = "--embed-node" ]; then
  VER="$(node -p 'process.version')"          # e.g. v26.5.0
  case "$(uname -m)" in
    arm64) NARCH=arm64 ;;
    x86_64) NARCH=x64 ;;
    *) echo "✗ unsupported arch $(uname -m)"; exit 1 ;;
  esac
  PKG="node-${VER}-darwin-${NARCH}"
  echo "• downloading official Node ${VER} (${NARCH})"
  curl -fL "https://nodejs.org/dist/${VER}/${PKG}.tar.gz" -o "/tmp/${PKG}.tar.gz"
  tar -xzf "/tmp/${PKG}.tar.gz" -C /tmp
  cp "/tmp/${PKG}/bin/node" "$RES/node"
  chmod +x "$RES/node"
  echo "• verifying embedded node: $("$RES/node" --version)"
fi

echo "• writing launcher"
cat > "$APP/Contents/MacOS/Collateral" <<'LAUNCH'
#!/bin/bash
# Finder launches apps with a minimal PATH, so find Node ourselves.
RES="$(cd "$(dirname "$0")/../Resources" && pwd)"
APP="$RES/app"
pick_node() {
  if [ -x "$RES/node" ] && "$RES/node" --version >/dev/null 2>&1; then echo "$RES/node"; return; fi
  for c in "$(command -v node 2>/dev/null || true)" \
           /opt/homebrew/bin/node /usr/local/bin/node /usr/bin/node \
           "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.volta/bin/node; do
    if [ -n "$c" ] && [ -x "$c" ] && "$c" --version >/dev/null 2>&1; then echo "$c"; return; fi
  done
}
NODE="$(pick_node)"
if [ -z "$NODE" ]; then
  osascript -e 'display alert "Node.js required" message "Collateral needs Node.js. Install it from nodejs.org, then reopen - or use a build made with --embed-node."' >/dev/null 2>&1
  exit 1
fi
cd "$APP"
exec "$NODE" "$APP/ui-server.js"
LAUNCH
chmod +x "$APP/Contents/MacOS/Collateral"

echo "• writing Info.plist"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Collateral</string>
  <key>CFBundleDisplayName</key><string>Collateral</string>
  <key>CFBundleIdentifier</key><string>com.collateral.app</string>
  <key>CFBundleVersion</key><string>0.1.0</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleExecutable</key><string>Collateral</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

SIZE="$(du -sh "$APP" | cut -f1)"
echo "✓ built $APP ($SIZE)"
echo "  run it:  open \"$APP\""
echo "  (on another Mac the first open is right-click → Open, to clear Gatekeeper)"
