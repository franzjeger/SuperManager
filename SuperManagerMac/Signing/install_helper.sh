#!/usr/bin/env bash
# Install / re-install the SuperManager privileged helper.
#
# Why this script exists
# ----------------------
# Helper binary lives at `/Library/PrivilegedHelperTools/`, root-owned,
# and is launched by launchd via the LaunchDaemon plist at
# `/Library/LaunchDaemons/com.sybr.supermanager.helper.plist`. Both
# locations are root-write-only, so any time the helper's RPC table
# changes we need a sudo'd file copy + a `launchctl` re-bootstrap.
#
# Once installed, the `deploy_self` RPC (gated behind the `dev-rpc`
# Cargo feature) lets the GUI replace the binary without sudo on
# subsequent rebuilds — but the FIRST install always needs this script.
#
# What it does
#   1. `cargo build --release --features dev-rpc` for the helper binary
#   2. `sudo cp` the binary into `/Library/PrivilegedHelperTools/`
#   3. `sudo cp` the plist into `/Library/LaunchDaemons/`
#   4. `sudo chown` + `sudo chmod` to root-owned + 0644/0755
#   5. `sudo launchctl bootout` the existing service (no-op if not
#      running)
#   6. `sudo launchctl bootstrap` the new plist
#
# `dev-rpc` MUST stay off for non-developer builds. It exposes a
# binary-replacement endpoint to anyone in the `admin` group, which is
# fine for a single-developer machine but not for distribution.

set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER_LABEL="com.sybr.supermanager.helper"
HELPER_BIN="/Library/PrivilegedHelperTools/${HELPER_LABEL}"
PLIST_DST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
SOURCE_PLIST="$WORKSPACE/SuperManagerMac/Signing/${HELPER_LABEL}.plist"

# 1. Build the helper with dev-rpc enabled.
echo "→ Building helper with dev-rpc feature…"
(cd "$WORKSPACE" && cargo build --release \
    --bin supermanager-helper \
    --features supermanager-helper/dev-rpc)

NEW_BIN="$WORKSPACE/target/release/supermanager-helper"
if [[ ! -x "$NEW_BIN" ]]; then
    echo "error: built binary missing at $NEW_BIN" >&2
    exit 1
fi

# 2. Plist content. The bundled plist uses `BundleProgram` (an
#    `SMAppService.daemon` path, relative to the app bundle); for a
#    LaunchDaemons-style install we need an absolute `Program` path
#    instead, so we generate a fresh plist on the fly rather than
#    trying to translate the bundled one.
TMP_PLIST="$(mktemp -t supermgr-helper-plist.XXXXXX)"
trap 'rm -f "$TMP_PLIST"' EXIT
cat > "$TMP_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${HELPER_LABEL}</string>
    <key>Program</key><string>${HELPER_BIN}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/>
        <key>Crashed</key><true/>
    </dict>
    <key>StandardOutPath</key><string>/var/log/supermanager-helper.log</string>
    <key>StandardErrorPath</key><string>/var/log/supermanager-helper.log</string>
    <key>SoftResourceLimits</key>
    <dict><key>NumberOfFiles</key><integer>2048</integer></dict>
</dict>
</plist>
EOF

echo "→ Installing helper (will prompt for sudo)…"
sudo install -d -m 0755 -o root -g wheel "$(dirname "$HELPER_BIN")"
sudo install -m 0755 -o root -g wheel "$NEW_BIN" "$HELPER_BIN"
sudo install -m 0644 -o root -g wheel "$TMP_PLIST" "$PLIST_DST"

# 3. Bootstrap the LaunchDaemon. `bootout` first to flush any stale
#    process that's still running an old binary; ignore failures
#    because a non-running service makes bootout return non-zero.
echo "→ Reloading LaunchDaemon…"
sudo launchctl bootout system "$PLIST_DST" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST_DST"

# 4. Sanity check — give it a moment to bind, then ping.
sleep 1
if [[ ! -S /var/run/com.sybr.supermanager.helper.sock ]]; then
    echo "warning: helper socket not appearing — check /var/log/supermanager-helper.log" >&2
    exit 1
fi

echo "✓ Helper installed and running."
echo ""
echo "Verify wg/ovpn RPCs are present:"
echo "  echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"wg_status\",\"params\":{\"profile_id\":\"x\"}}' | … (use the GUI)"
