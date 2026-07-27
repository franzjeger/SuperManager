#!/usr/bin/env bash
# installer/pkg/uninstall.sh
# ──────────────────────────
# Manually unloads and removes the VPN DNS cleanup LaunchDaemon.
# Run this only when uninstalling SuperManager entirely.
#
# Usage:
#   sudo ./installer/pkg/uninstall.sh
#
# The .pkg format does not ship an uninstaller by default; this script
# is the manual equivalent of reversing the postinstall step.

set -euo pipefail

LABEL="no.sybr.supermanager.vpn-dns-cleanup"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root — use: sudo $0" >&2
    exit 1
fi

echo "→ Unloading ${LABEL}"
# bootout is idempotent: exits non-zero if the service is not loaded.
launchctl bootout "system/${LABEL}" 2>/dev/null \
    && echo "  Unloaded." \
    || echo "  Not loaded (nothing to unload)."

echo "→ Removing ${PLIST}"
if [ -f "$PLIST" ]; then
    rm -f "$PLIST"
    echo "  Removed."
else
    echo "  File not found (already removed)."
fi

echo "Done. The VPN DNS cleanup daemon has been removed."
