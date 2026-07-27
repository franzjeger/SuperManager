#!/usr/bin/env bash
# installer/pkg/build-pkg.sh
# ──────────────────────────
# Builds SuperManager-vpn-dns-cleanup-<version>.pkg via pkgbuild.
#
# Usage:
#   ./installer/pkg/build-pkg.sh <version>
#   ./installer/pkg/build-pkg.sh <version> --sign "Developer ID Installer: ..."
#
# Output:
#   dist/SuperManager-vpn-dns-cleanup-<version>.pkg
#
# The package installs one file:
#   /Library/LaunchDaemons/no.sybr.supermanager.vpn-dns-cleanup.plist
#   owner root:wheel, mode 644
#
# The postinstall script loads the daemon immediately on the boot volume.
# The preinstall script unloads any running instance first (idempotent).

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <version> [--sign <identity>]" >&2
    echo "example: $0 1.2.3 --sign \"Developer ID Installer: Sybr AS (TEAM_ID)\"" >&2
    exit 2
fi

VERSION="$1"
SIGN_IDENTITY=""
if [ "${2:-}" = "--sign" ]; then
    SIGN_IDENTITY="${3:?'missing identity after --sign'}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
mkdir -p "$DIST_DIR"

PKG_ID="no.sybr.supermanager.vpn-dns-cleanup"
PKG_NAME="SuperManager-vpn-dns-cleanup-${VERSION}.pkg"
PLIST_SRC="$REPO_ROOT/supermanager-helper/resources/no.sybr.supermanager.vpn-dns-cleanup.plist"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

# Verify scripts are executable — pkgbuild requires it.
for script in preinstall postinstall; do
    if [ ! -x "$SCRIPTS_DIR/$script" ]; then
        echo "error: $SCRIPTS_DIR/$script is not executable" >&2
        echo "  fix: chmod +x $SCRIPTS_DIR/$script" >&2
        exit 1
    fi
done

# ---- Stage payload -----------------------------------------------------------
#
# pkgbuild expects a directory tree whose structure mirrors the install
# destination.  We install to /, so the layout is:
#
#   <payload>/
#   └── Library/
#       └── LaunchDaemons/
#           └── no.sybr.supermanager.vpn-dns-cleanup.plist
#
PAYLOAD_DIR="$(mktemp -d)"
trap 'rm -rf "$PAYLOAD_DIR"' EXIT

LAUNCHDAEMONS_DIR="$PAYLOAD_DIR/Library/LaunchDaemons"
mkdir -p "$LAUNCHDAEMONS_DIR"
cp "$PLIST_SRC" "$LAUNCHDAEMONS_DIR/"
chmod 644 "$LAUNCHDAEMONS_DIR/no.sybr.supermanager.vpn-dns-cleanup.plist"

echo "→ Payload staged"

# ---- Build component package -------------------------------------------------
#
# --ownership recommended  instructs pkgbuild to infer root:wheel for system
#                          paths like /Library/LaunchDaemons.  The postinstall
#                          script also enforces root:wheel 644 at install time.
#
echo "→ Running pkgbuild (id=$PKG_ID, version=$VERSION)"

PKGBUILD_ARGS=(
    --identifier  "$PKG_ID"
    --version     "$VERSION"
    --root        "$PAYLOAD_DIR"
    --scripts     "$SCRIPTS_DIR"
    --ownership   recommended
)

if [ -n "$SIGN_IDENTITY" ]; then
    PKGBUILD_ARGS+=(--sign "$SIGN_IDENTITY")
    echo "   signing with: $SIGN_IDENTITY"
else
    echo "   ⚠️  No signing identity — package will be unsigned."
    echo "      Pass --sign \"Developer ID Installer: ...\" for distribution builds."
fi

PKGBUILD_ARGS+=("$DIST_DIR/$PKG_NAME")

pkgbuild "${PKGBUILD_ARGS[@]}"

# ---- Verify ------------------------------------------------------------------
echo "→ Package: $DIST_DIR/$PKG_NAME ($(du -h "$DIST_DIR/$PKG_NAME" | cut -f1))"

if [ -n "$SIGN_IDENTITY" ]; then
    pkgutil --check-signature "$DIST_DIR/$PKG_NAME"
else
    echo "   (skipping signature check — unsigned build)"
fi
