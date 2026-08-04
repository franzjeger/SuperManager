#!/usr/bin/env bash
# One-command install of the latest SuperManager release on macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/franzjeger/SuperManager/main/scripts/install.sh | bash
#
# What it does, and deliberately nothing more:
#   1. Finds the newest GitHub release that carries a Mac zip
#      (releases are shared with Windows, so "latest" alone is not
#      enough — v1.4.0 was Windows-only).
#   2. Downloads and unzips it into /Applications.
#   3. Launches the app.
#
# The zip is Developer ID-signed, notarized and stapled, so Gatekeeper
# accepts it without any quarantine dance. Everything privileged — the
# root helper, optional strongSwan for IKEv2 — is installed BY THE APP
# with proper admin prompts on first use; a curl|bash script has no
# business doing privileged setup, and does not.

set -euo pipefail

REPO="franzjeger/SuperManager"
APP_NAME="SuperManagerMac.app"
DEST="/Applications/$APP_NAME"

say() { printf '→ %s\n' "$*"; }

command -v curl >/dev/null || { echo "error: curl not found" >&2; exit 1; }

# Newest release tag that actually has a Mac zip among its assets.
# The GitHub API returns releases newest-first; grab the first
# SuperManager-<version>.zip browser_download_url we see.
say "Looking up the newest Mac release of $REPO…"
ZIP_URL="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=15" \
    | grep -o '"browser_download_url": *"[^"]*SuperManager-[0-9][^"]*\.zip"' \
    | grep -v notarize \
    | head -1 \
    | sed 's/.*"\(https[^"]*\)"/\1/')"

if [ -z "$ZIP_URL" ]; then
    echo "error: no release with a Mac zip found." >&2
    echo "       (Releases are shared with Windows; a Mac build may not" >&2
    echo "        have shipped yet. See https://github.com/$REPO/releases)" >&2
    exit 1
fi
say "Found: $ZIP_URL"

TMP="$(mktemp -d /tmp/supermgr-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

say "Downloading…"
curl -fL --progress-bar -o "$TMP/app.zip" "$ZIP_URL"

say "Unpacking…"
ditto -x -k "$TMP/app.zip" "$TMP/unpacked"
[ -d "$TMP/unpacked/$APP_NAME" ] || { echo "error: zip did not contain $APP_NAME" >&2; exit 1; }

if [ -d "$DEST" ]; then
    say "Replacing existing $DEST"
    # Quit a running copy so the swap is clean; ignore if not running.
    osascript -e 'quit app "SuperManagerMac"' >/dev/null 2>&1 || true
    sleep 2
    rm -rf "$DEST"
fi

ditto "$TMP/unpacked/$APP_NAME" "$DEST"
say "Installed to $DEST"

# ---------------------------------------------------------------------------
# Dependency report.
#
# SuperManager drives the real VPN clients rather than reimplementing
# them, so each VPN type needs its tool present. We REPORT rather than
# install: a curl|bash script silently running `brew install` is not a
# trade anyone agreed to, and each tool is only needed if you actually
# use that VPN type. The app also surfaces this per profile when you
# try to connect.
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1 || [ -x "/opt/homebrew/bin/$1" ] || [ -x "/usr/local/bin/$1" ]; }

MISSING=""
have wg-quick   || MISSING="$MISSING\n  WireGuard profiles      brew install wireguard-tools"
have swanctl    || MISSING="$MISSING\n  IKEv2 / FortiGate IPsec brew install strongswan"
have openvpn3   || MISSING="$MISSING\n  Azure VPN (Entra ID)    ./contrib/build-openvpn3-mac.sh  (no brew formula)"
have openvpn    || MISSING="$MISSING\n  OpenVPN 2.x profiles    brew install openvpn"

echo
if [ -n "$MISSING" ]; then
    say "Optional VPN tools not found. Install only what you need:"
    printf '%b\n' "$MISSING"
    echo
    if ! have brew; then
        say "Homebrew itself is missing — https://brew.sh"
        echo
    fi
else
    say "All optional VPN tools present."
fi

say "Tailscale needs nothing: the app bundles tailscaled and installs it"
say "on first use. SSH, network scanning and compliance work out of the box."
say "The app asks for admin rights once, to install its privileged helper."
echo

open "$DEST"
