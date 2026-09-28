#!/bin/bash
# Build SuperManager (Release) from this checkout and install it into
# /Applications, replacing the installed copy.
#
# Nothing is removed until the new bundle has been built, found and
# verified, and the swap is two renames on the same volume, so a failure at
# any step leaves the installed app untouched.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"
BUNDLE_ID="com.sybr.supermanager"

LOG="$(mktemp -t supermanager-build)"
echo "→ Building (Release); log: $LOG"
if ! ./SuperManagerMac/build.sh --release >"$LOG" 2>&1; then
    tail -40 "$LOG" >&2
    echo "error: build failed; full log in $LOG" >&2
    exit 1
fi

BUILD_DIR="$(xcodebuild -project SuperManagerMac/SuperManager.xcodeproj \
    -scheme SuperManagerMac -configuration Release -showBuildSettings 2>/dev/null \
    | sed -n 's/^[[:space:]]*BUILT_PRODUCTS_DIR = //p' | head -1)"
APP="$BUILD_DIR/SuperManagerMac.app"
if [ -z "$BUILD_DIR" ] || [ ! -x "$APP/Contents/MacOS/com.sybr.supermanager.helper" ]; then
    echo "error: no built app at '$APP'" >&2
    exit 1
fi
codesign --verify --deep --strict "$APP"

# Replace whichever copy is installed. The release zip and install.sh use
# SuperManagerMac.app; older installs may have been renamed.
DEST="/Applications/SuperManagerMac.app"
for candidate in /Applications/SuperManagerMac.app /Applications/SuperManager.app; do
    if [ -d "$candidate" ]; then
        DEST="$candidate"
        break
    fi
done

version() { defaults read "$1/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "?"; }
NEW_VERSION="$(version "$APP")"
if [ -d "$DEST" ]; then
    echo "→ Replacing $DEST ($(version "$DEST")) with $NEW_VERSION from $REPO"
else
    echo "→ Installing $NEW_VERSION to $DEST"
fi

# Stage on the destination volume, so the swap below is a rename.
STAGING="$(dirname "$DEST")/.SuperManager-install.$$"
BACKUP="$(dirname "$DEST")/.SuperManager-previous.$$"
trap 'rm -rf "$STAGING"' EXIT
ditto "$APP" "$STAGING"

WAS_RUNNING=0
if pgrep -xq SuperManagerMac; then
    WAS_RUNNING=1
    osascript -e "quit app id \"$BUNDLE_ID\"" >/dev/null 2>&1 || true
    for _ in {1..50}; do
        pgrep -xq SuperManagerMac || break
        sleep 0.2
    done
    if pgrep -xq SuperManagerMac; then
        echo "error: SuperManager is still running; quit it and run this again" >&2
        exit 1
    fi
fi

if [ -d "$DEST" ]; then
    mv "$DEST" "$BACKUP"
fi
if ! mv "$STAGING" "$DEST"; then
    [ -d "$BACKUP" ] && mv "$BACKUP" "$DEST"
    echo "error: could not move the new app into place; previous app restored" >&2
    exit 1
fi
rm -rf "$BACKUP"
echo "→ Installed $DEST ($NEW_VERSION)"

if [ "$WAS_RUNNING" -eq 1 ]; then
    open "$DEST"
fi
