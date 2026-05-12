#!/usr/bin/env bash
# Build, sign, notarize, and prepare a Sparkle-ready release of
# SuperManager.
#
# Usage:
#   scripts/release.sh <version>
#
# Example:
#   scripts/release.sh 1.0.0
#
# What it does:
#   1. Pre-flight: confirm version isn't already tagged, Developer ID
#      cert is in Keychain, App Store Connect API key is configured.
#   2. Bump CFBundleShortVersionString + CFBundleVersion in project.yml.
#   3. Build Release configuration via xcodebuild → unsigned .app.
#   4. Sign the .app + the two embedded Rust binaries with the
#      Developer ID Application identity. Hardened runtime + timestamp.
#   5. Notarize through Apple. `notarytool` polls until verdict.
#   6. Staple the notarization ticket so first-launch works offline.
#   7. Zip the .app into SuperManager-<version>.zip.
#   8. Sign the zip with Sparkle's `sign_update` → emits an
#      EdDSA signature string.
#   9. Generate / update appcast.xml entry for this version.
#  10. Tell you to upload .zip + appcast.xml to GitHub Releases
#      (we don't auto-upload to avoid pushing half-baked builds).
#
# Required environment variables:
#   DEVELOPER_ID_APP   — e.g. "Developer ID Application: Frank Liaaen (LY6LJ395B8)"
#   AC_API_KEY_PATH    — path to AuthKey_XXXXXX.p8 from App Store Connect
#   AC_API_KEY_ID      — the 10-char key ID
#   AC_API_ISSUER_ID   — your Issuer ID (UUID)
#
# Set these in your shell profile, ~/.zshenv, or pass on the command line.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <version>" >&2
    echo "example: $0 1.0.0" >&2
    exit 2
fi
VERSION="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$REPO_ROOT/dist"
mkdir -p "$RELEASE_DIR"

# ---- 1. Pre-flight checks ---------------------------------------------------

echo "→ Pre-flight checks for v$VERSION"

# Required env vars.
for var in DEVELOPER_ID_APP AC_API_KEY_PATH AC_API_KEY_ID AC_API_ISSUER_ID; do
    if [ -z "${!var:-}" ]; then
        echo "error: \$$var is not set. See script header." >&2
        exit 1
    fi
done

# Tag must not already exist.
if git -C "$REPO_ROOT" rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "error: tag v$VERSION already exists. Pick a different version." >&2
    exit 1
fi

# Developer ID cert must be in Keychain.
if ! security find-identity -p codesigning -v | grep -q "Developer ID Application"; then
    echo "error: no Developer ID Application certificate in Keychain." >&2
    echo "       Get one from developer.apple.com → Certificates." >&2
    exit 1
fi

# Sparkle's sign_update tool.
SIGN_UPDATE=""
for candidate in \
    "$HOME/Library/Developer/Xcode/DerivedData"/SuperManager-*/SourcePackages/artifacts/sparkle/Sparkle/bin/sign_update \
    "$HOME/Library/Developer/Xcode/DerivedData"/*/SourcePackages/artifacts/sparkle/Sparkle/bin/sign_update
do
    [ -x "$candidate" ] && SIGN_UPDATE="$candidate" && break
done
if [ -z "$SIGN_UPDATE" ]; then
    echo "error: couldn't find Sparkle's sign_update tool in DerivedData." >&2
    echo "       Run \`./SuperManagerMac/build.sh\` once first to resolve SwiftPM artifacts." >&2
    exit 1
fi

# ---- 2. Bump version --------------------------------------------------------

echo "→ Bumping version to $VERSION in project.yml"
# `sed -i ''` is required on macOS for in-place edit.
sed -i '' "s|CFBundleShortVersionString: .*|CFBundleShortVersionString: \"$VERSION\"|" \
    "$REPO_ROOT/SuperManagerMac/project.yml"
sed -i '' "s|CFBundleVersion: .*|CFBundleVersion: \"$VERSION\"|" \
    "$REPO_ROOT/SuperManagerMac/project.yml"

(cd "$REPO_ROOT/SuperManagerMac" && xcodegen generate)

# ---- 3. Build Release -------------------------------------------------------

echo "→ Building Release configuration"
cd "$REPO_ROOT/SuperManagerMac"
xcodebuild \
    -project SuperManager.xcodeproj \
    -scheme SuperManagerMac \
    -configuration Release \
    -destination 'platform=macOS' \
    -allowProvisioningUpdates \
    clean build \
    2>&1 | grep -E '(error:|warning:|BUILD)' || true

BUILD_DIR="$(xcodebuild -project SuperManager.xcodeproj -scheme SuperManagerMac \
    -configuration Release -showBuildSettings 2>/dev/null \
    | awk '/^[[:space:]]*BUILT_PRODUCTS_DIR =/ { print $3 }')"
APP="$BUILD_DIR/SuperManagerMac.app"

if [ ! -d "$APP" ]; then
    echo "error: .app not found at $APP after build" >&2
    exit 1
fi
echo "  built: $APP"

# ---- 4. Sign (already done by build.sh post-build, but re-sign Release with
#               Developer ID instead of Apple Development) ---------------------

echo "→ Re-signing with Developer ID for distribution"

# The bundle is already signed by Xcode with whatever identity the
# project.yml selected (Personal Team for Debug). For Release we
# want Developer ID — re-sign each embedded binary + the bundle.
codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APP" \
    --identifier com.sybr.supermanager.daemon \
    --entitlements "$REPO_ROOT/SuperManagerMac/Signing/supermgrd-mac.entitlements" \
    "$APP/Contents/MacOS/supermgrd-mac"

codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APP" \
    --identifier com.sybr.supermanager.helper \
    --entitlements "$REPO_ROOT/SuperManagerMac/Signing/supermanager-helper.entitlements" \
    "$APP/Contents/MacOS/com.sybr.supermanager.helper"

codesign --force --options runtime --timestamp --deep \
    --sign "$DEVELOPER_ID_APP" \
    "$APP"

# Verify before notarization.
codesign --verify --verbose=2 "$APP"
spctl --assess --type execute --verbose=2 "$APP" || true

# ---- 5. Notarize -----------------------------------------------------------

echo "→ Zipping for notarization"
NOTARIZE_ZIP="$RELEASE_DIR/SuperManager-$VERSION-notarize.zip"
ditto -c -k --keepParent "$APP" "$NOTARIZE_ZIP"

echo "→ Submitting to Apple notary (this can take 5-15 minutes)…"
xcrun notarytool submit "$NOTARIZE_ZIP" \
    --key "$AC_API_KEY_PATH" \
    --key-id "$AC_API_KEY_ID" \
    --issuer "$AC_API_ISSUER_ID" \
    --wait

# ---- 6. Staple --------------------------------------------------------------

echo "→ Stapling notarization ticket"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

# ---- 7. Final zip for distribution ------------------------------------------

DIST_ZIP="$RELEASE_DIR/SuperManager-$VERSION.zip"
rm -f "$DIST_ZIP"
ditto -c -k --keepParent "$APP" "$DIST_ZIP"
echo "→ Distribution zip: $DIST_ZIP ($(du -h "$DIST_ZIP" | cut -f1))"

# ---- 8. Sparkle signature ---------------------------------------------------

echo "→ Computing Sparkle EdDSA signature"
SPARKLE_SIG_LINE="$("$SIGN_UPDATE" "$DIST_ZIP")"
# `sign_update` prints e.g. `sparkle:edSignature="..." length="12345"`
echo "  $SPARKLE_SIG_LINE"

# ---- 9. Appcast entry -------------------------------------------------------

# Beta-channel detection. SemVer pre-release identifiers
# (anything after a '-' in the version, e.g. `1.0.1-beta.2` or
# `1.1.0-rc.1`) signal a pre-release build. We write to
# `appcast-beta.xml` instead of `appcast.xml`, so only users
# who opted into the beta channel in Settings → Updates pick
# it up. Stable users keep getting `appcast.xml` updates.
case "$VERSION" in
    *-*)
        APPCAST="$RELEASE_DIR/appcast-beta.xml"
        CHANNEL_LABEL="beta"
        ;;
    *)
        APPCAST="$RELEASE_DIR/appcast.xml"
        CHANNEL_LABEL="stable"
        ;;
esac
echo "→ Channel: $CHANNEL_LABEL → $APPCAST"

PUB_DATE="$(date -u +"%a, %d %b %Y %H:%M:%S +0000")"
LENGTH="$(stat -f%z "$DIST_ZIP")"
DOWNLOAD_URL="https://github.com/franzjeger/SuperManager/releases/download/v$VERSION/SuperManager-$VERSION.zip"

cat > "$APPCAST" <<EOF
<?xml version="1.0" standalone="yes"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
    <channel>
        <title>SuperManager</title>
        <description>Update feed for SuperManager.app</description>
        <language>en</language>
        <item>
            <title>Version $VERSION</title>
            <pubDate>$PUB_DATE</pubDate>
            <sparkle:version>$VERSION</sparkle:version>
            <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion>
            <enclosure
                url="$DOWNLOAD_URL"
                length="$LENGTH"
                type="application/octet-stream"
                $SPARKLE_SIG_LINE />
        </item>
    </channel>
</rss>
EOF

echo "→ Wrote appcast: $APPCAST"

# ---- 10. Next steps ---------------------------------------------------------

cat <<EOF

════════════════════════════════════════════════════════════════
  Release v$VERSION ready.

  Artifacts:
    $DIST_ZIP
    $APPCAST

  Next steps (manual):
    1. \`git commit -am "chore: release v$VERSION"\`
    2. \`git tag v$VERSION && git push origin main v$VERSION\`
    3. \`gh release create v$VERSION "$DIST_ZIP" "$APPCAST" \\
            --title "v$VERSION" \\
            --notes-file CHANGELOG.md\`
    4. Sparkle picks up the new appcast within
       SUScheduledCheckInterval (1 day) — or sooner if the user
       hits "Check for Updates…" manually.
════════════════════════════════════════════════════════════════
EOF
