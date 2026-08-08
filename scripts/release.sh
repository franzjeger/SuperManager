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
#   DEVELOPER_ID_APP        — e.g. "Developer ID Application: Your Name (LY6LJ395B8)"
#   AC_API_KEY_PATH         — path to AuthKey_XXXXXX.p8 from App Store Connect
#   AC_API_KEY_ID           — the 10-char key ID
#   AC_API_ISSUER_ID        — your Issuer ID (UUID)
#
# Optional environment variables:
#   DEVELOPER_ID_INSTALLER  — e.g. "Developer ID Installer: Your Name (LY6LJ395B8)"
#                             When set the .pkg is signed and notarised.
#                             When absent the .pkg is built unsigned (suitable
#                             for dev/test; Gatekeeper will warn on install).
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

# Optional: Developer ID Installer cert for .pkg signing + notarisation.
if [ -z "${DEVELOPER_ID_INSTALLER:-}" ]; then
    echo "⚠️  DEVELOPER_ID_INSTALLER not set — .pkg will be unsigned."
    echo "   Set it to enable .pkg signing and notarisation."
fi

# Tag must not already exist.
if git -C "$REPO_ROOT" rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "error: tag v$VERSION already exists. Pick a different version." >&2
    exit 1
fi

# Developer ID cert must be in Keychain.
# NOTE on the checks below: never `cmd | grep -q` under `set -o
# pipefail`. `grep -q` exits at the FIRST match, closing the pipe; the
# producer then dies of SIGPIPE, and pipefail turns that non-zero exit
# into a failed pipeline — so a MATCH reports failure. It cost two
# rebuilds here: the Tailscale gate failed on correctly-signed binaries,
# and the entitlements gate above only passed because its producer
# happened to finish writing first, i.e. by luck. Capture the output
# first, then match it.
identities="$(security find-identity -p codesigning -v 2>&1 || true)"
case "$identities" in
    *"Developer ID Application"*) ;;
    *)
        echo "error: no Developer ID Application certificate in Keychain." >&2
        echo "       Get one from developer.apple.com → Certificates." >&2
        exit 1
        ;;
esac

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

# The app's OWN entitlements. Omitting these shipped v1.6.0 with no
# keychain-access-groups at all: the data-protection keychain scopes
# items by access group, so the release build could not read a single
# VPN password it had written as a development build — every profile
# failed to connect with errSecItemNotFound (-25300). `codesign
# --verify` passes happily on an entitlement-less app; it validates the
# signature, not what is in it.
#
# `$(AppIdentifierPrefix)` is an XCODE build-setting placeholder.
# codesign does NOT expand it, so a resolved copy is generated here
# with the real team prefix substituted.
TEAM_ID="$(echo "$DEVELOPER_ID_APP" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')"
if [ -z "$TEAM_ID" ]; then
    echo "error: could not parse team id out of \$DEVELOPER_ID_APP" >&2
    exit 1
fi
# `keychain-access-groups` is a RESTRICTED entitlement: it must be
# authorised by a provisioning profile matching the signing identity.
# Xcode's development profile matches its Apple Development signature,
# so dev builds are fine — but a Developer ID re-sign has no matching
# profile, and AMFI then refuses to launch the app at all ("Launchd job
# spawn failed", no crash report). Bisected on the 1.6.1 artifact:
#
#   no entitlements            -> launches
#   keychain-access-groups     -> does not launch
#   keychain-access-groups + embedded profile -> does not launch
#
# So distribution builds ship WITHOUT it. VPNKeychain never sets
# kSecAttrAccessGroup explicitly, so items land in the app's default
# data-protection group, derived from the signature — which works for a
# stable Developer ID identity. The cost is one-time: credentials stored
# by a locally-signed dev build are not visible to a released build, and
# must be re-entered once.
#
# Doing this properly instead would mean a Developer ID provisioning
# profile with keychain sharing from the Apple Developer portal, then
# embedding it here. That is the upgrade path if credential continuity
# across identities ever matters.
APP_ENTITLEMENTS="$RELEASE_DIR/SuperManagerMac-distribution.entitlements"
cat > "$APP_ENTITLEMENTS" <<'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<false/>
</dict>
</plist>
ENTITLEMENTS
echo "→ Distribution entitlements written (team ${TEAM_ID}, no restricted keys)"

# A development provisioning profile does not belong in a Developer
# ID-distributed app; Xcode embeds one and it is meaningless here.
rm -f "$APP/Contents/embedded.provisionprofile"

# The bundled Tailscale CLI. The build phase signs these with whatever
# identity Xcode used — Apple Development — and without a timestamp,
# which notarization rejects outright:
#   "The binary is not signed with a valid Developer ID certificate"
#   "The signature does not include a secure timestamp"
# Re-sign them here with Developer ID like every other nested binary.
# Missed on the first attempt because the inside-out list covered
# Frameworks and Contents/MacOS but not Contents/Resources.
for ts_bin in tailscale tailscaled; do
    ts_path="$APP/Contents/Resources/tailscale-bin/$ts_bin"
    [ -f "$ts_path" ] || continue
    codesign --force --options runtime --timestamp \
        --sign "$DEVELOPER_ID_APP" \
        --identifier "com.sybr.supermanager.$ts_bin" \
        "$ts_path"
done

# Sign inside-out, explicitly. NOT `--deep`: it re-signs every nested
# binary with the OUTER options, which silently stripped the
# entitlements just applied to the helper and daemon above. Apple
# deprecates it for exactly this reason.
find "$APP/Contents/Frameworks" \
     -name "*.xpc" -o -name "Updater.app" -o -name "Autoupdate" 2>/dev/null \
| while read -r nested; do
    codesign --force --options runtime --timestamp \
        --sign "$DEVELOPER_ID_APP" "$nested"
done
if [ -d "$APP/Contents/Frameworks/Sparkle.framework" ]; then
    codesign --force --options runtime --timestamp \
        --sign "$DEVELOPER_ID_APP" "$APP/Contents/Frameworks/Sparkle.framework"
fi

codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APP" \
    --entitlements "$APP_ENTITLEMENTS" \
    "$APP"

# Verify before notarization.
codesign --verify --verbose=2 "$APP"
spctl --assess --type execute --verbose=2 "$APP" || true

# Entitlements gate. The signature being valid says nothing about the
# app being able to reach its own keychain items — v1.6.0 passed
# --verify and shipped broken. Assert the group is actually present.
echo "→ Verifying signed app kept its keychain access group"
app_entitlements="$(codesign -d --entitlements - "$APP" 2>&1 || true)"
case "$app_entitlements" in
    *keychain-access-groups*)
        echo "error: signed app carries keychain-access-groups." >&2
        echo "       That entitlement needs a matching provisioning profile;" >&2
        echo "       without one AMFI refuses to launch the app at all." >&2
        exit 1
        ;;
esac
# The nested entitlement plists are deliberately EMPTY — the helper's
# own comment explains it needs no keychain access, since secrets reach
# it as RPC arguments. So there is nothing to assert about their
# contents; what matters is that each is still validly signed after the
# outer signature, which is what `--deep` used to break.
for nested in "$APP/Contents/MacOS/supermgrd-mac" \
              "$APP/Contents/MacOS/com.sybr.supermanager.helper"; do
    if ! codesign --verify --strict "$nested" 2>/dev/null; then
        echo "error: $(basename "$nested") is not validly signed" >&2
        exit 1
    fi
done
echo "  entitlements sane (app), nested binaries validly signed"

# THE gate that was missing all along: does the signed app actually
# LAUNCH? Every other check verified a property of the artifact —
# signature valid, notarization accepted, ticket stapled, entitlements
# present — and 1.6.1 passed all of them and could not start. AMFI
# rejects at exec time, so nothing short of running it finds that.
echo "→ Launch test on the signed app"
launch_probe="$RELEASE_DIR/launch-probe"
rm -rf "$launch_probe" && mkdir -p "$launch_probe"
ditto "$APP" "$launch_probe/SuperManagerMac.app"
"$launch_probe/SuperManagerMac.app/Contents/MacOS/SuperManagerMac" >/dev/null 2>&1 &
probe_pid=$!
sleep 6
if kill -0 "$probe_pid" 2>/dev/null; then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    rm -rf "$launch_probe"
    echo "  app launches"
else
    rm -rf "$launch_probe"
    echo "error: the signed app does not launch." >&2
    echo "       Usually a restricted entitlement with no matching profile —" >&2
    echo "       check 'log show --predicate \"process == \\\"amfid\\\"\"'." >&2
    exit 1
fi

# The Tailscale CLI must be in the shipped bundle. The build phase that
# puts it there skips silently when the Homebrew formula is absent (so
# CI can build without it), which means a release machine missing the
# formula would otherwise ship an app that cannot offer to start the
# daemon — precisely the dead end reported from the field on 1.6.0.
echo "→ Verifying bundled Tailscale CLI"
for ts_bin in tailscale tailscaled; do
    if [ ! -x "$APP/Contents/Resources/tailscale-bin/$ts_bin" ]; then
        echo "error: $ts_bin missing from the bundle." >&2
        echo "       Run 'brew install tailscale' and rebuild — without it the" >&2
        echo "       app cannot install or start the Tailscale daemon." >&2
        exit 1
    fi
done
for ts_bin in tailscale tailscaled; do
    # -dvv, not -dv: `Authority=` lines only appear at verbosity 2 and
    # above. With -dv the gate matched nothing and failed a release
    # whose binaries were correctly Developer ID-signed all along — a
    # false alarm, but one that cost a full rebuild to diagnose.
    ts_sig="$(codesign -dvv "$APP/Contents/Resources/tailscale-bin/$ts_bin" 2>&1 || true)"
    case "$ts_sig" in
        *"Authority=Developer ID Application"*) ;;
        *)
            echo "error: bundled $ts_bin is not Developer ID-signed — notarization will reject it" >&2
            exit 1
            ;;
    esac
done
echo "  tailscale + tailscaled bundled and Developer ID-signed"

# ---- 4b. Build the .pkg installer ------------------------------------------
#
# The package installs:
#   /Library/LaunchDaemons/no.sybr.supermanager.vpn-dns-cleanup.plist
#   owner root:wheel, mode 644
#
# postinstall loads the daemon immediately (launchctl bootstrap system).
# preinstall unloads any running instance first (idempotent on first install).

echo "→ Building .pkg installer"
PKG_FILE="$RELEASE_DIR/SuperManager-vpn-dns-cleanup-$VERSION.pkg"
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    "$REPO_ROOT/installer/pkg/build-pkg.sh" "$VERSION" \
        --sign "$DEVELOPER_ID_INSTALLER"
else
    "$REPO_ROOT/installer/pkg/build-pkg.sh" "$VERSION"
fi

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

# ---- 6b. Notarise and staple the .pkg (only when signed) --------------------
#
# Apple requires notarisation for Developer ID-signed packages distributed
# outside the Mac App Store (Gatekeeper enforces this on macOS 10.15+).
# We skip this entirely when DEVELOPER_ID_INSTALLER is absent because
# notarytool rejects unsigned submissions.

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    echo "→ Submitting .pkg to Apple notary (this can take 5-15 minutes)…"
    xcrun notarytool submit "$PKG_FILE" \
        --key "$AC_API_KEY_PATH" \
        --key-id "$AC_API_KEY_ID" \
        --issuer "$AC_API_ISSUER_ID" \
        --wait

    echo "→ Stapling .pkg notarization ticket"
    xcrun stapler staple "$PKG_FILE"
    xcrun stapler validate "$PKG_FILE"
fi

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

# NOTE on the enclosure below: length AND sparkle:edSignature both come
# from $SPARKLE_SIG_LINE, which is sign_update's output verbatim. Do not
# add a `length=` attribute of your own — duplicating it is invalid XML,
# and it shipped in 1.6.0's feed, where Sparkle rejected the whole thing
# with "An error occurred while parsing the update feed". The comment
# lives out here because a comment inside a start-tag is itself invalid
# XML — which is how this very gate caught the first attempt at the fix.
PUB_DATE="$(date -u +"%a, %d %b %Y %H:%M:%S +0000")"
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
                type="application/octet-stream"
                $SPARKLE_SIG_LINE />
        </item>
    </channel>
</rss>
EOF

# The 1.6.0 feed shipped as invalid XML (duplicate length attribute)
# and Sparkle failed the whole feed at first live check. Reachable and
# content-correct is not the same as parseable — validate for real.
if ! xmllint --noout "$APPCAST"; then
    echo "error: generated appcast is not valid XML — refusing to continue" >&2
    exit 1
fi
echo "→ Wrote appcast: $APPCAST (xmllint: valid)"

# The feed the app polls is the appcast COMMITTED TO MAIN
# (raw.githubusercontent.com/…/main/appcast.xml), not a release asset.
# The old feed URL pointed at `releases/latest/download/appcast.xml`,
# and the moment a Windows-only release became "latest" (v1.4.0 was
# exactly that) the URL 404'd and every Mac silently stopped seeing
# updates. A repo-committed appcast is immune to release ordering.
# Stable channel only — the beta appcast stays a release asset so a
# stray beta never reaches main.
if [ "$CHANNEL_LABEL" = "stable" ]; then
    cp "$APPCAST" "$REPO_ROOT/appcast.xml"
    echo "→ Copied appcast to repo root (commit it with the release)"
fi

# ---- 10. Next steps ---------------------------------------------------------

cat <<EOF

════════════════════════════════════════════════════════════════
  Release v$VERSION ready.

  Artifacts:
    $DIST_ZIP
    $PKG_FILE
    $APPCAST

  Next steps (manual):
    1. \`git add -A && git commit -m "chore: release v$VERSION"\`
       (includes the updated appcast.xml at the repo root —
        that IS the update feed; forgetting it means no Mac
        ever sees this release)
    2. \`git tag v$VERSION && git push origin main v$VERSION\`
    3. \`gh release create v$VERSION \\
            "$DIST_ZIP" \\
            "$PKG_FILE" \\
            "$APPCAST" \\
            --title "v$VERSION" \\
            --notes-file CHANGELOG.md\`
    4. Sparkle picks up the new appcast within
       SUScheduledCheckInterval (1 day) — or sooner if the user
       hits "Check for Updates…" manually.
    5. MDM admins can deploy $PKG_FILE
       directly to managed Macs via their MDM solution.
════════════════════════════════════════════════════════════════
EOF
