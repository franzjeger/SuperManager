#!/bin/bash
#
# Bundle the VPN runtime into SuperManager.app: the programs the root
# helper runs WireGuard with (scripts/build-vpn-runtime.sh).
#
# Invoked as a Run Script Build Phase in Xcode. Expects $TARGET_BUILD_DIR
# and $PRODUCT_NAME (set by Xcode).
#
# Output: $APP/Contents/Resources/vpn-runtime/{bash,wg,wg-quick,wireguard-go,licenses}
#
# Skips when Homebrew's WireGuard tools are not installed, like the
# Tailscale bundling: the helper then falls back to Homebrew's WireGuard,
# and scripts/release.sh refuses to ship a build without the runtime.

set -euo pipefail

APP="${TARGET_BUILD_DIR}/${PRODUCT_NAME}.app"
DEST_DIR="${APP}/Contents/Resources/vpn-runtime"
REPO="${SRCROOT}/.."

STAGED="$(mktemp -d)"
trap 'rm -rf "$STAGED"' EXIT
status=0
"${REPO}/scripts/build-vpn-runtime.sh" "$STAGED" || status=$?
if [ "$status" -eq 2 ]; then
    echo "note: skipping the VPN runtime; 'brew install wireguard-tools' to bundle it."
    exit 0
elif [ "$status" -ne 0 ]; then
    exit "$status"
fi

# Skip the copy when these exact files are bundled already: keeps
# incremental builds fast and the bundle's signature stable.
STAMP="$(cd "$STAGED" && shasum -a 256 bash wg wg-quick wireguard-go licenses/* | shasum -a 256 | cut -d' ' -f1)"
if [ -f "${DEST_DIR}/.stamp" ] && [ "$(cat "${DEST_DIR}/.stamp")" = "$STAMP" ]; then
    echo "VPN runtime already bundled, skipping."
    exit 0
fi

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp -R "$STAGED"/{bash,wg,wg-quick,wireguard-go,licenses} "$DEST_DIR/"

# The helper checks each Mach-O file's signature for SuperManager's team
# and these identifiers before it runs it as root. wg-quick is a script;
# the helper checks its content against a pinned SHA-256 instead.
if [ "${CODE_SIGNING_REQUIRED:-YES}" = "NO" ] \
   || [ "${CODE_SIGNING_ALLOWED:-YES}" = "NO" ] \
   || [ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
    echo "note: code signing disabled — the VPN runtime is left unsigned, and the helper will refuse it."
    exit 0
fi
for name in bash wg wireguard-go; do
    codesign --force \
        --options runtime \
        --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
        --identifier "com.sybr.supermanager.vpn.${name}" \
        "${DEST_DIR}/${name}"
done

echo "$STAMP" > "${DEST_DIR}/.stamp"
echo "Bundled the VPN runtime into $(basename "${APP}")."
