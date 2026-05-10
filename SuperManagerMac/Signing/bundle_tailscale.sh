#!/bin/bash
#
# Bundle the Tailscale CLI + daemon binaries into SuperManager.app.
#
# Why bundle: the user shouldn't need to install Tailscale separately.
# The official `Tailscale.app` from the App Store can be uninstalled
# at any moment, leaving a dead `/usr/local/bin/tailscale` shim that
# can't exec anything. Bundling our own binaries means SuperManager
# is the source of truth.
#
# Source: Homebrew's `tailscale` formula. We don't go to source
# because:
#   • Homebrew has darwin-native arm64/amd64 binaries already built,
#     signed by the bottle pipeline and freshly notarisable.
#   • No Go toolchain dependency on the dev machine.
#   • Updates are one `brew upgrade` away.
#
# This script is invoked as a Run Script Build Phase in Xcode. It
# expects:
#   - $TARGET_BUILD_DIR + $PRODUCT_NAME (set by Xcode)
#   - PATH including /opt/homebrew/bin (for `brew`)
#
# Outputs:
#   - $APP/Contents/Resources/tailscale-bin/tailscale
#   - $APP/Contents/Resources/tailscale-bin/tailscaled
#   - $APP/Contents/Resources/tailscale-bin/.version  (cached version stamp)

set -euo pipefail

# Xcode's sandbox sometimes strips PATH; rebuild it so we find brew.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

APP="${TARGET_BUILD_DIR}/${PRODUCT_NAME}.app"
DEST_DIR="${APP}/Contents/Resources/tailscale-bin"
mkdir -p "${DEST_DIR}"

# 1. Make sure Homebrew has tailscale installed. If it isn't, install
# it. This is normally a no-op for incremental builds.
if ! brew --prefix tailscale >/dev/null 2>&1; then
    echo "Tailscale formula not installed via Homebrew, installing now..."
    brew install tailscale
fi

BREW_PREFIX="$(brew --prefix tailscale)"
SRC_TS="${BREW_PREFIX}/bin/tailscale"
SRC_TSD="${BREW_PREFIX}/bin/tailscaled"

if [[ ! -x "${SRC_TS}" || ! -x "${SRC_TSD}" ]]; then
    echo "ERROR: Expected tailscale binaries not found at ${BREW_PREFIX}/bin/" >&2
    echo "       Run 'brew reinstall tailscale' to fix." >&2
    exit 1
fi

# 2. Skip the copy if the cached version stamp matches — keeps clean
# builds fast and avoids unnecessary code-sign churn on the Resources
# directory.
TS_VERSION="$("${SRC_TS}" version --short 2>/dev/null || echo unknown)"
STAMP_FILE="${DEST_DIR}/.version"
if [[ -f "${STAMP_FILE}" ]] \
   && [[ "$(cat "${STAMP_FILE}")" == "${TS_VERSION}" ]] \
   && [[ -x "${DEST_DIR}/tailscale" ]] \
   && [[ -x "${DEST_DIR}/tailscaled" ]]; then
    echo "Tailscale ${TS_VERSION} already bundled, skipping."
    exit 0
fi

# 3. Copy the binaries. We follow symlinks (Homebrew sometimes uses
# `bin/tailscale → ../Cellar/tailscale/<v>/bin/tailscale`) so the
# bundle gets the actual file rather than a symlink that breaks once
# Homebrew is upgraded.
cp -L "${SRC_TS}"  "${DEST_DIR}/tailscale"
cp -L "${SRC_TSD}" "${DEST_DIR}/tailscaled"
chmod 0755 "${DEST_DIR}/tailscale" "${DEST_DIR}/tailscaled"

# 4. Strip macOS quarantine, just in case Homebrew's bottle was
# downloaded with curl(1) and inherited the attribute.
xattr -d com.apple.quarantine "${DEST_DIR}/tailscale"  2>/dev/null || true
xattr -d com.apple.quarantine "${DEST_DIR}/tailscaled" 2>/dev/null || true

# 5. Re-sign with the same identity Xcode used for the host app, so
# the bundle's `_CodeSignature/CodeResources` matches the actual
# binary contents and the hardened runtime accepts them.
#
# The host app then re-seals (in the existing "Embed Rust binaries"
# phase) against this fresh signature. Without re-signing, `codesign
# --verify` on the .app fails because the bundled binaries either
# carry Homebrew's developer signature (which our team-id won't
# match) or no signature at all.
codesign --force \
    --options runtime \
    --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
    --identifier "com.sybr.supermanager.tailscale" \
    "${DEST_DIR}/tailscale"

codesign --force \
    --options runtime \
    --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
    --identifier "com.sybr.supermanager.tailscaled" \
    "${DEST_DIR}/tailscaled"

echo "${TS_VERSION}" > "${STAMP_FILE}"
echo "Bundled Tailscale ${TS_VERSION} into $(basename "${APP}")."
