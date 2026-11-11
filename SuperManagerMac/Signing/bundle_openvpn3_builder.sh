#!/bin/bash
#
# Bundle the OpenVPN 3 source-build recipe into SuperManager.app so the
# fallback "Build in Terminal…" repair never fetches mutable scripts from
# GitHub's `main` branch. Sealed under `_CodeSignature/CodeResources` by the
# subsequent bundle signing phase.

set -euo pipefail

APP="${TARGET_BUILD_DIR}/${PRODUCT_NAME}.app"
DEST_DIR="${APP}/Contents/Resources/openvpn3-builder"
REPO="${SRCROOT}/.."

mkdir -p "${DEST_DIR}/scripts" "${DEST_DIR}/contrib/openvpn3"
install -m 0755 "${REPO}/scripts/install.sh" "${DEST_DIR}/scripts/install.sh"
install -m 0755 "${REPO}/scripts/build-openvpn3-runtime.sh" "${DEST_DIR}/scripts/build-openvpn3-runtime.sh"
install -m 0755 "${REPO}/contrib/build-openvpn3-mac.sh" "${DEST_DIR}/contrib/build-openvpn3-mac.sh"
cp -f "${REPO}/contrib/openvpn3/"* "${DEST_DIR}/contrib/openvpn3/"
chmod 0755 \
    "${DEST_DIR}/contrib/openvpn3/apply_adapter.py" \
    "${DEST_DIR}/contrib/openvpn3/build_dependencies.sh" \
    "${DEST_DIR}/contrib/openvpn3/test_credentials.py"
