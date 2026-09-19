#!/usr/bin/env bash
# Build OpenVPN 3 (ovpncli) from upstream source for macOS.
#
# Why this exists
# ---------------
# Microsoft's Azure VPN gateway rejects OpenVPN 2.x clients with
# Entra ID auth — TLS handshake completes, but the gateway then
# RSTs the TCP connection without sending AUTH_FAILED. The
# protocol path that works (and that MSP-Toolkit-V2 / official
# Azure VPN Client both use) is OpenVPN 3.
#
# Homebrew has no `openvpn3` formula on macOS, and no prebuilt
# binary ships with macOS itself, so we build the upstream
# `ovpncli` test client from source. It's small (~3 MB), reads
# credentials via command-line arguments (matching our helper's
# invocation), and speaks the protocol the gateway is expecting.
#
# What this script installs
# -------------------------
#   $(brew --prefix)/bin/openvpn3   — the ovpncli binary, renamed
#                                       so `locate_openvpn` picks
#                                       it up automatically
#
# Re-running is idempotent.
#
# Prerequisites
# -------------
#   brew install cmake asio jsoncpp openssl@3 lz4 fmt
#   git, make, c++ toolchain (Xcode CLT)

set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo "error: this build script requires macOS" >&2
    exit 1
fi
if ! command -v brew >/dev/null 2>&1; then
    echo "error: install Homebrew and the prerequisites listed in this script first" >&2
    exit 1
fi

openvpn3_brew_prefix="$(brew --prefix)"
openvpn3_openssl_prefix="$(brew --prefix openssl@3)"
openvpn3_asio_prefix="$(brew --prefix asio)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/supermanager-openvpn3.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
SRC_DIR="$BUILD_DIR/openvpn3"
INSTALL_PATH="$openvpn3_brew_prefix/bin/openvpn3"

echo "→ Workspace: $BUILD_DIR"
cd "$BUILD_DIR"

echo "→ Cloning openvpn/openvpn3…"
git clone --depth 1 https://github.com/OpenVPN/openvpn3.git "$SRC_DIR"

cd "$SRC_DIR"

# asio is header-only; openvpn3's build wants ASIO_DIR pointing
# at the include root. Resolve Homebrew's prefix for both Intel and ARM Macs.
echo "→ Configuring (cmake)…"
cmake -B build -G "Unix Makefiles" \
    -DOPENSSL_ROOT_DIR="$openvpn3_openssl_prefix" \
    -DASIO_DIR="$openvpn3_asio_prefix" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DCMAKE_PREFIX_PATH="$openvpn3_brew_prefix"

echo "→ Building ovpncli…"
cmake --build build -j "$(sysctl -n hw.ncpu)" --target ovpncli

# Locate the produced binary. Path varies slightly across cmake
# generator versions; search rather than hardcode.
BIN="$(find build -type f -name ovpncli -perm -u+x | head -1)"
if [[ -z "$BIN" ]]; then
    echo "error: ovpncli binary not found after build" >&2
    exit 1
fi

echo "→ Installing $BIN -> $INSTALL_PATH (will prompt for sudo)…"
sudo install -m 0755 -o root -g wheel "$BIN" "$INSTALL_PATH"

echo ""
echo "✓ OpenVPN 3 (ovpncli) installed at $INSTALL_PATH"
"$INSTALL_PATH" --version 2>&1 | head -3 || true
echo ""
echo "Next: reconnect your Azure VPN in SuperManager. The helper"
echo "automatically selects OpenVPN 3 for the next connection."
