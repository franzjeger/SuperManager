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
# auth-user-pass from stdin (matches our helper's invocation
# pattern), and speaks the same protocol the gateway is expecting.
#
# What this script installs
# -------------------------
#   /opt/homebrew/bin/openvpn3       — the ovpncli binary, renamed
#                                       so `locate_openvpn` picks
#                                       it up automatically
#
# Re-running is idempotent.
#
# Prerequisites
# -------------
#   brew install cmake asio jsoncpp openssl@3 lz4
#   git, make, c++ toolchain (Xcode CLT)

set -euo pipefail

BUILD_DIR="${TMPDIR:-/tmp}/openvpn3-build"
SRC_DIR="$BUILD_DIR/openvpn3"
INSTALL_PATH="/opt/homebrew/bin/openvpn3"

echo "→ Workspace: $BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [[ ! -d "$SRC_DIR" ]]; then
    echo "→ Cloning openvpn/openvpn3…"
    git clone --depth 1 https://github.com/OpenVPN/openvpn3.git
else
    echo "→ openvpn3 source already present, fetching latest…"
    git -C "$SRC_DIR" fetch --depth 1 origin master
    git -C "$SRC_DIR" reset --hard origin/master
fi

cd "$SRC_DIR"

# asio is header-only; openvpn3's build wants ASIO_DIR pointing
# at the include root. Brew installs it at
# /opt/homebrew/opt/asio/include.
echo "→ Configuring (cmake)…"
cmake -B build -G "Unix Makefiles" \
    -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
    -DASIO_DIR=/opt/homebrew/opt/asio \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=/opt/homebrew

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
echo "Next: rebuild + relaunch SuperManager so the helper picks"
echo "this up via locate_openvpn (no other code change needed —"
echo "the openvpn3 path is already wired)."
