#!/usr/bin/env bash
# Build the pinned OpenVPN 3 client into OUT_DIR/openvpn3, with licenses.
# No privileged writes or signing. Only system dylibs may remain linked;
# the app signs this executable before vpn_runtime_install accepts it.
set -euo pipefail

out="${1:?usage: build-openvpn3-runtime.sh OUT_DIR}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
adapter="$repo/contrib/openvpn3"
cache="${SUPERMANAGER_OPENVPN3_CACHE_DIR:-$repo/target/openvpn3-runtime}"
revision=0b27d9df493db8bc9dc459a2b1cb6b67037742b2
archive_sha256=7c54159ff28ad2f477ce3bf12ea83c57cf1385f250aa782ac3481bab48732df9
source_url="https://codeload.github.com/OpenVPN/openvpn3/tar.gz/$revision"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
if [ "$(uname -s)" != Darwin ]; then
    echo "error: the OpenVPN 3 runtime builder requires macOS" >&2
    exit 1
fi
for tool in cmake python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: missing $tool; brew install cmake" >&2
        exit 1
    fi
done
# Source-built static libraries share the app's deployment target. Homebrew
# bottles may target a newer macOS than the one this app supports.
dependency_prefix="$("$adapter/build_dependencies.sh" "$cache/dependencies")"
openssl_prefix="$dependency_prefix"
asio_prefix="$dependency_prefix"
lz4_prefix="$dependency_prefix"
fmt_prefix="$dependency_prefix"

# Rebuild when source, adapter, architecture, toolchain or dependency changes.
# The source-dependency prefix includes its source pins, recipe and toolchain.
# Archive hashes also catch an unexpected library rebuilt in place.
stamp="$({
    printf '%s\n' "$revision" "$archive_sha256" "$(uname -m)" "$(xcrun --show-sdk-path)" \
        "$(xcrun clang --version)" "$(cmake --version)" \
        "$(realpath "$openssl_prefix")" "$(realpath "$asio_prefix")" \
        "$(realpath "$lz4_prefix")" "$(realpath "$fmt_prefix")"
    shasum -a 256 "$repo/scripts/build-openvpn3-runtime.sh" "$adapter/CMakeLists.txt" "$adapter/apply_adapter.py" \
        "$adapter/auth_user_pass.hpp" "$adapter/check_deployment.py" \
        "$openssl_prefix/lib/libssl.a" "$openssl_prefix/lib/libcrypto.a" \
        "$lz4_prefix/lib/liblz4.a" "$fmt_prefix/lib/libfmt.a"
} | shasum -a 256 | cut -d' ' -f1)"
build="$cache/$stamp"
source="$build/source"
binary="$build/build/openvpn3"
mkdir -p "$cache"
archive="$cache/openvpn3-$revision.tar.gz"
if [ ! -f "$archive" ] || ! echo "$archive_sha256  $archive" | shasum -a 256 -c - >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$archive.part" "$source_url"
    if ! echo "$archive_sha256  $archive.part" | shasum -a 256 -c - >/dev/null 2>&1; then
        echo "error: OpenVPN 3 source does not match its pinned SHA-256" >&2
        exit 1
    fi
    mv "$archive.part" "$archive"
fi
if [ ! -x "$binary" ]; then
    rm -rf "$source" "$build/build"
    mkdir -p "$source"
    tar -xzf "$archive" -C "$source" --strip-components 1
    python3 "$adapter/apply_adapter.py" "$source"
    echo "→ Building pinned OpenVPN 3 ($revision), with static dependencies"
    cmake -S "$adapter" -B "$build/build" -G 'Unix Makefiles' \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
        -DCMAKE_OSX_ARCHITECTURES="$(uname -m)" \
        -DCORE_SOURCE="$source" -DOPENSSL_PREFIX="$openssl_prefix" \
        -DASIO_PREFIX="$asio_prefix" -DLZ4_PREFIX="$lz4_prefix" -DFMT_PREFIX="$fmt_prefix" \
        >"$build/configure.log" 2>&1 || { tail -60 "$build/configure.log" >&2; exit 1; }
    cmake --build "$build/build" --target openvpn3 -j "$(sysctl -n hw.ncpu)" \
        >"$build/make.log" 2>&1 || { tail -80 "$build/make.log" >&2; exit 1; }
fi

python3 "$adapter/check_deployment.py" --maximum 14.0 "$binary"

# A root-owned executable is insufficient if it loads user-writable dylibs.
if otool -L "$binary" | tail -n +2 | grep -vE '^[[:space:]]+/(usr/lib|System/Library)/' >&2; then
    echo "error: OpenVPN 3 loads non-system libraries (listed above)" >&2
    exit 1
fi
if otool -l "$binary" | grep 'cmd LC_RPATH' >&2; then
    echo "error: OpenVPN 3 must not have runtime library search paths" >&2
    exit 1
fi
# Upstream's OpenSSL self-test currently returns an empty string; this is
# a CLI/startup check, not evidence of cryptographic known-answer tests.
"$binary" --self-test >"$build/self-test.log" 2>&1
python3 "$adapter/test_credentials.py" --binary "$binary" --ca "$source/test/ssl/ca.crt" \
    --openssl "$openssl_prefix/bin/openssl"

mkdir -p "$out/licenses"
install -m 0755 "$binary" "$out/openvpn3"
install -m 0644 "$source/LICENSE.md" "$out/licenses/openvpn3.LICENSE.md"
mkdir -p "$out/licenses/openvpn3-LICENSES"
cp -R "$source/LICENSES/." "$out/licenses/openvpn3-LICENSES/"
install -m 0644 "$dependency_prefix/licenses/"* "$out/licenses/"
cat >"$out/licenses/openvpn3.SOURCES" <<EOF
OpenVPN 3 core, upstream commit $revision
Source: $source_url
Archive SHA-256: $archive_sha256
Credential adapter and build recipe: contrib/openvpn3 and scripts/build-openvpn3-runtime.sh
https://github.com/franzjeger/SuperManager

Static build dependencies: see openvpn3-dependencies.SOURCES for source URLs,
SHA-256 pins and macOS deployment target. No Homebrew libraries are linked.

Build/adapter/dependency fingerprint: $stamp
EOF
echo "✓ OpenVPN 3 runtime ready: $out/openvpn3"
