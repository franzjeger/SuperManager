#!/usr/bin/env bash
# Build the runtime's pinned dependencies for the app's oldest macOS.
# Print only the completed prefix on stdout; build logs stay in the cache.
set -euo pipefail

cache="${1:?usage: build_dependencies.sh CACHE_DIR}"
adapter="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
minimum=14.0
architecture="$(uname -m)"
case "$architecture" in
    arm64) openssl_target=darwin64-arm64-cc ;;
    x86_64) openssl_target=darwin64-x86_64-cc ;;
    *) echo "error: unsupported macOS architecture: $architecture" >&2; exit 1 ;;
esac
sdk="$(xcrun --show-sdk-path)"
clang="$(xcrun --find clang)"
clangxx="$(xcrun --find clang++)"
# Hash source archives as well as toolchain/recipe. The same source recipe is
# used on CI and developer Macs; Homebrew bottle deployment targets cannot leak in.
openssl_version=3.5.9
openssl_sha256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
lz4_version=1.11.0
lz4_sha256=247e5fa64da5f7b75ee3dd3bed484076396c9ebe8254d9ccf693eb62800c5e26
fmt_version=12.2.1
fmt_sha256=870a49acec5bcdab236aeea834ebd7f0b8548a7d8cea33c996b6873a37f2d50c
asio_version=1.38.2
asio_sha256=c04e0e66ac29741faad763a56f3c50196421d4b968009fc237c53314769bf8ad

fingerprint="$({
    printf '%s\n' "$minimum" "$architecture" "$sdk" "$("$clang" --version)" \
        "$(cmake --version)" "$openssl_sha256" "$lz4_sha256" "$fmt_sha256" "$asio_sha256"
    shasum -a 256 "$adapter/build_dependencies.sh" "$adapter/check_deployment.py"
} | shasum -a 256 | cut -d' ' -f1)"
build="$cache/$fingerprint"
prefix="$build/prefix"
mkdir -p "$cache/downloads"

fetch() {
    local url="$1" digest="$2" name="$3" archive="$cache/downloads/$3"
    if [ ! -f "$archive" ] || ! echo "$digest  $archive" | shasum -a 256 -c - >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$archive.part" "$url"
        if ! echo "$digest  $archive.part" | shasum -a 256 -c - >/dev/null 2>&1; then
            echo "error: $name does not match its pinned SHA-256" >&2
            exit 1
        fi
        mv "$archive.part" "$archive"
    fi
}

if [ ! -f "$prefix/.complete" ]; then
    fetch "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz" \
        "$openssl_sha256" "openssl-$openssl_version.tar.gz"
    fetch "https://github.com/lz4/lz4/archive/refs/tags/v$lz4_version.tar.gz" \
        "$lz4_sha256" "lz4-$lz4_version.tar.gz"
    fetch "https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip" \
        "$fmt_sha256" "fmt-$fmt_version.zip"
    fetch "https://downloads.sourceforge.net/project/asio/asio/$asio_version%20%28Stable%29/asio-$asio_version.tar.bz2" \
        "$asio_sha256" "asio-$asio_version.tar.bz2"
    # Never reuse a half-built prefix or patched source after an interrupted build.
    rm -rf "$build"
    mkdir -p "$prefix/include" "$prefix/lib" "$prefix/licenses" "$build/openssl" \
        "$build/lz4" "$build/fmt" "$build/asio"
    tar -xf "$cache/downloads/openssl-$openssl_version.tar.gz" -C "$build/openssl" --strip-components 1
    tar -xf "$cache/downloads/lz4-$lz4_version.tar.gz" -C "$build/lz4" --strip-components 1
    # bsdtar understands zip. Extract in a separate directory before removing
    # the top-level source directory, just like the tar archives above.
    tar -xf "$cache/downloads/fmt-$fmt_version.zip" -C "$build/fmt" --strip-components 1
    tar -xf "$cache/downloads/asio-$asio_version.tar.bz2" -C "$build/asio" --strip-components 1
    jobs="$(sysctl -n hw.ncpu)"
    export MACOSX_DEPLOYMENT_TARGET="$minimum" SDKROOT="$sdk" CC="$clang" CXX="$clangxx"
    export CFLAGS="-O2 -mmacosx-version-min=$minimum -isysroot $sdk"
    export CXXFLAGS="$CFLAGS" LDFLAGS="-mmacosx-version-min=$minimum -isysroot $sdk"
    echo "→ Building pinned static OpenSSL, LZ4 and fmt for macOS $minimum ($architecture)" >&2
    (
        cd "$build/openssl"
        /usr/bin/perl ./Configure "$openssl_target" no-shared no-tests no-legacy \
            --prefix="$prefix" --libdir=lib --openssldir=/var/empty
        make -j"$jobs" build_sw
        make install_sw
    ) >"$build/openssl.log" 2>&1 || { tail -80 "$build/openssl.log" >&2; exit 1; }
    make -C "$build/lz4/lib" -j"$jobs" liblz4.a >"$build/lz4.log" 2>&1 \
        || { tail -60 "$build/lz4.log" >&2; exit 1; }
    install -m 0644 "$build/lz4/lib/liblz4.a" "$prefix/lib/liblz4.a"
    install -m 0644 "$build/lz4/lib/"*.h "$prefix/include/"
    cmake -S "$build/fmt" -B "$build/fmt-build" -G 'Unix Makefiles' \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$minimum" -DCMAKE_OSX_ARCHITECTURES="$architecture" \
        -DBUILD_SHARED_LIBS=OFF -DFMT_TEST=OFF -DFMT_DOC=OFF \
        >"$build/fmt.log" 2>&1 || { tail -60 "$build/fmt.log" >&2; exit 1; }
    cmake --build "$build/fmt-build" -j "$jobs" >>"$build/fmt.log" 2>&1 \
        || { tail -60 "$build/fmt.log" >&2; exit 1; }
    cmake --install "$build/fmt-build" >>"$build/fmt.log" 2>&1
    cp -R "$build/asio/include/." "$prefix/include/"
    install -m 0644 "$build/openssl/LICENSE.txt" "$prefix/licenses/openvpn3-OpenSSL.LICENSE.txt"
    install -m 0644 "$build/lz4/lib/LICENSE" "$prefix/licenses/openvpn3-LZ4.LICENSE"
    install -m 0644 "$build/fmt/LICENSE" "$prefix/licenses/openvpn3-fmt.LICENSE"
    install -m 0644 "$build/asio/COPYING" "$prefix/licenses/openvpn3-Asio.COPYING"
    cat >"$prefix/licenses/openvpn3-dependencies.SOURCES" <<EOF
Pinned dependencies, built from source with MACOSX_DEPLOYMENT_TARGET=$minimum:
OpenSSL $openssl_version: https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz
SHA-256: $openssl_sha256
LZ4 $lz4_version: https://github.com/lz4/lz4/archive/refs/tags/v$lz4_version.tar.gz
SHA-256: $lz4_sha256
fmt $fmt_version: https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip
SHA-256: $fmt_sha256
Asio $asio_version: https://downloads.sourceforge.net/project/asio/asio/$asio_version%20%28Stable%29/asio-$asio_version.tar.bz2
SHA-256: $asio_sha256
Build fingerprint: $fingerprint
EOF
    touch "$prefix/.complete"
fi
python3 "$adapter/check_deployment.py" --maximum "$minimum" \
    "$prefix/lib/libssl.a" "$prefix/lib/libcrypto.a" "$prefix/lib/liblz4.a" "$prefix/lib/libfmt.a" >&2
printf '%s\n' "$prefix"
