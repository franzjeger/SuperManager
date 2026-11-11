#!/usr/bin/env bash
# Assemble the WireGuard, Tailscale, IKEv2/strongSwan, and Azure/OpenVPN 3
# runtime from pinned, SHA-256-verified upstream source archives.
#
#   scripts/build-vpn-runtime.sh OUT_DIR
#
# The helper runs programs as root only from where only root can write:
# the app bundles these, and the helper checks each before it installs it
# into /Library/PrivilegedHelperTools/SuperManagerVPN
# (supermanager-helper/src/vpn_runtime.rs). Puts into OUT_DIR:
#
#   bash                     GNU bash 5.3 with its official patches, built from
#                            pinned source without readline, history or gettext,
#                            so it loads system libraries only.
#   wg                       pinned wireguard-tools, compiled for macOS 14.0
#   wg-quick                 the same source's darwin.bash, adapted with the
#                            helper-pinned digest
#   wireguard-go             pinned wireguard-go, built with `go build -trimpath`
#   tailscale, tailscaled    pinned Tailscale CLI + daemon, built with
#                            `go build -trimpath`
#   openvpn3                 pinned ovpncli with file-based credentials, built
#                            with static dependencies by build-openvpn3-runtime.sh
#   charon, swanctl          pinned monolithic strongSwan 6.0.7 + static OpenSSL
#   licenses/                per-component license files and SOURCES manifest
#   THIRD_PARTY_LICENSES.txt consolidated notice & license texts (GPL/BSD/MIT)
#
# The helper checks Mach-O binaries by the Developer ID signature and bundle
# identifier applied during signing; nothing is signed here. wg-quick is a
# script checked by content against supermanager-helper/src/wg-quick.sha256.
#
# Exits 2 and writes nothing when the Go toolchain is not installed:
# local Debug builds can skip optional runtime bundling, while release builds
# invoke this script directly and require exit 0.

set -euo pipefail

# The same digests Homebrew's bash formula pins.
BASH_URL=https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz
BASH_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba
# bash53-001 to bash53-020, applied in order.
BASH_PATCH_URL=https://ftp.gnu.org/gnu/bash/bash-5.3-patches
BASH_PATCHES=(
    1f608434364af86b9b45c8b0ea3fb3b165fb830d27697e6cdfc7ac17dee3287f
    e385548a00130765ec7938a56fbdca52447ab41fabc95a25f19ade527e282001
    f245d9c7dc3f5a20d84b53d249334747940936f09dc97e1dcb89fc3ab37d60ed
    9591d245045529f32f0812f94180b9d9ce9023f5a765c039b852e5dfc99747d0
    cca1ef52dbbf433bc98e33269b64b2c814028efe2538be1e2c9a377da90bc99d
    29119addefed8eff91ae37fd51822c31780ee30d4a28376e96002706c995ff10
    c0976bbfffa1453c7cfdd62058f206a318568ff2d690f5d4fa048793fa3eb299
    097cd723cbfb8907674ac32214063a3fd85282657ec5b4e544d2c0f719653fb4
    eee30fe78a4b0cb2fe20e010e00308899cfc613e0774ebb3c8557a1552f24f8c
    cf76f1cce2ea300c18bff9f002d21f280cc931acd17c28518110b93fe6e72569
    0298df8f5ea2a31d3be43ed7d269c5b3c7c342dd5b570bea7f64d66dcbbe7531
    d71379b39bebaedaf123414414e77fb458a0a43b9ad3116594c6df7ca6754573
    042f9cda967e24bf4211944697441e93d06ff42b4b998629a98a1b249279f200
    bd4360b401d38507e358783dcad8536a99c6789f0d3a5bd0cfb8c4a34144696c
    55b79ceee2fc27f6767eed697e939a7eb2fe2a28c01556bd75f18d581014f46e
    9ea29b266b7d24cb34d0ff3f1c4631e4d527bfe2d1ef15d17cdb924bf31ef767
    443b927b45c1558ca72052410f8b8f6e5152b617ed707061a2781d4375b0d1c3
    ae715d76c50341d7d7095e9a8d2eeed1ca9546152c2ac7289206f90cf30ac697
    a25c581e4d0057dea3833918438a930e2e86ee4c6dc17fe15267b7f04cbc4e3d
    df217ed3a9122aa2286d9b67bbe348661b6a9db262b580c29150dae55d532896
)
BASH_CONFIGURE=(--without-bash-malloc --disable-nls --disable-readline
                --disable-history --without-curses)

# Pinned WireGuard userspace Go implementation (MIT).
WG_GO_VERSION=0.0.20250522
WG_GO_REVISION=f333402bd9cbe0f3eeb02507bd14e23d7d639280
WG_GO_SHA256=4483dde7778ad264f3822b0a436c733ac82404e4d0265df3b603352111490987
WG_GO_URL="https://codeload.github.com/WireGuard/wireguard-go/tar.gz/$WG_GO_REVISION"

# Pinned Tailscale CLI & daemon (BSD-3-Clause).
TAILSCALE_VERSION=1.104.5
TAILSCALE_REVISION=73a48057aaf5f60e4f770b398e9b7af576b01dbe
TAILSCALE_SHORT_HASH=73a48057a
TAILSCALE_SHA256=f3b88e5ce851cabe097725de7deaa19528353061efd0d122b972a0d94cd2f5cd
TAILSCALE_URL="https://codeload.github.com/tailscale/tailscale/tar.gz/$TAILSCALE_REVISION"

out="${1:?usage: build-vpn-runtime.sh OUT_DIR}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="$repo/target/vpn-runtime"

# Xcode's script phases start with a minimal PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

# fetch URL SHA256 FILE: download URL to FILE unless FILE is there already,
# and refuse it unless it has SHA256.
fetch() {
    local url="$1" sha256="$2" file="$3"
    if [ -f "$file" ] && echo "$sha256  $file" | shasum -a 256 -c - >/dev/null 2>&1; then
        return 0
    fi
    curl -fsSL --proto '=https' --tlsv1.2 -o "$file.part" "$url"
    if ! echo "$sha256  $file.part" | shasum -a 256 -c - >/dev/null 2>&1; then
        rm -f "$file.part"
        echo "error: $url does not match its pinned SHA-256" >&2
        exit 1
    fi
    mv "$file.part" "$file"
}

assert_system_dylibs_only() {
    local binary="$1"
    if otool -L "$binary" | tail -n +2 | grep -vE '^[[:space:]]+/(usr/lib|System/Library)/' >&2; then
        echo "error: $(basename "$binary") loads libraries outside /usr/lib and /System/Library" >&2
        exit 1
    fi
}

if ! command -v go >/dev/null 2>&1; then
    echo "note: Go toolchain is not installed; no VPN runtime." >&2
    exit 2
fi

sdk_path="$(xcrun --show-sdk-path)"
clang_ver="$(xcrun clang --version)"
go_ver="$(go version)"
arch="$(uname -m)"
ncpu="$(sysctl -n hw.ncpu)"

# Build wireguard-go deterministically from pinned upstream archive.
wg_go_source="$cache/wireguard-go-$WG_GO_REVISION"
wg_go_stamp="$WG_GO_SHA256 $arch $go_ver $sdk_path macOS14.0"
if [ ! -x "$wg_go_source/wireguard-go" ] || [ "$(cat "$wg_go_source/.stamp" 2>/dev/null)" != "$wg_go_stamp" ]; then
    mkdir -p "$cache"
    fetch "$WG_GO_URL" "$WG_GO_SHA256" "$cache/wireguard-go-$WG_GO_REVISION.tar.gz"
    rm -rf "$wg_go_source"
    mkdir -p "$wg_go_source"
    tar -xzf "$cache/wireguard-go-$WG_GO_REVISION.tar.gz" -C "$wg_go_source" --strip-components 1
    (
        cd "$wg_go_source"
        env CC=/usr/bin/clang \
            SDKROOT="$sdk_path" \
            CGO_ENABLED=1 \
            MACOSX_DEPLOYMENT_TARGET=14.0 \
            CGO_CFLAGS="-mmacosx-version-min=14.0" \
            CGO_LDFLAGS="-mmacosx-version-min=14.0" \
            go build -trimpath -ldflags="-s -w" -o "$wg_go_source/wireguard-go" . \
            >"$wg_go_source/build.log" 2>&1 || { tail -60 "$wg_go_source/build.log" >&2; exit 1; }
    )
    printf '%s\n' "$wg_go_stamp" >"$wg_go_source/.stamp"
fi

# Build tailscale and tailscaled deterministically from pinned upstream archive.
ts_source="$cache/tailscale-$TAILSCALE_REVISION"
ts_ldflags="-s -w -X tailscale.com/version.longStamp=${TAILSCALE_VERSION}-t${TAILSCALE_SHORT_HASH} -X tailscale.com/version.shortStamp=${TAILSCALE_VERSION} -X tailscale.com/version.gitCommitStamp=${TAILSCALE_REVISION}"
ts_stamp="$TAILSCALE_SHA256 $ts_ldflags $arch $go_ver $sdk_path macOS14.0"
if [ ! -x "$ts_source/tailscale" ] || [ ! -x "$ts_source/tailscaled" ] || [ "$(cat "$ts_source/.stamp" 2>/dev/null)" != "$ts_stamp" ]; then
    mkdir -p "$cache"
    fetch "$TAILSCALE_URL" "$TAILSCALE_SHA256" "$cache/tailscale-$TAILSCALE_REVISION.tar.gz"
    rm -rf "$ts_source"
    mkdir -p "$ts_source"
    tar -xzf "$cache/tailscale-$TAILSCALE_REVISION.tar.gz" -C "$ts_source" --strip-components 1
    (
        cd "$ts_source"
        for ts_cmd in tailscale tailscaled; do
            env CC=/usr/bin/clang \
                SDKROOT="$sdk_path" \
                CGO_ENABLED=1 \
                MACOSX_DEPLOYMENT_TARGET=14.0 \
                CGO_CFLAGS="-mmacosx-version-min=14.0" \
                CGO_LDFLAGS="-mmacosx-version-min=14.0" \
                go build -trimpath -ldflags="$ts_ldflags" -o "$ts_source/$ts_cmd" "./cmd/$ts_cmd" \
                >"$ts_source/build-$ts_cmd.log" 2>&1 || { tail -60 "$ts_source/build-$ts_cmd.log" >&2; exit 1; }
        done
    )
    printf '%s\n' "$ts_stamp" >"$ts_source/.stamp"
fi
ts_ver_out="$("$ts_source/tailscale" version 2>&1 || true)"
case "$ts_ver_out" in
    *"$TAILSCALE_VERSION"*) ;;
    *)
        echo "error: built tailscale did not report expected version $TAILSCALE_VERSION: $ts_ver_out" >&2
        exit 1
        ;;
esac

# Homebrew's wg can be built for a newer OS than the app supports. Build the
# small C client from source instead, keeping the exact reviewed script pin.
WG_REVISION=49ce333da02056ae7b22ee2aeb6afe8aaed79b19
WG_SHA256=2b901ba5c3957b7bb310e1c6b7ced1cc3fc9c8f6d58d59bcbdbeebd053232ef0
WG_URL="https://codeload.github.com/WireGuard/wireguard-tools/tar.gz/$WG_REVISION"
wg_source="$cache/wireguard-tools-$WG_REVISION"
wg_stamp="$WG_SHA256 $arch $sdk_path $clang_ver macOS14.0"
if [ ! -x "$wg_source/src/wg" ] || [ "$(cat "$wg_source/.stamp" 2>/dev/null)" != "$wg_stamp" ]; then
    mkdir -p "$cache"
    fetch "$WG_URL" "$WG_SHA256" "$cache/wireguard-tools-$WG_REVISION.tar.gz"
    rm -rf "$wg_source"
    mkdir -p "$wg_source"
    tar -xzf "$cache/wireguard-tools-$WG_REVISION.tar.gz" -C "$wg_source" --strip-components 1
    env CC="$(xcrun --find clang)" SDKROOT="$sdk_path" \
        MACOSX_DEPLOYMENT_TARGET=14.0 CFLAGS="-O2 -mmacosx-version-min=14.0" \
        LDFLAGS="-mmacosx-version-min=14.0" \
        make -C "$wg_source/src" -j"$ncpu" wg \
        >"$wg_source/make.log" 2>&1 || { tail -60 "$wg_source/make.log" >&2; exit 1; }
    printf '%s\n' "$wg_stamp" >"$wg_source/.stamp"
fi
# Match the script that existing helpers already pin: Homebrew's macOS
# configuration search path adds /opt/homebrew/etc/wireguard. No other code
# is changed, and the complete resulting script must match the helper hash.
sed 's|CONFIG_SEARCH_PATHS=( /etc/wireguard /usr/local/etc/wireguard )|CONFIG_SEARCH_PATHS=( /etc/wireguard /usr/local/etc/wireguard /opt/homebrew/etc/wireguard )|' \
    "$wg_source/src/wg-quick/darwin.bash" >"$wg_source/wg-quick"
pinned="$(tr -d '[:space:]' <"$repo/supermanager-helper/src/wg-quick.sha256")"
if [ "$(shasum -a 256 <"$wg_source/wg-quick" | cut -d' ' -f1)" != "$pinned" ]; then
    echo "error: adapted wireguard-tools script does not match the helper's wg-quick pin" >&2
    exit 1
fi
python3 "$repo/contrib/openvpn3/check_deployment.py" --maximum 14.0 \
    "$wg_source/src/wg" "$wg_go_source/wireguard-go" "$ts_source/tailscale" "$ts_source/tailscaled"
assert_system_dylibs_only "$wg_source/src/wg"
assert_system_dylibs_only "$wg_go_source/wireguard-go"
assert_system_dylibs_only "$ts_source/tailscale"
assert_system_dylibs_only "$ts_source/tailscaled"

# bash, built once per source and configuration, then reused.
stamp="$BASH_SHA256 ${BASH_PATCHES[*]} ${BASH_CONFIGURE[*]} macOS14.0 $arch $sdk_path $clang_ver"
built="$cache/bash-build"
if [ ! -x "$built/bash" ] || [ "$(cat "$built/.stamp" 2>/dev/null)" != "$stamp" ]; then
    mkdir -p "$cache"
    fetch "$BASH_URL" "$BASH_SHA256" "$cache/${BASH_URL##*/}"
    rm -rf "$built"
    mkdir -p "$built"
    tar -xzf "$cache/${BASH_URL##*/}" -C "$built" --strip-components 1
    for i in "${!BASH_PATCHES[@]}"; do
        patch_file="$(printf 'bash53-%03d' $((i + 1)))"
        fetch "$BASH_PATCH_URL/$patch_file" "${BASH_PATCHES[$i]}" "$cache/$patch_file"
        patch -d "$built" -p0 -s <"$cache/$patch_file"
    done
    (
        cd "$built"
        ./configure "${BASH_CONFIGURE[@]}" CFLAGS="-O2 -mmacosx-version-min=14.0" >configure.log 2>&1 \
            || { tail -40 configure.log >&2; exit 1; }
        make -j"$ncpu" bash >make.log 2>&1 \
            || { tail -40 make.log >&2; exit 1; }
    )
    printf '%s\n' "$stamp" >"$built/.stamp"
fi

# A root helper must not load libraries from a prefix the user can write.
assert_system_dylibs_only "$built/bash"
python3 "$repo/contrib/openvpn3/check_deployment.py" --maximum 14.0 "$built/bash"

mkdir -p "$out/licenses"
install -m 0755 "$built/bash" "$out/bash"
install -m 0755 "$wg_source/src/wg" "$out/wg"
install -m 0755 "$wg_source/wg-quick" "$out/wg-quick"
install -m 0755 "$wg_go_source/wireguard-go" "$out/wireguard-go"
install -m 0755 "$ts_source/tailscale" "$out/tailscale"
install -m 0755 "$ts_source/tailscaled" "$out/tailscaled"

install -m 0644 "$built/COPYING" "$out/licenses/bash.COPYING"
install -m 0644 "$wg_source/COPYING" "$out/licenses/wireguard-tools.COPYING"
install -m 0644 "$wg_go_source/LICENSE" "$out/licenses/wireguard-go.LICENSE"
install -m 0644 "$ts_source/LICENSE" "$out/licenses/tailscale.LICENSE"
cat >"$out/licenses/SOURCES" <<EOF
The programs in vpn-runtime, and where their source is:

bash          GNU bash 5.3 with its official patches up to $(printf 'bash53-%03d' "${#BASH_PATCHES[@]}"):
                $BASH_URL (SHA-256: $BASH_SHA256)
                $BASH_PATCH_URL
              built by scripts/build-vpn-runtime.sh in
              https://github.com/franzjeger/SuperManager
wg, wg-quick  wireguard-tools v1.0.20260223, commit $WG_REVISION:
                $WG_URL (SHA-256: $WG_SHA256)
              wg built for macOS 14.0; wg-quick matches the helper SHA-256 pin
              https://git.zx2c4.com/wireguard-tools
wireguard-go  wireguard-go $WG_GO_VERSION, commit $WG_GO_REVISION:
                $WG_GO_URL (SHA-256: $WG_GO_SHA256)
              built from pinned source with go build -trimpath
              https://git.zx2c4.com/wireguard-go
tailscale,    Tailscale v$TAILSCALE_VERSION, commit $TAILSCALE_REVISION:
tailscaled      $TAILSCALE_URL (SHA-256: $TAILSCALE_SHA256)
              built from pinned source with go build -trimpath
              https://github.com/tailscale/tailscale
EOF

# Azure VPN must have a protected OpenVPN 3 as well. Keeping this in the
# normal bundle build prevents a release from requiring a runtime it omits.
"$repo/scripts/build-openvpn3-runtime.sh" "$out"

# IKEv2 must ship with Release too. A Homebrew strongSwan executable loads
# user-writable dylibs/plugins; build monolithically and link OpenSSL statically
# from the macOS 14.0 static dependency prefix.
#
# Unset Xcode's GCC_TREAT_WARNINGS_AS_ERRORS=NO before running autoconf:
# when exported by an Xcode Run Script Build Phase, /usr/bin/gcc downgrades
# -Werror to a warning, causing strongSwan's configure to misdetect GNU-style
# qsort_r on Darwin (BSD qsort_r) and segfault on startup in array_sort().
unset GCC_TREAT_WARNINGS_AS_ERRORS
ss_url=https://download.strongswan.org/strongswan-6.0.7.tar.bz2
ss_sha=e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55
ss="$cache/strongswan-build"
ssl="$("$repo/contrib/openvpn3/build_dependencies.sh" "${SUPERMANAGER_OPENVPN3_CACHE_DIR:-$repo/target/openvpn3-runtime}/dependencies")"
prefix=/Library/PrivilegedHelperTools/SuperManagerVPN
ss_options=(--prefix="$prefix" --sysconfdir="$prefix/etc" --with-piddir=/var/run
    --disable-defaults --enable-static --disable-shared --enable-monolithic
    --enable-ikev1 --enable-ikev2 --enable-charon --enable-swanctl --enable-vici
    --enable-openssl --enable-random --enable-nonce --enable-x509
    --enable-revocation --enable-constraints --enable-pubkey --enable-pem
    --enable-pkcs1 --enable-pkcs8 --enable-pgp --enable-sshkey
    --enable-curve25519 --enable-kdf --enable-kernel-pfroute
    --enable-kernel-pfkey --enable-socket-default --enable-osx-attr
    --enable-updown --enable-eap-identity --enable-eap-mschapv2
    --enable-eap-md5 --enable-eap-gtc --enable-eap-peap
    --enable-xauth-generic --enable-md4 --enable-des)
ss_stamp="$ss_sha ${ss_options[*]} HAVE_QSORT_R_BSD macOS14.0 $arch $(shasum -a 256 "$ssl/lib/libcrypto.a")"
if [ ! -x "$ss/src/swanctl/swanctl" ] || [ "$(cat "$ss/.stamp" 2>/dev/null)" != "$ss_stamp" ]; then
    fetch "$ss_url" "$ss_sha" "$cache/strongswan.tar.bz2"
    rm -rf "$ss"
    mkdir -p "$ss"
    tar -xjf "$cache/strongswan.tar.bz2" -C "$ss" --strip-components 1
    (
        cd "$ss"
        env CC=/usr/bin/clang \
            MACOSX_DEPLOYMENT_TARGET=14.0 \
            CPPFLAGS="-I$ssl/include" \
            CFLAGS="-O2 -mmacosx-version-min=14.0" \
            LDFLAGS="-L$ssl/lib -mmacosx-version-min=14.0 -framework SystemConfiguration -framework CoreFoundation" \
            ./configure "${ss_options[@]}" >configure.log 2>&1 \
            || { tail -40 configure.log >&2; exit 1; }
        if ! grep -q '^#define HAVE_QSORT_R_BSD' config.h; then
            echo "error: strongSwan did not select BSD qsort_r on macOS" >&2
            exit 1
        fi
        make -j"$ncpu" >make.log 2>&1 \
            || { tail -40 make.log >&2; exit 1; }
    )
    printf '%s\n' "$ss_stamp" >"$ss/.stamp"
fi
python3 "$repo/contrib/openvpn3/check_deployment.py" --maximum 14.0 \
    "$ss/src/charon/charon" "$ss/src/swanctl/swanctl"
ss_smoke_conf="$(mktemp)"
printf 'charon {\n  load_modular = no\n}\n' >"$ss_smoke_conf"
STRONGSWAN_CONF="$ss_smoke_conf" "$ss/src/charon/charon" --version >/dev/null
rm -f "$ss_smoke_conf"
for entry in charon swanctl; do
    binary="$ss/src/$entry/$entry"
    assert_system_dylibs_only "$binary"
    install -m 0755 "$binary" "$out/$entry"
done
install -m 0644 "$ss/COPYING" "$out/licenses/strongswan.COPYING"
printf '\nstrongSwan 6.0.7: %s (SHA-256 %s); static OpenSSL: %s\n' \
    "$ss_url" "$ss_sha" "$ss_stamp" >>"$out/licenses/SOURCES"

# Consolidated third-party license bundle covering all GPL/AGPL/BSD/MIT
# runtime executables shipped inside the application bundle (P1-7).
{
    cat <<EOF
================================================================================
SuperManager Bundled VPN & Mesh Runtime — Third-Party Licenses & Source Notice
================================================================================

All third-party executables in this runtime directory are built reproducibly
from pinned, SHA-256-verified upstream source archives by:
  https://github.com/franzjeger/SuperManager (scripts/build-vpn-runtime.sh
  and scripts/build-openvpn3-runtime.sh)

Component Summary:
  1. bash (GNU Bash 5.3 + patches 001..$(printf '%03d' "${#BASH_PATCHES[@]}"))
     License: GPL-3.0-or-later
     Source:  $BASH_URL
     SHA-256: $BASH_SHA256

  2. wg, wg-quick (wireguard-tools commit $WG_REVISION)
     License: GPL-2.0-only
     Source:  $WG_URL
     SHA-256: $WG_SHA256

  3. wireguard-go ($WG_GO_VERSION, commit $WG_GO_REVISION)
     License: MIT
     Source:  $WG_GO_URL
     SHA-256: $WG_GO_SHA256

  4. tailscale, tailscaled (v$TAILSCALE_VERSION, commit $TAILSCALE_REVISION)
     License: BSD-3-Clause
     Source:  $TAILSCALE_URL
     SHA-256: $TAILSCALE_SHA256

  5. openvpn3 (OpenVPN 3 Client Library + statically linked OpenSSL, mbedTLS,
     Asio, fmt, jsoncpp, lz4 — see licenses/openvpn3* below)
     License: AGPL-3.0-only (with OpenSSL Exception) / Apache-2.0 / BSL-1.0 /
              MIT / BSD-2-Clause

  6. charon, swanctl (strongSwan 6.0.7 + statically linked OpenSSL)
     License: GPL-2.0-or-later
     Source:  $ss_url
     SHA-256: $ss_sha

Corresponding build scripts, patches, and exact compiler/configure flags used
to produce these binaries are published in the SuperManager source repository
at https://github.com/franzjeger/SuperManager.
EOF
    for lic_file in "$out"/licenses/*; do
        [ -f "$lic_file" ] || continue
        printf '\n================================================================================\n'
        printf 'FILE: licenses/%s\n' "$(basename "$lic_file")"
        printf '================================================================================\n\n'
        cat "$lic_file"
        printf '\n'
    done
} >"$out/THIRD_PARTY_LICENSES.txt"
chmod 0644 "$out/THIRD_PARTY_LICENSES.txt"
