#!/usr/bin/env bash
# Assemble the WireGuard and Azure/OpenVPN 3 runtime for the root helper.
#
#   scripts/build-vpn-runtime.sh OUT_DIR
#
# The helper runs programs as root only from where only root can write:
# the app bundles these, and the helper checks each before it installs it
# into /Library/PrivilegedHelperTools/SuperManagerVPN
# (supermanager-helper/src/vpn_runtime.rs). Puts into OUT_DIR:
#
#   bash          GNU bash 5.3 with its official patches, built here from
#                 pinned source without readline, history or gettext, so
#                 it loads system libraries only. wg-quick needs bash 4 or
#                 later; macOS ships 3.2, and Homebrew's loads libraries
#                 from Homebrew.
#   wg            pinned wireguard-tools, compiled for macOS 14.0
#   wg-quick      the same source's darwin.bash, with the existing Homebrew
#                 configuration search path; exact helper-pinned digest
#   wireguard-go  from Homebrew's wireguard-go
#   openvpn3      pinned ovpncli with file-based credentials, built with
#                 static dependencies by build-openvpn3-runtime.sh
#   licenses/     their licenses, and where their source is
#
# The helper checks bash, wg, wireguard-go and openvpn3 by the signature the caller
# gives them; nothing is signed here. wg-quick is a script, so the helper
# checks it by content instead, against supermanager-helper/src/wg-quick.sha256,
# and this refuses to bundle any other. Review changes to wg-quick and update
# its source adaptation and helper pin together when updating wireguard-tools.
#
# Exits 2 and writes nothing when Homebrew's wireguard-go is not installed:
# the caller decides whether that is fatal.

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
        echo "error: $url does not match its pinned SHA-256" >&2
        exit 1
    fi
    mv "$file.part" "$file"
}

brew_bin() {
    local name="$1" dir
    for dir in /opt/homebrew/bin /usr/local/bin; do
        if [ -x "$dir/$name" ]; then
            printf '%s\n' "$dir/$name"
            return 0
        fi
    done
    return 1
}

if ! wireguard_go="$(brew_bin wireguard-go)"; then
    echo "note: Homebrew's wireguard-go is not installed; no VPN runtime." >&2
    exit 2
fi
go_keg="$(dirname "$(dirname "$(realpath "$wireguard_go")")")"

# Homebrew's wg can be built for a newer OS than the app supports. Build the
# small C client from source instead, keeping the exact reviewed script pin.
WG_REVISION=49ce333da02056ae7b22ee2aeb6afe8aaed79b19
WG_SHA256=2b901ba5c3957b7bb310e1c6b7ced1cc3fc9c8f6d58d59bcbdbeebd053232ef0
WG_URL="https://codeload.github.com/WireGuard/wireguard-tools/tar.gz/$WG_REVISION"
wg_source="$cache/wireguard-tools-$WG_REVISION"
wg_stamp="$WG_SHA256 $(uname -m) $(xcrun --show-sdk-path) $(xcrun clang --version) macOS14.0"
if [ ! -x "$wg_source/src/wg" ] || [ "$(cat "$wg_source/.stamp" 2>/dev/null)" != "$wg_stamp" ]; then
    mkdir -p "$cache"
    fetch "$WG_URL" "$WG_SHA256" "$cache/wireguard-tools-$WG_REVISION.tar.gz"
    rm -rf "$wg_source"
    mkdir -p "$wg_source"
    tar -xzf "$cache/wireguard-tools-$WG_REVISION.tar.gz" -C "$wg_source" --strip-components 1
    env CC="$(xcrun --find clang)" SDKROOT="$(xcrun --show-sdk-path)" \
        MACOSX_DEPLOYMENT_TARGET=14.0 CFLAGS="-O2 -mmacosx-version-min=14.0" \
        LDFLAGS="-mmacosx-version-min=14.0" \
        make -C "$wg_source/src" -j"$(sysctl -n hw.ncpu)" wg \
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
    "$wg_source/src/wg" "$wireguard_go"
if otool -L "$wg_source/src/wg" | tail -n +2 | grep -vE '^[[:space:]]+/(usr/lib|System/Library)/' >&2; then
    echo "error: wg loads libraries outside the system" >&2
    exit 1
fi

# bash, built once per source and configuration, then reused.
stamp="$BASH_SHA256 ${BASH_PATCHES[*]} ${BASH_CONFIGURE[*]} macOS14.0 $(uname -m) $(xcrun --show-sdk-path) $(xcrun clang --version)"
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
        make -j"$(sysctl -n hw.ncpu)" bash >make.log 2>&1 \
            || { tail -40 make.log >&2; exit 1; }
    )
    printf '%s\n' "$stamp" >"$built/.stamp"
fi

# A root helper must not load libraries from a prefix the user can write.
if otool -L "$built/bash" | tail -n +2 | grep -vE '^[[:space:]]+/(usr/lib|System/Library)/' >&2; then
    echo "error: the built bash loads the libraries above from outside the system" >&2
    exit 1
fi
python3 "$repo/contrib/openvpn3/check_deployment.py" --maximum 14.0 "$built/bash"

mkdir -p "$out/licenses"
install -m 0755 "$built/bash" "$out/bash"
install -m 0755 "$wg_source/src/wg" "$out/wg"
install -m 0755 "$wg_source/wg-quick" "$out/wg-quick"
install -m 0755 "$go_keg/bin/wireguard-go" "$out/wireguard-go"

install -m 0644 "$built/COPYING" "$out/licenses/bash.COPYING"
install -m 0644 "$wg_source/COPYING" "$out/licenses/wireguard-tools.COPYING"
install -m 0644 "$go_keg/LICENSE" "$out/licenses/wireguard-go.LICENSE"
cat >"$out/licenses/SOURCES" <<EOF
The programs in vpn-runtime, and where their source is:

bash          GNU bash 5.3 with its official patches up to $(printf 'bash53-%03d' "${#BASH_PATCHES[@]}"):
                $BASH_URL
                $BASH_PATCH_URL
              built by scripts/build-vpn-runtime.sh in
              https://github.com/franzjeger/SuperManager, which pins their
              SHA-256 digests and the options bash is configured with
wg, wg-quick  wireguard-tools v1.0.20260223, commit $WG_REVISION:
              $WG_URL
              archive SHA-256: $WG_SHA256
              wg built for macOS 14.0; wg-quick includes the existing
              /opt/homebrew/etc/wireguard search path and matches the helper pin
              https://git.zx2c4.com/wireguard-tools
wireguard-go  wireguard-go $(basename "$go_keg"), as Homebrew builds it:
              https://git.zx2c4.com/wireguard-go
EOF

# Azure VPN must have a protected OpenVPN 3 as well. Keeping this in the
# normal bundle build prevents a release from requiring a runtime it omits.
"$repo/scripts/build-openvpn3-runtime.sh" "$out"

# IKEv2 must ship with Release too. A Homebrew strongSwan executable loads
# user-writable dylibs/plugins; build monolithically and link OpenSSL statically
# from the macOS 14.0 static dependency prefix.
ss_url=https://download.strongswan.org/strongswan-6.0.7.tar.bz2
ss_sha=e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55
ss="$cache/strongswan-build"
ssl="$("$repo/contrib/openvpn3/build_dependencies.sh" "${SUPERMANAGER_OPENVPN3_CACHE_DIR:-$repo/target/openvpn3-runtime}/dependencies")"
prefix=/Library/PrivilegedHelperTools/SuperManagerVPN
ss_options=(--prefix="$prefix" --sysconfdir="$prefix/etc" --with-piddir=/var/run
    --disable-defaults --enable-static --disable-shared --enable-monolithic
    --enable-ikev2 --enable-charon --enable-swanctl --enable-vici --enable-openssl
    --enable-random --enable-nonce --enable-x509 --enable-pubkey --enable-pem
    --enable-pkcs1 --enable-kernel-pfroute --enable-kernel-pfkey --enable-socket-default
    --enable-eap-identity --enable-eap-mschapv2 --enable-md4 --enable-des)
ss_stamp="$ss_sha ${ss_options[*]} macOS14.0 $(uname -m) $(shasum -a 256 "$ssl/lib/libcrypto.a")"
if [ ! -x "$ss/src/swanctl/swanctl" ] || [ "$(cat "$ss/.stamp" 2>/dev/null)" != "$ss_stamp" ]; then
    fetch "$ss_url" "$ss_sha" "$cache/strongswan.tar.bz2"
    rm -rf "$ss"
    mkdir -p "$ss"
    tar -xjf "$cache/strongswan.tar.bz2" -C "$ss" --strip-components 1
    (
        cd "$ss"
        env MACOSX_DEPLOYMENT_TARGET=14.0 \
            CPPFLAGS="-I$ssl/include" \
            CFLAGS="-O2 -mmacosx-version-min=14.0" \
            LDFLAGS="-L$ssl/lib -mmacosx-version-min=14.0" \
            ./configure "${ss_options[@]}" >configure.log 2>&1 \
            || { tail -40 configure.log >&2; exit 1; }
        make -j"$(sysctl -n hw.ncpu)" >make.log 2>&1 \
            || { tail -40 make.log >&2; exit 1; }
    )
    printf '%s\n' "$ss_stamp" >"$ss/.stamp"
fi
python3 "$repo/contrib/openvpn3/check_deployment.py" --maximum 14.0 \
    "$ss/src/charon/charon" "$ss/src/swanctl/swanctl"
for entry in charon swanctl; do
    binary="$ss/src/$entry/$entry"
    if otool -L "$binary" | tail -n +2 | grep -vE '^[[:space:]]+/(usr/lib|System/Library)/' >&2; then
        echo "error: $entry loads non-system libraries" >&2
        exit 1
    fi
    install -m 0755 "$binary" "$out/$entry"
done
install -m 0644 "$ss/COPYING" "$out/licenses/strongswan.COPYING"
printf '\nstrongSwan 6.0.7: %s (SHA-256 %s); static OpenSSL: %s\n' \
    "$ss_url" "$ss_sha" "$ss_stamp" >>"$out/licenses/SOURCES"
