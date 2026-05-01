#!/usr/bin/env bash
# Generic Linux installer for SuperManager.
#
# Installs SuperManager from source, plus its runtime dependencies, including
# openvpn3-linux which is built from source so we don't depend on
# distribution-specific repos (the project's own COPR/PPA stops at older
# releases of each distro).
#
# Steps:
#   1. Detect the package manager and install build + runtime deps for both
#      SuperManager and openvpn3-linux.
#   2. Build and install openvpn3-linux from upstream source if `openvpn3`
#      isn't already on PATH.
#   3. Build the SuperManager workspace (cargo build --release).
#   4. Install binaries, the systemd unit, the D-Bus policy/activation files,
#      the desktop entry, the icon, and the man pages.
#   5. Enable + start supermgrd.service.
#
# Tested on Fedora 44 (CachyOS-flavored), should work on any RHEL/Fedora,
# Debian/Ubuntu or Arch derivative.  On Arch, prefer `contrib/aur/PKGBUILD`.
#
# Usage:
#   sudo contrib/install.sh                   # full install
#   sudo contrib/install.sh --skip-build      # reuse existing target/release
#   sudo contrib/install.sh --skip-openvpn3   # don't touch openvpn3
#   OPENVPN3_VERSION=v27_beta sudo contrib/install.sh   # pin a tag

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

SKIP_BUILD=0
SKIP_OPENVPN3=0
for arg in "$@"; do
    case "$arg" in
        --skip-build)    SKIP_BUILD=1 ;;
        --skip-openvpn3) SKIP_OPENVPN3=1 ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done

OPENVPN3_REPO="${OPENVPN3_REPO:-https://codeberg.org/OpenVPN/openvpn3-linux.git}"
OPENVPN3_VERSION="${OPENVPN3_VERSION:-v27_beta}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
detect_pm() {
    if command -v dnf >/dev/null 2>&1;       then echo dnf
    elif command -v apt-get >/dev/null 2>&1; then echo apt
    elif command -v pacman >/dev/null 2>&1;  then echo pacman
    elif command -v zypper >/dev/null 2>&1;  then echo zypper
    else echo unknown
    fi
}

PM="$(detect_pm)"
echo "==> Package manager: $PM"

# ---------------------------------------------------------------------------
# Dependency lists, per-distro
#
# Includes: SuperManager build deps + runtime deps, plus openvpn3-linux build
# deps so the from-source build below succeeds.
# ---------------------------------------------------------------------------
declare -a PKGS

case "$PM" in
    dnf)
        PKGS=(
            # Toolchain
            rust cargo pkgconf-pkg-config git
            gcc-c++ make cmake autoconf automake libtool
            # SuperManager runtime deps
            gtk4-devel libadwaita-devel vte291-gtk4-devel openssl-devel
            sshpass wireguard-tools strongswan nftables openssh-clients
            NetworkManager dbus-daemon
            # openvpn3-linux build deps
            glib2-devel libcap-ng-devel libnl3-devel libuuid-devel
            lz4-devel jsoncpp-devel protobuf-devel protobuf-compiler
            tinyxml2-devel libxml2-devel dbus-devel
            python3-jinja2 python3-docutils
            mbedtls-devel
        )
        ;;
    apt)
        PKGS=(
            cargo rustc pkg-config git
            g++ make cmake autoconf automake libtool
            libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev libssl-dev
            sshpass wireguard-tools strongswan nftables openssh-client
            network-manager dbus
            libglib2.0-dev libcap-ng-dev libnl-3-dev libnl-genl-3-dev uuid-dev
            liblz4-dev libjsoncpp-dev libprotobuf-dev protobuf-compiler
            libtinyxml2-dev libxml2-dev libdbus-1-dev
            python3-jinja2 python3-docutils
            libmbedtls-dev
        )
        ;;
    pacman)
        # On Arch, prefer the AUR PKGBUILD (which uses the prebuilt openvpn3
        # AUR package).  This script still works as a fallback.
        PKGS=(
            rust pkgconf git gcc make cmake autoconf automake libtool
            gtk4 libadwaita vte4 openssl
            sshpass wireguard-tools strongswan nftables openssh
            networkmanager dbus
            glib2 libcap-ng libnl util-linux
            lz4 jsoncpp protobuf
            tinyxml2 libxml2
            python-jinja python-docutils
            mbedtls2
        )
        ;;
    zypper)
        PKGS=(
            cargo rust pkgconf git gcc-c++ make cmake autoconf automake libtool
            gtk4-devel libadwaita-devel vte4-devel libopenssl-devel
            sshpass wireguard-tools strongswan nftables openssh
            NetworkManager dbus-1
            glib2-devel libcap-ng-devel libnl3-devel libuuid-devel
            liblz4-devel jsoncpp-devel libprotobuf-c-devel protobuf-compiler
            tinyxml2-devel libxml2-devel dbus-1-devel
            python3-Jinja2 python3-docutils
            mbedtls-devel
        )
        ;;
    *)
        echo "error: unsupported package manager — install dependencies manually" >&2
        echo "       and re-run with --skip-openvpn3 if openvpn3 is already present" >&2
        exit 1
        ;;
esac

echo "==> Installing ${#PKGS[@]} packages via $PM"
case "$PM" in
    dnf)    dnf install -y "${PKGS[@]}" >/dev/null ;;
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS[@]}" >/dev/null ;;
    pacman) pacman -S --needed --noconfirm "${PKGS[@]}" >/dev/null ;;
    zypper) zypper -n install "${PKGS[@]}" >/dev/null ;;
esac

# ---------------------------------------------------------------------------
# openvpn3-linux from source
#
# The Azure VPN backend invokes `openvpn3 session-start`; stock openvpn 2.x
# can't negotiate against Azure VPN gateways.  The upstream project ships
# packaged builds only on a handful of distros, so build from source for
# portability.
# ---------------------------------------------------------------------------
ensure_openvpn3() {
    if [[ $SKIP_OPENVPN3 -eq 1 ]]; then
        echo "==> Skipping openvpn3 (--skip-openvpn3)"
        return
    fi
    if command -v openvpn3 >/dev/null 2>&1; then
        echo "==> openvpn3 already installed ($(openvpn3 version 2>/dev/null | head -1))"
        return
    fi

    local build_dir
    build_dir="$(mktemp -d -t openvpn3-build.XXXXXX)"
    trap "rm -rf '$build_dir'" RETURN

    echo "==> Cloning openvpn3-linux ($OPENVPN3_VERSION) into $build_dir"
    git clone --depth 1 --branch "$OPENVPN3_VERSION" --recurse-submodules \
        "$OPENVPN3_REPO" "$build_dir/openvpn3-linux"
    cd "$build_dir/openvpn3-linux"

    echo "==> Building openvpn3-linux"
    if [[ -f meson.build ]]; then
        # v27+ uses Meson.
        if ! command -v meson >/dev/null 2>&1; then
            case "$PM" in
                dnf)    dnf install -y meson ninja-build >/dev/null ;;
                apt)    apt-get install -y meson ninja-build >/dev/null ;;
                pacman) pacman -S --needed --noconfirm meson ninja >/dev/null ;;
                zypper) zypper -n install meson ninja >/dev/null ;;
            esac
        fi
        meson setup build --prefix=/usr --buildtype=release
        meson compile -C build
        meson install -C build
    else
        # Older releases use autotools.
        ./bootstrap.sh
        ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
        make -j"$(nproc)"
        make install
    fi

    cd "$REPO_ROOT"
    ldconfig

    if ! command -v openvpn3 >/dev/null 2>&1; then
        echo "error: openvpn3 build/install completed but binary still missing" >&2
        exit 1
    fi
    echo "==> Installed openvpn3 ($(openvpn3 version 2>/dev/null | head -1))"
}
ensure_openvpn3

# ---------------------------------------------------------------------------
# Build SuperManager
# ---------------------------------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "==> Building SuperManager workspace"
    BUILD_USER="${SUDO_USER:-$(id -un)}"
    if [[ "$BUILD_USER" != "root" ]]; then
        sudo -u "$BUILD_USER" cargo build --release --workspace
    else
        cargo build --release --workspace
    fi
fi

if [[ ! -x target/release/supermgrd ]]; then
    echo "error: target/release/supermgrd not found — build failed?" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Install files
# ---------------------------------------------------------------------------
echo "==> Installing files"
install -Dm755 target/release/supermgrd     /usr/bin/supermgrd
install -Dm755 target/release/supermgr      /usr/bin/supermgr
install -Dm755 target/release/supermgr-mcp  /usr/bin/supermgr-mcp

install -Dm644 contrib/systemd/supermgrd.service \
    /usr/lib/systemd/system/supermgrd.service

install -Dm644 contrib/dbus/org.supermgr.Daemon.conf \
    /usr/share/dbus-1/system.d/org.supermgr.Daemon.conf
install -Dm644 contrib/dbus/org.supermgr.Daemon.service \
    /usr/share/dbus-1/system-services/org.supermgr.Daemon.service

[[ -f contrib/desktop/org.supermgr.SuperManager.desktop ]] && \
    install -Dm644 contrib/desktop/org.supermgr.SuperManager.desktop \
        /usr/share/applications/org.supermgr.SuperManager.desktop
[[ -f contrib/icons/org.supermgr.SuperManager.svg ]] && \
    install -Dm644 contrib/icons/org.supermgr.SuperManager.svg \
        /usr/share/icons/hicolor/scalable/apps/org.supermgr.SuperManager.svg
[[ -f contrib/man/supermgr.1 ]] && \
    install -Dm644 contrib/man/supermgr.1  /usr/share/man/man1/supermgr.1
[[ -f contrib/man/supermgrd.8 ]] && \
    install -Dm644 contrib/man/supermgrd.8 /usr/share/man/man8/supermgrd.8

install -dm750 /etc/supermgrd

# ---------------------------------------------------------------------------
# `supermgr` group — see the comment in
# contrib/dbus/org.supermgr.Daemon.conf.  The system D-Bus policy denies
# `org.supermgr.Daemon` to every caller outside this group, so the desktop
# user must be a member or the GUI / supermgr-mcp can't reach the daemon.
# ---------------------------------------------------------------------------
if ! getent group supermgr >/dev/null 2>&1; then
    echo "==> Creating system group 'supermgr'"
    groupadd --system supermgr
fi

INVOKING_USER="${SUDO_USER:-}"
if [[ -n "$INVOKING_USER" && "$INVOKING_USER" != "root" ]]; then
    if ! id -nG "$INVOKING_USER" | grep -qw supermgr; then
        echo "==> Adding '$INVOKING_USER' to the supermgr group"
        usermod -aG supermgr "$INVOKING_USER"
        ADDED_USER="$INVOKING_USER"
    fi
fi

# ---------------------------------------------------------------------------
# Enable services
# ---------------------------------------------------------------------------
echo "==> Enabling services"
systemctl daemon-reload
systemctl reload dbus.service 2>/dev/null || \
    systemctl reload-or-restart dbus.socket 2>/dev/null || \
    true
systemctl enable --now strongswan.service >/dev/null 2>&1 || true
if systemctl is-active --quiet supermgrd.service; then
    systemctl restart supermgrd.service
else
    systemctl enable --now supermgrd.service
fi

cat <<EOF

SuperManager installed.

  Launch GUI:        supermgr
  Daemon status:     systemctl status supermgrd
  Daemon logs:       journalctl -u supermgrd -f

EOF

if [[ -n "${ADDED_USER:-}" ]]; then
    cat <<EOF
NOTE: Added '$ADDED_USER' to the 'supermgr' group.  Group membership only
takes effect on a fresh login session — log out and back in (or run
\`newgrp supermgr\`) before launching the GUI, otherwise D-Bus calls will
return "AccessDenied".

EOF
fi
