#!/usr/bin/env bash
# One-command install of SuperManager on Linux, dependencies included.
#
#   ./scripts/install-linux.sh
#
# Replaces a page of README copy-paste: a distro-specific package line,
# a build invocation that has to name its crates, ten `sudo install`
# lines, and two systemctl calls. Everything here is what that page
# said to do, in the order it said to do it.
#
# What it does:
#   1. Installs build + runtime dependencies with your package manager,
#      in one invocation.
#   2. Verifies the libraries the build actually needs are present,
#      rather than trusting that the package names were right.
#   3. Builds supermgrd, supermgr, and supermgr-mcp.
#   4. Installs the binaries, systemd unit, D-Bus policy + activation,
#      polkit policy, desktop entry, icon, and man pages.
#   5. Enables and starts the daemon.
#
# Run it as yourself, not with sudo: the build belongs to you, and a
# root-owned target/ directory is a nuisance to clean up afterwards. The
# steps that need root ask for it individually.
#
#   --yes, -y        Don't ask before installing packages.
#   --no-deps        Skip step 1 — you manage the dependencies yourself.
#   --no-build       Skip step 3 — install what is already built. Looks in
#                    cargo's target directory, so CARGO_TARGET_DIR is honoured
#                    (needed on checkouts that cannot build in-tree — see the
#                    exec-bit note in the README).
#   --print-deps     Print the detected distro and the packages that would
#                    be installed, then stop. Changes nothing.
#   --uninstall      Remove everything this script installs, then stop.
#   --help, -h       This text.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ASSUME_YES=0
DO_DEPS=1
DO_BUILD=1
DO_UNINSTALL=0
PRINT_DEPS=0

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)     ASSUME_YES=1 ;;
        --no-deps)    DO_DEPS=0 ;;
        --no-build)   DO_BUILD=0 ;;
        --print-deps) PRINT_DEPS=1 ;;
        --uninstall)  DO_UNINSTALL=1 ;;
        -h|--help)    sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Where cargo puts the binaries.
#
# NOT hardcoded to `target/`. A checkout on a filesystem that cannot hold the
# exec bit — a OneDrive/Dropbox FUSE mount, exFAT/NTFS, some network shares —
# cannot build in-tree at all: cargo writes build-script binaries without +x
# and then cannot execute them ("Permission denied (os error 13)"). The fix,
# documented under "Checkouts on filesystems that don't preserve the exec bit"
# in the README, is to point CARGO_TARGET_DIR at a native filesystem. Before
# this, doing that left the installer looking in the wrong place: the build
# succeeded and then step 3's own check died on a missing
# `target/release/supermgrd`. Honour the setting instead of fighting it.
#
# `cargo metadata` is asked rather than reading CARGO_TARGET_DIR directly,
# because that variable is only one of three ways to move the directory —
# CARGO_BUILD_TARGET_DIR and `build.target-dir` in .cargo/config.toml do the
# same thing, and cargo is the only thing that knows which one won. It costs
# ~20ms and needs no network.
#
# The fallback chain matters for the `--no-build` path, which is allowed to run
# without a usable cargo: env var first, then plain `target`.
# ---------------------------------------------------------------------------
BUILD_DIR=""
if command -v cargo >/dev/null 2>&1; then
    BUILD_DIR=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
fi
[ -n "$BUILD_DIR" ] || BUILD_DIR="${CARGO_TARGET_DIR:-${CARGO_BUILD_TARGET_DIR:-target}}"

# ---------------------------------------------------------------------------
# What gets installed where.
#
# One table, used by both the install and the uninstall path, so the two
# cannot drift — an uninstall that misses a file is how a stale D-Bus
# policy outlives the package that shipped it.
# ---------------------------------------------------------------------------

# <source>|<destination>|<mode>
FILES=(
    "$BUILD_DIR/release/supermgrd|/usr/bin/supermgrd|755"
    "$BUILD_DIR/release/supermgr|/usr/bin/supermgr|755"
    "$BUILD_DIR/release/supermgr-mcp|/usr/bin/supermgr-mcp|755"
    "contrib/systemd/supermgrd.service|/etc/systemd/system/supermgrd.service|644"
    "contrib/modules-load.d/supermgr.conf|/etc/modules-load.d/supermgr.conf|644"
    "contrib/dbus/org.supermgr.Daemon.conf|/usr/share/dbus-1/system.d/org.supermgr.Daemon.conf|644"
    "contrib/dbus/org.supermgr.Daemon.service|/usr/share/dbus-1/system-services/org.supermgr.Daemon.service|644"
    "contrib/polkit/org.supermgr.Daemon.policy|/usr/share/polkit-1/actions/org.supermgr.Daemon.policy|644"
    "contrib/desktop/org.supermgr.SuperManager.desktop|/usr/share/applications/org.supermgr.SuperManager.desktop|644"
    "contrib/icons/org.supermgr.SuperManager.svg|/usr/share/icons/hicolor/scalable/apps/org.supermgr.SuperManager.svg|644"
    "contrib/icons/hicolor/16.png|/usr/share/icons/hicolor/16x16/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/24.png|/usr/share/icons/hicolor/24x24/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/32.png|/usr/share/icons/hicolor/32x32/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/48.png|/usr/share/icons/hicolor/48x48/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/64.png|/usr/share/icons/hicolor/64x64/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/128.png|/usr/share/icons/hicolor/128x128/apps/org.supermgr.SuperManager.png|644"
    "contrib/icons/hicolor/256.png|/usr/share/icons/hicolor/256x256/apps/org.supermgr.SuperManager.png|644"
    "contrib/man/supermgr.1|/usr/share/man/man1/supermgr.1|644"
    "contrib/man/supermgrd.8|/usr/share/man/man8/supermgrd.8|644"
)

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

if [ "$DO_UNINSTALL" = 1 ]; then
    say "Removing SuperManager"
    if systemctl list-unit-files supermgrd.service >/dev/null 2>&1; then
        sudo systemctl disable --now supermgrd.service 2>/dev/null || true
    fi
    for entry in "${FILES[@]}"; do
        dest="${entry#*|}"; dest="${dest%|*}"
        [ -e "$dest" ] && { sudo rm -f "$dest"; note "removed $dest"; }
    done
    sudo systemctl daemon-reload
    note ""
    note "Left in place, because they are yours and not ours to delete:"
    note "  /etc/supermgrd    profiles, hosts, keys, and the secret store"
    note "  /var/log/supermgrd"
    note "Remove them by hand if you are done with SuperManager entirely."
    exit 0
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

# Skipped for --print-deps, which touches nothing and should answer
# "what would this install" from anywhere, including a machine that is
# not the one being installed onto.
if [ "$PRINT_DEPS" != 1 ]; then
    [ "$(id -u)" != 0 ] || die "run this as your normal user, not root — it calls sudo where it needs to.
       Building as root leaves a root-owned target/ directory behind."

    command -v sudo >/dev/null || die "sudo not found — this needs it to install system files"
    command -v systemctl >/dev/null || die "no systemd found. SuperManager's daemon ships as a systemd unit;
       on a non-systemd distro you will need to write your own service file."

    cd "$REPO_ROOT"
    [ -f Cargo.toml ] || die "run this from a SuperManager checkout (Cargo.toml not found)"
fi

# ---------------------------------------------------------------------------
# Distro detection + package sets
#
# Grouped by what the packages are for, so a failure says which part of
# the install is affected rather than dumping one flat list.
# ---------------------------------------------------------------------------

. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release — unknown distribution"
FAMILY=""
for id in ${ID:-} ${ID_LIKE:-}; do
    case "$id" in
        arch|archlinux|cachyos|endeavouros|manjaro) FAMILY=arch; break ;;
        debian|ubuntu|linuxmint|pop)               FAMILY=debian; break ;;
        fedora|rhel|centos|rocky|almalinux)        FAMILY=fedora; break ;;
        opensuse*|suse|sles)                       FAMILY=suse; break ;;
    esac
done
[ -n "$FAMILY" ] || die "unrecognised distribution '${ID:-?}'.
       Install the equivalents of gtk4, libadwaita, vte4, openssl, dbus and
       glib development packages plus wireguard-tools, strongswan, openvpn,
       nftables, sshpass and polkit, then re-run with --no-deps."

case "$FAMILY" in
arch)
    INSTALL_CMD=(sudo pacman -S --needed --noconfirm)
    PKGS_RUST=(rust)
    PKGS_BUILD=(pkgconf gcc git)
    PKGS_GUI=(gtk4 libadwaita vte4 openssl)
    # polkit is not optional: the daemon's credential-reading methods
    # fail closed without it, so a missing polkit looks like a broken
    # install rather than a security posture.
    PKGS_CORE=(polkit openssh sshpass nftables)
    PKGS_VPN=(wireguard-tools strongswan openvpn)
    PKGS_OPTIONAL=(freerdp remmina networkmanager)
    ;;
debian)
    INSTALL_CMD=(sudo apt-get install -y)
    PKGS_RUST=(rustc cargo)
    PKGS_BUILD=(build-essential pkg-config)
    PKGS_GUI=(libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev libssl-dev libdbus-1-dev libglib2.0-dev)
    PKGS_CORE=(polkitd openssh-client sshpass nftables)
    PKGS_VPN=(wireguard-tools strongswan strongswan-swanctl openvpn)
    PKGS_OPTIONAL=(freerdp3-x11 remmina network-manager)
    ;;
fedora)
    INSTALL_CMD=(sudo dnf install -y)
    PKGS_RUST=(rust cargo)
    PKGS_BUILD=(gcc pkg-config)
    PKGS_GUI=(gtk4-devel libadwaita-devel vte291-gtk4-devel openssl-devel dbus-devel glib2-devel)
    PKGS_CORE=(polkit openssh-clients sshpass nftables)
    PKGS_VPN=(wireguard-tools strongswan openvpn)
    PKGS_OPTIONAL=(freerdp remmina NetworkManager)
    ;;
suse)
    INSTALL_CMD=(sudo zypper install -y)
    PKGS_RUST=(rust cargo)
    PKGS_BUILD=(gcc pkg-config)
    PKGS_GUI=(gtk4-devel libadwaita-devel vte-devel libopenssl-devel dbus-1-devel glib2-devel)
    PKGS_CORE=(polkit openssh sshpass nftables)
    PKGS_VPN=(wireguard-tools strongswan openvpn)
    PKGS_OPTIONAL=(freerdp remmina NetworkManager)
    ;;
esac

# ---------------------------------------------------------------------------
# Rust may already be managed outside the package manager.
#
# rustup is the usual case, and on Arch the `rust` package actively
# conflicts with it — pacman offers to remove rustup to make room, which
# would take the user's whole toolchain setup with it. That is not a trade
# an installer gets to make on somebody's behalf, and it is not needed:
# any working cargo builds this just as well.
#
# Checked by running `cargo --version`, not by looking for the binary. A
# rustup shim exists on PATH even when no toolchain is installed behind
# it, and reports the difference only when run.
# ---------------------------------------------------------------------------

RUST_NOTE=""
if CARGO_VERSION="$(cargo --version 2>/dev/null)"; then
    RUST_NOTE="already installed: $CARGO_VERSION"
    PKGS_RUST=()
fi

if [ "$PRINT_DEPS" = 1 ]; then
    printf 'distribution   %s (%s family)\n' "${PRETTY_NAME:-$ID}" "$FAMILY"
    printf 'installs with  %s\n\n' "${INSTALL_CMD[*]}"
    printf 'rust           %s\n' "${RUST_NOTE:-${PKGS_RUST[*]}}"
    printf 'build          %s\n' "${PKGS_BUILD[*]}"
    printf 'gui            %s\n' "${PKGS_GUI[*]}"
    printf 'core           %s\n' "${PKGS_CORE[*]}"
    printf 'vpn            %s\n' "${PKGS_VPN[*]}"
    printf 'optional       %s\n' "${PKGS_OPTIONAL[*]}"
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Dependencies
# ---------------------------------------------------------------------------

if [ "$DO_DEPS" = 1 ]; then
    REQUIRED=(
        ${PKGS_RUST[@]+"${PKGS_RUST[@]}"}
        "${PKGS_BUILD[@]}" "${PKGS_GUI[@]}" "${PKGS_CORE[@]}" "${PKGS_VPN[@]}"
    )

    say "Installing dependencies (${#REQUIRED[@]} packages, $FAMILY)"
    note "${REQUIRED[*]}"
    [ -z "$RUST_NOTE" ] || note "Rust $RUST_NOTE — leaving your toolchain alone"
    if [ "$ASSUME_YES" != 1 ]; then
        printf '\n  Proceed? [Y/n] '
        read -r reply </dev/tty || reply=y
        case "$reply" in [nN]*) die "cancelled" ;; esac
    fi

    if [ "$FAMILY" = debian ]; then
        sudo apt-get update
    fi

    # One invocation is the whole point. When it fails it is almost
    # always a single package that is renamed between distro releases
    # (policykit-1 -> polkitd, freerdp2 -> freerdp3) or that conflicts
    # with something already installed, and it takes the other thirty
    # down with it — so fall back to one-at-a-time rather than printing
    # the package manager's error and giving up.
    if ! "${INSTALL_CMD[@]}" "${REQUIRED[@]}"; then
        warn "the combined install failed — retrying package by package"
        FAILED=()
        CONFLICTED=()
        for pkg in "${REQUIRED[@]}"; do
            if ! out="$("${INSTALL_CMD[@]}" "$pkg" 2>&1)"; then
                # A conflict means something else on the system already
                # provides this, and resolving it would mean removing that
                # something. Reporting it as "not available" would be a
                # lie, and acting on it uninvited would be worse.
                if printf '%s' "$out" | grep -qi conflict; then
                    CONFLICTED+=("$pkg")
                else
                    FAILED+=("$pkg")
                fi
            fi
        done
        if [ ${#CONFLICTED[@]} -gt 0 ]; then
            warn "left alone because they conflict with something you already have:"
            warn "  ${CONFLICTED[*]}"
            warn "whatever provides them is presumably doing the job; the check below"
            warn "will say if it isn't."
        fi
        if [ ${#FAILED[@]} -gt 0 ]; then
            warn "not available under these names: ${FAILED[*]}"
            warn "your distro version may call them something else; the check below"
            warn "will tell you whether the build can proceed regardless."
        fi
    fi

    # Best-effort: RDP/VNC clients and NetworkManager integration. Named
    # separately and never fatal, because SuperManager works without
    # them — they light up buttons rather than carry features.
    say "Optional integrations (RDP/VNC clients, NetworkManager)"
    for pkg in "${PKGS_OPTIONAL[@]}"; do
        if "${INSTALL_CMD[@]}" "$pkg" >/dev/null 2>&1; then
            note "installed $pkg"
        else
            note "skipped $pkg (not available — the related buttons stay hidden)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# 2. Verify what the build actually needs
#
# Package names drift between distro releases; pkg-config asks the
# question that matters. Catching it here turns a wall of C linker errors
# ten minutes into a build into one line before the build starts.
# ---------------------------------------------------------------------------

say "Checking build prerequisites"
command -v cargo >/dev/null || die "cargo not found. Install Rust via your package manager or https://rustup.rs"

MISSING_LIBS=()
if command -v pkg-config >/dev/null; then
    for lib in gtk4 libadwaita-1 vte-2.91-gtk4 openssl dbus-1 glib-2.0; do
        pkg-config --exists "$lib" 2>/dev/null || MISSING_LIBS+=("$lib")
    done
else
    warn "pkg-config not found — skipping the library check; the build will tell you"
fi

if [ ${#MISSING_LIBS[@]} -gt 0 ]; then
    die "development libraries missing: ${MISSING_LIBS[*]}
       The GUI cannot build without them. Install your distro's -dev/-devel
       packages for those, then re-run. (Re-running with --no-deps skips
       straight to the build once you have.)"
fi
note "cargo $(cargo --version | awk '{print $2}'), all GUI libraries present"

# ---------------------------------------------------------------------------
# 3. Build
#
# The crates are named explicitly. A bare `cargo build` honours
# `default-members`, which is only the two crates that build on every
# platform — it produces neither supermgrd nor supermgr, and the install
# step below would then fail on a missing file.
# ---------------------------------------------------------------------------

if [ "$DO_BUILD" = 1 ]; then
    say "Building (this takes a few minutes the first time)"
    cargo build --release -p supermgrd -p supermgr -p supermgr-mcp
fi

for entry in "${FILES[@]}"; do
    src="${entry%%|*}"
    case "$src" in
        # `$BUILD_DIR` quoted so a path with glob characters in it stays
        # literal; only the trailing `*` is meant as a pattern.
        "$BUILD_DIR"/release/*)
            [ -f "$src" ] || die "$src not found. Drop --no-build, or build with:
       cargo build --release -p supermgrd -p supermgr -p supermgr-mcp

       Binaries are expected under $BUILD_DIR — set CARGO_TARGET_DIR to
       change that, and build with the same setting." ;;
    esac
done

# ---------------------------------------------------------------------------
# Can root read this checkout at all?
#
# Every install below is `sudo install`, i.e. root reading a file out of the
# working tree. A FUSE mount — OneDrive, Dropbox, sshfs, rclone — is private to
# the user who mounted it unless it was given `allow_other`, so root cannot see
# into it no matter what the file modes say. Without this check the run gets as
# far as `→ Installing`, puts the three binaries in /usr/bin (they come from
# cargo's target directory, which is usually elsewhere), and then dies on the
# first contrib file with a bare "install: cannot stat ...: Permission denied"
# — a half-installed system and an error that names the symptom, not the cause.
#
# Asked as a real `sudo test -r` rather than by parsing mount options, because
# the only question that matters is whether root can read the file.
# ---------------------------------------------------------------------------
readable_probe="contrib/systemd/supermgrd.service"
if ! sudo test -r "$readable_probe"; then
    die "root cannot read $readable_probe in this checkout.

       Almost always a FUSE mount without \`allow_other\` — OneDrive, Dropbox,
       sshfs. The files are fine; root simply cannot see into the mount, and
       every step below is \`sudo install\` reading from here.

       Work from a checkout on a normal filesystem:

           git clone https://github.com/franzjeger/SuperManager ~/SuperManager
           cd ~/SuperManager && ./scripts/install-linux.sh

       (The same mount is why in-tree builds fail with \"Permission denied
       (os error 13)\" — see the exec-bit note in the README.)"
fi

# ---------------------------------------------------------------------------
# 4. Install
# ---------------------------------------------------------------------------

say "Installing"
for entry in "${FILES[@]}"; do
    src="${entry%%|*}"
    rest="${entry#*|}"
    dest="${rest%|*}"
    mode="${rest##*|}"
    sudo install -Dm"$mode" "$src" "$dest"
    note "$dest"
done

# The daemon reads its config from here and creates it on first run, but
# creating it now with the right mode means the first run never has to
# widen it.
sudo install -dm750 /etc/supermgrd

if command -v update-desktop-database >/dev/null; then
    sudo update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
    sudo gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
fi
# Plasma keeps its own cache of desktop entries and icons, and it is per-user
# rather than system-wide — so this one runs as you, not under sudo. Without
# it the task manager and the system tray keep showing whatever icon they saw
# first, which makes a corrected icon look like it did not install.
for sycoca in kbuildsycoca6 kbuildsycoca5; do
    if command -v "$sycoca" >/dev/null; then
        "$sycoca" >/dev/null 2>&1 || true
        break
    fi
done

# ---------------------------------------------------------------------------
# 5. Start the daemon
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Kernel modules
#
# The file installed above handles every boot after this one. This handles
# the first one, so the first VPN connect does not fail on a module that is
# on disk but not loaded — which surfaces as EOPNOTSUPP from netlink and
# reads like the kernel has no WireGuard support at all.
#
# The daemon cannot do this itself: its bounding set has no CAP_SYS_MODULE,
# and giving a VPN manager the ability to load kernel modules to save an
# install step is not a trade worth making.
# ---------------------------------------------------------------------------

say "Kernel modules"

# Before blaming any individual module: if the running kernel has no module
# tree at all, every modprobe below fails for one reason and the remedy is a
# reboot, not a kernel rebuild. On a rolling distribution this is the common
# case — an update replaces /lib/modules and deletes the running kernel's,
# so `modprobe wireguard` says "not found in directory /lib/modules/<running>"
# on a kernel that was built with CONFIG_WIREGUARD=m all along.
RUNNING_KERNEL="$(uname -r)"
if [ ! -d "/lib/modules/$RUNNING_KERNEL" ]; then
    warn "no /lib/modules/$RUNNING_KERNEL — the running kernel has no modules to load."
    OTHER=""
    for d in /lib/modules/*/; do
        d="${d%/}"; d="${d##*/}"
        [ "$d" = "$RUNNING_KERNEL" ] || [ "$d" = "*" ] || OTHER="$d"
    done
    if [ -n "$OTHER" ]; then
        warn "  $OTHER is installed instead: the kernel was updated and not rebooted into."
        warn "  Reboot, then re-run this script. Nothing below can succeed until you do."
    else
        warn "  and nothing else is installed either. Reinstall your kernel package."
    fi
else
    for mod in wireguard tun nf_tables; do
        if [ -d "/sys/module/$mod" ]; then
            note "$mod already loaded"
        elif sudo modprobe "$mod" 2>/dev/null; then
            note "loaded $mod"
        else
            case "$mod" in
                wireguard)
                    warn "cannot load $mod — WireGuard profiles will not connect"
                    warn "  a stock kernel has had it since 5.6; a custom one may not"
                    ;;
                tun)       warn "cannot load $mod — OpenVPN and Azure VPN will not connect" ;;
                nf_tables) warn "cannot load $mod — the kill switch cannot block traffic" ;;
            esac
            warn "  sudo modprobe $mod   # for the actual reason"
        fi
    done
fi

say "Starting the daemon"
sudo systemctl daemon-reload
# Reloading D-Bus picks up the new system.d policy without a reboot;
# without it the GUI's first connection is refused by the bus.
sudo systemctl reload dbus 2>/dev/null || sudo systemctl reload messagebus 2>/dev/null || true

# strongswan is only needed for IKEv2/FortiGate IPsec profiles, so a
# failure to enable it is not a failure to install SuperManager.
if systemctl list-unit-files 2>/dev/null | grep -qE '^strongswan(-starter)?\.service'; then
    sudo systemctl enable --now strongswan 2>/dev/null \
        || sudo systemctl enable --now strongswan-starter 2>/dev/null \
        || warn "could not start strongswan — IKEv2 profiles will not connect until it runs"
fi

sudo systemctl enable --now supermgrd

if systemctl is-active --quiet supermgrd; then
    note "supermgrd is running"
else
    warn "supermgrd did not start. Logs:  sudo journalctl -u supermgrd -n 50"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

say "Installed"
note "Launch:      supermgr        (or find SuperManager in your app menu)"
note "Daemon:      sudo systemctl status supermgrd"
note "Logs:        sudo journalctl -u supermgrd -f"
note "Uninstall:   ./scripts/install-linux.sh --uninstall"
note ""
note "Working now: SSH, key management, network scan, compliance,"
note "             UniFi/FortiGate/OPNsense/Sophos APIs, WireGuard,"
note "             IKEv2 / FortiGate IPsec, Azure VPN."
note ""
# Said plainly because the alternative is finding out at connect time.
# `vpn::backend_for_profile` returns an error for this variant on Linux;
# the backend exists only in the Windows daemon.
note "Not on Linux: FortiGate SSL VPN. That backend is Windows-only, and a"
note "              profile of that type fails when you try to connect it."
note "              Use the FortiGate (IPsec/IKEv2) profile type instead."

# The OpenVPN backend drives the `openvpn3` CLI, not the `openvpn` binary
# installed above — so an OpenVPN profile does not work until this is
# present. Azure VPN is unaffected: that backend spawns `openvpn` itself.
if ! command -v openvpn3 >/dev/null 2>&1; then
    note ""
    note "Not installed: openvpn3. OpenVPN profiles are driven through that"
    note "               CLI, so they will not connect until it is present."
    case "$FAMILY" in
        arch)
            note "               On Arch it is in the AUR, which pacman does not"
            note "               reach:  paru -S openvpn3    (or yay, or makepkg)"
            ;;
        *)
            note "               No distribution but Arch packages it; build from"
            note "               https://github.com/OpenVPN/openvpn3-linux"
            ;;
    esac
    note "               Everything else above works without it."
fi
