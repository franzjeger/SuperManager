#!/usr/bin/env bash
# One-command install of the latest SuperManager release on macOS,
# dependencies included.
#
#   curl -fsSL https://raw.githubusercontent.com/franzjeger/SuperManager/main/scripts/install.sh | bash
#
# What it does:
#   1. Installs Homebrew if it isn't there.
#   2. Installs the VPN clients SuperManager drives — wireguard-tools,
#      strongswan, openvpn — in one go, skipping any already present.
#   3. Downloads the newest signed + notarized release into /Applications
#      and launches it.
#
# SuperManager drives the real VPN clients rather than reimplementing
# them, so each VPN type needs its client installed. That used to be a
# printed list of `brew install` lines to work through by hand; it is now
# step 2.
#
#   --yes, -y          Don't ask before installing anything.
#   --no-deps          App only. You manage the VPN clients yourself.
#   --deps-only        VPN clients only, don't touch /Applications.
#   --with-openvpn3    Also build OpenVPN 3 from source (~5 min). Needed
#                      only for Azure VPN (Entra ID) and openvpn3-driven
#                      OpenVPN profiles. No Homebrew formula exists.
#   --help, -h         This text.
#
# The zip is Developer ID-signed, notarized and stapled, so Gatekeeper
# accepts it without any quarantine dance. The privileged parts — the
# root helper, the Tailscale daemon — are still installed BY THE APP with
# proper admin prompts on first use. This script never runs as root, and
# Homebrew refuses to.

# Refuse to run under anything but bash, and say how to fix it.
#
# The shebang is only consulted when a file is executed — never when a script
# arrives on stdin. So `curl … | sh` and `sh -c "$(curl …)"` run this under
# dash or zsh, where `set -u` semantics and expansion rules differ from bash
# enough to abort on lines that are perfectly correct bash.
#
# Re-execing ourselves under bash was the obvious fix and does not work:
# the interpreting shell has already read ahead on stdin, so copying "the
# script" from stdin yields whatever is left after its parse buffer — under
# zsh that is a fragment starting mid-file, which then runs. Re-downloading
# instead would work but silently substitutes a different copy than the one
# the operator piped. Stopping is the only honest option, and one clear line
# beats an "unbound variable" from a shell nobody chose.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "install.sh needs bash (it is running under ${0##*/})." >&2
    echo "Pipe it into bash instead:" >&2
    echo "  curl -fsSL https://raw.githubusercontent.com/franzjeger/SuperManager/main/scripts/install.sh | bash" >&2
    exit 1
fi

set -euo pipefail

REPO="franzjeger/SuperManager"
APP_NAME="SuperManagerMac.app"
DEST="/Applications/$APP_NAME"
RAW="https://raw.githubusercontent.com/$REPO/main"

ASSUME_YES=0
DO_DEPS=1
DO_APP=1
WITH_OPENVPN3=0

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)        ASSUME_YES=1 ;;
        --no-deps)       DO_DEPS=0 ;;
        --deps-only)     DO_APP=0 ;;
        --with-openvpn3) WITH_OPENVPN3=1 ;;
        # `${BASH_SOURCE[0]}` is unset when the script arrives on stdin, which
        # is the documented invocation — so under `set -u` the bare expansion
        # aborted with "unbound variable" instead of printing help. Guard it,
        # and when there is genuinely no file to read from, say where the text
        # lives rather than printing nothing.
        -h|--help)
            self="${BASH_SOURCE[0]:-}"
            if [ -n "$self" ] && [ -r "$self" ]; then
                sed -n '2,31p' "$self" | sed 's/^# \{0,1\}//'
            else
                echo "Options and behaviour are documented at the top of the script:"
                echo "  $RAW/scripts/install.sh"
            fi
            exit 0 ;;
        *)               echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# Prompts have to read from the terminal, not stdin: stdin is the script
# itself when this is run the documented way, through a pipe from curl.
# With no terminal at all — CI, a provisioning run — proceed rather than
# hang waiting for an answer nobody can give.
ask() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ -e /dev/tty ] || return 0
    printf '  %s [Y/n] ' "$1"
    local reply
    read -r reply </dev/tty || reply=y
    case "$reply" in [nN]*) return 1 ;; *) return 0 ;; esac
}

[ "$(uname -s)" = Darwin ] || die "this is the macOS installer. On Linux use scripts/install-linux.sh;
       on Windows use SuperManager-Setup-<version>.exe from the releases page."
[ "$(id -u)" != 0 ] || die "don't run this with sudo. Homebrew refuses to install as root,
       and nothing here needs elevation — the app asks for it itself on first launch."
command -v curl >/dev/null || die "curl not found"

# ---------------------------------------------------------------------------
# 1. Homebrew
# ---------------------------------------------------------------------------

# Not on PATH for a fresh install until the shell is re-sourced, and
# Apple Silicon and Intel put it in different places.
brew_bin() {
    if command -v brew >/dev/null 2>&1; then command -v brew
    elif [ -x /opt/homebrew/bin/brew ]; then echo /opt/homebrew/bin/brew
    elif [ -x /usr/local/bin/brew ]; then echo /usr/local/bin/brew
    fi
}

BREW=""
if [ "$DO_DEPS" = 1 ]; then
    BREW="$(brew_bin)"
    if [ -z "$BREW" ]; then
        say "Homebrew is not installed"
        note "It is how the VPN clients get installed. The installer below is"
        note "Homebrew's own, from https://brew.sh — it asks for your password"
        note "and explains what it is doing before it does it."
        if ask "Install Homebrew?"; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            BREW="$(brew_bin)"
            [ -n "$BREW" ] || die "Homebrew installed but 'brew' still isn't findable.
       Open a new terminal and re-run this script."
        else
            warn "skipping Homebrew — no VPN clients will be installed"
            DO_DEPS=0
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 2. VPN clients
#
# Worked out first and installed in one `brew install`, rather than a
# printed list to work through. Formulas already present are left alone,
# so re-running is cheap and says so.
# ---------------------------------------------------------------------------

# A tool counts as present if it is anywhere the app will look, which
# includes both Homebrew prefixes and the sbin variants — a machine that
# already has WireGuard from elsewhere does not need it from brew.
have() {
    command -v "$1" >/dev/null 2>&1 \
        || [ -x "/opt/homebrew/bin/$1" ] \
        || [ -x "/opt/homebrew/sbin/$1" ] \
        || [ -x "/usr/local/bin/$1" ] \
        || [ -x "/usr/local/sbin/$1" ]
}

if [ "$DO_DEPS" = 1 ]; then
    WANT=()
    have wg-quick || WANT+=(wireguard-tools)   # WireGuard profiles
    have swanctl  || WANT+=(strongswan)        # IKEv2 / FortiGate IPsec
    have openvpn  || WANT+=(openvpn)           # OpenVPN 2.x profiles

    if [ ${#WANT[@]} -eq 0 ]; then
        say "VPN clients already present — nothing to install"
    else
        say "Installing VPN clients: ${WANT[*]}"
        if ask "Proceed?"; then
            "$BREW" install "${WANT[@]}"
        else
            warn "skipped — profiles of those types will not connect"
        fi
    fi

    # OpenVPN 3 has no Homebrew formula, so it is a source build and
    # opt-in: several minutes, and it matters only for Azure VPN with
    # Entra ID, whose gateway rejects OpenVPN 2.x outright.
    if [ "$WITH_OPENVPN3" = 1 ]; then
        if have openvpn3; then
            say "OpenVPN 3 already installed"
        else
            say "Building OpenVPN 3 from source"
            "$BREW" install cmake asio jsoncpp openssl@3 lz4
            # Use the in-tree script when this is a checkout, otherwise
            # fetch it: the documented install path is a curl pipe, which
            # has no repository to run it from.
            # Guarded for the same reason as --help above: piped in, there is
            # no BASH_SOURCE, and the unguarded expansion aborted here under
            # `set -u` — before reaching the curl fallback three lines down
            # that exists precisely for that case. Empty resolves to `.`, the
            # path does not exist, and the fallback runs as intended.
            LOCAL_BUILD="$(dirname "${BASH_SOURCE[0]:-}")/../contrib/build-openvpn3-mac.sh"
            if [ -f "$LOCAL_BUILD" ]; then
                bash "$LOCAL_BUILD"
            else
                curl -fsSL "$RAW/contrib/build-openvpn3-mac.sh" | bash
            fi
        fi
    fi
fi

if [ "$DO_APP" = 0 ]; then
    say "Dependencies done — leaving /Applications alone, as asked"
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. The app
# ---------------------------------------------------------------------------

# First of two dry-run stop points, and the only one CI can gate on.
#
# Everything above this line is offline: the bash-only guard, the platform and
# root checks, and expansion behaviour under `set -u`. Everything below reaches
# api.github.com unauthenticated, which is rate limited per source IP — and CI
# runners share IPs. Gating on the network call made the mac job fail on the
# third pull request of the day for reasons that had nothing to do with the
# change under test.
#
# So `guards` stops here and is a real gate; `1` (or anything else) continues
# through the release lookup and is useful to a human, and advisory in CI.
if [ "${SUPERMGR_INSTALL_DRY_RUN:-}" = guards ]; then
    say "Dry run (guards): interpreter, platform and privilege checks passed."
    exit 0
fi

# Newest release tag that actually carries a Mac zip. Releases are shared
# with Windows, so "latest" alone is not enough — v1.4.0 was
# Windows-only. The API returns releases newest-first; take the first
# SuperManager-<version>.zip we see.
say "Looking up the newest Mac release of $REPO"
ZIP_URL="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=15" \
    | grep -o '"browser_download_url": *"[^"]*SuperManager-[0-9][^"]*\.zip"' \
    | grep -v notarize \
    | head -1 \
    | sed 's/.*"\(https[^"]*\)"/\1/')"

if [ -z "$ZIP_URL" ]; then
    die "no release with a Mac zip found.
       (Releases are shared with Windows; a Mac build may not have shipped
        yet. See https://github.com/$REPO/releases)"
fi
note "$ZIP_URL"

# Stop here when asked. Everything above this line is the part CI can
# exercise for real: the bash-only guard, expansion behaviour under `set -u`,
# and the release lookup — a curl|grep|grep|head|sed pipeline that breaks
# silently if GitHub changes its response shape or no Mac zip has shipped. The
# operator never finds out until an install fails in front of them.
#
# Everything below downloads a zip and replaces /Applications, which CI has no
# business doing. This is the honest boundary between the two.
if [ -n "${SUPERMGR_INSTALL_DRY_RUN:-}" ]; then
    say "Dry run: release lookup succeeded, stopping before download."
    exit 0
fi

TMP="$(mktemp -d /tmp/supermgr-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

say "Downloading"
curl -fL --progress-bar -o "$TMP/app.zip" "$ZIP_URL"

say "Unpacking"
ditto -x -k "$TMP/app.zip" "$TMP/unpacked"
[ -d "$TMP/unpacked/$APP_NAME" ] || die "zip did not contain $APP_NAME"

if [ -d "$DEST" ]; then
    note "replacing the existing $DEST"
    # Quit a running copy so the swap is clean; ignore if not running.
    osascript -e 'quit app "SuperManagerMac"' >/dev/null 2>&1 || true
    sleep 2
    rm -rf "$DEST"
fi

ditto "$TMP/unpacked/$APP_NAME" "$DEST"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

say "Installed to $DEST"
note "Working now: SSH, key management, network scan, compliance,"
note "             UniFi/FortiGate/OPNsense/Sophos APIs."
note "Tailscale needs nothing — tailscaled is bundled and installed on first use."
note "The app asks for admin rights once, to install its privileged helper."

if [ "$DO_DEPS" = 1 ]; then
    STILL_MISSING=""
    have wg-quick || STILL_MISSING="$STILL_MISSING\n  WireGuard                brew install wireguard-tools"
    have swanctl  || STILL_MISSING="$STILL_MISSING\n  IKEv2 / FortiGate IPsec  brew install strongswan"
    have openvpn  || STILL_MISSING="$STILL_MISSING\n  OpenVPN 2.x              brew install openvpn"
    if [ -n "$STILL_MISSING" ]; then
        echo
        warn "these did not install — those profile types will not connect:"
        printf '%b\n' "$STILL_MISSING"
    fi
    if [ "$WITH_OPENVPN3" != 1 ] && ! have openvpn3; then
        note ""
        note "OpenVPN 3 not installed. Needed only for Azure VPN (Entra ID),"
        note "whose gateway rejects OpenVPN 2.x. Add it later with:"
        note "  curl -fsSL $RAW/scripts/install.sh | bash -s -- --deps-only --with-openvpn3"
    fi
fi

open "$DEST"
