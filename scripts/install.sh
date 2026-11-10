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
#   --with-openvpn3    Build and install protected OpenVPN 3 (~5 min).
#                      Repair for app versions without it, including
#                      1.8.25. New builds bundle it for Azure VPN (Entra ID).
#   --help, -h         This text.
#
# The zip is Developer ID-signed, notarized and stapled, so Gatekeeper
# accepts it without any quarantine dance. The privileged parts — the
# root helper, the Tailscale daemon — are still installed BY THE APP with
# proper admin prompts on first use. An explicit --with-openvpn3 repair
# asks for sudo after building. This script never runs as root.

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
       and privileged installation asks for elevation separately."
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

    # An explicit source-build repair for app versions without the runtime.
    # New builds bundle OpenVPN 3 and install it through the helper.
    if [ "$WITH_OPENVPN3" = 1 ]; then
        # A Homebrew executable alone is unusable by the Release helper.
        # Explicitly requested repairs rebuild the managed runtime even
        # when the old unprivileged openvpn3 is still on PATH.
        say "Building the protected OpenVPN 3 runtime"
        "$BREW" install cmake
        # Use the in-tree script when this is a checkout, otherwise
        # fetch it: the documented install path is a curl pipe, which
        # has no repository to run it from.
        # A piped installer has no source path. Never look for a builder
        # relative to the caller's working directory in that case.
        LOCAL_BUILD=""
        installer_source="${BASH_SOURCE[0]:-}"
        if [ -n "$installer_source" ]; then
            installer_dir="$(cd "$(dirname "$installer_source")" && pwd)"
            LOCAL_BUILD="$installer_dir/../contrib/build-openvpn3-mac.sh"
        fi
        if [ -n "$LOCAL_BUILD" ] && [ -f "$LOCAL_BUILD" ]; then
            bash "$LOCAL_BUILD"
        else
            # The builder includes pinned source and adapter files. Fetch
            # a complete checkout before executing it, including when
            # this installer itself arrived through a pipe.
            openvpn3_checkout="$(mktemp -d "${TMPDIR:-/tmp}/supermanager-openvpn3-source.XXXXXX")"
            if ! (
                trap 'rm -rf "$openvpn3_checkout"' EXIT
                curl -fsSL --proto '=https' --tlsv1.2 \
                    "https://api.github.com/repos/$REPO/tarball/main" \
                    -o "$openvpn3_checkout/source.tar.gz" || exit 1
                tar -xzf "$openvpn3_checkout/source.tar.gz" -C "$openvpn3_checkout" --strip-components 1 || exit 1
                bash "$openvpn3_checkout/contrib/build-openvpn3-mac.sh"
            ); then
                die "OpenVPN 3 runtime installation failed"
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

# Verify Apple Developer ID signature before installing into /Applications
# because `curl` does not attach `com.apple.quarantine` (so Gatekeeper will
# not evaluate the bundle automatically on first launch).
say "Verifying code signature"
codesign --verify --deep --strict "$TMP/unpacked/$APP_NAME" \
    || die "downloaded $APP_NAME failed code-signature verification"
SIGN_INFO="$(codesign -dv --verbose=2 "$TMP/unpacked/$APP_NAME" 2>&1 || true)"
case "$SIGN_INFO" in
    *"TeamIdentifier=LY6LJ395B8"*) ;;
    *) die "downloaded $APP_NAME is not signed by expected Apple Team LY6LJ395B8" ;;
esac

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
    if [ "$WITH_OPENVPN3" != 1 ] \
       && [ ! -x "$DEST/Contents/Resources/vpn-runtime/openvpn3" ] \
       && [ ! -x /Library/PrivilegedHelperTools/SuperManagerVPN/openvpn3 ]; then
        note ""
        note "The protected OpenVPN 3 runtime is missing. Azure VPN (Entra ID)"
        note "requires it even if a Homebrew copy is present. Install it with:"
        note "  curl -fsSL $RAW/scripts/install.sh | bash -s -- --deps-only --with-openvpn3"
    fi
fi

open "$DEST"
