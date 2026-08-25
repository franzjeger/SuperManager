#!/usr/bin/env bash
# Update an installed SuperManager from GitHub, in one command.
#
#   supermgr-update              (or ./scripts/update-linux.sh from a checkout)
#
# What it does:
#   1. Finds the git checkout the install came from — the one this script
#      is running out of, or the path install-linux.sh recorded in
#      /etc/supermgr/checkout-path.
#   2. git fetch, and compares what is installed with origin.
#   3. If there is anything new: fast-forwards, rebuilds, and re-runs
#      install-linux.sh --no-deps --no-build --yes, which installs the
#      binaries and restarts the daemon.
#
# Elevation: in a terminal the install phase asks via sudo, per step, the
# same way install-linux.sh does. Without a terminal — launched from the
# GUI's Settings → Updates page — it asks through polkit (pkexec) instead.
#
#   --check       Only report. Exit 0 = up to date, 10 = update available.
#   --force       Rebuild + reinstall even when already up to date.
#   --yes, -y     Don't ask before updating.
#   --help, -h    This text.
#
# The GUI does not update itself in place: a running supermgr keeps the old
# binary until you restart it. The daemon is restarted by the install step.

set -euo pipefail

DO_CHECK=0
FORCE=0
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --check)   DO_CHECK=1 ;;
        --force)   FORCE=1 ;;
        -y|--yes)  ASSUME_YES=1 ;;
        -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" != 0 ] || die "run this as your normal user, not root — the build belongs to you.
       The install phase elevates on its own (sudo in a terminal, polkit from the GUI)."

# ---------------------------------------------------------------------------
# Which checkout?
#
# Three answers, tried in order:
#   1. $SUPERMGR_CHECKOUT       — explicit override, wins always.
#   2. the checkout this script is inside — the ./scripts/update-linux.sh case.
#   3. /etc/supermgr/checkout-path — written by install-linux.sh, which is how
#      the installed /usr/bin/supermgr-update copy finds its way home.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKOUT=""
if [ -n "${SUPERMGR_CHECKOUT:-}" ]; then
    CHECKOUT="$SUPERMGR_CHECKOUT"
elif [ -f "$SCRIPT_DIR/../Cargo.toml" ] \
     && git -C "$SCRIPT_DIR/.." rev-parse --git-dir >/dev/null 2>&1; then
    CHECKOUT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -r /etc/supermgr/checkout-path ]; then
    CHECKOUT="$(head -n1 /etc/supermgr/checkout-path)"
fi

[ -n "$CHECKOUT" ] || die "cannot find the SuperManager checkout this install came from.
       Either run ./scripts/update-linux.sh from inside a checkout, or point
       SUPERMGR_CHECKOUT at one. If the original clone is gone:

           git clone https://github.com/franzjeger/SuperManager ~/SuperManager
           cd ~/SuperManager && ./scripts/install-linux.sh --no-deps"

if ! { [ -f "$CHECKOUT/Cargo.toml" ] && git -C "$CHECKOUT" rev-parse --git-dir >/dev/null 2>&1; }; then
    die "$CHECKOUT is not a SuperManager git checkout any more.
       Re-clone it and re-run install-linux.sh once; after that supermgr-update
       will find it again (the install records the path in /etc/supermgr)."
fi

# ---------------------------------------------------------------------------
# What's new?
# ---------------------------------------------------------------------------

say "Checking origin for updates"
git -C "$CHECKOUT" fetch --tags --quiet origin \
    || die "git fetch failed — no network, or the remote is unreachable"

LOCAL="$(git -C "$CHECKOUT" rev-parse HEAD)"
# Upstream of the current branch when it has one, origin/main otherwise —
# a checkout deliberately sitting on a feature branch tracks that branch.
REMOTE="$(git -C "$CHECKOUT" rev-parse '@{upstream}' 2>/dev/null \
          || git -C "$CHECKOUT" rev-parse origin/main)"

STATE=""
if [ "$LOCAL" = "$REMOTE" ]; then
    STATE=current
elif git -C "$CHECKOUT" merge-base --is-ancestor "$REMOTE" "$LOCAL"; then
    STATE=ahead
elif git -C "$CHECKOUT" merge-base --is-ancestor "$LOCAL" "$REMOTE"; then
    STATE=behind
else
    STATE=diverged
fi

case "$STATE" in
current) note "up to date ($(git -C "$CHECKOUT" rev-parse --short HEAD))" ;;
ahead)   note "your checkout is ahead of origin — nothing to pull" ;;
behind)
    COUNT="$(git -C "$CHECKOUT" rev-list --count "$LOCAL..$REMOTE")"
    note "$COUNT new commit(s) on origin:"
    git -C "$CHECKOUT" log --oneline "$LOCAL..$REMOTE" | head -10 | sed 's/^/    /'
    [ "$COUNT" -le 10 ] || note "    … and $((COUNT - 10)) more"
    ;;
diverged)
    die "your checkout and origin have diverged — local commits exist that
       origin does not have. Not something an updater should resolve for you:
       rebase or reset the checkout at $CHECKOUT by hand, then re-run."
    ;;
esac

if [ "$DO_CHECK" = 1 ]; then
    if [ "$STATE" = behind ]; then
        exit 10
    fi
    exit 0
fi

if [ "$STATE" != behind ] && [ "$FORCE" != 1 ]; then
    note "nothing to do (use --force to rebuild + reinstall anyway)"
    exit 0
fi

# A dirty tree makes --ff-only fail halfway with git's error instead of ours,
# so say it in terms of what the user has to decide.
if [ "$STATE" = behind ]; then
    if ! { git -C "$CHECKOUT" diff --quiet && git -C "$CHECKOUT" diff --cached --quiet; }; then
        die "the checkout at $CHECKOUT has uncommitted changes.
       Stash or commit them, then re-run."
    fi
fi

if [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; then
    printf '\n  Update, rebuild, and reinstall now? [Y/n] '
    read -r reply </dev/tty || reply=y
    case "$reply" in [nN]*) die "cancelled" ;; esac
fi

# ---------------------------------------------------------------------------
# Pull + build (as the invoking user, never root)
# ---------------------------------------------------------------------------

if [ "$STATE" = behind ]; then
    say "Fast-forwarding to origin"
    git -C "$CHECKOUT" merge --ff-only "$REMOTE"
fi

say "Building (this can take a few minutes)"
command -v cargo >/dev/null || die "cargo not found — install Rust, or re-run install-linux.sh"
(cd "$CHECKOUT" && cargo build --release -p supermgrd -p supermgr -p supermgr-mcp)

# ---------------------------------------------------------------------------
# Install + restart the daemon, via install-linux.sh so the two can't drift.
#
# The elevated environment is minimal (pkexec strips it), so a target
# directory moved with CARGO_TARGET_DIR has to be handed over explicitly —
# install-linux.sh falls back to exactly that variable when cargo isn't on
# root's PATH.
# ---------------------------------------------------------------------------

BUILD_DIR=$(cd "$CHECKOUT" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')

say "Installing"
INSTALL=(bash "$CHECKOUT/scripts/install-linux.sh" --no-deps --no-build --yes)
if [ -t 0 ]; then
    "${INSTALL[@]}"
else
    command -v pkexec >/dev/null \
        || die "no terminal to ask for sudo in, and pkexec is missing.
       Run supermgr-update from a terminal instead."
    if [ -n "$BUILD_DIR" ]; then
        pkexec env "CARGO_TARGET_DIR=$BUILD_DIR" "${INSTALL[@]}"
    else
        pkexec "${INSTALL[@]}"
    fi
fi

say "Updated to $(git -C "$CHECKOUT" rev-parse --short HEAD)"
note "The daemon has been restarted with the new binary."
note "Restart the GUI (supermgr) to run the new version yourself."
