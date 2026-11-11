#!/usr/bin/env bash
# Update an installed SuperManager from GitHub, in one command.
#
#   supermgr-update              (or ./scripts/update-linux.sh from a checkout)
#
# What it does:
#   1. Finds the git checkout the install came from — the one this script
#      is running out of, or the path install-linux.sh recorded in
#      /etc/supermgr/checkout-path.
#   2. Fetches tags from origin (refusing rewritten tags unless explicitly
#      requested), resolves the latest annotated release tag (`v*`), and
#      verifies its cryptographic SSH signature against the pinned signers in
#      /etc/supermgr/release-signers.
#   3. Fast-forwards/checks out the verified release tag and builds as the
#      unprivileged invoking user (`cargo build --release --locked`).
#   4. Elevates (`sudo` in a terminal, `pkexec` without one), re-verifies the
#      release tag as root, extracts `scripts/` and `contrib/` from the
#      verified tag into a `0700` root-owned staging directory alongside the
#      built binaries, and runs `install-linux.sh --no-deps --no-build --yes`
#      from that root-owned copy.
#
#   --check              Only report. Exit 0 = up to date, 10 = update available.
#   --force              Rebuild + reinstall even when already at the release tag.
#   --yes, -y            Don't ask before updating.
#   --allow-moved-tags   Allow `git fetch --force` if origin re-pointed a tag.
#   --installed-commit SHA
#                        Also compare the running GUI build (used by the GUI).
#   --help, -h           This text.
#
# The GUI does not update itself in place: a running supermgr keeps the old
# binary until you restart it. The daemon is restarted by the install step.

set -euo pipefail

DO_CHECK=0
FORCE=0
ASSUME_YES=0
ALLOW_MOVED_TAGS=0
INSTALLED_COMMIT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --check)            DO_CHECK=1 ;;
        --force)            FORCE=1 ;;
        -y|--yes)           ASSUME_YES=1 ;;
        --allow-moved-tags) ALLOW_MOVED_TAGS=1 ;;
        --installed-commit)
            [ $# -ge 2 ] || { echo "--installed-commit requires a SHA" >&2; exit 2; }
            INSTALLED_COMMIT="$2"
            shift
            ;;
        -h|--help) sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }
trap 'printf "\033[31merror: line %s: \`%s\` failed (exit %s)\033[0m\n" "$LINENO" "$BASH_COMMAND" "$?" >&2' ERR

owner_uid() {
    stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

if [ -n "$INSTALLED_COMMIT" ] \
   && [[ ! "$INSTALLED_COMMIT" =~ ^[0-9a-fA-F]{40,64}$ ]]; then
    die "--installed-commit must be a full hexadecimal Git commit ID"
fi

[ "$(id -u)" != 0 ] || die "run this as your normal user, not root — the build belongs to you.
       The install phase elevates on its own (sudo in a terminal, polkit from the GUI)."

# ---------------------------------------------------------------------------
# Which checkout?
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
# Pinned release-tag signers.
#
# Prefer the root-owned /etc/supermgr/release-signers installed by
# install-linux.sh so a modified working tree cannot swap its own trust root.
# SUPERMGR_TAG_SIGNERS overrides the path for offline/hermetic tests.
# ---------------------------------------------------------------------------
SIGNERS_FILE=""
if [ -n "${SUPERMGR_TAG_SIGNERS:-}" ]; then
    SIGNERS_FILE="$SUPERMGR_TAG_SIGNERS"
elif [ -f /etc/supermgr/release-signers ]; then
    [ "$(owner_uid /etc/supermgr/release-signers)" = 0 ] \
        || die "/etc/supermgr/release-signers is not owned by root (uid 0)"
    SIGNERS_FILE="/etc/supermgr/release-signers"
elif [ -f "$SCRIPT_DIR/../contrib/release-signers" ]; then
    SIGNERS_FILE="$(cd "$SCRIPT_DIR/.." && pwd)/contrib/release-signers"
fi

[ -n "$SIGNERS_FILE" ] && [ -s "$SIGNERS_FILE" ] \
    || die "release tag signers file not found (/etc/supermgr/release-signers).
       Re-run ./scripts/install-linux.sh to install the pinned release keys."

# ---------------------------------------------------------------------------
# Fetch + verify latest signed annotated release tag
# ---------------------------------------------------------------------------
say "Checking origin for signed release tags"
FETCH_ARGS=(fetch --tags --quiet origin)
if [ "$ALLOW_MOVED_TAGS" = 1 ]; then
    FETCH_ARGS=(fetch --tags --force --quiet origin)
fi
if ! fetch_output="$(git -C "$CHECKOUT" "${FETCH_ARGS[@]}" 2>&1)"; then
    die "git fetch from origin failed:
$(printf '%s\n' "$fetch_output" | sed 's/^/       /')"
fi

TARGET_TAG="$(git -C "$CHECKOUT" for-each-ref \
    --sort=-version:refname \
    --format='%(objecttype) %(refname:strip=2)' \
    'refs/tags/v[0-9]*' \
    | awk '$1 == "tag" { print $2; exit }')"

[ -n "$TARGET_TAG" ] \
    || die "no annotated release tags (v*) found on origin — refusing to build untagged branch commits"

if ! [[ "$TARGET_TAG" =~ ^v[0-9][0-9A-Za-z._-]*$ ]]; then
    die "refusing malformed release tag name: $TARGET_TAG"
fi

if ! verify_output="$(git -C "$CHECKOUT" \
    -c gpg.format=ssh \
    -c "gpg.ssh.allowedSignersFile=$SIGNERS_FILE" \
    verify-tag "$TARGET_TAG" 2>&1)"; then
    die "signature verification failed for release tag $TARGET_TAG:
$(printf '%s\n' "$verify_output" | sed 's/^/       /')"
fi

LOCAL="$(git -C "$CHECKOUT" rev-parse HEAD)"
REMOTE="$(git -C "$CHECKOUT" rev-parse "$TARGET_TAG^{commit}")"

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
current) note "up to date at verified release $TARGET_TAG ($(git -C "$CHECKOUT" rev-parse --short HEAD))" ;;
ahead)   note "your checkout is ahead of verified release $TARGET_TAG — nothing to pull" ;;
behind)
    COUNT="$(git -C "$CHECKOUT" rev-list --count "$LOCAL..$REMOTE")"
    note "$COUNT new commit(s) in verified release $TARGET_TAG:"
    git -C "$CHECKOUT" log --oneline -n 10 "$LOCAL..$REMOTE" | sed 's/^/    /'
    [ "$COUNT" -le 10 ] || note "    … and $((COUNT - 10)) more"
    ;;
diverged)
    die "your checkout and release $TARGET_TAG have diverged — local commits exist that
       $TARGET_TAG does not have. Not something an updater should resolve for you:
       rebase or reset the checkout at $CHECKOUT by hand, then re-run."
    ;;
esac

BINARY_STALE=0
if [ -n "$INSTALLED_COMMIT" ] && [ "$INSTALLED_COMMIT" != "$REMOTE" ]; then
    if git -C "$CHECKOUT" cat-file -e "$INSTALLED_COMMIT^{commit}" 2>/dev/null \
       && git -C "$CHECKOUT" merge-base --is-ancestor "$INSTALLED_COMMIT" "$REMOTE"; then
        BINARY_STALE=1
        note "installed GUI ($(printf '%.7s' "$INSTALLED_COMMIT")) is older than $TARGET_TAG"
    else
        warn "installed GUI commit is not an ancestor of $TARGET_TAG; leaving source-state decision unchanged"
    fi
fi

if [ "$DO_CHECK" = 1 ]; then
    if [ "$STATE" = behind ] || [ "$BINARY_STALE" = 1 ]; then
        exit 10
    fi
    exit 0
fi

if [ "$STATE" != behind ] && [ "$BINARY_STALE" != 1 ] && [ "$FORCE" != 1 ]; then
    note "nothing to do (use --force to rebuild + reinstall $TARGET_TAG anyway)"
    exit 0
fi

if [ "$STATE" = behind ]; then
    if ! { git -C "$CHECKOUT" diff --quiet && git -C "$CHECKOUT" diff --cached --quiet; }; then
        die "the checkout at $CHECKOUT has uncommitted changes.
       Stash or commit them, then re-run."
    fi
fi

if [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; then
    printf '\n  Update to %s, rebuild, and reinstall now? [Y/n] ' "$TARGET_TAG"
    read -r reply </dev/tty || reply=y
    case "$reply" in [nN]*) die "cancelled" ;; esac
fi

# ---------------------------------------------------------------------------
# Fast-forward / checkout + build (as the invoking user, never root)
# ---------------------------------------------------------------------------
if [ "$STATE" = behind ]; then
    say "Advancing checkout to verified release $TARGET_TAG"
    if git -C "$CHECKOUT" symbolic-ref -q HEAD >/dev/null 2>&1; then
        git -C "$CHECKOUT" merge --ff-only "$REMOTE"
    else
        git -C "$CHECKOUT" checkout --detach "$REMOTE"
    fi
fi

BUILD_DIR=$(cd "$CHECKOUT" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p') || BUILD_DIR=""
[ -n "$BUILD_DIR" ] || BUILD_DIR="${CARGO_TARGET_DIR:-${CARGO_BUILD_TARGET_DIR:-$CHECKOUT/target}}"

if [ "${SUPERMGR_TEST_SKIP_BUILD:-0}" != 1 ]; then
    say "Building $TARGET_TAG (this can take a few minutes)"
    command -v cargo >/dev/null || die "cargo not found — install Rust, or re-run install-linux.sh"
    (cd "$CHECKOUT" && cargo build --release --locked -p supermgrd -p supermgr -p supermgr-mcp)
fi

# ---------------------------------------------------------------------------
# Stage into a root-owned 0700 directory + run install-linux.sh from there.
#
# Never execute `$CHECKOUT/scripts/install-linux.sh` as root: `$CHECKOUT`
# lives in the user's home directory and remains writable by any unprivileged
# process in the session. Instead, root re-verifies `$TARGET_TAG` against the
# root-owned `/etc/supermgr/release-signers` (when installed), extracts
# `Cargo.toml`, `scripts/`, and `contrib/` straight from the verified Git tag
# object into a `0700` `root:root` directory, copies the built binaries in as
# `0755` `root:root` regular files, and runs `install-linux.sh` from there.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016  # Intentional: expanded by the elevated root bash, not the caller.
ROOT_INSTALL_SCRIPT='
set -euo pipefail
checkout="$1"
tag="$2"
fallback_signers="$3"
build_dir="$4"
stage_only_dest="${5:-}"

signers="$fallback_signers"
if [ -z "$stage_only_dest" ] && [ -f /etc/supermgr/release-signers ]; then
    uid="$(stat -c "%u" /etc/supermgr/release-signers 2>/dev/null || stat -f "%u" /etc/supermgr/release-signers)"
    [ "$uid" = 0 ] || { echo "error: /etc/supermgr/release-signers is not owned by root" >&2; exit 1; }
    signers="/etc/supermgr/release-signers"
fi

git -C "$checkout" \
    -c "safe.directory=$checkout" \
    -c gpg.format=ssh \
    -c "gpg.ssh.allowedSignersFile=$signers" \
    verify-tag "$tag" >/dev/null

if [ -n "$stage_only_dest" ]; then
    stage="$stage_only_dest"
    mkdir -p "$stage"
    chmod 0700 "$stage"
else
    umask 077
    stage="$(mktemp -d /run/supermgr-stage.XXXXXX 2>/dev/null || mktemp -d /tmp/supermgr-stage.XXXXXX)"
    trap '\''rm -rf "$stage"'\'' EXIT
    chown 0:0 "$stage"
    chmod 0700 "$stage"
fi

git -C "$checkout" -c "safe.directory=$checkout" \
    archive --format=tar "$tag" Cargo.toml scripts contrib \
    | tar -xf - -C "$stage"

install -dm0755 "$stage/target/release"
for bin in supermgrd supermgr supermgr-mcp; do
    src="$build_dir/release/$bin"
    if [ -L "$src" ] || [ ! -f "$src" ]; then
        echo "error: expected regular binary at $src" >&2
        exit 1
    fi
    install -m0755 "$src" "$stage/target/release/$bin"
done

if [ -n "$stage_only_dest" ]; then
    exit 0
fi

chown -R 0:0 "$stage"
CARGO_TARGET_DIR="$stage/target" \
    bash "$stage/scripts/install-linux.sh" \
    --no-deps --no-build --yes --record-checkout "$checkout"
'

if [ -n "${SUPERMGR_TEST_STAGE_DEST:-}" ]; then
    bash -ceu "$ROOT_INSTALL_SCRIPT" -- \
        "$CHECKOUT" "$TARGET_TAG" "$SIGNERS_FILE" "$BUILD_DIR" "$SUPERMGR_TEST_STAGE_DEST"
    exit 0
fi

say "Installing $TARGET_TAG"
rc=0
if [ -t 0 ]; then
    sudo -- bash -ceu "$ROOT_INSTALL_SCRIPT" -- \
        "$CHECKOUT" "$TARGET_TAG" "$SIGNERS_FILE" "$BUILD_DIR" || rc=$?
else
    command -v pkexec >/dev/null \
        || die "no terminal to ask for sudo in, and pkexec is missing.
       Run supermgr-update from a terminal instead."
    pkexec bash -ceu "$ROOT_INSTALL_SCRIPT" -- \
        "$CHECKOUT" "$TARGET_TAG" "$SIGNERS_FILE" "$BUILD_DIR" || rc=$?
    [ "$rc" != 126 ] || die "authentication was cancelled, so nothing was installed.
       The build is done; running the update again only installs it."
    [ "$rc" != 127 ] || die "pkexec could not ask for your password: no polkit authentication
       agent is answering in this session, so nothing was installed.
       The build is done. Install it from a terminal:

           supermgr-update --force"
fi
[ "$rc" = 0 ] || die "the install step failed (exit $rc) — the new build is not installed"

say "Updated to $TARGET_TAG ($(git -C "$CHECKOUT" rev-parse --short HEAD))"
note "The daemon has been restarted with the new binary."
note "Restart the GUI (supermgr) to run the new version yourself."
