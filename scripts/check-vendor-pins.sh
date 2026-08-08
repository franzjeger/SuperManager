#!/usr/bin/env bash
#
# Verify every entry in vendor/manifest.toml still resolves to the bytes
# it pins, and that no entry points at a rotating "latest" pointer.
#
# ## Why this exists
#
# The Windows job stages these files and checks the same hashes, but it
# does so ~15 minutes into a build, on the slowest runner we have. When a
# pin goes stale the whole job is wasted to learn one fact. This runs in
# seconds on Linux and says the same thing.
#
# Staleness is not a hypothetical. `[openvpn]` used to track
# `.../releases/latest/openvpn-latest-stable-amd64.msi`, a pointer
# upstream rotates on release, so the pin broke on somebody else's
# schedule — twice, each time turning `windows` red on every branch
# including main. Worse, one of those rotations moved us from OpenVPN 2.6
# to 2.7: a major version change in a bundled VPN client that nobody
# chose. Hence the second check here, which is structural rather than
# temporal — no entry may point at a moving target, ever.
#
# ## What it does NOT do
#
# It does not verify upstream signatures. Doing that properly needs each
# publisher's key pinned somewhere trustworthy, which is a bigger
# decision than a CI script should make on its own. `vendor/manifest.toml`
# documents the manual `gpg --verify` step for whoever re-pins; this
# script only proves the bytes still match what that person recorded.
#
# So a passing run means "the pin is intact and well-formed", not "the
# artifact is trustworthy". The trust decision happens at re-pin time.
#
# Usage: scripts/check-vendor-pins.sh [path/to/manifest.toml]

set -uo pipefail

MANIFEST="${1:-$(dirname "$0")/../vendor/manifest.toml}"

if [ ! -f "$MANIFEST" ]; then
    printf 'error: manifest not found at %s\n' "$MANIFEST" >&2
    exit 2
fi

# Mirrors the minimal parser in scripts/windows/Get-VendorFiles.ps1:
# `[section]` headers and `key = "value"` lines, with `#` comments
# skipped. Kept deliberately as dumb as that one so the two agree about
# what the file means — if you teach one of them real TOML, teach both.
sections=$(sed -n 's/^\[\([a-zA-Z0-9_-]*\)\]$/\1/p' "$MANIFEST")

if [ -z "$sections" ]; then
    printf 'error: no entries found in %s — parser or file is wrong\n' "$MANIFEST" >&2
    exit 2
fi

# Linux CI has sha256sum, macOS has shasum. Resolve once rather than
# per-entry so an environment with neither fails immediately and says so,
# instead of reporting every pin as a mismatch against an empty hash.
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    printf 'error: neither sha256sum nor shasum found\n' >&2
    exit 2
fi

field() {
    # field <section> <key> — value of `key = "..."` inside [section]
    sed -n "/^\[$1\]\$/,/^\[/p" "$MANIFEST" \
        | sed -n "s/^$2 *= *\"\([^\"]*\)\".*/\1/p" \
        | head -1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rc=0
checked=0

for name in $sections; do
    url=$(field "$name" url)
    want=$(field "$name" sha256)
    output=$(field "$name" output)

    # An empty extraction must fail loudly. Comparing two empty strings
    # and calling it a match is the one way this script could lie.
    if [ -z "$url" ] || [ -z "$want" ] || [ -z "$output" ]; then
        printf '[%s] FAIL: missing url/sha256/output (got url=%q sha256=%q output=%q)\n' \
            "$name" "$url" "$want" "$output"
        rc=1
        continue
    fi

    case "$url" in
        */latest/*|*latest-stable*|*/current/*)
            printf '[%s] FAIL: url points at a rotating pointer, pin an exact version\n' "$name"
            printf '        %s\n' "$url"
            rc=1
            continue
            ;;
    esac

    if ! curl -fsSL --retry 2 --retry-delay 3 "$url" -o "$tmp/$output"; then
        printf '[%s] FAIL: download failed — %s\n' "$name" "$url"
        rc=1
        continue
    fi

    got=$(sha256_of "$tmp/$output" | tr '[:lower:]' '[:upper:]')
    want_uc=$(printf '%s' "$want" | tr '[:lower:]' '[:upper:]')
    size=$(wc -c < "$tmp/$output" | tr -d ' ')
    checked=$((checked + 1))

    if [ "$got" = "$want_uc" ]; then
        printf '[%s] ok  %s bytes  %s\n' "$name" "$size" "$got"
    else
        printf '[%s] FAIL: hash mismatch at a fixed url\n' "$name"
        printf '        expected: %s\n' "$want_uc"
        printf '        actual:   %s\n' "$got"
        printf '        The bytes at a fixed address changed. That is not routine\n'
        printf '        staleness — investigate before re-pinning. See the update\n'
        printf '        procedure at the top of vendor/manifest.toml.\n'
        rc=1
    fi
done

printf '\n%s entr(y/ies) verified, exit %s\n' "$checked" "$rc"
exit $rc
