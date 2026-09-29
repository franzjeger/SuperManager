#!/usr/bin/env bash
# The version to stamp on a Mac app build, from the release tags.
#
#   scripts/app-version.sh [CHECKOUT]
#
# Prints the version and exits 0:
#   $SUPERMANAGER_VERSION   when set: release.sh passes the version it releases,
#                           which may not be tagged yet.
#   X.Y.Z                   on the commit tagged vX.Y.Z.
#   X.Y.Z.N                 N commits past the last vX.Y.Z tag. A build from
#                           main then sorts after the release it builds on and
#                           before the next one, so Sparkle neither "updates"
#                           it back to that release nor withholds the next.
#
# Prints nothing and exits 1 when git has no release tag to go by (no .git, or
# a shallow checkout without tags). The caller keeps the version it has.

set -euo pipefail

if [ -n "${SUPERMANAGER_VERSION:-}" ]; then
    printf '%s\n' "$SUPERMANAGER_VERSION"
    exit 0
fi

checkout="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Only release tags: vX.Y.Z, not pre-releases (v1.9.0-rc1) or the archive/*
# tags that mark old branches.
described="$(git -C "$checkout" describe --tags --long \
    --match 'v[0-9]*' --exclude 'v*-*' 2>/dev/null)" || exit 1

if [[ ! "$described" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-g[0-9a-f]+$ ]]; then
    exit 1
fi
version="${BASH_REMATCH[1]}"
commits="${BASH_REMATCH[2]}"

if [ "$commits" = 0 ]; then
    printf '%s\n' "$version"
else
    printf '%s.%s\n' "$version" "$commits"
fi
