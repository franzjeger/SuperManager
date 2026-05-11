#!/usr/bin/env bash
# Generate an EdDSA Ed25519 keypair for Sparkle 2 appcast signing.
#
# Run this ONCE per repo. The private key never leaves your machine
# (and never goes into git). The public key gets baked into
# Info.plist via `SUPublicEDKey`.
#
# What we do:
#   1. Find Sparkle's `generate_keys` CLI (it ships inside the .xcframework
#      bundle that SwiftPM downloads as part of the package).
#   2. Run it — it stores the private key in the Mac Keychain under the
#      label `https://sparkle-project.org` and prints the base64 public key.
#   3. Echo the public key + remind you to update Info.plist + SUFeedURL.
#
# Private-key safekeeping:
#   • Keychain Access → search "Sparkle" → that entry is your private key.
#   • If you ever lose the Mac, you lose the ability to sign updates.
#     Either back it up offline (Keychain Access → File → Export Items)
#     or be prepared to ship users a new public-key bake-in.
#
# Re-running this script is safe — Sparkle's `generate_keys` checks for an
# existing entry and refuses to overwrite. Use `--force` (commented out
# below) only if you intentionally want a fresh key.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Look for `generate_keys` inside DerivedData. SwiftPM downloads
# Sparkle's xcframework as part of the package resolution, and the
# CLI tools live alongside the framework bundle.
#
# We don't pin a specific Xcode-DerivedData path — globbing `**`
# finds whichever DerivedData folder SwiftPM populated.
echo "→ Resolving Sparkle's generate_keys tool…"
GENERATE_KEYS=""
for candidate in \
    "$HOME/Library/Developer/Xcode/DerivedData"/SuperManager-*/SourcePackages/artifacts/sparkle/Sparkle/bin/generate_keys \
    "$HOME/Library/Developer/Xcode/DerivedData"/*/SourcePackages/artifacts/sparkle/Sparkle/bin/generate_keys
do
    if [ -x "$candidate" ]; then
        GENERATE_KEYS="$candidate"
        break
    fi
done

if [ -z "$GENERATE_KEYS" ]; then
    cat >&2 <<EOF
error: couldn't find Sparkle's generate_keys tool in DerivedData.

Most likely cause: you haven't done a full Xcode build yet, so SwiftPM
hasn't downloaded the Sparkle artifacts. Run \`./SuperManagerMac/build.sh\`
once first, then re-run this script.

Alternatively, install Sparkle's CLI tools manually from
https://github.com/sparkle-project/Sparkle/releases and point this
script at \$GENERATE_KEYS.
EOF
    exit 1
fi
echo "  found: $GENERATE_KEYS"

# Run it. `generate_keys` is interactive on stdout — it asks you to
# confirm + then writes the private key into the Keychain.
echo
echo "→ Generating keypair (private → Mac Keychain, public → stdout)…"
echo
"$GENERATE_KEYS"
echo
echo "════════════════════════════════════════════════════════════════"
echo "Next steps:"
echo "  1. Copy the SUPublicEDKey base64 string above."
echo "  2. Open SuperManagerMac/project.yml, find SUPublicEDKey, and"
echo "     replace REPLACE_ME_RUN_sparkle-keygen.sh with your value."
echo "  3. Run \`xcodegen generate\` inside SuperManagerMac/ so the"
echo "     change lands in the .xcodeproj."
echo "  4. Commit project.yml. The private key stays in Keychain."
echo "════════════════════════════════════════════════════════════════"
