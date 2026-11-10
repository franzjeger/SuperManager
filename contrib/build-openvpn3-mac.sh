#!/usr/bin/env bash
# Build and install SuperManager's protected OpenVPN 3 runtime for macOS.
#
# Run as your normal user. Only installation asks for sudo. Prerequisites:
#   brew install cmake
#   Xcode command-line tools, including python3 and the C/C++ toolchain
#
# Uses the same pinned source, credential-file adapter and static dependencies
# as the app bundle. Nothing is installed into Homebrew's writable prefix.
# Reconnect Azure VPN after installation; the helper locates this runtime
# without an app restart. The adapter also accepts the -a FILE form used by
# the shipped 1.8.25 helper.

set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo "error: this build script requires macOS" >&2
    exit 1
fi
if [[ "$(id -u)" = 0 ]]; then
    echo "error: run this as your normal user; only installation uses sudo" >&2
    exit 1
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
staged="$(mktemp -d "${TMPDIR:-/tmp}/supermanager-openvpn3-install.XXXXXX")"
trap 'rm -rf "$staged"' EXIT

"$repo/scripts/build-openvpn3-runtime.sh" "$staged"

runtime="/Library/PrivilegedHelperTools/SuperManagerVPN"
echo "→ Installing OpenVPN 3 into $runtime (admin password may be required)…"
sudo install -d -m 0755 -o root -g wheel "$runtime" "$runtime/licenses"
sudo install -m 0755 -o root -g wheel "$staged/openvpn3" "$runtime/openvpn3"
while IFS= read -r -d '' license; do
    relative="${license#"$staged/licenses/"}"
    sudo install -d -m 0755 -o root -g wheel "$runtime/licenses/$(dirname "$relative")"
    sudo install -m 0644 -o root -g wheel "$license" "$runtime/licenses/$relative"
done < <(find "$staged/licenses" -type f -print0)

echo "✓ Protected OpenVPN 3 installed. Reconnect Azure VPN in SuperManager."
