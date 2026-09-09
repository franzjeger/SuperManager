#!/bin/bash
# Developer scripts must never install an unsigned helper or grant NOPASSWD.
set -euo pipefail
echo 'Install the signed SuperManager system package with macOS Installer.' >&2
echo 'Direct helper copying and dev-rpc self-installation are disabled.' >&2
exit 1
