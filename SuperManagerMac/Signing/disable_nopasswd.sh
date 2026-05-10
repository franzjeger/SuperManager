#!/usr/bin/env bash
# Tear down the passwordless-sudo file that `enable_nopasswd.sh`
# created. Run this when you're done with a SuperManager dev session.

set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/supermanager-dev"

if [[ ! -f "$SUDOERS_FILE" ]]; then
    echo "✓ Already gone — no $SUDOERS_FILE on this machine."
    exit 0
fi

# Removal also goes through sudo — but if NOPASSWD is currently
# active, `rm` is in our allow-list, so this completes silently. If
# the user has already taken `rm` out of the list, sudo will prompt
# normally.
echo "→ Removing $SUDOERS_FILE…"
sudo rm "$SUDOERS_FILE"
echo "✓ NOPASSWD disabled. sudo will now prompt for password again."
