#!/usr/bin/env bash
# Retired. It wrote /etc/sudoers.d/supermanager-dev, a NOPASSWD rule for file
# and launchctl commands: much broader than a development shortcut should
# be. The script it served, install_helper.sh, is retired as well.
#
# If you ran it before, remove the rule with disable_nopasswd.sh.

echo "enable_nopasswd.sh is retired: its sudo rule was far broader than a dev shortcut should be." >&2
echo "If you enabled it before, run disable_nopasswd.sh." >&2
exit 1
