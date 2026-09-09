#!/bin/bash
set -euo pipefail
echo 'Passwordless root installation is no longer supported.' >&2
echo 'Use the signed system package. Remove any older SuperManager sudoers exception with disable_nopasswd.sh.' >&2
exit 1
