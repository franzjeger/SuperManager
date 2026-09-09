#!/bin/bash
# Recovery is deliberately usable after a killed installer or reboot.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
[[ $EUID == 0 ]] || exit 1
base='/Library/Application Support/SuperManagerSystem'
backup="$base/backup-@BUILD@"
[[ -f "$base/pending" && $(cat "$base/pending") == "$backup" ]] || { echo 'No matching pending transaction.' >&2; exit 1; }
helper='/Library/PrivilegedHelperTools/com.sybr.supermanager.helper'
runtime='/Library/PrivilegedHelperTools/SuperManagerVPN'
plist='/Library/LaunchDaemons/com.sybr.supermanager.helper.plist'
launchctl bootout system/com.sybr.supermanager.helper >/dev/null 2>&1 || true
rm -f "$helper" "$plist"
# Fixed root-owned path; never expand caller-controlled deletion targets.
rm -rf "$runtime"
[[ ! -e "$backup/helper" ]] || cp -p "$backup/helper" "$helper"
[[ ! -e "$backup/runtime" ]] || ditto "$backup/runtime" "$runtime"
if [[ -e "$backup/helper.plist" ]]; then
    cp -p "$backup/helper.plist" "$plist"
    launchctl bootstrap system "$plist"
fi
rm "$base/pending"
rmdir "$base/install.lock" 2>/dev/null || true
echo 'Previous components restored. VPN sessions and OS networking still require verification.'
