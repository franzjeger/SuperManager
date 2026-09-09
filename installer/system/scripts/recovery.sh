#!/bin/bash
# Recovery is deliberately usable after a killed installer or reboot.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
[[ $EUID == 0 ]] || exit 1
base='/Library/Application Support/SuperManagerSystem'
backup=$(dirname -- "$0")
[[ "$backup" == "$base"/backup-@BUILD@.* ]] || exit 1
[[ -f "$base/pending" && $(cat "$base/pending") == "$backup" ]] || { echo 'No matching pending transaction.' >&2; exit 1; }
helper='/Library/PrivilegedHelperTools/com.sybr.supermanager.helper'
runtime='/Library/PrivilegedHelperTools/SuperManagerVPN'
plist='/Library/LaunchDaemons/com.sybr.supermanager.helper.plist'
label='com.sybr.supermanager.helper'
# launchd bootout can return before its job and child processes are gone.
stop_service() {
    local previous pid=''
    previous=$(launchctl print "system/$label" 2>/dev/null || true)
    if [[ "$previous" =~ pid[[:space:]]*=[[:space:]]*([0-9]+) ]]; then pid=${BASH_REMATCH[1]}; fi
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
    for attempt in {1..30}; do
        if ! launchctl print "system/$label" >/dev/null 2>&1; then
            if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then return 0; fi
        fi
        sleep 1
    done
    echo "Timed out waiting for $label to unload; installed files left intact." >&2
    return 1
}
start_service() {
    for attempt in {1..10}; do
        if launchctl bootstrap system "$plist"; then return 0; fi
        # A failed bootstrap must not trigger another start over a loaded job.
        if launchctl print "system/$label" >/dev/null 2>&1; then return 1; fi
        sleep 1
    done
    return 1
}

stop_service
rm -f "$helper" "$plist"
# Fixed root-owned path; never expand caller-controlled deletion targets.
rm -rf "$runtime"
[[ ! -e "$backup/helper" ]] || cp -p "$backup/helper" "$helper"
[[ ! -e "$backup/runtime" ]] || ditto "$backup/runtime" "$runtime"
if [[ -e "$backup/helper.plist" ]]; then
    cp -p "$backup/helper.plist" "$plist"
    start_service
fi
rm "$base/pending"
rmdir "$base/install.lock" 2>/dev/null || true
echo 'Previous components restored. VPN sessions and OS networking still require verification.'
