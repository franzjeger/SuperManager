#!/usr/bin/env bash
# Check the daemon's polkit gates against the polkit daemon actually
# running on this machine.
#
#   ./scripts/verify-polkit.sh
#
# # Why this exists
#
# Every polkit guard in `supermgrd` is covered by tests that check the
# action ids, the shipped policy file and the call sites agree with each
# other. None of that can tell you whether the prompt appears, whether
# `auth_admin_keep` really caches for the session, or whether polkit even
# found the policy file — those need a system bus, a polkit daemon and an
# authentication agent, which no CI runner has. So they have never been
# tried, and this is the thing that tries them.
#
# # What it does, and what it does not
#
# The gated methods are called with a sentinel that cannot resolve: a nil
# UUID for the ones taking an id, and an unassigned 100.64/10 address for
# the exit-node one. Authorization runs before the daemon looks anything
# up, so the gate is exercised in full and the operation then fails with
# "not found" — nothing is exported, no tunnel is raised, no credential is
# staged, and no traffic is rerouted. Read-only throughout.
#
# The exit-node sentinel matters more than the others: a real address there
# would send every packet this machine emits through another host as a side
# effect of running a test script.
#
# It cannot check what the prompt looks like or what the GUI shows when
# you dismiss it. Those need eyes; the summary at the end says so.
#
#   --yes, -y   Don't pause between steps.
#   --help, -h  This text.

set -uo pipefail   # not -e: a failing check is a result, not a crash

ACTION_SECRETS="org.supermgr.daemon.secrets"
ACTION_SSH_CONNECT="org.supermgr.daemon.ssh-connect"
ACTION_TS_EXIT="org.supermgr.daemon.tailscale-exit-node"
SERVICE="org.supermgr.Daemon"
OBJECT="/org/supermgr/Daemon"
IFACE="org.supermgr.Daemon1"
NIL_UUID="00000000-0000-0000-0000-000000000000"
# An address inside Tailscale's 100.64/10 range that no node holds. Shape-valid,
# so it passes the daemon's own argument check and reaches tailscaled, which
# refuses it — the exit-node equivalent of the nil UUID. Never route through
# a real peer from here.
UNASSIGNED_TS_IP="100.64.255.254"

ASSUME_YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)  ASSUME_YES=1 ;;
        # Range tracks the header comment above: it ends at the "--help"
        # line. Widen it when the header grows, or --help silently truncates.
        -h|--help) sed -n '2,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

PASS=0; FAIL=0; SKIP=0; MANUAL=0

say()   { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
pass()  { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
fail()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
skip()  { printf '  \033[33mSKIP\033[0m  %s\n' "$*"; SKIP=$((SKIP+1)); }
info()  { printf '        %s\n' "$*"; }
manual(){ printf '  \033[36mLOOK\033[0m  %s\n' "$*"; MANUAL=$((MANUAL+1)); }

pause() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ -e /dev/tty ] || return 0
    printf '\n  %s — press Enter when ready ' "$1"
    read -r _ </dev/tty || true
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

say "Environment"

[ "$(id -u)" != 0 ] || {
    printf '\033[31merror: run this as your normal desktop user.\033[0m\n' >&2
    printf '       As root every check passes trivially and proves nothing —\n' >&2
    printf '       polkit grants root everything without asking.\n' >&2
    exit 1
}

for tool in busctl pkaction pkcheck; do
    command -v "$tool" >/dev/null || {
        printf '\033[31merror: %s not found.\033[0m Install polkit and systemd.\n' "$tool" >&2
        exit 1
    }
done
info "running as uid $(id -u) ($(id -un))"

if busctl --system status "$SERVICE" >/dev/null 2>&1; then
    pass "supermgrd is on the system bus"
else
    fail "supermgrd is not reachable on the system bus"
    info "start it:  sudo systemctl start supermgrd"
    info "Everything below needs it; stopping here."
    exit 1
fi

# An agent is what turns "needs authentication" into a dialog. Without one
# polkit returns the challenge unanswered and every gated call is denied —
# which looks exactly like a broken gate.
if [ -n "${XDG_SESSION_ID:-}" ] || [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    info "graphical session detected — your desktop's polkit agent should prompt"
else
    skip "no graphical session; run 'pkttyagent' in another terminal first, or"
    info "the authentication steps below will be denied with nothing shown"
fi

# ---------------------------------------------------------------------------
# 1. Does polkit know about the actions at all?
#
# The most likely failure in the field, and the quietest: without the
# policy file installed polkit has no rule, denies by default, and the
# daemon reports a refusal that reads like a bug.
# ---------------------------------------------------------------------------

say "Policy file"

INSTALLED_POLICY=/usr/share/polkit-1/actions/org.supermgr.Daemon.policy
POLKIT_DTD=/usr/share/polkit-1/policyconfig-1.dtd

# Against polkit's own DTD, not just "is it well-formed XML". Catches a
# misspelled element or a value polkit does not accept, and does it
# without needing the daemon — so it still says something useful on a
# machine where polkit is installed but not running.
if [ -f "$INSTALLED_POLICY" ]; then
    pass "policy file is installed at $INSTALLED_POLICY"
    if command -v xmllint >/dev/null && [ -f "$POLKIT_DTD" ]; then
        if xmllint --noout --dtdvalid "$POLKIT_DTD" "$INSTALLED_POLICY" 2>/dev/null; then
            pass "it validates against polkit's DTD"
        else
            fail "it does NOT validate against $POLKIT_DTD"
            xmllint --noout --dtdvalid "$POLKIT_DTD" "$INSTALLED_POLICY" 2>&1 | sed 's/^/        /' | head -5
        fi
    else
        skip "xmllint or the polkit DTD is missing — cannot validate the file offline"
    fi
else
    fail "no policy file at $INSTALLED_POLICY"
    info "install it:  sudo install -Dm644 contrib/polkit/org.supermgr.Daemon.policy \\"
    info "                  $INSTALLED_POLICY"
    info "Without it polkit has no rule for these actions and denies by default,"
    info "which looks exactly like a broken daemon."
fi

# `pkaction` exits 1 both when an action is undeclared and when polkit
# cannot be reached at all, so its status alone would have this reporting
# "polkit has never heard of your action" on a machine where polkit is
# simply not running — and sending you to reinstall a file that is
# already there. Ask about polkit itself first.
POLKIT_LIVE=1
if ! busctl --system status org.freedesktop.PolicyKit1 >/dev/null 2>&1; then
    POLKIT_LIVE=0
    fail "polkit is not running on the system bus"
    info "  systemctl status polkit"
    info "The daemon fails closed without it, so every gated method is denied."
fi

if [ "$POLKIT_LIVE" = 1 ]; then
    for action in "$ACTION_SECRETS" "$ACTION_SSH_CONNECT" "$ACTION_TS_EXIT"; do
        if pkaction --action-id "$action" >/dev/null 2>&1; then
            pass "polkit knows $action"
        else
            fail "polkit does not know $action"
            info "the file above is installed but polkit has not picked it up —"
            info "it re-reads the actions directory on start:  systemctl restart polkit"
        fi
    done
else
    skip "action lookup — polkit is down, every answer would be a false negative"
    skip "default levels — same reason"
fi

check_default() {  # <action> <expected implicit_active>
    local action="$1" want="$2" got
    got="$(pkaction --action-id "$action" --verbose 2>/dev/null \
           | awk -F': *' '/implicit active/ {print $2; exit}')"
    if [ -z "$got" ]; then
        skip "$action — could not read its defaults back from polkit"
    elif [ "$got" = "$want" ]; then
        pass "$action is $want, as shipped"
    else
        fail "$action is '$got', expected '$want'"
        info "a local rule in /etc/polkit-1/rules.d/ may be overriding the policy"
    fi
}

if [ "$POLKIT_LIVE" = 1 ]; then
    check_default "$ACTION_SECRETS" auth_admin
    check_default "$ACTION_SSH_CONNECT" auth_admin_keep
    check_default "$ACTION_TS_EXIT" auth_admin_keep
fi

# ---------------------------------------------------------------------------
# 2. What does polkit decide for *this* process?
#
# `pkcheck` asks the same question the daemon asks, without going through
# the daemon — so a disagreement between this and step 3 localises the
# fault to one side or the other.
# ---------------------------------------------------------------------------

say "Decision for this session (no daemon involved)"

info "Expect an authentication dialog. Cancel it — a refusal is the"
info "result we want here, and it proves the prompt reached you."
pause "Ready to be prompted"

if pkcheck --action-id "$ACTION_SECRETS" --process $$ --allow-user-interaction >/dev/null 2>&1; then
    pass "$ACTION_SECRETS authorised (you completed the prompt)"
    info "note: with auth_admin there is no grace period — you will be asked again"
else
    pass "$ACTION_SECRETS refused (you cancelled, or you are not an admin)"
    info "either way the policy is live and polkit is deciding"
fi

# ---------------------------------------------------------------------------
# 3. Does the daemon actually ask?
#
# The nil UUID is the point: authorization runs before any lookup, so an
# 'AccessDenied' means the gate fired and a 'not found' means it passed
# and the harmless operation then failed. Both prove the guard is wired
# in. Anything else — a success, a different error — does not.
# ---------------------------------------------------------------------------

say "The gated methods"

call() {  # <Method> [arg]
    if [ $# -ge 2 ]; then
        busctl --system call "$SERVICE" "$OBJECT" "$IFACE" "$1" s "$2" 2>&1
    else
        busctl --system call "$SERVICE" "$OBJECT" "$IFACE" "$1" 2>&1
    fi
}

verdict() {  # <label> <output>
    local label="$1" out="$2"
    if printf '%s' "$out" | grep -qi 'AccessDenied\|not permitted\|not completed'; then
        pass "$label — refused by polkit"
    elif printf '%s' "$out" | grep -qi 'not found\|UnknownObject\|no node found'; then
        pass "$label — authorised, then failed on the sentinel as intended"
    elif printf '%s' "$out" | grep -qi 'cannot reach polkit\|refused to decide'; then
        fail "$label — polkit could not be consulted, so the call failed closed"
        info "that is the designed behaviour, but it means polkit is unreachable:"
        info "  systemctl status polkit"
    elif printf '%s' "$out" | grep -qi 'timed out\|Timeout'; then
        # The gate is working — too well to observe from here. polkit raised a
        # challenge and nothing answered it, so the daemon is still waiting
        # when the bus call gives up. Reporting "the gate may not be wired in"
        # for this sends the reader to audit code that is fine; the fault is
        # that there is no agent, or nobody is looking at the screen.
        skip "$label — the call timed out waiting for authentication"
        info "polkit asked and got no answer. Either no authentication agent is"
        info "running, or the prompt is on screen unanswered. With no graphical"
        info "session:  pkttyagent  in another terminal, then re-run."
    else
        fail "$label — unexpected result, the gate may not be wired in"
        info "${out%%$'\n'*}"
    fi
}

info "Expect a prompt for each. Cancel or authenticate — both are valid."
pause "Ready"

verdict "SshExportPrivateKey ($ACTION_SECRETS)" "$(call SshExportPrivateKey "$NIL_UUID")"
verdict "SshConnectCommand   ($ACTION_SSH_CONNECT)" "$(call SshConnectCommand "$NIL_UUID")"
verdict "TailscaleSetExitNode ($ACTION_TS_EXIT)" "$(call TailscaleSetExitNode "$UNASSIGNED_TS_IP")"

# ---------------------------------------------------------------------------
# 4. Does auth_admin_keep keep?
#
# The whole reason SshConnectCommand is not held at auth_admin. If the
# grace period does not work, every SSH session an operator opens gets a
# password prompt, and the policy file starts looking deletable.
# ---------------------------------------------------------------------------

say "The grace period on $ACTION_SSH_CONNECT"

info "Calling SshConnectCommand again. If you authenticated a moment ago,"
info "this should NOT prompt — that is what auth_admin_keep buys."
pause "Ready"

SECOND="$(call SshConnectCommand "$NIL_UUID")"
verdict "SshConnectCommand, second call" "$SECOND"
manual "did the second call prompt again? It should not have."
info "If it did, auth_admin_keep is not caching and the level is buying"
info "nothing over auth_admin — worth reconsidering which one to ship."

# ---------------------------------------------------------------------------
# 5. The ungated majority still works
#
# Prompt fatigue is the failure mode #109 warns about: gate something the
# GUI polls and the user gets a dialog every refresh, then turns the whole
# thing off. This is the canary.
# ---------------------------------------------------------------------------

say "Ungated methods are still ungated"

OUT="$(call ListHosts)"
if printf '%s' "$OUT" | grep -qi 'AccessDenied'; then
    fail "ListHosts asked for authentication — the GUI would prompt on every refresh"
else
    pass "ListHosts answered without a prompt"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

say "Result"
printf '  %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$MANUAL" -gt 0 ] && printf '  %d thing(s) marked LOOK need your eyes, not this script\n' "$MANUAL"

cat <<'EOF'

  Not covered here, and still worth a look while you are at it:

    - Open a real SSH session from the GUI and cancel the polkit prompt.
      It should say "Authentication was cancelled, so the session was not
      opened." — not "Failed to build SSH command:" followed by a D-Bus
      error name.

    - Open a second session straight after authenticating once. No prompt.

    - Check the daemon's view of what happened:
        sudo journalctl -u supermgrd -n 50 | grep -i 'authorized\|denied'
EOF

[ "$FAIL" -eq 0 ] || exit 1
exit 0
