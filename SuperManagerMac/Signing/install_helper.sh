#!/usr/bin/env bash
# Retired. The app installs its own helper the first time it needs one,
# through HelperInstaller and one admin prompt, and that helper is the one
# inside the app bundle, signed like the app.
#
# This script installed a helper straight from cargo: signed only ad hoc and
# built with the `dev-rpc` feature. Neither works any more.
# - The helper now verifies that its client is the signed SuperManager app
#   (supermanager-helper/src/client_auth.rs). That links Security.framework,
#   and macOS kills a root daemon that links system frameworks under an ad
#   hoc signature (OS_REASON_CODESIGNING; see the note in build.rs).
# - `dev-rpc` adds development-only RPCs that must never reach a user's
#   machine.

echo "install_helper.sh is retired: build and run the app, which installs its own signed helper." >&2
echo "The comment at the top of this script says why." >&2
exit 1
