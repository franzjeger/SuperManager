# Local single-app consolidation — 2026-09-09

Installed `/Applications/SuperManager.app`, version `1.8.0-local.16`, build
`2026090916`. This is the locally tested Dev implementation with a rebuilt,
Developer-ID-signed UI. It is not a merge into main or a public release.

## Identity and data

The app deliberately retains `com.sybr.supermanager.dev`, the Dev Keychain
services, `~/Library/Application Support/SuperManager Dev`, the installed Dev
helper/runtime, and the existing Dev Tailscale node. No credentials were exported,
overwritten, or moved. Keeping these implementation identities avoids a second
data/credential migration; there is only one installed user-facing app.

The visible app/window/executable name is SuperManager. The DEV Dock badge and
two-service Tailscale switch panel were removed. Existing manual-networking
restrictions and disabled automatic updates remain. This consolidation does not
enable exit-node/DNS recovery, always-on VPN, scheduled scans, or production
update distribution. Historical activity can still contain old Dev messages.

The old Azure tunnel was disconnected through its helper's `ovpn_disconnect`
RPC before shutdown. The regular helper was stopped and persistently disabled
with launchd; regular Tailscale is also disabled. Dev Tailscale was left running.
The old helper socket was moved aside only after launchd reported no job and
connecting to the socket returned connection refused. This preserves the Dev
helper's networking exclusion gate rather than removing it.

## Archive and rollback

Private archive, excluded from Spotlight:

`~/Library/Application Support/SuperManager Archives.noindex/2026-09-09-consolidation/`

Contains both data snapshots, preferences, three previous installed app bundles,
and the old DerivedData Release app. Old bundles were unregistered from Launch
Services. Original regular data remains in place. No source-code checkout was
removed. Comparison found no regular-only profile/customer/SSH/Azure/OpenVPN/UniFi
files; differing profile fields were config_file, kill_switch, and updated_at.

For a local UI rollback, quit SuperManager and disconnect its tunnels, archive
the new app, restore `Apps/SuperManager Dev.app` to `/Applications`, and register
it with Launch Services. The preserved Dev helper, runtime, data and Keychain
remain compatible. Do not re-enable the regular helper while Dev tunnels are
active. A full return to the old regular channel requires an explicit network
handoff; the archived regular bundle and original data are retained for that.

## Rebuild

Use `scripts/dev/prepare_single_app.py --source . --output <new directory>`.
It applies the normal isolated Dev overlay plus `single-app.patch`, checking
the patch against the source layout. Generate Xcode and build the Release UI
as documented in `scripts/dev/README.md`.

The original local installation reused existing Rust binaries. The maintained
build entry point now builds both Rust components and the Swift UI from a clean
Git commit; it does not copy binaries from an installed app. See
`scripts/dev/SINGLE-APP.md` for the current build and installer instructions.

## Verification

- Native Xcode Release build succeeded; signed app passed deep/strict codesign.
- Prepared single-app source successfully reproduced with patch validation.
- GUI opened as SuperManager and loaded SSH hosts and all 26 VPN profiles.
- Azure reconnected through the signed GUI with existing cached credentials;
  GUI showed connected state, utun interface, assigned IP, traffic and routes.
- The customer's internal DNS server answered a DNS query after reconnection.
- Existing Tailscale node remained Running and online, with no identity copy.
- launchd confirms regular helper and Tailscale disabled, Dev helper running.
- Spotlight query for SuperManager app bundles returns only the installed app.
- `git diff --check` passed. No full Rust rerun: Rust/runtime binaries unchanged.

Reboot behavior was not exercised. Persistent launchd disablement was inspected.
App was left open with Azure connected and Tailscale online.
