# Local single-app build

This is the maintained local SuperManager channel. The visible app is
`SuperManager.app`; its existing Dev bundle, Keychain, data, helper and Tailscale
identities are intentionally retained. Do not rename these identifiers without
an explicit migration. This channel does not consume the public Sparkle feed.

## Build from one commit

Commit source changes first. Use the selected Xcode installation, Rust, XcodeGen
and the existing Developer ID Application signing identity. Supply a reviewed
pair of Tailscale executables; their hashes are recorded as external build inputs.

```sh
python3 scripts/dev/build_single_app.py \
  --output /absolute/new-build-directory \
  --tailscale /absolute/reviewed-tailscale-directory \
  --build 2026090917 --version 1.8.0-local.17
```

The command rejects dirty source, archives only committed files, generates the
local overlay, builds the engine/helper with `cargo --locked`, resolves the
committed Swift package pins, builds the UI, and signs all nested components.
`--cargo-target /absolute/cache` optionally reuses Cargo's normal build cache;
Cargo still builds the current source. Installed engine/helper binaries are
never used as build inputs. Output is a signed app and `build-provenance.json`
containing the commit, dependency pins/hashes, tool versions and final file
hashes. Signing timestamps/toolchain versions mean this is not a claim of
byte-for-byte reproducibility across machines or time.

The build never installs, restarts services, connects VPNs, publishes a release,
or modifies customer data. Keep generated output and provenance outside Git.

## System package

Build the matching runtime/package with the generated source's
`installer/system/` scripts and pinned runtime sources. The helper input must
come from this build's signed app. The generated preinstall script detects both
`SuperManager` and the older `SuperManagerDev` process names. Use a larger system
build number and disconnect tunnels/quit the app before an upgrade.

The original installed `.16` app reused the `.15` helper/runtime. Updating the
source does not silently upgrade that live installation. Package installation,
sleep/wake/reboot and recovery need their own recorded validation. Public
notarization, release feed activation and migration to the regular bundle ID
are separate work; do not enable the old regular helper alongside this channel.

## Review and publication

Use a feature branch and draft PR for the outstanding audit/consolidation work.
Commit source, tests, pins and documentation. Keep credentials, customer data,
machine snapshots, binaries and unreviewed diagnostic logs outside the PR.
Merge only after the remaining runtime/platform gates are addressed. The
historical remediation document records what was tested at each stage; the
consolidation document records the local installation rather than a public
release certification.

## Validation on 2026-09-09

The complete builder succeeded from clean commit
`b55e1e1ce48fc9446f7972886d932187c675efd1`, producing local build
`2026090918` (`1.8.0-local.18`) and its provenance manifest. The GUI, freshly built
engine and freshly built helper all contain ARM64 code; deep/strict signature
verification passed. This artifact was not installed over the working `.16` app.

The source snapshot passed 555 selected Rust tests (one subprocess helper is
intentionally ignored by the runner and exercised by its parent), 18 isolated
installer/runtime tests, 6 Dev preparation tests, and 14 isolated Swift
resolver/deployment tests. Six additional existing Keychain-query/version tests
passed in a disposable Swift package using the production Keychain sources and
the unchanged pure version enum; they did not read or change real credentials.
The generated installer contains both app executable names in its active-app
check and passes shell syntax validation. Full build/test logs and binary
artifacts remain local, outside the public repository.

No system package upgrade, reboot, live VPN change, new update feed, or public
release was performed during this source/build validation.

## Local upgrade and sleep validation — 2026-09-09

With the user's authorization, installed app `1.8.0-local.18` and signed system
package `2026090918` on the existing ARM64 Mac. The runtime was reused from
installed package `2026090915` after all 24 runtime files matched that release's
final payload hashes. Its source metadata was retained, with explicit repackaging
provenance; this was not a new runtime source build. The validator accepted all
seven Mach-O components. The new helper came from the clean-commit app build.

Azure was disconnected through the authorized helper before the app/engine were
stopped. Data, preferences and the previous app were privately backed up. macOS
Installer completed an actual upgrade with the old helper initially running.
The root-owned build counter is `2026090918`, no pending transaction remains,
and the signed client successfully queried the replacement helper. The upgraded
GUI connected Azure, displayed its interface/routes, and internal DNS answered.
Tailscale retained its existing online identity. The old regular helper remains
disabled, and Spotlight still finds only `/Applications/SuperManager.app`.

The first sleep request did not reach full system sleep and is not counted as a
passing test. A second attempt reached kernel system sleep at 16:37:02 CEST and
woke at 16:37:35, confirmed by `kern.sleeptime`/`kern.waketime`. Azure status and
an internal DNS query succeeded after waking; Tailscale remained Running/online.
This verifies one short sleep/wake cycle, not prolonged hibernation or every VPN.

Full reboot validation remains pending until the user logs back in. Before
reboot, the baseline boot time was 2026-09-09 13:08:30 CEST. After login, verify
the new boot time, build counter, one enabled helper, signed GUI authorization,
Tailscale identity and VPN connect/disconnect/route/DNS behavior. Installer
rollback backups remain under the system package state directory, and the
private user rollback snapshot is in `SuperManager Archives.noindex`.

## Reboot finding and ServiceManagement retirement

The 16:42:33 reboot exposed a migration defect: ServiceManagement restarted the
old regular helper from its archived app and reset its launchd enablement.
`launchctl disable` alone was not a durable removal of that SMAppService.
The new helper and app started, but their intended exclusion gate correctly
blocked VPN operations while the regular helper existed.

The regular service was then unregistered using the signed app-identity-bound
`SMAppService.daemon(plistName:).unregister()` API. Status changed from enabled
(`1`) to notRegistered (`0`); BTM records the daemon as disabled, and launchd no
longer has that service. The separate legacy `/Library/LaunchDaemons` plist was
moved into the private rollback archive too. Only after a connection to the old
socket was refused was that stale socket moved out of the active path.
Azure connected from the installed GUI after this correction.

For this migration, build `scripts/dev/build_retirement_tool.py` with `--old-app`
pointing at the preserved regular app and `--output` a new local `.app` path.
It constructs/signs the fixed-service tool but does not execute it. Disconnect
all regular-channel VPNs before running the printed executable. Confirm status
`0`, no regular launchd job, and no old process before retiring any stale socket
or legacy plist. Do not reset the machine-wide BTM database or disable other
developers' background items. Keep profiles and Keychain entries intact.

A further full reboot after this ServiceManagement correction has not yet been
verified; the earlier successful sleep test does not cover this registration
issue. The live post-correction VPN test is separate from reboot persistence.
