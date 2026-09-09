# SuperManager Dev (macOS, local test build)

This is a separate, manually operated test application. It is **not a network
sandbox** and does not establish full feature parity with the installed app.
The scripts generate a disposable source overlay; they never rewrite the input
checkout or copy customer data into Git. Keep this overlay temporary until the
application's scattered platform constants can move into a tested build-channel
configuration. Review the overlay whenever upstream source changes.

## Isolation

| Component | Dev identity |
|---|---|
| Application | `/Applications/SuperManager Dev.app` |
| Bundle / preferences | `com.sybr.supermanager.dev` |
| GUI executable | `SuperManagerDev` |
| User engine executable | `supermanager-dev-engine` |
| User data | `~/Library/Application Support/SuperManager Dev` |
| Keychain services | `com.sybr.supermanager.dev.{vpn,masterpassword,azure-vpn,tailscale}` |
| Privileged service | `com.sybr.supermanager.dev.helper` |
| VPN runtime | `/Library/PrivilegedHelperTools/SuperManagerDevVPN` |
| IKE control socket | `/private/var/run/supermanager-dev-ipsec/charon.vici` |
| WireGuard mapping prefix | `sdwg` (regular app uses `smwg`) |
| OpenVPN process prefix | `supermgr-dev-ovpn-` |
| Package state | `/Library/Application Support/SuperManagerDevSystem` |

Profiles retain their identifiers within an independent private data copy. No
ongoing synchronization occurs. The snapshot disables `auto_connect` and
`kill_switch`; the generated engine disables scheduled scans. The Dev helper
starts no route/DNS/reconnect watchdogs and exposes only manual VPN operations,
status, and capability inspection. Its root RPC gate refuses VPN changes while
the regular helper or regular strongSwan socket exists. A stale socket also
blocks deliberately; do not delete sockets to evade a running service.

**Closing the regular app does not stop its privileged service.** Disconnect its
tunnels and arrange an explicit test window before stopping that service. Dev
and stable share OS routing, DNS and IKE ports. This gate does not isolate them
from unrelated VPN applications or a stable service restarted during a test.

Azure VPN now uses the pinned, statically linked OpenVPN 3 runtime extension in
`installer/system/openvpn3/`. The helper selects this engine explicitly for
Azure; regular OpenVPN continues to use OpenVPN 2. Tokens cross a private stdin
pipe, never argv or an authentication file. The UI checks runtime capability
before Microsoft sign-in. Build the extension with `--dev` and package its
returned runtime/manifest, not the base runtime. Existing stable/Dev networking
exclusion still applies; this build does not disconnect existing customer VPNs.

Tailscale's machine identity and service are separate from stable. Manual install,
start, uninstall, login, peer access and subnet-route acceptance are enabled.
Exit-node routing and global DNS/recovery RPCs remain unavailable; Dev starts
with accept-DNS and accept-routes disabled. Pause other Tailscale nodes before
authenticating Dev to avoid competing routes. VPN always-on/kill-switch RPCs
remain unavailable. Existing signed-runtime restrictions on WireGuard
DNS/Table/hooks/SaveConfig and external OpenVPN files/scripts also apply. Do not
interpret an imported profile as evidence that its connection is supported.

## Build

Requirements: macOS ARM64, Xcode, XcodeGen, Rust, Go, and the pinned Developer ID
Application/Installer identities described in `installer/system/README.md`.
Choose new output paths. Build from the checkout whose actual local changes you
intend to test; the snapshot includes uncommitted source changes.

```sh
python3 scripts/dev/prepare.py --source . --output /tmp/supermanager-dev-source
cd /tmp/supermanager-dev-source
CARGO_TARGET_DIR=/tmp/supermanager-dev-target cargo build --release -p supermgrd-mac -p supermanager-helper
cd SuperManagerMac
xcodegen generate
xcodebuild -project SuperManager.xcodeproj -scheme SuperManagerMac -configuration Release -derivedDataPath /tmp/supermanager-dev-derived CODE_SIGNING_ALLOWED=NO build
```

From the original checkout, assemble using `scripts/dev/assemble.py --app
<DerivedData>/Build/Products/Release/SuperManagerMac.app --rust
/tmp/supermanager-dev-target/release --output '/Applications/SuperManager Dev.app'
--build <monotonic-build> --version <dev-version>`. Optionally pass
`--tailscale <reviewed-stable-app>/Contents/Resources/tailscale-bin` to include
version inspection/CLI support. Assembly refuses to overwrite an existing app;
quit and move the previous Dev bundle to a backup first. Never replace stable.

Build the runtime and signed system package with the **generated overlay's**
`installer/system/build_runtime.py` and `build.py`, following that directory's
instructions. Use the Dev app's signed `com.sybr.supermanager.dev.helper` as the
helper input. A production runtime is not interchangeable: strongSwan's compiled
control socket, runtime prefix and wg-quick config path must match Dev. Increase
the system build number on every replacement. Quit Dev and stop its VPN sessions
before installing the signed package with macOS Installer. The package installs
only the separately named Dev service/runtime; it does not stop stable.

## One-time data and credential copy

Run `copy_data.py --source "$HOME/Library/Application Support/SuperManager"
--destination "$HOME/Library/Application Support/SuperManager Dev"`. It refuses
an existing destination and symlinks, omits transient sockets/PIDs/logs, rewrites
internal data paths and writes private directories/files (0700/0600). For a
consistent snapshot, avoid editing stable data during copying. External SSH
paths/config references are not automatically duplicated.

Compile `CopyKeychain.swift` with Xcode's Swift compiler and matching macOS SDK,
sign it with the Developer ID Application identity, then run it locally. It
copies only the four app-owned login-Keychain services, never prints values,
and never replaces existing Dev items. Normal Keychain prompts may occur. It
does not claim access to legacy Data Protection Keychain items. Never use a
plaintext credential export. Preferences start with the Dev bundle's defaults.

## Validation on 2026-09-09

Native release Swift and Rust builds and all 87 helper tests passed. Five Python tests cover namespace
replacement, independent/private snapshots, no-overwrite, symlink rejection and
source-layout drift. Installed the signed Dev package; verified the running
separate launchd service, code signatures and GUI/engine connection. The GUI
loaded the copied VPN profiles and customer/SSH/UniFi records. The app-owned
login-Keychain copy completed without errors.
No customer VPN connection was established as part of validation. Stable app
and helper binaries were left untouched. These are local test artifacts, not a
notarized public release.

Azure extension verification: four compiled credential-adapter tests passed
(size boundaries, control characters, stalled pipe timeout, argument rejection,
and actual CLI configuration evaluation). The actual local Azure profile passed
both the helper input validator and OpenVPN 3 evaluation. OpenVPN 3's crypto
self-test passed. No live customer connection is claimed by these checks.

### macOS live verification — 2026-09-09, Dev 1.8.0-dev.7

With the user's authorization, stopped the stable Azure tunnel and helper before testing Dev. Removed the stable socket only after launchd reported no service and a socket connection was refused.

Live testing exposed a PID persistence failure: `/var` is a symlink and `/private/var/run` is root:daemon 0775 on the test Mac. OpenVPN session files now use the protected `SuperManagerVPNState` directory beside the runtime (transformed to `SuperManagerDevVPNState` for Dev). The strict ancestor checks remain enabled; system directory permissions were not changed.

Verified the signed Dev OpenVPN 3 executable connected to the existing Azure profile, created a utun interface, installed the gateway-pushed customer routes, and received a DNS response from the customer's internal DNS server. The GUI displayed the matching interface and connected status. Disconnect terminated the process, removed customer routes, and restored the original DNS servers. Reconnect was tested afterward. Helper tests: 87 passed. Other VPN profile types were not live-tested in this run.

### Credential recovery and WireGuard follow-up

User reports WireGuard works in Dev. FortiGate/IKEv2 connection failed before reaching the helper because referenced credentials were absent from the accessible login Keychain. An attributes-only inventory found no VPN-service items in either stable or Dev, with 32 non-empty profile password/PSK references unmatched. This does not establish whether the values remain in the older entitlement-protected Data Protection Keychain. No secret values were exported.

Missing-item errors now explain credential re-entry and IKEv2 connection errors provide an Edit credentials action. Other Keychain failures retain their distinct error status. The editor clarifies that a blank field cannot recover a missing secret. FortiGate end-to-end validation remains blocked until credentials are supplied through the application.

### IKEv2 live verification — Dev 1.8.0-dev.11

Fixed two independent packaging defects exposed by the FortiGate test:

- Dev charon PID/VICI state now lives in `/Library/PrivilegedHelperTools/SuperManagerDevIPSecState`. The helper and strongSwan build agree on this path, outside the immutable runtime and outside group-writable `/private/var/run`.
- The curated strongSwan build explicitly enables IKEv2. `--disable-defaults` had disabled the protocol itself even though the daemon and authentication plugins were present. The build checks generated `config.h` for `USE_IKEV2`.

A clean native rebuild was required: changing configure compiler flags did not invalidate all existing VICI object files. Verified both installed executables contain the new socket path and no old Dev socket path. Do not reuse an incremental strongSwan build when changing its runtime path.

Verified the user's FortiGate profile reaches ESTABLISHED IKEv2 and INSTALLED CHILD_SA, receives a virtual address, and installs the configured split routes. A two-packet ICMP check to the customer's gateway succeeded through the tunnel. Disconnect removed the SA and route; reconnect was exercised. The generic CHILD_SA failure message no longer falsely asserts that IKE authentication succeeded. Validation: 87 helper tests, 15 installer/runtime tests, 5 Dev tests.

### Tailscale Dev support — 1.8.0-dev.14 (system package 2026090913)

The signed helper installs independently signed Dev CLI/daemon binaries, the
`com.sybr.supermanager.dev.tailscaled` LaunchDaemon, private 0700 state at
`/private/var/lib/supermanager-dev-tailscale`, a separate local API socket, and
UDP port 41642. Node credentials are never copied from the stable daemon.
Installation omits the stable implementation's global exit-route cleanup.

The launchd environment pins `TS_LOGS_DIR` to the Dev state directory. Tailscale
otherwise chooses a shared default log-state directory independently of its
`--statedir` setting ([upstream implementation](https://github.com/tailscale/tailscale/blob/main/logpolicy/logpolicy.go)).
The first startup probe exposed that shared logging default; the final service
was restarted and its independent log configuration verified.

Verified through the signed GUI: installation succeeds, the local CLI reaches
the Dev socket without elevation, the daemon reaches NeedsLogin with no node
identity, and stopping/starting through the Start daemon flow succeeds. Stable
Tailscale was left running because permission to pause it remained pending.
The user then signed in through the app. Dev reached Running under its own
`supermanager-dev` identity. A daemon-specific Tailscale ping reached the home
subnet router via DERP. After enabling route acceptance, the OS installed the
advertised home subnet and ordinary ICMP to its LAN gateway succeeded.
Connect now preserves saved preferences instead of resetting route acceptance.
The settings switch is labelled "Access LANs through subnet routers" with a
plain-language explanation. Stable Tailscale remains a separate running node;
permission to pause it was still pending at this point.
Validation: macOS Release build, 87 helper tests, 6 Dev tests; signed app and
system package installed. A launchd bootstrap race triggered installer rollback;
the rollback backup was preserved, and installation succeeded after explicitly
stopping the old helper. That installer timing issue remains follow-up work.
