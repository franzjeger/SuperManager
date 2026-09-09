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

Azure profiles are copied, but **Azure VPN is unavailable**: the signed runtime
does not yet package OpenVPN 3. Dev explains this before starting Microsoft
sign-in. Tailscale's live machine identity/service is deliberately not shared;
Tailscale install, recovery, exit routes, always-on and kill-switch RPCs are
unavailable in this build. Existing signed-runtime restrictions on WireGuard
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

Native release Swift and Rust builds and all 83 helper tests passed. Five Python tests cover namespace
replacement, independent/private snapshots, no-overwrite, symlink rejection and
source-layout drift. Installed the signed Dev package; verified the running
separate launchd service, code signatures and GUI/engine connection. The GUI
loaded the copied VPN profiles and customer/SSH/UniFi records. The app-owned
login-Keychain copy completed without errors.
No customer VPN connection was established as part of validation. Stable app
and helper binaries were left untouched. These are local test artifacts, not a
notarized public release.
