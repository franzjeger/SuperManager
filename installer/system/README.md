# macOS system components — candidate packaging pipeline

This pipeline replaces unsigned helper copying, `deploy_self`, Homebrew root
execution and the GUI's administrator-shell fallback. It builds a matching helper
and VPN runtime package. **It is not cleared for production rollout until the
live test matrix below passes on a disposable macOS host.**

## Build and trust chain

Build on the target architecture with Xcode CLI tools, make, Perl, Python 3.9+,
pkg-config and Go. Build tools are not installed by these scripts. Everything is
built under the output directory; no `sudo`, service startup or VPN connection is
part of the build.

```sh
python3 installer/system/build_runtime.py \
  --output /absolute/new-build-directory --go /absolute/path/to/go
```

`--source-cache /absolute/cache` can reuse previously downloaded `<name>.archive`
files. Every cached file is still SHA-256 checked. The output contains `runtime/`,
`manifest.json`, retained source archives and the build tree. Archive extraction
rejects escaping paths, links and special files; the one known upstream wg-quick
source-tree convenience symlink is omitted explicitly.

`sources.lock.json` pins archives, versions and license metadata. WireGuard-Go's
2025-05-22 archive differed from the published Homebrew archive hash on 2026-09-09.
Before changing the pin, the upstream Git tag's PGP signature was verified with
fingerprint `AB9942E6D4A4CFC3412620A749FC7012A5DE03AE`, and **every regular archive
file** was compared byte-for-byte with the signed Git tree, with no extra/missing
files. The previous hash, tag object, commit and verification record are retained
in the lock. This establishes source-content equivalence; it does not explain why
the compressed archive bytes changed. References: [upstream signed tag](https://git.zx2c4.com/wireguard-go/tag/?h=0.0.20250522),
[author's public key](https://www.zx2c4.com/keys/AB9942E6D4A4CFC3412620A749FC7012A5DE03AE.asc),
[Homebrew formula](https://raw.githubusercontent.com/Homebrew/homebrew-core/HEAD/Formula/w/wireguard-go.rb).

OpenSSL is static and strongSwan is monolithic. The package excludes development
headers, archives and extra tools. wg-quick uses the packaged Bash and a fixed
protected/system PATH. Native dependency load commands must resolve to system
libraries or files inside the protected runtime; unresolved `@rpath`, external
libraries, Homebrew strings, symlinks, writable files and wrong architectures fail
validation. License texts are retained. Retain the corresponding source/build
materials with releases; a URL list is not a substitute for source distribution.
Go modules are pinned by the upstream go.mod/go.sum; archive hashes do not cover
the downloaded Go compiler or the local C toolchain. Record those tool versions
in release evidence. This is not a claim of bit-for-bit reproducible builds.

Build/sign the release helper separately with bundle ID
`com.sybr.supermanager.helper`, Developer ID team `LY6LJ395B8`, hardened runtime
and the helper's empty entitlements. The package builder verifies the supplied
helper rather than silently signing an arbitrary helper input.

```sh
python3 installer/system/build.py \
  --runtime /absolute/new-build-directory/runtime \
  --manifest /absolute/new-build-directory/manifest.json \
  --helper /absolute/path/to/signed-helper \
  --build 2026090906 \
  --application-identity 'Developer ID Application: Frank Lia (LY6LJ395B8)' \
  --installer-identity 'Developer ID Installer: Frank Lia (LY6LJ395B8)' \
  --output /absolute/output/SuperManager-system-arm64.pkg
```

Use a fresh, monotonically increasing **integer system build**, separate from the
app's semantic version. Same-build replacement is rejected too. The package
builder checks a private snapshot before signing runtime Mach-O files and records
hashes of the final signed payload. There is no unsigned distribution fallback.
`release.sh` requires the runtime, manifest, integer build and both signing
identities; it propagates Xcode failures and notarizes/staples the signed package.
Do not distribute a locally signed-but-unnotarized test artifact as a release.

## Installation and recovery

Install with macOS Installer on a disposable host first. Only the running system
volume and the package's architecture are accepted. Quit the app and disconnect
VPNs first; active SuperManager/OpenVPN/charon/wireguard-go processes block setup.
Preflight refuses unsafe root directories and legacy installations without a
trusted build counter. **There is no automatic legacy migration.** Preserve
credentials/configurations and establish a tested migration procedure before
replacing earlier manual/Homebrew setups. Do not remove an existing production
helper merely to bypass this gate.

The root-owned state directory is
`/Library/Application Support/SuperManagerSystem`. Versioned payloads are under
`releases/<build>`; the active runtime remains at
`/Library/PrivilegedHelperTools/SuperManagerVPN`. The helper and launchd plist use
the fixed `com.sybr.supermanager.helper` identifier. The former DNS-only package
referenced a different helper path; it is not a substitute for this system package.
This candidate does not add a new boot-time DNS reaper.

Publication holds an exclusive directory lock and rechecks the build floor.
The previous helper/runtime/plist are backed up privately before the `pending`
journal is published. Failed launchd activation restores the prior components.
A killed installer can be recovered by running the exact root-owned
`backup-<build>/recovery.sh` identified by `pending`, after ensuring no installer
is still running. Recovery will not adopt an unrelated journal. If the process
died before journal creation, inspect the unchanged live installation and release
the stale `install.lock` only after confirming no installer remains.

Backups and versioned payloads remain for operator inspection. Backups may contain
VPN secrets: preserve mode 0700 and use a retention policy. Do not delete pending
recovery materials. Shell/file rename tests cover process interruption, **not
power-loss durability**. Recovery restores files and service registration; it does
not prove restoration of routes, DNS or live VPN sessions. A socket and running
launchd state are activation evidence, not an authenticated end-to-end health test.

The GUI now requires an authorized version RPC and policy version 2; socket
existence alone is insufficient. System Component Setup reports signed-app,
package and runtime requirements. Unsupported profile directives remain errors.
OpenVPN3/Azure, WireGuard hooks/DNS/Table/SaveConfig and external OpenVPN credential
paths are still unsupported through this helper; there is no advertised parity.

## Tests and release gate

```sh
python3 -m unittest discover -s installer/system/tests -v
python3 installer/system/tests/test_identity.py --run-signed
cargo test --locked -p supermanager-helper --features dev-rpc
```

The first command runs the real transaction scripts against temporary files, with
root identity, signing and launchd mocked. It tests commit, rollback, interrupted
recovery, altered payloads, build-floor enforcement and concurrent publication.
The second signs temporary client fixtures and exercises the actual kernel audit-token/Security.framework boundary through an unprivileged listener. It performs
no infrastructure actions and requires local access to the Developer ID key.

Before release, record results on **both supported Mac architectures**:

- Actual signed GUI → installed helper authorization, including unsigned/debug,
  wrong identity, stale helper and malformed-frame rejection.
- Fresh package installation, permitted upgrade, downgrade refusal, and interrupted
  installation/recovery; verify receipt, permissions, signatures and private logs.
- WireGuard, OpenVPN 2 and IKEv2: connect, handshake, traffic, route/DNS changes,
  disconnect, reconnect and concurrent-profile behavior against disposable gateways.
- GUI/helper/VPN process crash, sleep/wake, network loss and reboot: verify both
  connectivity recovery and absence of unexpected routes/DNS/credential residue.
- Legacy migration and uninstall, with customer credentials preserved intentionally.

Compilation, signature validity, package construction and mocked transactions do
not satisfy this live release gate. Do not merge this candidate into a release
until the missing operational results are available.
