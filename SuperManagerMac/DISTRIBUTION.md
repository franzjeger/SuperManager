# SuperManager Mac — Distribution Strategy

## Where we are today

The app ships **ad-hoc signed**, with **strongSwan** as an external Homebrew
dependency. This is the only configuration that delivers full
"control-VPN-from-the-app" behaviour without an Apple Developer Program
membership.

| Path                                       | Cost      | Fully programmatic VPN? | First-run UX |
| ------------------------------------------ | --------- | ----------------------- | ------------ |
| Ad-hoc + brew strongSwan ← **today**       | $0        | ✅                      | ❌ Manual brew install |
| Ad-hoc + bundled strongSwan                | $0 + work | ✅                      | ✅ Self-contained |
| Developer ID + bundled strongSwan          | $99/yr    | ✅                      | ✅ Self-contained, signed, notarised |
| Mac App Store (NEVPNManager)               | $99/yr    | ✅                      | ✅ Signed, sandboxed, easy install |

The two remaining pillars to get to "actual product" are:

1. **Bundle strongSwan** — strip the brew dependency.
2. **Developer ID signing + notarisation** — strip the Gatekeeper warning.

## The bundled-strongSwan path (next milestone)

strongSwan brew formula's runtime artefacts are:

```
<prefix>/bin/swanctl                       — vici client, ~600 KB
<prefix>/bin/charon-cmd                    — single-shot runner (we don't use it)
<prefix>/libexec/ipsec/charon              — IKE daemon, ~1.5 MB
<prefix>/libexec/ipsec/{starter,stroke}    — legacy stroke control plane
<prefix>/etc/swanctl/                      — config root (we own the supermanager-* subset)
<prefix>/etc/strongswan.d/charon{,.conf}/  — daemon config
<prefix>/etc/strongswan.conf               — main config
<prefix>/share/                            — manpages (skip)
```

Total: ~4.7 MB. Acceptable for a VPN helper.

### Build approach

```
contrib/build-strongswan.sh
  - Clone strongswan/strongswan tag 6.0.6
  - ./autogen.sh && ./configure --prefix=/opt/sm-strongswan \
      --enable-vici --enable-swanctl --enable-eap-mschapv2 \
      --enable-eap-identity --enable-pubkey --enable-openssl \
      --disable-systemd --disable-charon-cmd
  - make -j $(sysctl -n hw.ncpu)
  - DESTDIR=$BUILDROOT make install
  - lipo together arm64 + x86_64 builds for universal2
  - Copy under SuperManager.app/Contents/Resources/strongswan/
```

### Runtime changes required

`supermanager-helper/src/strongswan.rs`:

```rust
const BREW_PATHS: &[&str] = &["/opt/homebrew", "/usr/local"];
```

becomes:

```rust
fn install_root() -> PathBuf {
    // Bundle path is the canonical location once the helper is installed.
    // Only fall back to brew during dev iteration.
    let bundled = Path::new("/Library/PrivilegedHelperTools")
        .parent().unwrap()
        .join("SuperManager.app/Contents/Resources/strongswan");
    if bundled.exists() { return bundled; }
    PathBuf::from("/opt/homebrew/opt/strongswan")
}
```

Plus `tools/cargo-bundle.sh` to copy the strongSwan tree into the app
during `cargo build --release`.

### Why we haven't done it yet

It's a one-shot 1-2 day sprint that doesn't gate the current daily-use
workflow on this machine. Brew is installed; rolling our own strongSwan
build is best done after the Developer ID path is committed.

## The Developer ID path (current — Apple Developer Program enrolled)

### One-time setup (done once per developer machine)

1. **Create the Developer ID Application certificate.**
   - https://developer.apple.com/account/resources/certificates
   - "Create a Certificate" → "Developer ID Application" → upload a CSR
     generated from Keychain Access → download + install the .cer.
   - Verify with `security find-identity -p codesigning -v` — should show
     a line like `"Developer ID Application: Your Name (LY6LJ395B8)"`.

2. **Create an App Store Connect API key for notarisation.**
   - https://appstoreconnect.apple.com/access/integrations/api
   - Generate a key with the "Developer" role.
   - Download the `AuthKey_XXXXXX.p8` file (one-time download — re-create
     the key if you lose it).
   - Note the Key ID + Issuer ID printed alongside.

3. **Export the API key env vars in your shell profile** (`~/.zshenv`):
   ```sh
   export DEVELOPER_ID_APP="Developer ID Application: Your Name (LY6LJ395B8)"
   export AC_API_KEY_PATH="$HOME/.appstoreconnect/AuthKey_ABCD123456.p8"
   export AC_API_KEY_ID="ABCD123456"
   export AC_API_ISSUER_ID="00000000-0000-0000-0000-000000000000"
   ```

4. **Generate the Sparkle EdDSA keypair** (one-time):
   ```sh
   ./scripts/sparkle-keygen.sh
   ```
   This stores the private key in your Mac Keychain and prints a public
   key. Paste the public key into `SUPublicEDKey` in
   `SuperManagerMac/project.yml`, then `xcodegen generate`.

5. **Update `project.yml`'s `DEVELOPMENT_TEAM`** if your paid Team ID
   differs from the Personal Team ID currently baked in.

### Per-release flow

```sh
./scripts/release.sh 1.0.0
```

The script:
1. Bumps `CFBundleShortVersionString` + `CFBundleVersion` in `project.yml`.
2. Regenerates `.xcodeproj` via xcodegen.
3. `xcodebuild build` in Release config.
4. Re-signs the app + embedded daemon + helper with the Developer ID
   identity (hardened runtime, secure timestamp).
5. Submits to Apple's notary via `notarytool` and waits for verdict.
6. Staples the notarisation ticket onto the .app.
7. Zips for distribution → `dist/SuperManager-<version>.zip`.
8. Signs the zip with Sparkle's `sign_update` → appcast signature.
9. Generates `dist/appcast.xml` pointing at the GitHub Releases download URL.

Then manually:
```sh
git commit -am "chore: release v1.0.0"
git tag v1.0.0 && git push origin main v1.0.0
gh release create v1.0.0 dist/SuperManager-1.0.0.zip dist/appcast.xml \
    --title "v1.0.0" --notes-file CHANGELOG.md
```

Sparkle picks up the new appcast within `SUScheduledCheckInterval` (1 day)
or immediately when the user clicks **SuperManager → Check for Updates…**.

### CI-driven release (preferred, after one-time secret setup)

`.github/workflows/release.yml` reproduces the entire local
`release.sh` flow on a GitHub-hosted macOS runner. Trigger by
pushing a `v*.*.*` tag — no local build needed. The workflow:

1. Spins up a temporary signing keychain on the runner
2. Imports the Developer ID cert + Sparkle private key from
   repository secrets
3. Stages the App Store Connect API key
4. Runs `./scripts/release.sh "$TAG"` end-to-end
5. Uploads `dist/SuperManager-<version>.zip` + `dist/appcast.xml`
   to the GitHub Release that the tag triggered
6. Tears down the keychain so no signing material lingers

#### One-time secret setup

Add these via **Settings → Secrets and variables → Actions →
New repository secret**:

| Secret | Value | How to produce |
|---|---|---|
| `MACOS_CERTIFICATE` | Base64 of `.p12` export | Keychain Access → My Certificates → right-click cert → Export → .p12 → `base64 -i cert.p12 -o cert.b64` then copy contents |
| `MACOS_CERTIFICATE_PASSWORD` | Plain string | Password you chose during the .p12 export |
| `MACOS_DEV_ID_APP` | `Developer ID Application: Your Name (LY6LJ395B8)` | From `security find-identity -p codesigning -v` |
| `AC_API_KEY_BASE64` | Base64 of `AuthKey_XXXXXX.p8` | `base64 -i ~/.appstoreconnect/AuthKey_*.p8 -o ac.b64` |
| `AC_API_KEY_ID` | 10-char key id | Already in `~/.zshenv` (`$AC_API_KEY_ID`) |
| `AC_API_ISSUER_ID` | UUID | Already in `~/.zshenv` (`$AC_API_ISSUER_ID`) |
| `SPARKLE_PRIVATE_KEY` | Base64 ed25519 seed | `security find-generic-password -a ed25519 -s 'https://sparkle-project.org' -w` |

The `SPARKLE_PRIVATE_KEY` is the most sensitive secret — anyone
with it can push malicious updates to all installed copies.
Rotate via `./scripts/sparkle-keygen.sh --force` if it ever
leaks; the matching public key in `project.yml` would then need
to be updated, breaking existing installs' ability to auto-update
(they'd need to manually download the next signed release).

#### Cutting a release through CI

```sh
# After updating CHANGELOG, project.yml is bumped automatically by
# release.sh INSIDE CI. So locally:
git tag v1.0.1
git push origin v1.0.1
```

Watch progress at https://github.com/franzjeger/SuperManager/actions.
Apple notarisation takes 5-30 min, so the full workflow typically
runs 12-35 min.

### Auto-update internals

The app reads `SUFeedURL` from Info.plist on launch. Sparkle polls that
URL for `appcast.xml`, compares versions, and — if newer — verifies the
appcast's EdDSA signature against `SUPublicEDKey` (also in Info.plist)
before offering the update. An attacker who controls the feed URL cannot
ship a malicious update without the matching private key.

The release script is the only path that signs an update for production.
Lose the Sparkle private key → can't ship updates until you generate a new
keypair + ship a new public-key bake-in (which breaks existing installs'
ability to auto-update; they'd have to manually download the next signed
release).

`SUPublicEDKey` lives in `project.yml` → `SuperManagerMac.info.properties.SUPublicEDKey`.
The string `REPLACE_ME_RUN_sparkle-keygen.sh` is the placeholder shipped
in source — Sparkle will refuse to install anything until it's replaced
with the real key from `sparkle-keygen.sh`.

## The MAS / NEVPNManager path (revisited)

Adding strongSwan as a bundled binary blocks Mac App Store eligibility
(MAS forbids bundled executables that aren't sandboxed). Going MAS
requires switching to `NEVPNProtocolIKEv2` and the Personal VPN
entitlement, which is a full rewrite of the VPN bring-up. Out of scope
for the current architecture.

## Today's user-facing improvements

Without changing the distribution model, we can still close the worst
day-1 friction:

1. **Detect missing strongSwan and offer to install it.**
   - Helper already returns `"strongSwan not installed"` from
     `vpn_status` when the binaries can't be resolved.
   - Add a banner in the VPN tab and an "Install strongSwan…" button
     that opens Terminal with the brew command on the clipboard.
2. **Detect missing Homebrew and surface the install one-liner.**
3. **Diagnostics export** for bug reports: zip helper log + daemon log
   + redacted profile listing into `~/Desktop/SuperManager-diagnostics-<date>.zip`.

These are tracked as todo items C7 and the E1-followups in the roadmap.

## Decision log

| Date       | Decision                                          | Rationale |
| ---------- | ------------------------------------------------- | --------- |
| 2026-05-08 | Tunnelblick-style helper + brew strongSwan        | Free-tier path that actually controls the VPN from the app |
| 2026-05-08 | `dev-rpc` cargo feature for `deploy_self`         | Production builds drop the priv-esc dev RPC |
| 2026-05-08 | Defer Developer ID purchase                       | Architecture is decoupled; it can be added later without rework |
| TBD        | Bundle strongSwan or stay on brew                 | Pending: when the install-Homebrew-first friction becomes the top complaint |
