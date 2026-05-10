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

## The Developer ID path (real-product milestone)

Steps:

1. Buy Apple Developer Program — $99/yr.
2. Create a "Developer ID Application" certificate from
   https://developer.apple.com/account/resources/certificates.
3. `codesign --sign "Developer ID Application: <YOUR NAME>" --options runtime
   --entitlements SuperManager.entitlements --deep --force SuperManager.app`.
4. Notarise: `xcrun notarytool submit SuperManager.zip
   --keychain-profile SM-Notarisation --wait`.
5. Staple: `xcrun stapler staple SuperManager.app`.
6. Distribute via a `.dmg` with a code-signed `pkg` installer that drops
   the bundle into `/Applications/`.

`SuperManager.entitlements` should contain only the absolute minimum:

```xml
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <false/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <false/>
</dict>
```

We do NOT need the Personal VPN entitlement
(`com.apple.developer.networking.vpn.api`) because the bundled-strongSwan
+ root-helper architecture does not call NEVPNManager.

### Auto-update

Use **Sparkle 2** with EdDSA-signed appcasts. Host the appcast on
`https://supermanager.sybr.no/appcast.xml`. EdDSA keys generated with
`generate_keys` from Sparkle's tools.

### Why we haven't done it yet

The user has explicitly opted not to pay Apple. The path is documented
here for the day they change their mind.

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
