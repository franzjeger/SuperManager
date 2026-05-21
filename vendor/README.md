# Third-party binaries (`vendor/`)

Drop the following files into this directory before building the MSI to
get a fully bundled SuperManager installer.

| Filename / dir                | Source | Purpose |
|-------------------------------|--------|---------|
| `wireguard-installer.msi`     | Pinned in `manifest.toml`, fetched by `scripts/windows/Get-VendorFiles.ps1` from <https://download.wireguard.com/windows-client/> | WireGuardNT driver + DLL |
| `openvpn-installer.msi`       | Pinned in `manifest.toml`, fetched by `Get-VendorFiles.ps1` from <https://build.openvpn.net/> | OpenVPN Community Edition + TAP-Windows6 |
| `openfortivpn-bundle/`        | Produced by `scripts/windows/Stage-Openfortivpn.ps1` after installing the Cygwin `openfortivpn` + `ppp` packages | FortiGate SSL VPN client (`openfortivpn.exe` + `pppd.exe` + cygwin runtime DLLs) |
| `openfortivpn.exe` (legacy)   | User-supplied static binary (no maintained upstream) | Single-file fallback if you've built openfortivpn statically yourself |

## What happens with each file

- **`openfortivpn.exe`** — embedded directly inside `SuperManager.msi` by
  the WiX preprocessor (`installer/wix/supermanager.wxs`). If the file is
  absent, the MSI still builds and the FortiClient backend just surfaces
  a typed `MissingDependency` error at connect time pointing the user at
  `OPENFORTIVPN_EXE`.

- **`wireguard-installer.msi`** and **`openvpn-installer.msi`** — chain-
  installed by the optional **Burn bootstrapper** built from
  `installer/wix/bundle.wxs`. The bootstrapper produces a single
  `SuperManager-Setup.exe` that the user runs once; it walks the WireGuard
  installer's EULA + UAC, then OpenVPN's, then SuperManager's, in order.
  Without these MSIs the bare `SuperManager.msi` still ships — but users
  who don't already have the drivers installed get a typed error at
  connect time instead of an automatic install.

## Why the binaries aren't committed

`vendor/` is `.gitignore`d for two reasons:

1. **License separation**: WireGuard, OpenVPN, and openfortivpn ship under
   their own licenses (GPL, GPL, GPL respectively). Re-distributing them
   from the SuperManager Git repo would conflate the licenses; pulling
   them at build time keeps everyone honest.
2. **Version drift**: upstream releases come fast; pinning a version in
   git rots quickly. The build script verifies SHA-256 hashes against a
   manifest you control (`vendor/manifest.toml` — see `bundle.wxs`).

## Verifying downloads

Always compute the SHA-256 of each download and compare against the
publisher's signed hash file (WireGuard publishes `.sig` GPG signatures;
OpenVPN signs releases with the OpenVPN GPG key). The Burn bundle's
`<Payload>` elements carry their own `Hash="..."` attributes that you
update each time you bump a dependency.
