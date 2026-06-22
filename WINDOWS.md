# SuperManager on Windows

Windows port of SuperManager. Native Slint GUI (`supermgr-win`) talking over a
named pipe to a Windows Service daemon (`supermgrd-win`). The same
`supermgr-core` crate, the same on-disk JSON formats, the same MCP server,
and the same RPC method names as the Linux/macOS apps — only the transport
and the privileged-side mechanisms differ.

## Architecture

```
┌──────────────────────┐   named pipe   ┌──────────────────────┐
│  supermgr-win (GUI)  │ ─────────────► │  supermgrd-win       │
│  Slint UI            │ \\.\pipe\      │  Windows Service     │
│  Runs as user        │  supermgrd     │  Runs as LocalSystem │
└──────────────────────┘                └──────────────────────┘
        ▲                                        │
        │                                        ▼
┌──────────────────────┐                ┌──────────────────────┐
│  supermgr-mcp        │                │  Win32 subsystems    │
│  MCP server (stdio)  │                │  • Credential Manager│
│  Same named pipe ↑   │                │  • WireGuardNT       │
└──────────────────────┘                │  • OpenVPN exe       │
                                        │  • Windows RAS (IKEv2)│
                                        │  • openfortivpn exe  │
                                        │  • WFP / IP Helper   │
                                        └──────────────────────┘
```

## Building

Toolchain: Rust stable 1.75+ with the MSVC target.

```powershell
# From the repo root
cargo build --release -p supermgrd-win -p supermgr-win -p supermgr-mcp
```

Do **not** use `cargo build --workspace` on Windows — that would also try to
compile the Linux daemon (`supermgrd`) which depends on `rtnetlink`, `nix`,
and other Linux-only crates. The workspace `default-members` list is set to
just `supermgr-core` and `supermgr-mcp` so plain `cargo build` Just Works on
any host.

## Installing

The recommended install is **`SuperManager-Setup-<version>.exe`** from
the latest GitHub Release. It is a single executable that installs
everything SuperManager needs — **no additional applications required**.

- **WireGuard**: `wireguard.dll` (WireGuardNT) + `wintun.dll` are
  bundled directly inside `SuperManager.msi`. The WireGuardNT kernel
  driver (`wireguard.sys`, signed by Microsoft WHQL) is embedded inside
  `wireguard.dll` and self-installs on first adapter creation. No
  WireGuard for Windows GUI, no system tray app, nothing in
  Add/Remove Programs beyond SuperManager itself.
- **OpenVPN**: `openvpn.exe` (CLI only, extracted from the upstream
  OpenVPN Community MSI at build time) is bundled directly inside
  `SuperManager.msi`. OpenVPN 2.6+ picks up `wintun.dll` from the
  same `bin\` directory and uses it as its TUN driver — no
  TAP-Windows6 driver, no OpenVPN GUI, no OpenVPN system service.
- **SuperManager**: daemon + GUI + MCP server + Windows Service
  registration, all in one MSI.

You get **one UAC prompt**, and the only thing that appears in
Add/Remove Programs is "SuperManager". WireGuard and OpenVPN are not
installed as separate applications.

To install the bare MSI directly (e.g. via Intune / SCCM):

```powershell
msiexec /i SuperManager-<version>.msi /qn
```

### Manual service registration (developer flow)

For local builds without an MSI, the same registration steps live in
PowerShell so a `cargo run -p supermgrd-win -- --console` cycle can
graduate to a service install once you're happy with the build:

```powershell
.\scripts\windows\install-service.ps1
```

### SmartScreen warning on the MSI

The published MSI is **not code-signed** (an EV / OV code-signing
certificate costs ~$200–300/year and the project doesn't ship one).
Windows SmartScreen flags unsigned installers with a "Microsoft Defender
SmartScreen prevented an unrecognized app from starting" prompt. To
proceed:

1. Verify the MSI's SHA-256 matches the `.sha256` file published next
   to it on the GitHub Release. From PowerShell:

   ```powershell
   Get-FileHash .\SuperManager-1.0.0.msi -Algorithm SHA256
   ```

2. Right-click the MSI → **Properties** → tick **Unblock** → **OK**.
   This stamps the file with the local `MOTW` zone-clean bit so
   SmartScreen accepts it for this user.
3. Alternatively, run the SmartScreen prompt → **More info** →
   **Run anyway**.

If you've procured a code-signing certificate later, the release
workflow ([`.github/workflows/release-windows.yml`](.github/workflows/release-windows.yml))
has a commented-out signing block ready to wire in — just set the
`WINDOWS_PFX_BASE64` and `WINDOWS_PFX_PASSWORD` repo secrets and
uncomment the step.

The script registers `supermgrd-win.exe` under the service name
`SuperManager`, sets it to auto-start, configures restart-on-failure, and
starts it. State lives under `%PROGRAMDATA%\SuperManager`.

To remove:

```powershell
.\scripts\windows\uninstall-service.ps1
```

## Packaging the installer

For end-user distribution, [`installer/wix/`](installer/wix/) contains a
WiX v5 MSI specification. The Burn bootstrapper wraps only the
SuperManager MSI — **no chained WireGuard or OpenVPN installers**.

```powershell
# Prerequisite: .NET SDK 8+ and WiX Toolset v5.
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add WixToolset.UI.wixext/5.0.2 --global
#   wix extension add WixToolset.Util.wixext/5.0.2 --global
#   wix extension add WixToolset.BootstrapperApplications.wixext/5.0.2 --global

# 1. Fetch + hash-verify the individual vendor binaries:
.\scripts\windows\Get-VendorFiles.ps1

# 2. Build the MSI (and optionally the Burn bundle wrapper):
.\installer\wix\build-msi.ps1          # bare MSI
.\installer\wix\build-msi.ps1 -Bundle  # Burn .exe wrapper around the MSI
```

`Get-VendorFiles.ps1` downloads the upstream packages listed in
[`vendor/manifest.toml`](vendor/manifest.toml), verifies their
SHA-256 hashes, and **extracts only the specific files SuperManager
needs** — it does not install WireGuard or OpenVPN system-wide.
Re-pin the manifest when you bump upstream versions.

The build script runs `cargo build --release` (skip with `-SkipBuild`),
then compiles the `.wxs` and emits `installer\wix\SuperManager.msi`. The MSI:

- Installs all binaries + vendor files under `%ProgramFiles%\SuperManager\bin\`:
  `supermgrd-win.exe`, `supermgr-win.exe`, `supermgr-mcp.exe`,
  `wireguard.dll`, `wintun.dll`, `openvpn.exe`, and optionally
  `openfortivpn.exe`.
- Registers `supermgrd-win.exe` as the `SuperManager` Windows Service
  (LocalSystem, Automatic start, Tcpip + Dhcp dependencies).
- Drops the install/uninstall/smoke-test PowerShell scripts under `scripts\`.
- Creates a Start Menu shortcut for the GUI.
- Tracks upgrades via a stable `UpgradeCode`; a new MSI uninstalls the
  old version in the same transaction.
- Handles service stop/start on install and uninstall so you don't have
  to touch `services.msc` manually.

### Bundling third-party binaries (vendor/)

`vendor/` is `.gitignore`d on purpose (license separation + version
drift). The only thing committed there is
[`vendor/manifest.toml`](vendor/manifest.toml), which pins the upstream
URLs + SHA-256 hashes. `Get-VendorFiles.ps1` populates the directory on
every CI run and locally before a release build.

| File                     | Source                                      | Runtime role |
|--------------------------|---------------------------------------------|--------------|
| `vendor/wireguard.dll`   | Extracted from WireGuardNT zip by `Get-VendorFiles.ps1` | Loaded by `wireguard-nt` crate at connect time. Embeds and self-installs `wireguard.sys` (WHQL-signed kernel driver) on first adapter creation. |
| `vendor/wintun.dll`      | Extracted from Wintun zip by `Get-VendorFiles.ps1` | Loaded by OpenVPN 2.6+ from its working directory. Embeds and self-installs `wintun.sys` on first use. |
| `vendor/openvpn.exe`     | Extracted from upstream OpenVPN Community MSI by `Get-VendorFiles.ps1` | Spawned as a subprocess by the OpenVPN backend. CLI-only; no GUI, no system service, not installed system-wide. |
| `vendor/openfortivpn.exe` | User-supplied (no upstream Windows binary exists) | Spawned by the FortiClient SSL VPN backend. Absent → `MissingDependency` error at connect time. Use FortiGate IKEv2 (Windows RAS, no extra software) for FortiGate connections. |

## Developer / console mode

Running the daemon outside the Service Control Manager is supported with
`--console` — useful for `cargo run`:

```powershell
cargo run -p supermgrd-win -- --console
```

In console mode logs go to stderr (filtered by `RUST_LOG`) instead of the
Application event log.

## What works today

- **SSH key management**: Ed25519, RSA-2048, RSA-4096 generation, listing, deletion, public-key export. Full round-trip GUI → pipe → daemon → Credential Manager + on-disk metadata. Public-key copy-to-clipboard via `arboard`.
- **Host CRUD**: Add / list / get / delete / toggle-pin against `%PROGRAMDATA%\SuperManager\hosts\*.json`.
- **SSH command execution** (`ssh_execute_command`): real `russh` session, password or key-based auth pulled from Credential Manager, captures stdout/stderr/exit-code.
- **VPN profile store**: TOML files under `%PROGRAMDATA%\SuperManager\profiles\`, fully compatible with the on-disk format the Linux daemon writes. Save / list / list-summary / get / delete.
- **WireGuard import**: parses `wg-quick` `.conf` files end-to-end, persists private key + PSKs to Credential Manager, writes the profile TOML.
- **WireGuard connect/disconnect** via `wireguard-nt` (requires the official WireGuardNT driver installed). Creates the adapter, applies config, assigns IPs and `AllowedIPs` routes via `Adapter::set_default_route`, brings the interface up, pushes DNS via `Set-DnsClientServerAddress`, applies MTU override via `Set-NetIPInterface`. Disconnect drops the adapter (kernel removes the interface) and reverts DNS. Gracefully reports a typed error when `wireguard.dll` isn't present.
- **OpenVPN connect/disconnect** via subprocess. Spawns `openvpn.exe` (probed from `%ProgramFiles%\SuperManager\bin\openvpn.exe` first — the bundled copy — then `OPENVPN_EXE` env var, then `%PATH%`, then the legacy OpenVPN install path). The subprocess working directory is set to `bin\` so OpenVPN 2.6+ finds `wintun.dll` automatically and uses it instead of TAP-Windows6 (no separate TUN driver installation needed). Opens its management socket on `127.0.0.1`, authenticates with a random per-connection token, waits for `>STATE:...,CONNECTED,SUCCESS` or a `>FATAL:` event. Disconnect sends `signal SIGTERM` over the management socket and falls back to `Child::kill` after 5 s. Resolves auth-user-pass from Credential Manager and cleans up the credentials file on disconnect.
- **IKEv2 connect/disconnect** (FortiGate profiles + any standards-compliant IKEv2 endpoint) via Windows' built-in RAS stack: `Add-VpnConnection` to register, `rasdial` to dial, polled `(Get-VpnConnection ...).ConnectionStatus` until `Connected`. Disconnect via `rasdial /disconnect` + `Remove-VpnConnection`. PSK + EAP password resolved from Credential Manager.
- **Azure Point-to-Site VPN** via Entra ID PKCE auth + generated `.ovpn`: token refresh from Credential Manager → fallback browser flow (PKCE code+challenge, loopback redirect listener) → access-token exchange → write `tls-auth.key` + `auth.txt` + `client.ovpn` to `%PROGRAMDATA%\SuperManager\runtime\azure-<id>\` → spawn `openvpn.exe` → wait for `Initialization Sequence Completed` → push DNS to the TAP/Wintun adapter via `Set-DnsClientServerAddress`. Refresh tokens are cached in Credential Manager so subsequent connects skip the browser flow.
- **FortiGate IKEv2** via Windows RAS — `Add-VpnConnection -TunnelType Ikev2 -AuthenticationMethod Eap -L2tpPsk <psk>` then `rasdial <name> <user> <password>`, polled to `Connected`. PSK + EAP password resolved from Credential Manager. GUI import form on the VPN tab; RPC method `import_fortigate`. No third-party client required — Windows ships everything needed.
- **FortiGate SSL VPN** via `openfortivpn.exe` (skeleton): spawn the open-source FortiGate SSL VPN client with the user's password fed on stdin (never argv), watch stdout for `Tunnel is up and running.` or a fatal `Could not authenticate`/`Connection refused` marker, sniff the PPP/Wintun interface name out of the log lines so DNS push targets the right alias. New profile import via `import_forticlient_sslvpn` RPC. `OPENFORTIVPN_EXE` env var, `%PATH%`, and `%ProgramFiles%\SuperManager\bin\openfortivpn.exe` are probed in order. **No upstream Windows binary exists**, so the FortiClient SSL VPN backend surfaces `MissingDependency` at connect time unless an admin provides their own build. Use the FortiGate IKEv2 backend above for the common case.
- **Connect/disconnect routing**: dispatcher picks the matching backend from `ProfileConfig` discriminator; `get_status` walks the active backends and returns the one with an open tunnel.
- **FortiGate REST API**: `fortigate_api`, `fortigate_push_ssh_key`, `fortigate_backup_config`. Bearer-token auth resolved from Credential Manager; backups saved to `%PROGRAMDATA%\SuperManager\backups\<host>_<timestamp>.conf`. HTTP semantics + error mapping identical to the Linux daemon.
- **UniFi Controller REST API**: `unifi_api` (cookie-based session via `POST /api/auth/login`), `unifi_set_inform` (SSH `set-inform <url>` against UniFi-adopted devices).
- **OPNsense REST API**: `opnsense_api`, `opnsense_backup_config`. HTTP Basic auth using the key/secret pair from Credential Manager; backups saved as `<host>_<timestamp>.opnsense.xml` so they don't collide with FortiGate `.conf` filenames.
- **Sophos XG XML Configuration API**: `sophos_xml_api`. Wraps the caller's `<Get>/<Set>/<Remove>` body in the WebAdmin `<Request><Login>...</Login>` envelope; credentials come from Credential Manager.
- **Persistent known_hosts**: SSH host keys recorded in `%PROGRAMDATA%\SuperManager\known_hosts.json` on first sight; subsequent connections require an exact match. A changed fingerprint surfaces as `RpcError::PermissionDenied` rather than silently going through TOFU again.
- **Named-pipe ACL hardening**: explicit SDDL grants `SYSTEM` + `Administrators` Generic All and `Authenticated Users` Read + Write (no DACL-modify). Built via `ConvertStringSecurityDescriptorToSecurityDescriptorW` and applied with `ServerOptions::create_with_security_attributes_raw`.
- **Tray icon** with Show / Hide / Quit.
- **Windows Service** start/stop/restart via the SCM.

### Smoke-test

A scripted end-to-end check lives at `scripts/windows/smoke-test.ps1`:
opens the named pipe, exercises the SSH-key lifecycle, imports a
deterministic WireGuard config, round-trips it through `list_profiles`,
and tears everything down.

```powershell
# In one terminal:
cargo run -p supermgrd-win -- --console

# In another:
.\scripts\windows\smoke-test.ps1
```

The first terminal logs every dispatched method; the second prints the
JSON-RPC responses end-to-end.

## What is stubbed (intentionally)

The Windows port now covers every VPN backend SuperManager supports and
every appliance API the Linux daemon exposes. Open items are MSI
polishing and code-signing for distribution — see the roadmap below.

## Roadmap

1. ✅ ~~`wireguard-nt` integration with active-tunnel tracking, DNS push, MTU override.~~
2. ✅ ~~Real ACL on the named pipe (SDDL for SYSTEM + Administrators + Authenticated Users).~~
3. ✅ ~~OpenVPN subprocess + management-protocol parser.~~
4. ✅ ~~PowerShell-driven IKEv2 (`Add-VpnConnection` / `rasdial`).~~
5. ✅ ~~FortiGate REST API + UniFi Controller API + UniFi set-inform.~~
6. ✅ ~~Persistent `known_hosts.json` for SSH host-key verification.~~
7. ✅ ~~Azure VPN backend (Entra ID PKCE auth + generated .ovpn + openvpn.exe).~~
8. ✅ ~~OPNsense REST API (`opnsense_api`, `opnsense_backup_config`).~~
9. ✅ ~~Sophos XG XML Configuration API (`sophos_xml_api`).~~
10. ✅ ~~WiX MSI installer specification + `build-msi.ps1` build script.~~
11. ✅ ~~FortiGate SSL VPN via `openfortivpn` (new `ForticlientSslvpn` profile type + `import_forticlient_sslvpn` RPC).~~
12. ✅ ~~Bundle `wireguard.dll` (WireGuardNT), `wintun.dll`, and `openvpn.exe` directly inside `SuperManager.msi`. No separate WireGuard for Windows or OpenVPN application installs — end users run one `SuperManager-Setup-<version>.exe` and get a single entry in Add/Remove Programs.~~
13. Code-signing (`signtool sign /fd SHA256` on the MSI + EXEs) is
    optional. The release workflow at `.github/workflows/release-windows.yml`
    has a commented-out signing block ready: drop a PFX cert into the
    `WINDOWS_PFX_BASE64` repo secret + uncomment the step. Until that
    lands, users see a SmartScreen prompt → "Run anyway" once per
    install (documented in the SmartScreen section above; SHA-256 of
    each release artifact is published as `.sha256` for hash verification).
14. Build openfortivpn from source in CI (MSYS2 or Cygwin toolchain)
    so FortiGate **SSL VPN** profiles also work out-of-the-box. The
    other four VPN backends (WireGuard, OpenVPN, Azure P2S, FortiGate
    IKEv2) all install bundled today.

Each item is independent; see the `TODO` comments in the corresponding
module for the precise next step.
