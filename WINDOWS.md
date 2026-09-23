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

Download **[SuperManager-Setup.exe](https://github.com/franzjeger/SuperManager/releases/latest/download/SuperManager-Setup.exe)** and open it. Approve the Windows administrator prompt, then choose Install. It is a single
executable that installs the app and its supported VPN dependencies:

1. Microsoft Visual C++ x64 runtime (when missing or older)
2. WireGuard for Windows and the WireGuardNT DLL beside SuperManager
3. OpenVPN Community Edition (openvpn.exe and VPN drivers)
4. SuperManager (app, background service, MCP server and Start menu shortcut)

You get one administrator prompt and one progress window. The dependencies
are embedded; no separate downloads or terminal commands are needed. Open
**SuperManager** from the Start menu afterward.

**Scope:** this package includes the dependencies for WireGuard, OpenVPN,
Azure OpenVPN and native Windows networking. FortiClient SSL VPN remains
unavailable without a compatible Windows client; the current backend expects
openfortivpn, which upstream does not distribute for Windows. Installing the
bundle does not make this unsupported backend functional.

Every release must pass a Windows installation test covering the service,
app startup, RPC, OpenVPN executable, WireGuard driver creation, repair,
uninstall and preservation of user state.

If you already manage Visual C++ x64, WireGuard and OpenVPN out-of-band (e.g. via
Group Policy / Intune), grab the bare **`SuperManager-<version>.msi`**
instead — same payload as the bundle minus the chained installers.

## Updating

In-app: **Settings → About → Check for updates** (also in the tray
menu). It asks the GitHub API for the newest release, and when one is
newer than the running build it downloads the `SuperManager-Setup` exe
(falling back to the bare MSI) into `%TEMP%`, verifies it against the
`.sha256` sidecar CI published — the only integrity check there is
while the artifacts are unsigned — starts the installer, and exits.
The MSI's `MajorUpgrade` removes the old version and restarts the
service in the same transaction, so the update is one UAC prompt.

A release with no `.sha256` sidecar is refused rather than run
unverified. Manual updates keep working exactly as before: run the
newer installer yourself.

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
WiX v5 MSI specification plus a Burn bootstrapper that chains the
WireGuardNT and OpenVPN Community installers as prerequisites.

```powershell
# Prerequisite: .NET SDK 8+ and WiX Toolset v5.
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add WixToolset.UI.wixext/5.0.2 --global
#   wix extension add WixToolset.Util.wixext/5.0.2 --global
#   wix extension add WixToolset.BootstrapperApplications.wixext/5.0.2 --global

# Stage the native DLL and prerequisite installers:
.\scripts\windows\Get-VendorFiles.ps1

# Bare MSI (assumes runtime and VPN clients already installed):
.\installer\wix\build-msi.ps1

# Burn bundle (auto-installs WireGuard + OpenVPN alongside SuperManager):
.\scripts\windows\Get-VendorFiles.ps1
.\installer\wix\build-msi.ps1 -Bundle
```

`Get-VendorFiles.ps1` downloads + hash-verifies the upstream MSIs
listed in [`vendor/manifest.toml`](vendor/manifest.toml). The pinned
hashes are the only thing the build trusts; a tampered CDN won't
get past the manifest check. Re-pin the manifest when you bump
either upstream installer.

The script runs `cargo build --release` (skip with `-SkipBuild`), then
compiles the `.wxs` and emits `installer\wix\SuperManager.msi`. The MSI:

> **Versioning:** release CI exports `SUPERMGR_RELEASE_VERSION` from the
> git tag before building; `build.rs` stamps it into the exes'
> VS_FIXEDFILEINFO (which the MSI's ProductVersion binds to) and into
> the in-app update check. A local build without that variable is
> versioned as the crate version (1.0.0) — fine for dev, but such an
> MSI will not upgrade another 1.0.0 install, and every published
> release offers to replace it.

- Installs the three binaries under `%ProgramFiles%\SuperManager\bin\`.
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
URLs + SHA-256 hashes of the WireGuard and OpenVPN installers chained
by the Burn bundle. `Get-VendorFiles.ps1` populates the directory on
every CI run + lets you populate it locally before a release build.

| File                            | Source             | Effect when present |
|---------------------------------|--------------------|--------------------|
| `vendor/wireguard-installer.msi` | Pinned in `manifest.toml`, fetched by `Get-VendorFiles.ps1` | Chained into `SuperManager-Setup.exe` by `-Bundle`. Installs WireGuardNT driver + `wireguard.dll`. |
| `vendor/openvpn-installer.msi`   | Pinned in `manifest.toml`, fetched by `Get-VendorFiles.ps1` | Chained into `SuperManager-Setup.exe` by `-Bundle`. Installs `openvpn.exe` + TAP-Windows6 driver. |
| `vendor/openfortivpn.exe`        | User-supplied (no upstream Windows release exists) | Embedded directly into `SuperManager.msi`. Absent → FortiClient SSL VPN backend surfaces a typed `MissingDependency` error at connect time. |

`-Bundle` additionally requires `installer/wix/license.rtf` (the
bootstrapper's RTF license file shown on the welcome page).

## Using the app

The window follows the Windows light/dark setting and accent colour
(Settings → Appearance overrides it). Navigation is on the left — VPN,
Hosts, SSH keys, Settings — and goes icon-only in a narrow window.

**VPN.** The card at the top always says where the tunnel stands:
connecting (with the step it is on), waiting for a Microsoft sign-in,
connected (backend, interface, since when), or failed — with the reason
the VPN client gave, and **Copy details** for passing it on. Profiles are
listed on the left; the selected one has one main button on the right:
**Connect**, **Disconnect**, or **Cancel** while it is connecting.
Connecting another profile closes the current tunnel first.

**Adding a profile.** **Add profile** asks what kind, then for the details:

| Kind | What you need |
|---|---|
| WireGuard | The `.conf` file (choose it, or paste it). Its `DNS =` line is honoured. |
| OpenVPN | The `.ovpn` file with certificates and keys inline; a username and password if the server asks for them. |
| Azure VPN (Entra ID) | The VPN client profile `.zip` from the Azure portal (gateway → Point-to-site configuration → Download VPN client), as downloaded. |
| FortiGate IPsec (IKEv2) | Gateway, username, password. Windows' own IKEv2 client; the gateway's certificate must be trusted by Windows. |
| FortiGate SSL VPN | Shown, but disabled unless an SSL VPN client is installed (see below). |

A kind this PC cannot run — `wireguard.dll` or `openvpn.exe` missing — is
shown disabled with the reason, instead of importing fine and failing on
every connect.

**Azure sign-in.** The service runs in session 0, where a browser it
started would be invisible, so the app opens Microsoft's sign-in page in
your browser when a connect needs it (and offers **Open sign-in page** and
**Copy link** in case it didn't). Once you have signed in, the refresh
token is cached and later connects skip the browser.

**Per-profile options.** *Use the VPN's DNS servers* (WireGuard, Azure,
SSL VPN) is what makes internal names resolve over a split tunnel. *Send
all traffic through the VPN* (Azure, SSL VPN) is off for a new Azure
profile: the gateway pushes routes for the networks behind it, and a P2S
gateway not built for forced tunnelling would drop internet traffic. Both
apply from the next connect.

**Host keys.** The first connection to a host records the SSH key it
presents; the host's page shows it under *Host key*, in the form
`ssh-keygen -lf` prints. After that, a host presenting any other key is
refused before anything is sent to it. **Test connection** then shows
both keys side by side: a reinstalled server or a replaced appliance
explains the change, and **Trust the new key…** accepts exactly the key
shown — compare it with the one the host reports first. If nothing
explains the change, someone may be intercepting the connection; don't
trust it. **Forget** next to the key drops it instead, so the next
connection records whatever key answers.

**Tray.** Left-click opens the window. The tooltip says where the tunnel
stands; the menu has Open, Disconnect VPN, Check for updates and Quit.

### When a VPN won't connect

The failure the app shows is the client's own last complaint, cleaned up.
Common ones:

- *OpenVPN did not connect within 45 s — it was waiting for the server to
  answer*: nothing came back from the server. Check the address and that
  its port (usually UDP 1194) is reachable.
- *RAS error 809* (IKEv2): UDP 500 and 4500 are blocked between this PC
  and the gateway.
- *RAS error 13801* (IKEv2): Windows does not trust the gateway's
  certificate. Import the issuing CA into the computer's Trusted Root
  Certification Authorities.
- *Cannot listen on http://localhost:2023* (Azure): another program — the
  Azure VPN Client, typically — holds the port the sign-in returns to.

The service logs to the Application event log (source *SuperManager*,
information and above); run it with `--console` (below) to watch it live,
with the VPN clients' own output at `RUST_LOG=vpn_client=debug`.

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
- **Host connection test** (`test_host_connection`): signs in with the host's stored credentials and out again, without running anything; same result shape as the Linux daemon (`{"ssh": "ok" | "auth_failed" | "connection_refused" | "timeout" | …}`).
- **VPN profile store**: TOML files under `%PROGRAMDATA%\SuperManager\profiles\`, fully compatible with the on-disk format the Linux daemon writes. Save / list / list-summary / get / delete.
- **WireGuard import**: parses `wg-quick` `.conf` files end-to-end, persists private key + PSKs to Credential Manager, writes the profile TOML. A `DNS =` line switches on *use the VPN's DNS servers*.
- **OpenVPN import** (`import_openvpn`): validates the config (the same checks as Linux), keeps it in `%PROGRAMDATA%\SuperManager\ovpn\` — readable by SYSTEM and Administrators only, since configs carry private keys inline — and stores a username/password in Credential Manager when given. Deleting the profile deletes the file.
- **Azure VPN import** (`import_azure_vpn`): reads `azurevpnconfig.xml` + `VpnSettings.xml` with the Linux daemon's parser; imported as a split tunnel.
- **Profile options**: `rename_profile`, `set_push_dns`, `set_full_tunnel`; `vpn_capabilities` reports which backends can run on this PC and why not.
- **WireGuard connect/disconnect** via `wireguard-nt` (requires the official WireGuardNT driver installed). Creates the adapter, applies config, assigns IPs and `AllowedIPs` routes via `Adapter::set_default_route`, brings the interface up, pushes DNS via `Set-DnsClientServerAddress`, applies MTU override via `Set-NetIPInterface`. Disconnect drops the adapter (kernel removes the interface) and reverts DNS. Gracefully reports a typed error when `wireguard.dll` isn't present.
- **OpenVPN connect/disconnect** via subprocess. Spawns `openvpn.exe` (located via `OPENVPN_EXE` env var, `%PATH%`, or the default install path), opens its management socket on `127.0.0.1`, authenticates with a random per-connection token, waits for `>STATE:...,CONNECTED,SUCCESS` or a `>FATAL:` event. Disconnect sends `signal SIGTERM` over the management socket and falls back to `Child::kill` after 5 s. Resolves auth-user-pass from Credential Manager and cleans up the credentials file on disconnect.
- **IKEv2 connect/disconnect** (FortiGate profiles + any standards-compliant IKEv2 endpoint) via Windows' built-in RAS stack: `Add-VpnConnection` to register, `rasdial` to dial, polled `(Get-VpnConnection ...).ConnectionStatus` until `Connected`. Disconnect via `rasdial /disconnect` + `Remove-VpnConnection`. The EAP password is resolved from Credential Manager. Native Windows IKEv2 requires certificate-based gateway authentication; PSK-only gateways are not supported.
- **Azure Point-to-Site VPN** via Entra ID PKCE auth + generated `.ovpn`: token refresh from Credential Manager → fallback browser flow (PKCE code+challenge, loopback redirect listener) → access-token exchange → write `tls-auth.key` + `auth.txt` + `client.ovpn` to `%PROGRAMDATA%\SuperManager\runtime\azure-<id>\` → spawn `openvpn.exe` → wait for `Initialization Sequence Completed` → push DNS to the TAP/Wintun adapter via `Set-DnsClientServerAddress`. Refresh tokens are cached in Credential Manager so subsequent connects skip the browser flow.
- **FortiGate IKEv2** via Windows RAS uses `Add-VpnConnection -TunnelType Ikev2 -AuthenticationMethod Eap` and `rasdial`. The gateway must support Windows native IKEv2 authentication. A Mac profile using a pre-shared gateway key is not automatically compatible; Windows' `-L2tpPsk` option applies to L2TP, not IKEv2.
- **FortiGate SSL VPN** via `openfortivpn.exe` (skeleton): spawn the open-source FortiGate SSL VPN client with the user's password fed on stdin (never argv), watch stdout for `Tunnel is up and running.` or a fatal `Could not authenticate`/`Connection refused` marker, sniff the PPP/Wintun interface name out of the log lines so DNS push targets the right alias. New profile import via `import_forticlient_sslvpn` RPC. `OPENFORTIVPN_EXE` env var, `%PATH%`, and `%ProgramFiles%\SuperManager\bin\openfortivpn.exe` are probed in order. **No upstream Windows binary exists**, so the FortiClient SSL VPN backend surfaces `MissingDependency` at connect time unless an admin provides their own build. IKEv2 is an alternative only when the gateway supports Windows native authentication.
- **Connect/disconnect** go through one session (`vpn::session`) that owns the tunnel's state — the Linux daemon's `VpnState`, as the same JSON. `connect` returns as soon as the bring-up has started; `get_status` then reports `connecting` (with the current step, and `auth_url` while an Azure sign-in is pending), `connected`, or `error` with the client's reason. `disconnect` also cancels a connect in progress (a cancelled IKEv2 dial is hung up by name). A tunnel that drops on its own — the client exits, or RAS reports the dial gone — becomes an error rather than a stale "connected". Stopping the service takes the tunnel down. Every VPN client's stdout/stderr is read for its whole life (an unread pipe stalls the client) and child processes are killed if their connect is cancelled.
- **FortiGate REST API**: `fortigate_api`, `fortigate_push_ssh_key`, `fortigate_backup_config`. Bearer-token auth resolved from Credential Manager; backups saved to `%PROGRAMDATA%\SuperManager\backups\<host>_<timestamp>.conf`. HTTP semantics + error mapping identical to the Linux daemon.
- **UniFi Controller REST API**: `unifi_api` (cookie-based session via `POST /api/auth/login`), `unifi_set_inform` (SSH `set-inform <url>` against UniFi-adopted devices).
- **OPNsense REST API**: `opnsense_api`, `opnsense_backup_config`. HTTP Basic auth using the key/secret pair from Credential Manager; backups saved as `<host>_<timestamp>.opnsense.xml` so they don't collide with FortiGate `.conf` filenames.
- **Sophos XG XML Configuration API**: `sophos_xml_api`. Wraps the caller's `<Get>/<Set>/<Remove>` body in the WebAdmin `<Request><Login>...</Login>` envelope; credentials come from Credential Manager.
- **Persistent known_hosts**: SSH host keys recorded in `%PROGRAMDATA%\SuperManager\known_hosts.json` on first sight; subsequent connections require an exact match. A changed key stops the handshake before any credential is sent: `test_host_connection` reports `{"ssh":"host_key_changed","stored":…,"presented":…}`, and commands fail with `RpcError::PermissionDenied` naming both fingerprints. `ssh_list_known_hosts` lists what is on file, `ssh_trust_host_key` replaces a key with the one the operator checked, and `ssh_forget_host_key` (the Linux daemon's method) drops it.
- **Named-pipe ACL hardening**: explicit SDDL grants `SYSTEM` + `Administrators` Generic All and `Authenticated Users` Read + Write (no DACL-modify). Built via `ConvertStringSecurityDescriptorToSecurityDescriptorW` and applied with `ServerOptions::create_with_security_attributes_raw`.
- **Tray icon**: the app icon, a tooltip with the tunnel's state, and Open / Disconnect VPN / Check for updates / Quit.
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

### VPN end to end, in CI

Every push runs `scripts/windows/test-vpn.ps1` on the Windows runner,
against the service the bundle just installed. It stands up real servers
on the runner — a WireGuard tunnel through WireGuard for Windows, and an
OpenVPN server with a throwaway PKI — and drives the service over its
pipe the way the app does:

- **WireGuard**: import (a DNS line and AllowedIPs with host bits set),
  connect, then check the adapter, its address, the AllowedIPs route, the
  DNS server, the server's handshake, and bytes arriving at the server
  through the tunnel; deleting the connected profile is refused;
  switching profiles removes the first adapter; disconnecting removes the
  second; stopping the service takes a connected tunnel down.
- **OpenVPN**: a connect to a server that never answers can be cancelled
  and leaves no `openvpn.exe` behind; left alone, it gives up after 45 s
  with a reason; against the local server it connects, is listed by the
  server, gets an address, and disconnects cleanly.

Both ends share one IP stack, so no reply can come back through a tunnel;
traffic is proven one way, by the bytes the server decrypts. The test is
destructive (adapters, a tunnel service, firewall rules) and refuses to
run outside GitHub Actions. On failure its logs — the service's own
Application-log entries, adapters, routes, DNS, `wg show`, the OpenVPN
server log — are in the `windows-installer-test-logs` artifact, under
`vpn\`.

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
12. ✅ ~~Burn bootstrapper that chain-installs the WireGuard for Windows + OpenVPN Community MSIs alongside `SuperManager.msi`. End users run one `SuperManager-Setup-<version>.exe` and get every dependency installed.~~
13. Code-signing (`signtool sign /fd SHA256` on the MSI + EXEs) is
    optional. The release workflow at `.github/workflows/release-windows.yml`
    has a commented-out signing block ready: drop a PFX cert into the
    `WINDOWS_PFX_BASE64` repo secret + uncomment the step. Until that
    lands, users see a SmartScreen prompt → "Run anyway" once per
    install (documented in the SmartScreen section above; SHA-256 of
    each release artifact is published as `.sha256` for hash verification).
14. Integrate and validate a supported Windows FortiGate **SSL VPN** client.
    Upstream openfortivpn does not provide a Windows client; this is not
    solved by adding a missing download to the installer.
15. Follow a system light/dark switch live after the operator has picked a
    fixed appearance and gone back to *Use Windows setting* in the same
    session (it applies the current setting once; a restart restores live
    following).

Each item is independent; see the `TODO` comments in the corresponding
module for the precise next step.
