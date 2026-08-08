# SuperManager

A unified SSH, VPN, and network device management application for **Linux** (GTK4), **macOS** (SwiftUI), and **Windows** (Slint), built with a shared Rust core.

SuperManager consolidates SSH key management, VPN connections (WireGuard, FortiGate IPsec + SSL VPN, OpenVPN, Azure VPN, IKEv2), network device monitoring (FortiGate, UniFi, OPNsense, Sophos XG), and remote desktop into a single desktop application with an integrated AI assistant.

- **Linux** — GTK4 + libadwaita GUI talking to a `supermgrd` D-Bus system daemon.
- **macOS** — native SwiftUI app talking to a privileged `supermanager-helper` LaunchDaemon over a Unix socket.
- **Windows** — Slint GUI talking to a `supermgrd-win` Windows Service over a named pipe. See [WINDOWS.md](WINDOWS.md) for install + build instructions.

All three share `supermgr-core` (types, traits, secret-store abstraction, RPC protocol) and `supermgr-engine` (renderers, scan logic).

## Install

One command per platform, dependencies included. None of them leave you
a list of things to install afterwards.

### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/franzjeger/SuperManager/main/scripts/install.sh | bash
```

Installs Homebrew if it's missing, then the VPN clients SuperManager
drives (`wireguard-tools`, `strongswan`, `openvpn`) in one go, then the
newest signed + notarized release into `/Applications`. Anything already
present is left alone.

```bash
--yes             # don't ask before installing anything
--no-deps         # app only, you manage the VPN clients
--deps-only       # VPN clients only, leave /Applications alone
--with-openvpn3   # also build OpenVPN 3 from source (~5 min)
```

`openvpn3` is opt-in because it has no Homebrew formula and has to be
built from source. It matters only for **Azure VPN (Entra ID)**, whose
gateway rejects OpenVPN 2.x outright.

Or grab `SuperManager-<version>.zip` (drag-and-drop) from the
[releases page](https://github.com/franzjeger/SuperManager/releases)
yourself. (The `.pkg` asset is NOT the app — it is a small standalone
VPN/DNS cleanup payload for MDM remediation.)

Updates after that are in-app: the app checks the committed
[appcast](appcast.xml) daily (Sparkle), or on demand via
**Check for Updates…**.

### Linux

```bash
git clone https://github.com/franzjeger/SuperManager.git
cd SuperManager
./scripts/install-linux.sh
```

Detects your distribution (Arch, Debian/Ubuntu, Fedora/RHEL, openSUSE
and their derivatives), installs build + runtime dependencies in one
invocation, builds, installs the binaries and all the system integration
files, and starts the daemon.

```bash
--yes           # don't ask before installing packages
--print-deps    # show the distro and package list, change nothing
--no-deps       # you manage the packages
--no-build      # install what's already in target/release
--uninstall     # remove everything it installed
```

Run it as yourself, not with `sudo` — it asks for root only where it
needs it, and building as root leaves a root-owned `target/` behind.
There are no prebuilt Linux binaries, so it builds from source; expect a
few minutes the first time. The [manual steps](#linux) are still
documented if you'd rather do it yourself.

### Windows

Download **`SuperManager-Setup-<version>.exe`** from the
[releases page](https://github.com/franzjeger/SuperManager/releases). It
is a single bootstrapper that chain-installs WireGuard, OpenVPN, and
SuperManager itself — one UAC prompt, no separate installs. If you
already manage WireGuard and OpenVPN through Intune or Group Policy,
take the bare `.msi` instead. See [WINDOWS.md](WINDOWS.md).

### What works out of the box, and what needs a tool

SuperManager drives the real VPN clients rather than reimplementing
them, so each VPN type needs its client present. The installers put
these in place for you; the table is here for when you're assembling a
machine by hand or wondering why one profile type won't connect.

| Feature | Needs |
|---|---|
| SSH, key management, network scan, compliance, UniFi, FortiGate API | nothing |
| Tailscale | nothing — `tailscaled` is bundled and installed on first use |
| WireGuard | `wireguard-tools` |
| IKEv2 / FortiGate IPsec | `strongswan` |
| FortiGate SSL VPN | **Windows only** — `openfortivpn.exe`, which you supply (no upstream Windows release). Linux and macOS have no backend for it; use the IPsec/IKEv2 profile type instead |
| OpenVPN 2.x | `openvpn` |
| Azure VPN (Entra ID) | `openvpn3` — no Homebrew formula and packaged only on Arch; Microsoft's gateway rejects OpenVPN 2.x |
| Reading stored credentials (Linux) | `polkit` — the daemon fails closed without it |

The app tells you again if you try to connect a profile whose tool isn't
there.

On macOS the app asks for admin rights once, on first launch, to install
its privileged helper (`/Library/PrivilegedHelperTools`). On Linux the
installer asks for `sudo` to place system files and start the daemon.

## Features

### Dashboard
- Multi-vendor device monitoring — FortiGate and UniFi in one view
- **UI.com Site Manager API** — cloud-based monitoring of all UniFi sites and devices
- FortiGate cards: model, serial, firmware (with update check), CPU/memory bars, WAN IP, sessions, VPN tunnels, last backup
- UniFi cards: model, firmware, uptime, status, site name
- Auto-refresh (30s / 60s / 5m), search, filter tabs (All / FortiGate / UniFi)
- Offline devices sorted first with device count summary
- Quick-action buttons: backup config, compare config diffs, view details
- **UniFi device actions** from the controller pane — adopt a pending device,
  flash the locate LED, restart, or forget. Restart and forget confirm first and
  state the consequence (a minute offline / factory default, re-adoption usually
  needs physical access)
- Click any card to navigate to host detail

### SSH Management
- Generate, import, and manage SSH key pairs (Ed25519, RSA)
- Organize hosts by groups with device type support (Linux, FortiGate, UniFi, pfSense, OpenWrt)
- One-click SSH terminal sessions with automatic credential handling
- Push/revoke public keys to remote hosts via SSH or FortiGate REST API — SFTP
  where available, falling back to BusyBox-safe shell commands for embedded gear
- Host-key verification with a visible fingerprint and a Forget action
  ([details](#ssh-host-keys))
- Host health monitoring with live reachability indicators
- **Batch command execution** — run commands on multiple hosts simultaneously
- **~/.ssh/config sync** — generate SSH config entries for all managed hosts
- Search, filter, and pin favorite hosts
- Bastion/jump host support with ProxyJump

### VPN Management
- **WireGuard** — kernel netlink API, split-tunnel, kill switch
- **FortiGate IPsec/IKEv2** — strongSwan backend, EAP-MSCHAPv2
- **OpenVPN** — openvpn3 CLI wrapper with credential management
- **Azure VPN (Entra ID)** — PKCE OAuth2 flow, compatible with OpenVPN 2.7+
- Auto-VPN per host — automatically connects the right VPN before SSH
- Import profiles from `.conf`, `.ovpn`, `.toml`, or Azure XML configs
- Connection timer in sidebar showing elapsed time
- **Auto-reconnect** on unexpected disconnect (for auto-connect profiles)
- **IKEv2 failure diagnosis** — a failed connect names the cause (EAP rejection,
  no proposal chosen, unacceptable traffic selectors, no route to host, and so on)
  instead of printing the raw swanctl negotiation log
- **Always-on reports armed vs enrolled.** A profile can be enrolled for
  auto-reconnect while the watchdog still lacks the connect args it needs to
  replay — captured on the first successful manual connect. The toggle shows that
  state rather than claiming protection it cannot yet deliver

### Remote Desktop
- RDP and VNC with one-click launch from host detail
- Credentials auto-filled from stored SSH passwords
- Configurable client: Auto / Remmina / xfreerdp3 / xfreerdp
- Remmina profile generation with pre-filled settings

### FortiGate Integration
- REST API dashboard — firmware, CPU/memory, sessions, VPN tunnels
- Firmware update checker — compares installed vs available versions
- Config backup with timestamp tracking
- Config diff — compare two most recent backups side-by-side
- SSH key deployment via REST API
- API token generation via SSH

### Notification Center
- Bell icon in header bar with event history
- Captures: VPN connect/disconnect, errors, backups, operations
- Timestamps, icons, wrapping text, clear button
- Webhook notifications for offline UniFi devices (Slack/Teams/Discord)

### Claude AI Console
- Built-in chat interface with Claude (Anthropic)
- Two modes: **Subscription** (Claude Code CLI) or **API key** (pay-per-token)
- Streaming responses with conversation memory
- 10+ tools: list hosts/keys, execute remote commands, manage VPN, FortiGate API

### Network Provisioning Wizard
- 5-step guided setup for FortiGate and UniFi devices
- Customer info, network design (WAN/LAN/VLANs), services, security policies
- Claude generates production-ready configurations following CIS benchmarks
- Push config via SSH/REST API or export to file

### Daemon Logs
- Category filters: All / VPN / SSH / Backup / Errors
- Free-text search
- Pause button to freeze log output for reading
- Clear button (clears daemon buffer)
- Configurable daemon log level (ERROR through TRACE)

### Security
- Master password hashed with Argon2id (salted PHC string); hashes written by
  pre-Argon2 builds still verify and are re-hashed on the next unlock
- Auto-lock after configurable inactivity timeout
- Secrets stored via system keyring (Secret Service API)
- Audit logging for all SSH, VPN, and API operations
- **SSH host-key verification** on every platform — trust-on-first-use, then
  a fingerprint mismatch refuses the connection (see below)
- **Polkit authorization** on the Linux daemon's credential-reading methods
  and on opening an SSH session (see below)

#### Who may talk to the daemon (Linux)

`supermgrd` runs as root on the D-Bus system bus, and its bus policy lets any
local user send it messages — that is how the unprivileged GUI reaches it.
Authorization is therefore the daemon's job, not the bus's.

Two actions, at different levels, because the risk and the frequency differ:

| Action | Methods | Default |
|---|---|---|
| `org.supermgr.daemon.secrets` | `SshExportPrivateKey`, `SshGetPassword`, `ExportProfile`, `ExportAll` (the whole secret store), `GetWebhookConfig` | `auth_admin` |
| `org.supermgr.daemon.ssh-connect` | `SshConnectCommand` | `auth_admin_keep` |

`auth_admin` means administrator authentication **every time**, with no
session-wide grace period. `auth_admin_keep` asks once and then holds the
grant for the rest of the session. Neither is reachable from an inactive or
remote session.

`SshConnectCommand` gets its own action because it discloses the same material
as `SshExportPrivateKey` — it stages the host's password or private key on
disk for your `ssh` to read — but it is also the Connect button. At
`auth_admin` that is a password prompt for every SSH session you open, and a
control that makes the tool unusable gets switched off. Raise it to
`auth_admin` in the policy file if your threat model calls for it; nothing in
the daemon depends on the weaker setting.

Those staged credential files are mode 0600 and owned by the calling user, in
a directory nobody else can create entries in. Every secret the daemon writes
— VPN keys and passwords included — gets its mode in the same syscall that
creates the file, rather than being narrowed afterwards.

This **fails closed**: if polkit is not installed or cannot be reached, the
gated methods are refused rather than allowed. Install
`contrib/polkit/org.supermgr.Daemon.policy` (the installer does this for you)
— without it, polkit has no rule for the action and denies by default. That
is also why `polkit` is a hard dependency and not an optional one.

The remaining methods are not yet gated. See issue #109 for the shape of the
rest, and for the caveat that none of this has yet been exercised against a
live polkit daemon.

#### SSH host keys

Every outbound SSH connection is checked against a stored fingerprint, on
Linux, macOS and Windows alike. The policy matches OpenSSH's
`StrictHostKeyChecking=accept-new`:

- **First connection** to a `host:port` records the server's SHA-256 host-key
  fingerprint and proceeds.
- **Later connections** must present the same fingerprint. A mismatch aborts
  the connection and reports both fingerprints — it is never silently
  accepted.

The host detail panel shows the recorded fingerprint with a **Forget host
key** button. Use it after a deliberate rebuild, appliance swap or key
rotation; the next connection re-records whatever the host presents. From a
script, the same thing over D-Bus:

```bash
busctl call org.supermgr.Daemon /org/supermgr/Daemon org.supermgr.Daemon1 \
    SshForgetHostKey sq fw.example.com 22
```

Fingerprints live in `known_hosts.json` (mode 0600) alongside the daemon's
SSH data — `/etc/supermgrd/ssh/` when running as root. If that file is
present but unreadable or corrupt the daemon refuses to start rather than
starting with an empty store and re-trusting the whole fleet.

### Other
- Desktop notifications for VPN and host health changes
- Full config backup and restore (including secrets)
- **Verify Backup** — dress-rehearses an archive without touching live data:
  extracts to a 0700 scratch directory removed before returning, then checks the
  tar extracts, `secrets.json` parses, every referenced profile and daemon-store
  secret is present, and no `.ovpn` is zero-byte. Keychain-held credentials are
  expected to be absent on macOS and are not flagged
- Keyboard shortcuts (Ctrl+1-6 tabs, Ctrl+F search, Ctrl+L lock)
- System tray with VPN status and quick actions; on macOS the menu bar icon's
  tooltip names which tunnel is up, keeps connecting tunnels on their own line so
  a negotiating tunnel is never reported as carrying traffic, and warns when the
  daemon is down and the reading is a stale cache
- Systemd service with D-Bus activation

## Architecture

```
# Shared by every platform
supermgr-core/         Types, IPC interface definitions (D-Bus / named pipe),
                       keychain abstraction (Linux: secret-service, macOS:
                       Keychain, Windows: Credential Manager), error
                       hierarchy, and the shared SSH layer — key generation,
                       ~/.ssh import scanning, known-hosts verification, and
                       authorized_keys push/revoke
supermgr-engine/       Renderers (Azure VPN, OpenVPN), scan and recon logic,
                       JSON-RPC handlers (used by the macOS daemon)
supermgr-mcp/          MCP server for Claude Code integration

# Linux
supermgrd/             Privileged daemon (runs as root via systemd, D-Bus)
supermgr/              GTK4/Adwaita GUI (runs as user)

# macOS
supermgrd-mac/         User-space daemon — wraps supermgr-engine, JSON-RPC
                       over Unix socket
supermanager-helper/   Privileged helper (LaunchDaemon, JSON-RPC over Unix
                       socket, ovpncli/openvpn/strongSwan supervision)
SuperManagerMac/       Native SwiftUI app

# Windows
supermgrd-win/         Privileged daemon (Windows Service running as
                       LocalSystem, named-pipe RPC)
supermgr-win/          Slint GUI (runs as user)
```

**Linux:** the GUI talks to `supermgrd` over D-Bus on the system bus. The daemon handles privileged operations: network interface creation, secret storage (Secret Service), SSH connections, and VPN management.

**macOS:** the SwiftUI app talks to `supermgrd-mac` (user) and `supermanager-helper` (root) over Unix sockets. The helper supervises VPN tunnels (`ovpncli` for OpenVPN3 / `openvpn` for 2.x, `strongSwan` for IKEv2, kernel `wg` for WireGuard). Secrets live in the macOS Keychain via `security-framework`.

**Windows:** the Slint GUI talks to the `supermgrd-win` service over `\\.\pipe\supermgrd`. The service drives WireGuardNT, the OpenVPN and openfortivpn executables, Windows RAS for IKEv2, and WFP for the kill switch. Secrets live in Credential Manager. See [WINDOWS.md](WINDOWS.md).

### Where the shared code lives

Anything a host-management operation does that isn't platform-specific belongs in
`supermgr-core`, not in a daemon. The SSH layer got there the hard way: `supermgrd`
and `supermgr-engine` carried byte-identical copies of key generation, import,
push and revoke, and copies drift — macOS and Windows both verified SSH host keys
while Linux accepted whatever it was offered. The daemons now keep only what is
genuinely theirs (session setup, auth methods, transport) and drive the shared
logic through `supermgr_core::ssh::remote::RemoteShell`.

## Building

### Linux

`./scripts/install-linux.sh` does everything below in one command —
dependencies, build, install, and starting the daemon. The manual steps
are kept here for people packaging SuperManager or building on a distro
the script doesn't recognise. `--print-deps` prints the package list for
your distro without installing anything.

#### Dependencies

<details>
<summary><b>Arch Linux / CachyOS</b></summary>

```bash
sudo pacman -S --needed rust pkgconf gcc git \
    gtk4 libadwaita vte4 openssl \
    polkit openssh sshpass nftables \
    wireguard-tools strongswan openvpn \
    freerdp remmina networkmanager

# Optional (AUR) — for Azure VPN and openvpn3-driven OpenVPN profiles
paru -S openvpn3
```
</details>

<details>
<summary><b>Fedora 40+</b></summary>

```bash
sudo dnf install -y rust cargo gcc pkg-config \
    gtk4-devel libadwaita-devel vte291-gtk4-devel \
    openssl-devel dbus-devel glib2-devel \
    polkit openssh-clients sshpass nftables \
    wireguard-tools strongswan openvpn \
    freerdp remmina NetworkManager
```

`openvpn3` is not packaged for Fedora — needed only for Azure VPN and
openvpn3-driven OpenVPN profiles.
</details>

<details>
<summary><b>Debian / Ubuntu (24.04+)</b></summary>

```bash
sudo apt install -y rustc cargo build-essential pkg-config \
    libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev \
    libssl-dev libdbus-1-dev libglib2.0-dev \
    polkitd openssh-client sshpass nftables \
    wireguard-tools strongswan strongswan-swanctl openvpn \
    freerdp3-x11 remmina network-manager
```

On releases before 24.04 the polkit package is `policykit-1`.

If your distro's `rustc` is too old to build the workspace, install via
[rustup](https://rustup.rs) instead.
</details>

`polkit` is not optional. The daemon's credential-reading methods are
gated on it and **fail closed**, so without it a working install looks
like a broken one — see [Security](#security).

#### Build

Name the crates explicitly. A bare `cargo build` honours `default-members` in
the workspace `Cargo.toml`, which is only the two crates that build on every
platform — it will not produce `supermgrd` or `supermgr`, and the install step
below would then fail on a missing file.

```bash
cargo build --release -p supermgrd -p supermgr -p supermgr-mcp

# Install
sudo install -m755 target/release/supermgrd /usr/bin/supermgrd
sudo install -m755 target/release/supermgr /usr/bin/supermgr
sudo install -m755 target/release/supermgr-mcp /usr/bin/supermgr-mcp
sudo install -Dm644 contrib/systemd/supermgrd.service /etc/systemd/system/supermgrd.service
sudo install -Dm644 contrib/dbus/org.supermgr.Daemon.conf /usr/share/dbus-1/system.d/org.supermgr.Daemon.conf
sudo install -Dm644 contrib/polkit/org.supermgr.Daemon.policy /usr/share/polkit-1/actions/org.supermgr.Daemon.policy
sudo install -Dm644 contrib/dbus/org.supermgr.Daemon.service /usr/share/dbus-1/system-services/org.supermgr.Daemon.service
sudo install -Dm644 contrib/desktop/org.supermgr.SuperManager.desktop /usr/share/applications/org.supermgr.SuperManager.desktop
sudo install -Dm644 contrib/icons/org.supermgr.SuperManager.svg /usr/share/icons/hicolor/scalable/apps/org.supermgr.SuperManager.svg
sudo install -Dm644 contrib/man/supermgr.1 /usr/share/man/man1/supermgr.1
sudo install -Dm644 contrib/man/supermgrd.8 /usr/share/man/man8/supermgrd.8
sudo systemctl daemon-reload
sudo systemctl enable --now strongswan supermgrd
```

#### AUR (Arch Linux)

```bash
cd contrib/aur
makepkg -si
```

### macOS

#### Dependencies

```bash
# Required for any build
brew install xcodegen openssl@3 lz4

# OpenVPN3 (ovpncli) — required for Azure VPN with Entra ID, since
# Microsoft's gateway rejects OpenVPN 2.x clients in the AAD flow.
# No Homebrew formula exists; the contrib script clones upstream
# and builds it for you.
./contrib/build-openvpn3-mac.sh

# OpenVPN 2.x — fallback for non-Azure profiles
brew install openvpn

# strongSwan — for FortiGate IPsec/IKEv2
brew install strongswan
```

Xcode 15+ with the macOS SDK is required for the SwiftUI app build.

#### Build

```bash
cd SuperManagerMac
./build.sh                # debug build
./build.sh --release      # release build
./build.sh --run          # build + relaunch
```

The build script regenerates `SuperManager.xcodeproj` from `project.yml` via `xcodegen`, runs `cargo build --release` for the Rust binaries (`supermgrd-mac`, `supermanager-helper`), and bundles everything into `SuperManagerMac.app` under DerivedData.

#### Helper install

The privileged helper needs to be installed once into `/Library/PrivilegedHelperTools/`:

```bash
./SuperManagerMac/Signing/install_helper.sh
```

This requires `sudo` for the install + `launchctl bootstrap`. Re-run after pulling helper-side changes; subsequent builds can hot-swap the helper via the dev-rpc `deploy_self` path with no admin prompt.

For a smoother dev loop, pre-authorise the specific commands the install script uses:

```bash
./SuperManagerMac/Signing/enable_nopasswd.sh   # writes /etc/sudoers.d/supermanager-dev
```

(Disable with `disable_nopasswd.sh` when done.)

#### VPN DNS cleanup package

`installer/pkg/` builds a small signed `.pkg` — not an app installer. It ships
one file, the `no.sybr.supermanager.vpn-dns-cleanup` LaunchDaemon, which cleans
up VPN DNS state; the app and privileged helper are installed separately by the
steps above.

```bash
./installer/pkg/build-pkg.sh <version>
./installer/pkg/build-pkg.sh <version> --sign "Developer ID Installer: ..."
# → dist/SuperManager-vpn-dns-cleanup-<version>.pkg

./installer/pkg/uninstall.sh   # unloads and removes that LaunchDaemon only
```

### Windows

See [WINDOWS.md](WINDOWS.md) for the full install and packaging story. To build:

```powershell
cargo build --release -p supermgrd-win -p supermgr-win -p supermgr-mcp
```

## Development

### Building and testing a platform

There is no single command that builds everything — the daemons and GUIs each need
SDKs the other platforms don't have. Name the crates for the host you're on:

```bash
# Linux — daemon, GTK GUI, engine, core, MCP server
cargo build   -p supermgr-core -p supermgr-engine -p supermgr-mcp -p supermgrd -p supermgr
cargo test    -p supermgr-core -p supermgr-engine -p supermgr-mcp -p supermgrd -p supermgr
cargo clippy --all-targets -p supermgr-core -p supermgr-engine -p supermgr-mcp -p supermgrd -p supermgr

# macOS — everything, including the SwiftUI app
cargo test --workspace
cd SuperManagerMac && xcodegen generate && xcodebuild test \
    -project SuperManager.xcodeproj -scheme SuperManagerMac -destination 'platform=macOS'

# Windows
cargo test -p supermgr-core -p supermgr-mcp -p supermgrd-win -p supermgr-win
```

`default-members` in the workspace `Cargo.toml` is deliberately just
`supermgr-core` + `supermgr-mcp`, so a bare `cargo build` stays fast and portable on
any machine. It is **not** the set to build or test against — see the Linux build
note above.

Extra system packages the tests need beyond the build dependencies:

- **Linux:** `tcpdump` — the engine's traffic-sniff analysis shells out to it, and
  its tests do too. Without it, two `traffic_sniff` tests fail with
  `spawn tcpdump: No such file or directory`; nothing else in the suite needs it.

### Checkouts on filesystems that don't preserve the exec bit

Cloud-sync and foreign filesystems — OneDrive/Dropbox FUSE mounts, exFAT/NTFS,
some network shares — report every file as mode `644` and silently ignore
`chmod`. Two things break, both fixable from outside the tree:

```bash
# 1. Builds. Cargo writes build-script binaries without +x, then cannot run
#    them: "Permission denied (os error 13)" on proc-macro2, serde, libc…
#    Point the target dir at a native filesystem. Nothing in target/ is
#    source, so it does not need to live in the synced tree — and keeping
#    the multi-GB build cache out of the sync client is a win regardless.
export CARGO_TARGET_DIR="$HOME/.cache/supermanager-target"

# 2. Git. Every committed 755 file shows as a phantom "mode change
#    100755 => 100644" modification. Left alone, `git commit -a` strips the
#    exec bit from all of them, including install.sh, build-pkg.sh and the
#    pkg maintainer scripts — which ships broken installers.
git config core.fileMode false
```

`core.fileMode false` is per-clone and does not affect what is committed: the
modes already recorded in the index stay `755`.

### CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs three jobs, one per
platform, each naming its crates the same way. The Linux job also runs clippy; the
Windows job additionally builds the WiX MSI and Burn bundle on every push so
installer schema mistakes surface before a release tag.

## Usage

```bash
# Linux
supermgr          # Launch the GUI (daemon starts automatically via D-Bus activation)

# macOS
open /Applications/SuperManagerMac.app   # or via Spotlight
```

On Windows the MSI installs the `supermgrd-win` service and adds a Start Menu
shortcut for the GUI.

## Tech Stack

- **Languages:** Rust (core, daemons, helpers, MCP), Swift / SwiftUI (macOS app)
- **GUI (Linux):** GTK4 + libadwaita (Adwaita design language)
- **GUI (macOS):** SwiftUI (Sequoia/Tahoe), AppKit interop
- **GUI (Windows):** Slint
- **IPC:** zbus D-Bus on Linux, JSON-RPC over Unix sockets on macOS, named pipe on Windows
- **SSH:** russh (pure Rust, async), with host-key verification and `authorized_keys` editing shared across all three platforms in `supermgr-core`
- **VPN:** WireGuard netlink (Linux) / kernel `wg` (macOS) / WireGuardNT (Windows), strongSwan swanctl, OpenVPN3 `ovpncli` (macOS Azure path) + OpenVPN 2.x CLI, Windows RAS for IKEv2, Azure Entra ID OAuth2 (PKCE)
- **Keychain:** Secret Service / GNOME Keyring on Linux, `security-framework` on macOS, Credential Manager on Windows
- **Password hashing:** Argon2id (`argon2` crate, OWASP defaults)
- **AI:** Anthropic Claude API + Claude Code CLI
- **HTTP:** reqwest (native-tls)
- **Cloud:** UI.com Site Manager API (UniFi)
- **Packaging:** systemd + D-Bus activation (Linux), signed `.app` with Sparkle updates (macOS), WiX MSI + Burn bundle (Windows)

## License

GPL-3.0-or-later
