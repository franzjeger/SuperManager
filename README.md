# SuperManager

A unified SSH, VPN, and network device management application for **Linux** (GTK4) and **macOS** (SwiftUI), built with a shared Rust core.

SuperManager consolidates SSH key management, VPN connections (WireGuard, FortiGate IPsec, OpenVPN, Azure VPN), network device monitoring, and remote desktop into a single desktop application with an integrated AI assistant.

The Linux client uses GTK4 + libadwaita and a `supermgrd` D-Bus system daemon. The macOS client is a native SwiftUI app talking to a privileged `supermanager-helper` LaunchDaemon over a Unix socket. Both share `supermgr-core` (types, traits, keychain abstraction) and `supermgr-engine` (renderers, scan logic, RPC handlers).

## Features

### Dashboard
- Multi-vendor device monitoring — FortiGate and UniFi in one view
- **UI.com Site Manager API** — cloud-based monitoring of all UniFi sites and devices
- FortiGate cards: model, serial, firmware (with update check), CPU/memory bars, WAN IP, sessions, VPN tunnels, last backup
- UniFi cards: model, firmware, uptime, status, site name
- Auto-refresh (30s / 60s / 5m), search, filter tabs (All / FortiGate / UniFi)
- Offline devices sorted first with device count summary
- Quick-action buttons: backup config, compare config diffs, view details
- Click any card to navigate to host detail

### SSH Management
- Generate, import, and manage SSH key pairs (Ed25519, RSA)
- Organize hosts by groups with device type support (Linux, FortiGate, UniFi, pfSense, OpenWrt)
- One-click SSH terminal sessions with automatic credential handling
- Push/revoke public keys to remote hosts via SSH or FortiGate REST API
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
- Master password with SHA-256 hash + salt
- Auto-lock after configurable inactivity timeout
- Secrets stored via system keyring (Secret Service API)
- Audit logging for all SSH, VPN, and API operations

### Other
- Desktop notifications for VPN and host health changes
- Full config backup and restore (including secrets)
- Keyboard shortcuts (Ctrl+1-6 tabs, Ctrl+F search, Ctrl+L lock)
- System tray with VPN status and quick actions
- Systemd service with D-Bus activation

## Architecture

```
supermgr-core/         Shared types, D-Bus interface definitions, keychain
                       abstraction (Linux: secret-service, macOS: Keychain),
                       error hierarchy
supermgr-engine/       Shared engine — renderers (Azure VPN, OpenVPN), scan
                       logic, JSON-RPC handlers (used by macOS daemon)
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
```

**Linux:** the GUI talks to `supermgrd` over D-Bus on the system bus. The daemon handles privileged operations: network interface creation, secret storage (Secret Service), SSH connections, and VPN management.

**macOS:** the SwiftUI app talks to `supermgrd-mac` (user) and `supermanager-helper` (root) over Unix sockets. The helper supervises VPN tunnels (`ovpncli` for OpenVPN3 / `openvpn` for 2.x, `strongSwan` for IKEv2, kernel `wg` for WireGuard). Secrets live in the macOS Keychain via `security-framework`.

## Building

### Linux

#### Dependencies

<details>
<summary><b>Arch Linux / CachyOS</b></summary>

```bash
sudo pacman -S gtk4 libadwaita vte4 openssl sshpass wireguard-tools strongswan openvpn nftables freerdp remmina networkmanager

# Optional (AUR) — for non-Azure OpenVPN profiles
paru -S openvpn3
```
</details>

<details>
<summary><b>Fedora 40+</b></summary>

```bash
sudo dnf install -y rust cargo gcc pkg-config \
    gtk4-devel libadwaita-devel vte291-gtk4-devel \
    openssl-devel dbus-devel glib2-devel \
    sshpass wireguard-tools strongswan openvpn nftables \
    freerdp remmina NetworkManager
```

`openvpn3` is not packaged for Fedora — needed only for non-Azure OpenVPN profiles.
</details>

<details>
<summary><b>Debian / Ubuntu (24.04+)</b></summary>

```bash
sudo apt install -y rustc cargo build-essential pkg-config \
    libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev \
    libssl-dev libdbus-1-dev libglib2.0-dev \
    sshpass wireguard-tools strongswan strongswan-swanctl \
    openvpn nftables freerdp3-x11 remmina network-manager
```

If your distro's `rustc` is older than the workspace MSRV, install via [rustup](https://rustup.rs) instead.
</details>

#### Build

```bash
cargo build --release

# Install
sudo install -m755 target/release/supermgrd /usr/bin/supermgrd
sudo install -m755 target/release/supermgr /usr/bin/supermgr
sudo install -m755 target/release/supermgr-mcp /usr/bin/supermgr-mcp
sudo install -Dm644 contrib/systemd/supermgrd.service /etc/systemd/system/supermgrd.service
sudo install -Dm644 contrib/dbus/org.supermgr.Daemon.conf /usr/share/dbus-1/system.d/org.supermgr.Daemon.conf
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

## Usage

```bash
# Linux
supermgr          # Launch the GUI (daemon starts automatically via D-Bus activation)

# macOS
open /Applications/SuperManagerMac.app   # or via Spotlight
```

## Tech Stack

- **Languages:** Rust (core, daemons, helpers, MCP), Swift / SwiftUI (macOS app)
- **GUI (Linux):** GTK4 + libadwaita (Adwaita design language)
- **GUI (macOS):** SwiftUI (Sequoia/Tahoe), AppKit interop
- **IPC:** zbus D-Bus on Linux, JSON-RPC over Unix sockets on macOS
- **SSH:** russh (pure Rust, async)
- **VPN:** WireGuard netlink (Linux) / kernel `wg` (macOS), strongSwan swanctl, OpenVPN3 `ovpncli` (macOS Azure path) + OpenVPN 2.x CLI, Azure Entra ID OAuth2 (PKCE)
- **Keychain:** Secret Service / GNOME Keyring on Linux, `security-framework` on macOS
- **AI:** Anthropic Claude API + Claude Code CLI
- **HTTP:** reqwest (native-tls)
- **Cloud:** UI.com Site Manager API (UniFi)

## License

GPL-3.0-or-later
