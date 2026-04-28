# SuperManager

A unified SSH, VPN, and network device management application for Linux, built with Rust, GTK4, and libadwaita.

SuperManager consolidates SSH key management, VPN connections (WireGuard, FortiGate IPsec, OpenVPN, Azure VPN), network device monitoring, and remote desktop into a single desktop application with an integrated AI assistant.

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
supermgr-core/    Shared types, D-Bus interface definitions, error hierarchy
supermgrd/        Privileged daemon (runs as root via systemd)
supermgr/         GTK4/Adwaita GUI (runs as user)
supermgr-mcp/     MCP server for Claude Code integration
```

The GUI communicates with the daemon over D-Bus on the system bus. The daemon handles all privileged operations: network interface creation, secret storage, SSH connections, and VPN management.

## Building

### Dependencies

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

### Build

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

### AUR (Arch Linux)

```bash
cd contrib/aur
makepkg -si
```

## Usage

```bash
supermgr          # Launch the GUI (daemon starts automatically via D-Bus activation)
```

## Tech Stack

- **Language:** Rust
- **GUI:** GTK4 + libadwaita (Adwaita design language)
- **D-Bus:** zbus (tokio backend)
- **SSH:** russh (pure Rust, async)
- **VPN:** WireGuard netlink, strongSwan swanctl, OpenVPN CLI, Azure Entra ID OAuth2
- **AI:** Anthropic Claude API + Claude Code CLI
- **HTTP:** reqwest (native-tls)
- **Cloud:** UI.com Site Manager API (UniFi)

## License

GPL-3.0-or-later
