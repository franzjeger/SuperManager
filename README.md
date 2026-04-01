# SuperManager

A unified SSH, VPN, and network device management application for Linux, built with Rust, GTK4, and libadwaita.

SuperManager consolidates SSH key management, VPN connections (WireGuard, FortiGate IPsec, OpenVPN, Azure VPN), and network device provisioning into a single desktop application with an integrated AI assistant.

## Features

### SSH Management
- Generate, import, and manage SSH key pairs (Ed25519, RSA)
- Organize hosts by groups with device type support (Linux, FortiGate, UniFi, pfSense, OpenWrt)
- One-click SSH terminal sessions with automatic credential handling
- Push/revoke public keys to remote hosts via SSH or FortiGate REST API
- Host health monitoring with live reachability indicators
- Search and filter across all hosts and keys
- Pin favorite hosts to the top of the list

### VPN Management
- WireGuard — kernel netlink API, split-tunnel, kill switch
- FortiGate IPsec/IKEv2 — strongSwan backend, EAP-MSCHAPv2
- OpenVPN — CLI wrapper with credential management
- Azure Point-to-Site — Entra ID device-code OAuth2 flow
- Auto-VPN per host — automatically connects the right VPN before SSH
- Import profiles from `.conf`, `.ovpn`, `.toml`, or Azure XML configs

### FortiGate Integration
- REST API dashboard — firmware, hostname, serial, HA status, CPU/memory
- SSH key deployment via REST API (`ssh-public-key1`)
- Connection testing (SSH + API)
- Full API access from the Claude Console

### Claude AI Console
- Built-in chat interface with Claude (Anthropic)
- Two modes: **Subscription** (Claude Code CLI, no token cost) or **API key** (pay-per-token)
- Streaming responses with conversation memory
- 10+ tools: list hosts/keys, execute remote commands, manage VPN, FortiGate API
- Auto-injects current VPN status and host list as context

### Network Provisioning Wizard
- 5-step guided setup for FortiGate and UniFi devices
- Customer info, network design (WAN/LAN/VLANs), services (VPN/DNS/NTP), security policies
- Claude generates production-ready configurations following CIS benchmarks
- Push config via SSH/REST API or export to file
- Demo mode for testing without real hardware

### Security
- Master password with SHA-256 hash + salt
- Auto-lock after configurable inactivity timeout
- Secrets stored in encrypted JSON (0600 permissions)
- Audit logging for all SSH, VPN, and API operations
- Automatic cleanup of temporary credential files

### Other
- Desktop notifications for host health changes
- Full config backup and restore (including secrets)
- Keyboard shortcuts (Ctrl+1-4 tabs, Ctrl+K search, Ctrl+L lock)
- System tray integration
- Systemd service for the daemon
- AUR package (`supermanager-git`)

## Architecture

```
supermgr-core/    Shared types, D-Bus interface definitions, error hierarchy
supermgrd/        Privileged daemon (runs as root via systemd)
supermgr/         GTK4/Adwaita GUI (runs as user)
supermgr-mcp/     MCP server for Claude Code integration
```

The GUI communicates with the daemon over D-Bus on the system bus. The daemon handles all privileged operations: network interface creation, secret storage, SSH connections, and VPN management.

## Building

```bash
# Dependencies (Arch Linux)
sudo pacman -S gtk4 libadwaita vte4 sshpass wireguard-tools strongswan

# Build
cargo build --release

# Install
sudo cp target/release/supermgrd /usr/bin/
sudo cp target/release/supermgr /usr/bin/
sudo cp contrib/systemd/supermgrd.service /etc/systemd/system/
sudo cp contrib/dbus/org.supermgr.Daemon.conf /etc/dbus-1/system.d/
sudo systemctl enable --now supermgrd
```

### AUR (Arch Linux)

```bash
cd contrib/aur
makepkg -si
```

## Usage

```bash
supermgr          # Launch the GUI (daemon starts automatically)
```

## Tech Stack

- **Language:** Rust
- **GUI:** GTK4 + libadwaita (Adwaita design language)
- **D-Bus:** zbus (tokio backend)
- **SSH:** russh (pure Rust, async)
- **VPN:** WireGuard netlink, strongSwan swanctl, OpenVPN CLI
- **AI:** Anthropic Claude API + Claude Code CLI
- **HTTP:** reqwest (native-tls)

## License

GPL-3.0-or-later
