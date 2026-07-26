# SuperManager on iOS — feasibility

_Written 2026-07-26 from a measured inventory of the existing crates, not an estimate._

## Problem

Is there an iOS version of SuperManager, and what would it cost? The workspace already
targets Linux, macOS and Windows off a shared Rust core, so "add a fourth platform"
looks like more of the same. It isn't: the other three all assume a privileged daemon
and the ability to run programs, and iOS gives you neither.

## Headline

**Ship it as a companion, not a port.** The parts that survive are the parts that are
just Rust talking TCP: SSH sessions, FortiGate/UniFi REST monitoring, compliance and
CVE data, provisioning templates. 61 of the engine's 72 modules never spawn a process.
What does not survive is the entire privileged layer — `supermanager-helper` shells out
to `route`, `pfctl`, `ifconfig`, `scutil`, `networksetup` and `launchctl`, none of which
exist on iOS — plus every scanning feature that shells out to `tcpdump`, `snmpwalk`,
`smbclient` or `dig`.

Scope an iOS app to **monitor, connect, respond**. Do not scope it to feature parity;
feature parity is not reachable and chasing it is how this turns into a year of work
that ends in an App Store rejection.

## What the inventory says

| Measure | Value |
|---|---|
| Engine modules that never spawn a process | 61 of 72 |
| Engine modules that shell out (would need gating) | 11 |
| Engine JSON-RPC methods | 108 |
| `Command::new` calls in `supermanager-helper` | 99 |
| `Command::new` calls in `supermgr-engine` | 23 |
| Unix-socket call sites in the engine | 3 |
| Swift files with no AppKit dependency | 75 of 121 |

The 11 process-bound engine modules are `asset_enrich`, `discovery`, `dns_axfr`,
`dns_health`, `netdetect`, `probes`, `report`, `smb_enum`, `snmp_walk`, `tools` and
`traffic_sniff`.

## What iOS actually changes

**The daemon disappears, and that is a simplification.** On every current platform the
GUI talks to a privileged process over D-Bus, a Unix socket or a named pipe. iOS has one
sandboxed process, so the app links the engine directly as a static library. The
`server.rs` Unix-socket layer and the 108-method RPC dispatch are not ported — they are
skipped. Only 3 call sites touch Unix sockets, so the engine is close to being usable as
a plain library already.

**VPN becomes NetworkExtension, and none of the current backend code transfers.**
`supermanager-helper` supervises `ovpncli`, `openvpn`, `strongSwan` and kernel `wg` as
child processes. iOS has no child processes. The replacements are:

| Backend today | iOS route | Difficulty |
|---|---|---|
| FortiGate IPsec / IKEv2 (strongSwan) | `NEVPNProtocolIKEv2` | Straightforward — first-class Apple API |
| WireGuard (kernel `wg`) | WireGuardKit in a `NEPacketTunnelProvider` | Moderate — well-trodden |
| OpenVPN (`ovpncli` / `openvpn` 2.x) | OpenVPNAdapter in a packet-tunnel extension | Hard — third-party, and the Azure Entra ID PKCE flow needs re-proving |
| Azure VPN (Entra ID) | Depends on the OpenVPN path above | Hard, and highest risk |

The `NEVPNManager` / packet-tunnel entitlements require a paid Apple Developer account,
and the app extension is a separate target with its own memory ceiling (~15 MB for
packet tunnel providers on older devices). That ceiling is a real constraint on
linking a large Rust library into the extension.

**Terminal and remote desktop need replacing outright.** The Linux GUI uses VTE; there
is no equivalent. SwiftTerm is the usual answer for the terminal. RDP and VNC currently
launch external clients (Remmina, xfreerdp) — on iOS there is nothing to launch, so
either drop them or embed a client, which is its own project.

**The Claude console is half-portable.** API-key mode works. Subscription mode shells
out to the Claude Code CLI and does not.

## Feature triage

**Ports with modest work** — SSH sessions and batch command execution (russh is pure
Rust), SSH key management, host and group management, FortiGate REST dashboard, UniFi /
UI.com Site Manager monitoring, notification centre, compliance and CVE views,
provisioning template generation, Keychain-backed secrets (`security-framework` covers
iOS).

**Ports with significant work** — VPN (per the table above), terminal emulation, config
backup and restore, audit log viewing.

**Does not port** — traffic capture, SNMP walk, SMB and LDAP enumeration, DNS zone
transfer, network discovery via `dns-sd`, PDF report rendering via `pandoc`, RDP and
VNC, the MCP server, Claude subscription mode, and every kill-switch / route / DNS
manipulation path in the helper.

## The three hard problems

**1. App Store review, and it is not a detail.** SSH clients ship on the App Store
routinely — Termius and Prompt exist. Network *scanners* are treated differently, and
this codebase has default-credential probing (`creds.rs` carries a curated list of vendor
logins to try), vulnerability scanning, subdomain enumeration and WAF fingerprinting.
Submitting those is a plausible rejection under the "not designed to harm" and
developer-tools rules. Since most of that surface can't run on iOS anyway, the honest
move is to build the iOS target without it and treat that as a product decision, not a
temporary gap.

**2. Where does the data live?** Desktop stores hosts and keys as TOML under
`/etc/supermgrd` or `~/Library/Application Support`. An iOS device has neither, and a
phone that knows nothing about your fleet is useless. The options are CloudKit sync,
pairing to a desktop instance over the existing RPC surface, or a small self-hosted sync
service. This is a design decision that has to be made *before* any code, because it
determines whether the iOS app is standalone or a satellite.

**3. Local network access.** Reaching a firewall on the LAN needs
`NSLocalNetworkUsageDescription`, and any discovery needs the multicast entitlement,
which Apple grants by application. Over a VPN this is moot, but "connect to the box in
front of me" is exactly the field-engineer case an iOS app is for.

## Staged plan

1. **Prove the core links.** Build `supermgr-core` and `supermgr-engine` for
   `aarch64-apple-ios` behind a cargo feature that compiles out the 11 process-bound
   modules. This is the cheapest possible test of the whole premise and it either works
   in a day or reveals the real blockers.
2. **Read-only app.** Host list, FortiGate and UniFi dashboards, findings, notifications.
   No VPN, no SSH. Settles the sync question with the least code at risk.
3. **SSH.** Sessions via russh plus SwiftTerm, key management, batch execution. This is
   the feature that justifies the app existing.
4. **VPN, IKEv2 first.** It maps to a native Apple API and covers the FortiGate case.
   Add WireGuard next. Treat OpenVPN and Azure as separate decisions with their own
   justification.

Steps 1 and 2 are the ones worth committing to now. Steps 3 and 4 should be re-scoped
once step 1 has told us what actually compiles.

## Open questions

- Does the engine's dependency tree (reqwest, russh, rsa, tera) link cleanly for
  `aarch64-apple-ios`, and how large is the resulting static library? This decides
  whether any of it can live inside a packet-tunnel extension.
- Standalone or satellite? Nothing else can be sized until this is answered.
- Is an iPad-first build a better fit than iPhone? The layouts are closer to the
  existing macOS ones and the field-engineer use case tolerates a larger device.
- Do the 75 AppKit-free Swift files actually share, or do they lean on macOS layout
  idioms — three-column `NavigationSplitView`, hover states, right-click menus — that
  need rewriting even without an `import AppKit`?

## What has not been verified

None of this was compiled. The container this was written in is Linux with no Apple
SDK, so `cargo build --target aarch64-apple-ios` was never run. The portability claims
come from reading every module's imports and counting `Command::new` call sites — good
enough to scope the work, not good enough to promise it. Step 1 of the plan exists
precisely to replace this document's central assumption with a fact.
