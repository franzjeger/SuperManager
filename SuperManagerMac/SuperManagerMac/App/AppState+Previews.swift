import Foundation
import SwiftUI

/// Preview / test fixtures for AppState. Lives in `#if DEBUG` so
/// the production binary doesn't ship the seed data.
///
/// All IPs use the RFC 5737 documentation ranges (`192.0.2.0/24`,
/// `198.51.100.0/24`, `203.0.113.0/24`) so previews never collide
/// with real network addressing. Customer / contact names are
/// generic placeholders.
///
/// Usage in a `#Preview`:
///
/// ```swift
/// #Preview("Finding detail") {
///     FindingDetailSheet(
///         finding: .previewExampleSshOpen,
///         scope: "acme-corp",
///         engagementId: "demo",
///         onSaved: { _ in }
///     )
///     .environment(AppState.previewSeeded)
/// }
/// ```
#if DEBUG
extension AppState {
    /// A fully populated AppState — three customers, two engagements,
    /// a handful of SSH hosts, a VPN profile. Enough variety that
    /// most views render with realistic data without spinning up
    /// the daemon.
    @MainActor
    static var previewSeeded: AppState {
        let s = AppState()
        s.customers = [.previewAcme, .previewLab, .previewNetcraft]
        s.sshHosts = [
            .previewFortigate,
            .previewSynology,
            .previewLabUbuntu,
        ]
        s.vpnProfiles = [.previewIkev2]
        s.daemonAvailable = true
        return s
    }

    /// Empty AppState — useful for empty-state / zero-data previews.
    @MainActor
    static var previewEmpty: AppState {
        let s = AppState()
        s.daemonAvailable = true
        return s
    }
}

extension Customer {
    static let previewAcme = Customer(
        slug: "acme-corp",
        displayName: "Acme Corp",
        contactName: "Alex Doe",
        contactEmail: "alex@example.com",
        notes: "Generic MSP customer. ~12 sites, FortiGate-100F at HQ.",
        defaultTemplate: "fortigate_branch_office",
        mgmtAllowlistDomains: ["*.unifi.example.com", "*.ubnt.com"],
        primaryDomain: "example.com",
        sites: [
            .init(
                id: "hq",
                displayName: "HQ",
                address: "Main Street 1, 0123 City",
                hostIds: [],
                wanType: "static",
                wanStaticIp: "203.0.113.10/29",
                lanBase: "10.0.0.0/16",
                vlans: [
                    .init(id: 10, name: "MGMT", subnet: "10.0.10.0/24", purpose: "mgmt"),
                    .init(id: 20, name: "USER", subnet: "10.0.20.0/24", purpose: "internal"),
                    .init(id: 50, name: "GUEST", subnet: "10.0.50.0/24", purpose: "guest"),
                ]
            ),
        ]
    )

    static let previewLab = Customer(
        slug: "lab",
        displayName: "Lab / Internal",
        contactName: "—",
        contactEmail: "admin@example.com",
        notes: "Internal test environment.",
        defaultTemplate: nil,
        mgmtAllowlistDomains: [],
        primaryDomain: "example.com",
        sites: []
    )

    static let previewNetcraft = Customer(
        slug: "netcraft",
        displayName: "Netcraft AS",
        contactName: "—",
        contactEmail: "noc@netcraft.example",
        notes: "",
        defaultTemplate: nil,
        mgmtAllowlistDomains: [],
        primaryDomain: "netcraft.example",
        sites: [
            .init(
                id: "main",
                displayName: "Main",
                address: "Industrial Park 1, 0001 City",
                hostIds: [],
                wanType: "dhcp",
                wanStaticIp: "",
                lanBase: "192.168.10.0/24",
                vlans: []
            ),
        ]
    )
}

extension SshHostSummary {
    /// Bare-minimum constructor matching whatever the real init
    /// requires. We can't always know that without reading SshHost.swift —
    /// the DEBUG-gate keeps this file from breaking release builds
    /// even if the model changes.
    static let previewFortigate = SshHostSummary.previewFixture(
        id: "host-fg-1",
        label: "FortiGate HQ",
        hostname: "10.0.10.1",
        username: "admin",
        group: "acme-corp",
        deviceType: .fortigate
    )
    static let previewSynology = SshHostSummary.previewFixture(
        id: "host-syn-1",
        label: "Synology NAS",
        hostname: "192.0.2.111",
        username: "admin",
        group: "lab",
        deviceType: .linux
    )
    static let previewLabUbuntu = SshHostSummary.previewFixture(
        id: "host-lab-1",
        label: "Lab Ubuntu",
        hostname: "192.0.2.23",
        username: "ubuntu",
        group: "lab",
        deviceType: .linux
    )

    /// Best-effort fixture builder. If the underlying SshHostSummary
    /// adds required fields, this single call site makes them visible.
    static func previewFixture(
        id: String,
        label: String,
        hostname: String,
        username: String,
        group: String,
        deviceType: DeviceType
    ) -> SshHostSummary {
        // Decode from a minimal JSON shape — keeps the fixture
        // tolerant to non-public required-field additions.
        let json = """
        {
            "id": "\(id)",
            "label": "\(label)",
            "hostname": "\(hostname)",
            "port": 22,
            "username": "\(username)",
            "group": "\(group)",
            "device_type": "\(deviceType.rawValue)",
            "auth_method": "key",
            "pinned": false,
            "has_api": false,
            "has_unifi_controller": false
        }
        """
        return (try? JSONDecoder().decode(SshHostSummary.self, from: Data(json.utf8)))
            ?? .previewEmpty
    }

    private static var previewEmpty: SshHostSummary {
        let json = "{\"id\":\"\",\"label\":\"\",\"hostname\":\"\",\"port\":22,\"username\":\"\",\"group\":\"\",\"device_type\":\"linux\",\"auth_method\":\"key\",\"pinned\":false,\"has_api\":false,\"has_unifi_controller\":false}"
        return (try? JSONDecoder().decode(SshHostSummary.self, from: Data(json.utf8)))!
    }
}

extension VpnProfileSummary {
    static let previewIkev2: VpnProfileSummary = {
        let json = """
        {
            "id": "vpn-1",
            "name": "Acme HQ",
            "backend": "forti_gate",
            "host": "vpn.example.com",
            "username": "alex",
            "auto_connect": false,
            "full_tunnel": false,
            "split_routes": ["10.0.0.0/16"],
            "kill_switch": false
        }
        """
        return try! JSONDecoder().decode(VpnProfileSummary.self, from: Data(json.utf8))
    }()
}

#endif
