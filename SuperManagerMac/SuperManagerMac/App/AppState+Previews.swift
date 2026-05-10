import Foundation
import SwiftUI

/// Preview / test fixtures for AppState. Lives in `#if DEBUG` so
/// the production binary doesn't ship the seed data.
///
/// Usage in a `#Preview`:
///
/// ```swift
/// #Preview("Finding detail") {
///     FindingDetailSheet(
///         finding: .previewExampleSshOpen,
///         scope: "aarsleff-norge",
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
        s.customers = [.previewAarsleff, .previewLab, .previewNetcraft]
        s.engagements = [.previewActive, .previewExpired]
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
    static let previewAarsleff = Customer(
        slug: "aarsleff-norge",
        displayName: "Aarsleff Norge",
        contactName: "Frank Liaaen",
        contactEmail: "frank@aarsleff.no",
        notes: "Construction-MSP customer. ~12 sites, FortiGate-100F at HQ.",
        defaultTemplate: "fortigate_branch_office",
        mgmtAllowlistDomains: ["*.unifi.aarsleff.no", "*.ubnt.com"],
        primaryDomain: "aarsleff.no",
        sites: [
            .init(
                id: "hq-oslo",
                displayName: "HQ Oslo",
                address: "Strandveien 50, 1366 Lysaker",
                hostIds: [],
                wanType: "static",
                wanStaticIp: "81.10.42.10/29",
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
        contactName: "Me",
        contactEmail: "support@sybr.no",
        notes: "Internal test environment.",
        defaultTemplate: nil,
        mgmtAllowlistDomains: [],
        primaryDomain: "sybr.no",
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
                address: "Industrigata 1, 0123 Oslo",
                hostIds: [],
                wanType: "dhcp",
                wanStaticIp: "",
                lanBase: "192.168.10.0/24",
                vlans: []
            ),
        ]
    )
}

extension Engagement {
    static let previewActive = Engagement(
        id: "preview-eng-1",
        customerSlug: "aarsleff-norge",
        title: "Aarsleff Q1 2026 audit",
        scopeCidrs: ["10.0.0.0/16"],
        scopeHosts: [],
        exclusions: [],
        allowedTechniques: SecurityTechnique.allCases.filter {
            $0 != .wireless && $0 != .dosTest
        },
        startedAt: Date().addingTimeInterval(-30 * 86400),
        expiresAt: Date().addingTimeInterval(60 * 86400),
        authorizedBy: "Frank Liaaen, CTO",
        authorizationDocPath: nil,
        log: [],
        notes: "Quarterly authorised pen-test."
    )

    static let previewExpired = Engagement(
        id: "preview-eng-2",
        customerSlug: "lab",
        title: "Lab continuous",
        scopeCidrs: ["192.168.200.0/24"],
        scopeHosts: [],
        exclusions: [],
        allowedTechniques: SecurityTechnique.allCases,
        startedAt: Date().addingTimeInterval(-200 * 86400),
        expiresAt: Date().addingTimeInterval(-10 * 86400),
        authorizedBy: "self",
        authorizationDocPath: nil,
        log: [],
        notes: ""
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
        group: "aarsleff-norge",
        deviceType: .fortigate
    )
    static let previewSynology = SshHostSummary.previewFixture(
        id: "host-syn-1",
        label: "Synology NAS",
        hostname: "192.168.200.111",
        username: "admin",
        group: "lab",
        deviceType: .linux
    )
    static let previewLabUbuntu = SshHostSummary.previewFixture(
        id: "host-lab-1",
        label: "Lab Ubuntu",
        hostname: "192.168.200.23",
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
            "name": "Aarsleff HQ",
            "backend": "forti_gate",
            "host": "vpn.aarsleff.no",
            "username": "frank",
            "auto_connect": false,
            "full_tunnel": false,
            "split_routes": ["10.0.0.0/16"],
            "kill_switch": false
        }
        """
        return try! JSONDecoder().decode(VpnProfileSummary.self, from: Data(json.utf8))
    }()
}

extension PersistedFinding {
    /// CVE-2023-38408 OpenSSH on Synology — visible default story.
    static let previewExampleSshOpen: PersistedFinding = {
        let json = """
        {
            "key": "cve.cve-2023-38408|192.168.200.111|22|ssh",
            "finding": {
                "id": "cve.cve-2023-38408",
                "host_ip": "192.168.200.111",
                "port": 22,
                "service": "ssh",
                "severity": "high",
                "title": "OpenSSH agent forwarding RCE (CVE-2023-38408)",
                "detail": "Detected via banner: SSH-2.0-OpenSSH_8.2. PKCS#11 provider RCE via forwarded ssh-agent. Affects OpenSSH < 9.3p2.",
                "recommendation": "Upgrade to OpenSSH 9.3p2 or later. Disable agent forwarding (-A flag) where not strictly needed.",
                "cve": "CVE-2023-38408",
                "cvss": 7.4
            },
            "disposition": { "kind": "open" },
            "first_seen": "2026-04-10T09:30:00Z",
            "last_seen": "2026-05-10T08:20:00Z",
            "scan_count": 4,
            "history": [],
            "note": ""
        }
        """
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try! dec.decode(PersistedFinding.self, from: Data(json.utf8))
    }()

    /// Same finding marked Accepted Risk — for the "after disposition" preview.
    static let previewAccepted: PersistedFinding = {
        let json = """
        {
            "key": "config.smb-open|192.168.200.111|139|smb",
            "finding": {
                "id": "config.smb-open",
                "host_ip": "192.168.200.111",
                "port": 139,
                "service": "smb",
                "severity": "medium",
                "title": "SMB share-server open",
                "detail": "SMB is high-value to attackers (EternalBlue / SMBGhost / share enumeration).",
                "recommendation": "Disable SMBv1 protocol. Restrict SMB access to internal-only via firewall.",
                "cve": null,
                "cvss": 5.0
            },
            "disposition": {
                "kind": "accepted_risk",
                "reason": "NAS shares are intentional, hardened (SMBv1 disabled, signing required)",
                "until": null
            },
            "first_seen": "2026-04-10T09:30:00Z",
            "last_seen": "2026-05-10T08:20:00Z",
            "scan_count": 4,
            "history": [],
            "note": ""
        }
        """
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try! dec.decode(PersistedFinding.self, from: Data(json.utf8))
    }()
}
#endif
