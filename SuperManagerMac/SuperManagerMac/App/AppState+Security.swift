import Foundation

/// The RPC calls that outlived the Security/Recon/Fleet cut.
///
/// This file used to be the whole security-posture API surface: engagements,
/// findings, dispositions, discovery scans, report rendering, traffic capture,
/// DNS and subdomain audits — 32 functions behind three sections that no longer
/// exist. Cutting those sections left all of it unreachable except five calls
/// that two *surviving* sections reach into:
///
///   - Provisioning's customer editor runs a passive discovery scan to infer
///     VLANs and import hosts (`runPassiveDiscovery`).
///   - Settings' Integrations panel reads and writes the notification config
///     (`loadNotifyConfig` plus the three `setNotify*` setters).
///
/// Those five are the only reason this file survives. Everything else is gone;
/// `git log` has it if a future section ever wants it back.
///
/// The filename is now slightly wrong — these are not "security" calls any
/// more, they are the discovery and notification plumbing two ordinary
/// sections use. Renaming the file is a separate, noisier change.
extension AppState {

    // MARK: - Discovery (used by Provisioning's customer editor)

    /// Passive network discovery: ARP/mDNS observation, no active probing.
    /// Provisioning uses this when setting up a customer, to infer the VLAN
    /// layout and import the hosts it observes.
    func runPassiveDiscovery(customerSlug: String?, engagementId: String?) async -> PassiveScanResult? {
        guard !discoveryInFlight else { return nil }
        discoveryInFlight = true
        defer { discoveryInFlight = false }
        var params: [String: Any] = [:]
        if let s = customerSlug { params["customer_slug"] = s }
        if let e = engagementId { params["engagement_id"] = e }
        do {
            let result: PassiveScanResult = try await client.call(
                "discovery_passive_scan",
                params: params
            )
            lastDiscoveryResult = result
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - Notification config (used by Settings → Integrations)

    func loadNotifyConfig() async -> NotifyConfig? {
        do {
            return try await client.call("notify_get_config")
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func setNotifyPagerduty(scope: String, key: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_pagerduty",
                params: ["scope": scope, "key": key]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    @discardableResult
    func setNotifyOpsgenie(scope: String, key: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_opsgenie",
                params: ["scope": scope, "key": key]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func setNotifyWebhook(scope: String, webhookUrl: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_webhook",
                params: ["scope": scope, "webhook_url": webhookUrl]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }
}
