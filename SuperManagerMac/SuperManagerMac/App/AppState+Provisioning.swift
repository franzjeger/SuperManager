import AppKit
import Foundation
import SwiftUI

extension AppState {
    func refreshCustomers() async {
        do {
            customers = try await client.call("customer_list")
        } catch {
            handleError(error)
        }
    }

    func saveCustomer(_ customer: Customer) async -> Customer? {
        do {
            // Pass the full customer record so the daemon doesn't
            // have to round-trip to validate sites.
            let saved: Customer = try await client.call(
                "customer_save",
                params: [
                    "display_name": customer.displayName,
                    "customer": try jsonValue(of: customer),
                ]
            )
            await refreshCustomers()
            return saved
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Render an aggregated Markdown report for a customer:
    /// site map + per-host compliance + deployment history.
    /// Returns the markdown string or nil + error toast.
    func renderCustomerReport(slug: String) async -> String? {
        struct ReportResponse: Codable { let markdown: String }
        do {
            let resp: ReportResponse = try await client.call(
                "customer_report",
                params: ["slug": slug]
            )
            return resp.markdown
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func deleteCustomer(slug: String) async -> Bool {
        struct Result: Codable { let deleted: Bool }
        do {
            let _: Result = try await client.call(
                "customer_delete",
                params: ["slug": slug]
            )
            await refreshCustomers()
            if selectedCustomerSlug == slug {
                selectedCustomerSlug = nil
                selectedSiteId = nil
            }
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func loadProvisioningTemplates() async {
        do {
            provisioningTemplates = try await client.call("provisioning_list_templates")
        } catch {
            DebugLog.write("[provisioning] template list failed: \(error)")
        }
    }

    func renderProvisioningTemplate(
        templateId: String,
        customerSlug: String,
        siteId: String,
        extras: [String: String] = [:]
    ) async -> ProvisioningRenderResult? {
        do {
            // Tera accepts arbitrary JSON for `extras`; we send
            // strings only here since the GUI form values are all
            // strings. Future enhancement: typed form fields.
            let extrasObj: [String: Any] = extras
            let result: ProvisioningRenderResult = try await client.call(
                "provisioning_render",
                params: [
                    "template_id": templateId,
                    "customer_slug": customerSlug,
                    "site_id": siteId,
                    "extras": extrasObj,
                ]
            )
            lastRenderResult = result
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Encode a Codable value to JSONSerialization-compatible
    /// `Any`. Used because `client.call`'s params dict accepts
    /// Foundation types, not Codables, so we round-trip via JSON.
    fileprivate func jsonValue<T: Encodable>(of value: T) throws -> Any {
        let data = try JSONEncoder().encode(value)
        return try JSONSerialization.jsonObject(with: data)
    }

    // MARK: Provisioning — diff preview + deploy

    func diffPreview(
        hostId: String,
        templateId: String,
        customerSlug: String,
        siteId: String,
        extras: [String: String] = [:]
    ) async -> DiffPreviewResult? {
        do {
            let renderRequest: [String: Any] = [
                "template_id": templateId,
                "customer_slug": customerSlug,
                "site_id": siteId,
                "extras": extras,
            ]
            let result: DiffPreviewResult = try await client.call(
                "provisioning_diff_preview",
                params: [
                    "host_id": hostId,
                    "render_request": renderRequest,
                ]
            )
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func deployTemplate(
        hostId: String,
        templateId: String,
        customerSlug: String,
        siteId: String,
        extras: [String: String] = [:]
    ) async -> Deployment? {
        do {
            let renderRequest: [String: Any] = [
                "template_id": templateId,
                "customer_slug": customerSlug,
                "site_id": siteId,
                "extras": extras,
            ]
            let result: Deployment = try await client.call(
                "provisioning_deploy",
                params: [
                    "host_id": hostId,
                    "render_request": renderRequest,
                ]
            )
            // Push to local cache so the History list updates
            // immediately without a separate fetch.
            var existing = deploymentHistory[hostId] ?? []
            existing.insert(result, at: 0)
            deploymentHistory[hostId] = existing
            // Auto-trigger a compliance scan so the user sees
            // immediate post-deploy feedback. Only when the
            // host has an API token; otherwise the scan would
            // error and we'd just confuse the user.
            if let host = sshHosts.first(where: { $0.id == hostId }), host.hasApi {
                Task { @MainActor in
                    _ = await runCompliance(hostId: hostId)
                }
            }
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadDeploymentHistory(hostId: String) async {
        do {
            let list: [Deployment] = try await client.call(
                "provisioning_list_deployments",
                params: ["host_id": hostId, "limit": 50]
            )
            deploymentHistory[hostId] = list
        } catch {
            DebugLog.write("[provisioning] history fetch failed: \(error)")
        }
    }

    @discardableResult
    func rollbackDeployment(hostId: String, backupPath: String) async -> Deployment? {
        do {
            let result: Deployment = try await client.call(
                "provisioning_rollback",
                params: ["host_id": hostId, "backup_path": backupPath]
            )
            await loadDeploymentHistory(hostId: hostId)
            return result
        } catch {
            handleError(error)
            return nil
        }
    }
}
