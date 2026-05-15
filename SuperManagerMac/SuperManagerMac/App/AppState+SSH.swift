import AppKit
import Foundation
import SwiftUI

extension AppState {
    // MARK: - SSH Hosts

    func refreshHosts() async {
        do {
            sshHosts = try await client.call("ssh_list_hosts")
        } catch {
            handleError(error)
        }
    }

    func addHost(label: String, hostname: String, port: UInt16, username: String,
                 group: String, deviceType: DeviceType, authMethod: AuthMethod,
                 authKeyId: String? = nil, password: String? = nil) async {
        var host: [String: Any] = [
            "label": label,
            "hostname": hostname,
            "port": port,
            "username": username,
            "group": group,
            "device_type": deviceType.rawValue,
            "auth_method": authMethod.rawValue,
            "pinned": false,
        ]
        if let keyId = authKeyId {
            host["auth_key_id"] = keyId
        }
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: host)
            let jsonStr = String(data: jsonData, encoding: .utf8) ?? "{}"
            var params: [String: Any] = ["host_json": jsonStr]
            if let pw = password, !pw.isEmpty {
                params["password"] = pw
            }
            let _: String = try await client.call("ssh_add_host", params: params)
            await refreshHosts()
        } catch {
            handleError(error)
        }
    }

    func updateHost(id: String, label: String, hostname: String, port: UInt16,
                    username: String, group: String, deviceType: DeviceType,
                    authMethod: AuthMethod, authKeyId: String? = nil,
                    password: String? = nil) async {
        var host: [String: Any] = [
            "label": label,
            "hostname": hostname,
            "port": port,
            "username": username,
            "group": group,
            "device_type": deviceType.rawValue,
            "auth_method": authMethod.rawValue,
        ]
        if let keyId = authKeyId { host["auth_key_id"] = keyId }
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: host)
            let jsonStr = String(data: jsonData, encoding: .utf8) ?? "{}"
            try await client.callVoid("ssh_update_host", params: ["host_id": id, "host_json": jsonStr])
            if let pw = password, !pw.isEmpty {
                try await client.callVoid("ssh_set_password", params: ["host_id": id, "password": pw])
            }
            await refreshHosts()
        } catch {
            handleError(error)
        }
    }

    func deleteHost(_ id: String) async {
        do {
            try await client.callVoid("ssh_delete_host", params: ["host_id": id])
            await refreshHosts()
            if selectedHostId == id { selectedHostId = nil }
        } catch {
            handleError(error)
        }
    }

    func togglePin(_ id: String) async {
        do {
            sshHosts = try await client.call("ssh_toggle_pin", params: ["host_id": id])
        } catch {
            handleError(error)
        }
    }

    func executeCommand(hostId: String, command: String) async -> (stdout: String, stderr: String, exitCode: Int)? {
        do {
            let result: CommandResult = try await client.call(
                "ssh_execute_command",
                params: ["host_id": hostId, "command": command]
            )
            return (result.stdout, result.stderr, result.exitCode)
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Typed result for SSH test-connection. The daemon now
    /// emits structured errors (`ssh_auth` vs `ssh_network` vs
    /// `other`) so the UI can react accordingly — e.g. surface a
    /// "Re-enter password" sheet on auth failure vs a "Connect VPN"
    /// suggestion on network failure.
    enum SshTestResult: Equatable {
        case ok
        case authFailed(String)
        case networkFailed(String)
        case otherFailure(String)
    }

    func testConnection(hostId: String) async -> SshTestResult {
        do {
            let result: [String: String] = try await client.call(
                "ssh_test_connection",
                params: ["host_id": hostId]
            )
            // Daemon returns `{"ssh": "ok"}` on success — anything
            // else means the typed error path is no longer wired
            // up correctly. Treat as success since the call didn't
            // throw.
            return result["ssh"] == "ok"
                ? .ok
                : .otherFailure(result["ssh"] ?? "Unknown")
        } catch let err as ServiceError {
            if case .rpcError(let info) = err {
                switch info.kind {
                case "ssh_auth":     return .authFailed(info.message)
                case "ssh_network":  return .networkFailed(info.message)
                default:             return .otherFailure(info.message)
                }
            }
            return .otherFailure(err.localizedDescription)
        } catch {
            return .otherFailure(error.localizedDescription)
        }
    }

    // MARK: - FortiGate REST API

    /// Generate a new FortiGate API token via SSH and store it.
    /// Returns the cleartext token on success (so the GUI can show it
    /// once + offer "Copy") or nil + error toast on failure. Refreshes
    /// the host list afterwards so the API badge appears immediately.
    @discardableResult
    func generateFortigateApiToken(hostId: String, apiUser: String = "supermgr-api") async -> String? {
        do {
            let result: GeneratedFortigateToken = try await client.call(
                "fortigate_generate_api_token",
                params: ["host_id": hostId, "api_user": apiUser]
            )
            await refreshHosts()
            return result.token
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Verify the stored token by calling /monitor/system/status.
    /// Returns rich device info on success. Used by the "Test
    /// connection" button under the API panel in HostDetailView.
    func testFortigateConnection(hostId: String) async -> FortigateTestInfo? {
        do {
            let info: FortigateTestInfo = try await client.call(
                "fortigate_test_connection",
                params: ["host_id": hostId]
            )
            return info
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Read the stored token in cleartext for "Copy" / "Show".
    func getFortigateApiToken(hostId: String) async -> String? {
        do {
            let result: [String: String] = try await client.call(
                "fortigate_get_api_token",
                params: ["host_id": hostId]
            )
            return result["token"]
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Paste-in flow for an externally-generated token.
    @discardableResult
    func setFortigateApiToken(hostId: String, token: String, apiPort: UInt16 = 443) async -> Bool {
        struct SetTokenResult: Codable { let stored: Bool }
        do {
            let _: SetTokenResult = try await client.call(
                "ssh_set_api_token",
                params: [
                    "host_id": hostId,
                    "token": token,
                    "api_port": apiPort,
                ]
            )
            await refreshHosts()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Forget the stored token. Idempotent — clearing an already-
    /// absent token is a no-op rather than an error.
    @discardableResult
    func clearFortigateApiToken(hostId: String) async -> Bool {
        struct ClearResult: Codable { let cleared: Bool }
        do {
            let _: ClearResult = try await client.call(
                "ssh_clear_api_token",
                params: ["host_id": hostId]
            )
            await refreshHosts()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Pull a fresh dashboard snapshot. Returns nil on any error
    /// (including transient ones — the caller's polling loop is
    /// responsible for retry; we don't blow up on intermittent
    /// failures since FortiOS is sometimes briefly unavailable
    /// during config changes).
    func fetchFortigateDashboard(hostId: String) async -> FortigateDashboardSnapshot? {
        do {
            let snap: FortigateDashboardSnapshot = try await client.call(
                "fortigate_get_dashboard",
                params: ["host_id": hostId]
            )
            return snap
        } catch {
            // Don't `handleError` here — the dashboard polling is
            // background-y and a single failed tick shouldn't show
            // a red toast banner. Log it and let the next tick
            // succeed (or fail twice in a row, at which point the
            // UI shows a stale-data indicator).
            DebugLog.write("[fortigate dashboard] fetch failed for host \(hostId): \(error)")
            return nil
        }
    }

    /// Generic FortiGate REST proxy. Returns (status, body). Phase 2
    /// uses this for the live dashboard; phase 5 builds compliance
    /// and template-deploy on top.
    func fortigateApi(
        hostId: String,
        method: String,
        path: String,
        body: String = ""
    ) async -> (status: Int, body: String)? {
        do {
            let result: FortigateApiRawResponse = try await client.call(
                "fortigate_api",
                params: [
                    "host_id": hostId,
                    "method": method,
                    "path": path,
                    "body": body,
                ]
            )
            return (status: result.status, body: result.body)
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - UniFi controller

    @discardableResult
    func setUnifiController(
        hostId: String,
        url: String,
        username: String,
        password: String
    ) async -> Bool {
        struct R: Codable { let saved: Bool }
        do {
            let _: R = try await client.call(
                "unifi_set_controller",
                params: [
                    "host_id": hostId,
                    "url": url,
                    "username": username,
                    "password": password,
                ]
            )
            await refreshHosts()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    @discardableResult
    func clearUnifiController(hostId: String) async -> Bool {
        struct R: Codable { let cleared: Bool }
        do {
            let _: R = try await client.call(
                "unifi_clear_controller",
                params: ["host_id": hostId]
            )
            await refreshHosts()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func testUnifiController(hostId: String) async -> UnifiTestInfo? {
        do {
            let info: UnifiTestInfo = try await client.call(
                "unifi_test",
                params: ["host_id": hostId]
            )
            return info
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Run `set-inform <inform_url>` on the device via SSH.
    /// Used both for first-time adoption (factory defaults
    /// ubnt/ubnt) and to repoint a device at a different
    /// controller.
    @discardableResult
    func unifiSetInform(hostId: String, informUrl: String) async -> String? {
        struct R: Codable { let stdout: String }
        do {
            let r: R = try await client.call(
                "unifi_set_inform",
                params: ["host_id": hostId, "inform_url": informUrl]
            )
            return r.stdout
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Detailed outcome of a UniFi `set-inform` invocation —
    /// success carries stdout; failure carries the raw engine
    /// error string for direct surfacing in the UI.
    enum UnifiSetInformOutcome {
        case success(stdout: String)
        case failure(message: String)
    }

    /// Detailed variant of `unifiSetInform`. Used by the
    /// Network-scan → Adopt flow so it can surface the actual
    /// SSH exit / stderr / "command not found" / etc. instead
    /// of swallowing it into a generic "something went wrong".
    func unifiSetInformDetailed(
        hostId: String,
        informUrl: String
    ) async -> UnifiSetInformOutcome {
        struct R: Codable { let stdout: String }
        do {
            let r: R = try await client.call(
                "unifi_set_inform",
                params: ["host_id": hostId, "inform_url": informUrl]
            )
            return .success(stdout: r.stdout)
        } catch {
            return .failure(message: String(describing: error))
        }
    }

    /// Generic UniFi REST proxy. Returns (status, body).
    func unifiApi(
        hostId: String,
        method: String,
        path: String,
        body: String = ""
    ) async -> (status: Int, body: String)? {
        struct R: Codable {
            let status: Int
            let body: String
        }
        do {
            let r: R = try await client.call(
                "unifi_api",
                params: [
                    "host_id": hostId,
                    "method": method,
                    "path": path,
                    "body": body,
                ]
            )
            return (status: r.status, body: r.body)
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - SSH Keys

    func refreshKeys() async {
        do {
            sshKeys = try await client.call("ssh_list_keys")
        } catch {
            handleError(error)
        }
    }

    func generateKey(name: String, keyType: String, description: String, tags: [String]) async {
        let tagsJson = (try? JSONSerialization.data(withJSONObject: tags))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        do {
            let _: String = try await client.call(
                "ssh_generate_key",
                params: ["name": name, "key_type": keyType, "description": description, "tags_json": tagsJson]
            )
            await refreshKeys()
        } catch {
            handleError(error)
        }
    }

    func deleteKey(_ id: String) async {
        do {
            try await client.callVoid("ssh_delete_key", params: ["key_id": id])
            await refreshKeys()
            if selectedKeyId == id { selectedKeyId = nil }
        } catch {
            handleError(error)
        }
    }

    func pushKey(keyId: String, hostIds: [String], useSudo: Bool) async -> [PushResult]? {
        let hostIdsJson = (try? JSONSerialization.data(withJSONObject: hostIds))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        do {
            let results: [PushResult] = try await client.call(
                "ssh_push_key",
                params: ["key_id": keyId, "host_ids_json": hostIdsJson, "use_sudo": useSudo]
            )
            await refreshKeys()
            return results
        } catch {
            handleError(error)
            return nil
        }
    }
}
