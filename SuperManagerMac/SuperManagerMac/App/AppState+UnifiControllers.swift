import Foundation

/// Lightweight Error type for surfaces that return raw engine
/// error strings to the GUI. `Result<T, Error>` won't accept a
/// bare `String`, so we wrap it. The `String` initialiser lets
/// callers say `Result<T, AppError>.failure(.init(msg))` with
/// the same ergonomics as a string-keyed Result.
struct AppError: Error, LocalizedError {
    let message: String
    init(_ m: String) { self.message = m }
    var errorDescription: String? { message }
}

/// Standalone-UniFi-controller RPC surface. Separate from the
/// host-tied `unifi_set_inform` / `unifi_set_controller` / etc.
/// methods on `AppState+SSH.swift`, which target the legacy
/// "controller-as-an-SSH-host" model and stay for back-compat.
///
/// New code should prefer everything in this file: register a
/// controller with `unifi_controller_save`, list devices with
/// `unifi_controller_devices`, run actions with
/// `unifi_controller_devmgr`.
extension AppState {
    /// Refresh the in-memory list of configured controllers
    /// from the daemon. Called on app launch + after any
    /// mutation (save/delete).
    func refreshUnifiControllers() async {
        do {
            let list: [UnifiController] = try await client.call("unifi_controller_list")
            await MainActor.run { self.unifiControllers = list }
        } catch {
            handleError(error)
        }
    }

    /// Upsert a controller. Pass `id: nil` for a fresh save.
    /// `password` is required on first save; on update it can
    /// be omitted to leave the existing keychain entry intact.
    @discardableResult
    func saveUnifiController(
        id: String?,
        label: String,
        url: String,
        username: String,
        password: String?,
        siteId: String = "default",
        customerSlug: String? = nil
    ) async -> Result<UnifiController, AppError> {
        struct Resp: Codable {
            let controller: UnifiController
            let sysinfo: UnifiSysInfo
        }
        var params: [String: Any] = [
            "label": label,
            "url": url,
            "username": username,
            "site_id": siteId,
        ]
        if let id { params["id"] = id }
        if let password { params["password"] = password }
        if let customerSlug { params["customer_slug"] = customerSlug }
        do {
            let resp: Resp = try await client.call(
                "unifi_controller_save",
                params: params
            )
            await refreshUnifiControllers()
            return .success(resp.controller)
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }

    @discardableResult
    func deleteUnifiController(id: String) async -> Bool {
        struct R: Codable { let deleted: Bool }
        do {
            let _: R = try await client.call(
                "unifi_controller_delete",
                params: ["id": id]
            )
            await refreshUnifiControllers()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func testUnifiController(id: String) async -> Result<UnifiSysInfo, AppError> {
        struct R: Codable {
            let ok: Bool
            let sysinfo: UnifiSysInfo
        }
        do {
            let r: R = try await client.call(
                "unifi_controller_test",
                params: ["id": id]
            )
            await refreshUnifiControllers()
            return .success(r.sysinfo)
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }

    func listUnifiControllerDevices(id: String) async -> Result<[UnifiManagedDevice], AppError> {
        do {
            let devices: [UnifiManagedDevice] = try await client.call(
                "unifi_controller_devices",
                params: ["id": id]
            )
            return .success(devices)
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }

    /// Run a devmgr command (adopt / forget / restart / locate /
    /// unset-locate / upgrade / set-inform) against a MAC the
    /// controller manages. `extra` carries command-specific
    /// args — e.g. `["url": "http://controller:8080/inform"]`
    /// for set-inform.
    func runUnifiDevmgrCommand(
        controllerId: String,
        cmd: String,
        mac: String,
        extra: [String: Any] = [:]
    ) async -> Result<String, AppError> {
        var params: [String: Any] = [
            "id": controllerId,
            "cmd": cmd,
            "mac": mac,
        ]
        if !extra.isEmpty {
            params["extra"] = extra
        }
        do {
            let body: [String: AnyDecodable] = try await client.call(
                "unifi_controller_devmgr",
                params: params
            )
            // Stringify the controller's JSON response so the
            // GUI can show it raw in a success drawer.
            let data = try? JSONSerialization.data(
                withJSONObject: body.mapValues { $0.value },
                options: .prettyPrinted
            )
            let str = data.flatMap { String(data: $0, encoding: .utf8) }
            return .success(str ?? "ok")
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }
}

/// Tiny `Any`-wrapper so we can decode JSON objects with
/// unknown value types into a Swift dictionary without writing
/// a full struct.
private struct AnyDecodable: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let b = try? c.decode(Bool.self)      { self.value = b; return }
        if let i = try? c.decode(Int.self)       { self.value = i; return }
        if let d = try? c.decode(Double.self)    { self.value = d; return }
        if let s = try? c.decode(String.self)    { self.value = s; return }
        if let a = try? c.decode([AnyDecodable].self) { self.value = a.map(\.value); return }
        if let o = try? c.decode([String: AnyDecodable].self) {
            self.value = o.mapValues(\.value); return
        }
        if c.decodeNil() { self.value = NSNull(); return }
        throw DecodingError.dataCorruptedError(
            in: c,
            debugDescription: "unrecognised JSON value"
        )
    }
}
