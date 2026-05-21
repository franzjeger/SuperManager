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

    /// Outcome of an attempted controller registration.
    enum SaveOutcome {
        case saved(UnifiController)
        /// Controller demanded a second factor. The GUI must
        /// route the operator through email-MFA via
        /// `sendUnifiMfaEmail` + `completeUnifiMfa` using the
        /// returned `challengeId`.
        case mfaRequired(challengeId: String, authenticators: [MfaAuthenticator])
    }

    /// Upsert a controller. Pass `id: nil` for a fresh save.
    /// `credential` (password OR API key, depending on
    /// `authMethod`) is required on first save; on update it
    /// can be omitted to leave the existing keychain entry
    /// intact.
    func saveUnifiController(
        id: String?,
        label: String,
        url: String,
        authMethod: UnifiAuthMethod,
        username: String,
        credential: String?,
        siteId: String = "default",
        customerSlug: String? = nil
    ) async -> Result<SaveOutcome, AppError> {
        // Wire payload shape — server accepts the credential
        // under either `password` or `api_key` so we use the
        // semantically correct one.
        var params: [String: Any] = [
            "label": label,
            "url": url,
            "username": username,
            "site_id": siteId,
            "auth_method": authMethod.rawValue,
        ]
        if let id { params["id"] = id }
        if let credential {
            switch authMethod {
            case .apiKey: params["api_key"] = credential
            case .password: params["password"] = credential
            }
        }
        if let customerSlug { params["customer_slug"] = customerSlug }
        // One Codable type with every field optional — the
        // engine returns either the saved shape (controller +
        // sysinfo) or the MFA-required shape (mfa_required +
        // challenge_id + authenticators) from the same RPC.
        // Branching on which fields decoded keeps this single
        // RPC contract clean.
        struct SaveResp: Codable {
            let controller: UnifiController?
            let sysinfo: UnifiSysInfo?
            let mfaRequired: Bool?
            let challengeId: String?
            let authenticators: [MfaAuthenticator]?
            enum CodingKeys: String, CodingKey {
                case controller, sysinfo, authenticators
                case mfaRequired = "mfa_required"
                case challengeId = "challenge_id"
            }
        }
        do {
            let resp: SaveResp = try await client.call(
                "unifi_controller_save",
                params: params
            )
            if resp.mfaRequired == true {
                return .success(.mfaRequired(
                    challengeId: resp.challengeId ?? "",
                    authenticators: resp.authenticators ?? []
                ))
            }
            guard let controller = resp.controller else {
                return .failure(AppError("server returned no controller and no MFA challenge"))
            }
            await refreshUnifiControllers()
            return .success(.saved(controller))
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }

    /// Trigger the email leg of an in-flight MFA challenge.
    /// `authenticatorId` is one of the IDs from the
    /// `.mfaRequired` outcome's `authenticators` list.
    func sendUnifiMfaEmail(
        challengeId: String,
        authenticatorId: String
    ) async -> Result<Void, AppError> {
        struct R: Codable { let sent: Bool }
        do {
            let _: R = try await client.call(
                "unifi_controller_mfa_send",
                params: [
                    "challenge_id": challengeId,
                    "authenticator_id": authenticatorId,
                ]
            )
            return .success(())
        } catch {
            return .failure(AppError(String(describing: error)))
        }
    }

    /// Submit the email-MFA code to complete a pending
    /// controller registration. On success the controller is
    /// persisted + verified.
    func completeUnifiMfa(
        challengeId: String,
        code: String
    ) async -> Result<UnifiController, AppError> {
        struct R: Codable {
            let controller: UnifiController
            let sysinfo: UnifiSysInfo
        }
        do {
            let r: R = try await client.call(
                "unifi_controller_mfa_complete",
                params: [
                    "challenge_id": challengeId,
                    "code": code,
                ]
            )
            await refreshUnifiControllers()
            return .success(r.controller)
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

/// Mirrors `engine::device_type_overrides::SnapshotView`: two
/// scoped dictionaries of operator-set overrides. `byMac`
/// applies to one specific MAC; `byOui` applies to every MAC
/// with that three-octet prefix. Lookup priority on the engine
/// side is exact-MAC first, then OUI prefix.
struct DeviceTypeOverrides: Codable, Equatable {
    var byMac: [String: String]
    var byOui: [String: String]

    static let empty = DeviceTypeOverrides(byMac: [:], byOui: [:])

    enum CodingKeys: String, CodingKey {
        case byMac = "by_mac"
        case byOui = "by_oui"
    }

    init(byMac: [String: String], byOui: [String: String]) {
        self.byMac = byMac
        self.byOui = byOui
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        byMac = (try? c.decode([String: String].self, forKey: .byMac)) ?? [:]
        byOui = (try? c.decode([String: String].self, forKey: .byOui)) ?? [:]
    }

    var isEmpty: Bool { byMac.isEmpty && byOui.isEmpty }
    var totalCount: Int { byMac.count + byOui.count }
}

extension AppState {
    /// Pull every persisted device-type override from the
    /// daemon, returned as a typed `DeviceTypeOverrides`
    /// (two scoped dictionaries). Used by the Settings →
    /// Network tab + by per-host scan-row rendering.
    func loadDeviceTypeOverrides() async -> DeviceTypeOverrides {
        do {
            return try await client.call("device_type_overrides_list")
        } catch {
            handleError(error)
            return .empty
        }
    }

    /// Scope of a device-type override.
    /// `mac` applies to the exact MAC only;
    /// `oui` applies to every device sharing the first three
    /// octets (e.g. all `58:d6:1f:*` devices) — useful when
    /// the operator finds an unrecognised Ubiquiti / Fortinet
    /// prefix and wants to classify the whole bunch at once.
    enum DeviceTypeOverrideScope: String {
        case mac
        case oui
    }

    /// Set or clear a manual device-type override.
    /// Pass `deviceType: nil` to clear. The override persists
    /// across re-scans on the daemon side.
    @discardableResult
    func setDeviceTypeOverride(
        mac: String,
        scope: DeviceTypeOverrideScope = .mac,
        deviceType: String?
    ) async -> Bool {
        struct R: Codable { let ok: Bool }
        var params: [String: Any] = [
            "mac": mac,
            "scope": scope.rawValue,
        ]
        if let dt = deviceType, !dt.isEmpty {
            params["device_type"] = dt
        } else {
            params["device_type"] = ""
        }
        do {
            let _: R = try await client.call(
                "device_type_override_set",
                params: params
            )
            return true
        } catch {
            handleError(error)
            return false
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
