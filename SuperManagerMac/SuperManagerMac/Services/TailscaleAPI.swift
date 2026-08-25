import Foundation

/// Minimal client for the Tailscale **admin API** (`api.tailscale.com`),
/// used by the "Manage tailnet devices" UI to list and delete devices.
///
/// ## Why this exists separately from `TailscaleClient`
///
/// `TailscaleClient` drives the *local* `tailscale` CLI over the daemon
/// socket — it can bring the tunnel up, set prefs, read status. But the
/// CLI can only act on *this* node; it cannot delete an arbitrary peer
/// from the tailnet. Removing a device is a control-plane operation that
/// only the admin API can do (`DELETE /api/v2/device/{id}`).
///
/// ## Auth: OAuth client credentials
///
/// The user creates a one-time OAuth client in the admin console
/// (Settings → OAuth clients) with the `devices:core` scope, and pastes
/// the `client_id` / `client_secret` into SuperManager. We exchange them
/// for a short-lived bearer token and cache it until it nears expiry.
///
/// An OAuth client is preferred over a personal API access token because
/// the latter is capped at 90 days and would force periodic re-setup;
/// the OAuth client does not expire, matching the "configure once" goal.
///
/// This type is deliberately **pure**: credentials are passed in, never
/// read from storage here. Persistence lives in `TailscaleAPIConfig` so
/// this layer stays trivially testable and free of Keychain concerns.
enum TailscaleAPI {
    private static let base = URL(string: "https://api.tailscale.com/api/v2")!

    // MARK: - Model

    /// One device as returned by `GET /tailnet/-/devices`. Only the
    /// fields the UI needs are decoded; the API returns many more.
    struct Device: Identifiable, Decodable, Hashable {
        /// Numeric device id — the value `DELETE /device/{id}` expects.
        let id: String
        /// Stable node id (e.g. `nXXXX…CNTRL`). Not reliably equal to a
        /// local `tailscale status` peer's `ID`, so self-detection in the
        /// UI keys off tailnet-IP overlap rather than this field.
        let nodeId: String?
        /// Short hostname (e.g. `cachyos-x8664`).
        let hostname: String?
        /// MagicDNS name (e.g. `cachyos-x8664.tailXXXX.ts.net`).
        let name: String?
        /// Tailscale IPs assigned to the device.
        let addresses: [String]?
        /// Reported OS (`linux`, `macOS`, `iOS`, …).
        let os: String?
        /// Owning user (login email).
        let user: String?
        /// ISO-8601 timestamp of last contact.
        let lastSeen: String?

        enum CodingKeys: String, CodingKey {
            case id, nodeId, hostname, name, addresses, os, user, lastSeen
        }
    }

    // MARK: - Errors

    enum APIError: LocalizedError {
        case notConfigured
        case tokenExchangeFailed(Int, String)
        case http(Int, String)
        case malformed(String)

        var errorDescription: String? {
            switch self {
            case .notConfigured:
                return "No Tailscale OAuth client is configured. Add one in Settings first."
            case .tokenExchangeFailed(let code, let body):
                return "Tailscale sign-in failed (HTTP \(code)). Check the OAuth client id/secret. \(body)"
            case .http(let code, let body):
                return "Tailscale API error (HTTP \(code)). \(body)"
            case .malformed(let detail):
                return "Unexpected response from Tailscale (\(detail))."
            }
        }
    }

    // MARK: - Token cache

    /// Access tokens are ~1h-lived; we cache one per (id, secret) pair
    /// and refresh a minute before expiry so a long-lived UI session
    /// doesn't re-exchange on every call. An actor because the device
    /// list and each delete may race.
    private actor TokenCache {
        static let shared = TokenCache()
        private var token: String?
        private var expiry: Date?
        private var key: String?

        func valid(for key: String) -> String? {
            guard self.key == key, let token, let expiry, expiry > Date().addingTimeInterval(60)
            else { return nil }
            return token
        }

        func store(_ token: String, ttl: TimeInterval, for key: String) {
            self.token = token
            self.expiry = Date().addingTimeInterval(ttl)
            self.key = key
        }

        func invalidate() {
            token = nil; expiry = nil; key = nil
        }
    }

    // MARK: - Public API

    /// List every device in the caller's default tailnet (`-`).
    static func listDevices(clientId: String, clientSecret: String) async throws -> [Device] {
        let token = try await accessToken(clientId: clientId, clientSecret: clientSecret)
        var req = URLRequest(url: base.appendingPathComponent("tailnet/-/devices"))
        req.httpMethod = "GET"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        try Self.check(resp, data, context: "list devices")

        struct Envelope: Decodable { let devices: [Device]? }
        do {
            return try JSONDecoder().decode(Envelope.self, from: data).devices ?? []
        } catch {
            throw APIError.malformed("device list: \(error.localizedDescription)")
        }
    }

    /// Permanently remove a device from the tailnet by its numeric id.
    /// Irreversible on Tailscale's side — the UI must confirm first.
    static func deleteDevice(id: String, clientId: String, clientSecret: String) async throws {
        let token = try await accessToken(clientId: clientId, clientSecret: clientSecret)
        var req = URLRequest(url: base.appendingPathComponent("device/\(id)"))
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        try Self.check(resp, data, context: "delete device")
    }

    /// Drop any cached bearer token — call when the stored OAuth client
    /// changes or is forgotten, so a stale token isn't reused.
    static func forgetCachedToken() async {
        await TokenCache.shared.invalidate()
    }

    // MARK: - Internals

    /// Exchange client credentials for a bearer token, using the cache.
    private static func accessToken(clientId: String, clientSecret: String) async throws -> String {
        guard !clientId.isEmpty, !clientSecret.isEmpty else { throw APIError.notConfigured }
        let cacheKey = clientId + "\u{0}" + clientSecret
        if let cached = await TokenCache.shared.valid(for: cacheKey) { return cached }

        var req = URLRequest(url: base.appendingPathComponent("oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // Encode each value ourselves rather than via URLComponents:
        // `percentEncodedQuery` leaves `+` literal (valid in a query),
        // but a form parser reads `+` as a space, corrupting any secret
        // that contains one. Strip `&=+%` from the allowed set so those
        // separators are always percent-escaped. Mirrors AzureOAuth.
        let body = [
            "client_id=\(Self.formEncode(clientId))",
            "client_secret=\(Self.formEncode(clientSecret))",
            "grant_type=client_credentials",
        ].joined(separator: "&")
        req.httpBody = body.data(using: .utf8)

        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw APIError.tokenExchangeFailed(http.statusCode, Self.snippet(data))
        }
        struct TokenResp: Decodable { let access_token: String; let expires_in: Double? }
        let tr: TokenResp
        do {
            tr = try JSONDecoder().decode(TokenResp.self, from: data)
        } catch {
            throw APIError.malformed("token response: \(error.localizedDescription)")
        }
        await TokenCache.shared.store(tr.access_token, ttl: tr.expires_in ?? 3600, for: cacheKey)
        return tr.access_token
    }

    /// Throw `APIError.http` for any non-2xx, carrying a short body snippet.
    private static func check(_ resp: URLResponse, _ data: Data, context: String) throws {
        guard let http = resp as? HTTPURLResponse else {
            throw APIError.malformed("\(context): no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw APIError.http(http.statusCode, Self.snippet(data))
        }
    }

    /// Percent-encode a value for an `x-www-form-urlencoded` body,
    /// escaping the `&=+%` separators that `urlQueryAllowed` leaves raw.
    private static func formEncode(_ s: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+%")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    /// First 300 chars of a response body, for error messages.
    private static func snippet(_ data: Data) -> String {
        let s = String(data: data, encoding: .utf8) ?? ""
        return s.count > 300 ? String(s.prefix(300)) + "…" : s
    }
}
