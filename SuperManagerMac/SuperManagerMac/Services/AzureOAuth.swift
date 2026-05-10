import AppKit
import CryptoKit
import Darwin
import Foundation

/// Microsoft Entra ID PKCE auth-code flow for Azure VPN, ported
/// from MSP-Toolkit-V2's `get_auth_url` + `exchange_code` pair.
///
/// # Why PKCE, not device-code, for the audience-as-client_id trick
///
/// The Azure VPN gateway's audience GUID (`c632b3df-…`) is
/// registered as a **confidential** AAD client. Hitting the
/// device-code grant against it without a `client_secret` fails
/// with `AADSTS7000218: client_secret required` — there's no
/// public-client signal in the device-code request shape.
///
/// PKCE (RFC 7636) is the OAuth2 extension specifically designed
/// to let public clients prove identity without a secret. The
/// `code_verifier` sent to the token endpoint hashes to the
/// `code_challenge` that was sent to the authorize endpoint;
/// matching them is cryptographic proof that the same client
/// holds both. AAD treats a PKCE-signed token request as
/// public-client even when the app registration says confidential.
/// This is exactly what MSP-Toolkit-V2's interactive flow does
/// in production and what we replicate here.
///
/// # Flow
///
/// 1. Generate PKCE verifier + challenge (S256).
/// 2. Spin up an `NWListener` on a random localhost port.
/// 3. Open the system browser to v2 authorize endpoint with
///    `client_id=<audience>`, `scope=<audience>/.default …`,
///    `redirect_uri=http://localhost:<port>/`,
///    `code_challenge=<challenge>`.
/// 4. AAD walks the user through sign-in / MFA / consent.
/// 5. AAD redirects the browser to our loopback URL with
///    `?code=…&state=…`.
/// 6. The listener catches one GET, replies with a friendly
///    close-page, resolves the awaiting Task with the code.
/// 7. POST `code + code_verifier` to the v2 token endpoint;
///    AAD verifies PKCE and returns the access token.
/// 8. Refresh token cached in macOS Keychain so the next
///    connect tries silent refresh first.
enum AzureOAuth {

    struct AccessToken {
        /// Bearer token to send in the OpenVPN `auth-user-pass`
        /// password slot. Short-lived (~1 hour).
        let accessToken: String
        /// User principal name lifted from the id_token.
        let username: String
        /// Refresh token, if AAD issued one. Cached to Keychain.
        let refreshToken: String?
        let expiresAt: Date
    }

    enum AuthError: LocalizedError {
        case authorizationDenied(String)
        case userCancelled
        case browserOpenFailed
        case listenerFailed(String)
        case missingCode
        case tokenExchangeFailed(String)
        case decodeFailed(String)

        var errorDescription: String? {
            switch self {
            case .authorizationDenied(let s): return "Microsoft refused the sign-in: \(s)"
            case .userCancelled:              return "Sign-in was cancelled."
            case .browserOpenFailed:          return "Couldn't open the browser for sign-in."
            case .listenerFailed(let s):      return "Couldn't open a loopback callback: \(s)"
            case .missingCode:                return "AAD redirect didn't include an authorization code."
            case .tokenExchangeFailed(let s): return "Couldn't exchange the auth code for a token: \(s)"
            case .decodeFailed(let s):        return "Couldn't decode AAD's token response: \(s)"
            }
        }
    }

    /// Interactive sign-in. `audience` is the gateway audience
    /// from the imported `.azurevpnconfig` (e.g. `c632b3df-…`),
    /// used as both OAuth client_id and the resource in the scope.
    static func signIn(tenant: String, audience: String) async throws -> AccessToken {
        DebugLog.write("[AzureOAuth] signIn START tenant=\(tenant.prefix(8))… audience=\(audience.prefix(8))…")
        let pkce = PKCE.generate()
        let state = randomURLSafe(length: 32)
        DebugLog.write("[AzureOAuth] generated PKCE verifier (\(pkce.verifier.count) chars), challenge (\(pkce.challenge.count) chars), state nonce")

        let listener = try LoopbackOAuthListener.start(expectedState: state)
        DebugLog.write("[AzureOAuth] loopback listener bound at \(listener.redirectURI)")
        defer { listener.cancel() }

        var authorize = URLComponents()
        authorize.scheme = "https"
        authorize.host = "login.microsoftonline.com"
        authorize.path = "/\(tenant)/oauth2/v2.0/authorize"
        authorize.queryItems = [
            URLQueryItem(name: "client_id", value: audience),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: listener.redirectURI),
            URLQueryItem(name: "scope", value: "\(audience)/.default offline_access openid profile"),
            URLQueryItem(name: "response_mode", value: "query"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "prompt", value: "select_account"),
        ]
        if let hint = loadLoginHint(audience: audience, tenant: tenant) {
            authorize.queryItems?.append(URLQueryItem(name: "login_hint", value: hint))
        }
        guard let authorizeURL = authorize.url else {
            DebugLog.write("[AzureOAuth] FAILED to construct authorize URL")
            throw AuthError.browserOpenFailed
        }
        DebugLog.write("[AzureOAuth] opening browser → \(authorizeURL.host ?? "?")\(authorizeURL.path)?client_id=\(audience.prefix(8))…&redirect_uri=\(listener.redirectURI)&scope=…")
        guard NSWorkspace.shared.open(authorizeURL) else {
            DebugLog.write("[AzureOAuth] NSWorkspace.open returned false — no default browser?")
            throw AuthError.browserOpenFailed
        }

        DebugLog.write("[AzureOAuth] awaiting redirect callback on \(listener.redirectURI)…")
        let code = try await listener.awaitCode()
        DebugLog.write("[AzureOAuth] received auth code (\(code.count) chars), exchanging for token")
        return try await exchangeCodeForToken(
            tenant: tenant,
            audience: audience,
            code: code,
            redirectURI: listener.redirectURI,
            codeVerifier: pkce.verifier
        )
    }

    /// Try silent refresh first; fall back to interactive
    /// `signIn(...)` if no fresh refresh-token is cached.
    static func acquireToken(tenant: String, audience: String) async throws -> AccessToken {
        if let token = await tryRefreshSilently(tenant: tenant, audience: audience) {
            return token
        }
        return try await signIn(tenant: tenant, audience: audience)
    }

    static func tryRefreshSilently(tenant: String, audience: String) async -> AccessToken? {
        guard let refresh = loadRefreshToken(audience: audience, tenant: tenant) else {
            return nil
        }
        // `client_info=1` keeps refresh requests on the public-client
        // path too — the audience client is registered confidential.
        let body = formEncode([
            ("client_id", audience),
            ("client_info", "1"),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("scope", "\(audience)/.default offline_access openid profile"),
        ])
        guard let token = try? await postToken(tenant: tenant, body: body) else {
            return nil
        }
        if let r = token.refreshToken {
            saveRefreshToken(audience: audience, tenant: tenant, token: r)
        }
        return token
    }

    // ---------------------------------------------------------------
    // Token exchange
    // ---------------------------------------------------------------

    private static func exchangeCodeForToken(
        tenant: String,
        audience: String,
        code: String,
        redirectURI: String,
        codeVerifier: String
    ) async throws -> AccessToken {
        // PKCE: `code_verifier` proves we're the same client that
        // sent the `code_challenge` at authorize-time. AAD uses
        // this in lieu of `client_secret` for public-client style
        // requests against the audience client.
        //
        // `client_info=1` is the load-bearing magic. AAD's v2
        // endpoint inspects this and downgrades the request from
        // "confidential client missing secret" (AADSTS7000218) to
        // "public client with PKCE proof" — which is what we are.
        // Without it, even a perfectly-formed PKCE request fails
        // for the audience client. Confirmed in the production
        // SuperManager Linux Azure backend.
        let body = formEncode([
            ("client_id", audience),
            ("client_info", "1"),
            ("code", code),
            ("code_verifier", codeVerifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirectURI),
            ("scope", "\(audience)/.default offline_access openid profile"),
        ])
        let token = try await postToken(tenant: tenant, body: body)
        if let r = token.refreshToken {
            saveRefreshToken(audience: audience, tenant: tenant, token: r)
        }
        if token.username != "azure_vpn" {
            saveLoginHint(audience: audience, tenant: tenant, hint: token.username)
        }
        return token
    }

    private static func postToken(tenant: String, body: String) async throws -> AccessToken {
        // Sanitised body for logging — strips the auth-code,
        // refresh-token, and code-verifier so they don't land
        // in the user's debug log on disk.
        let sanitised = body.split(separator: "&")
            .map { pair -> String in
                let p = String(pair)
                if p.hasPrefix("code=") { return "code=<redacted>" }
                if p.hasPrefix("code_verifier=") { return "code_verifier=<redacted>" }
                if p.hasPrefix("refresh_token=") { return "refresh_token=<redacted>" }
                return p
            }
            .joined(separator: "&")
        DebugLog.write("[AzureOAuth] POST /oauth2/v2.0/token body=\(sanitised)")

        let url = URL(string: "https://login.microsoftonline.com/\(tenant)/oauth2/v2.0/token")!
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            DebugLog.write("[AzureOAuth] token endpoint returned non-HTTP response")
            throw AuthError.tokenExchangeFailed("non-HTTP response")
        }
        DebugLog.write("[AzureOAuth] token endpoint HTTP \(http.statusCode), \(data.count) bytes")
        let json = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]

        if !(200..<300).contains(http.statusCode) {
            let err = (json["error_description"] as? String)
                ?? (json["error"] as? String)
                ?? "HTTP \(http.statusCode)"
            DebugLog.write("[AzureOAuth] TOKEN EXCHANGE FAILED: \(err)")
            DebugLog.write("[AzureOAuth] full response body: \(String(data: data, encoding: .utf8) ?? "<binary>")")
            throw AuthError.tokenExchangeFailed(err)
        }

        guard let access = json["access_token"] as? String else {
            DebugLog.write("[AzureOAuth] decode failed — token endpoint omitted access_token; keys=\(json.keys.sorted())")
            throw AuthError.decodeFailed("token endpoint omitted access_token")
        }
        let refresh = json["refresh_token"] as? String
        let expiresIn: TimeInterval = {
            if let n = json["expires_in"] as? NSNumber { return TimeInterval(n.intValue) }
            if let s = json["expires_in"] as? String, let n = TimeInterval(s) { return n }
            return 3600
        }()
        // UPN comes from the access token itself (production
        // SuperManager Linux behaviour). `upn` first (corporate
        // tenants), then `preferred_username` (consumer accounts),
        // then the `AzureAD` fallback the Azure VPN gateway accepts.
        let username = decodeJWTUsername(access) ?? "AzureAD"
        DebugLog.write("[AzureOAuth] token OK: access_token=\(access.prefix(20))… (\(access.count) chars), refresh=\(refresh != nil ? "yes" : "no"), expires_in=\(Int(expiresIn))s, upn=\(username)")
        // Diagnostic: dump the JWT's `iss`, `aud`, `appid`, `tid`,
        // `ver` claims so we can compare against what the Azure VPN
        // gateway expects from the .azurevpnconfig (`<issuer>` /
        // `<audience>` fields). Token-rejected-without-AUTH_FAILED
        // is almost always an iss/aud mismatch — without these in
        // the log there's no way to tell which.
        if let claims = decodeJWTClaims(access) {
            let iss  = (claims["iss"]  as? String) ?? "?"
            let aud  = (claims["aud"]  as? String) ?? "?"
            let appid = (claims["appid"] as? String) ?? "?"
            let tid  = (claims["tid"]  as? String) ?? "?"
            let ver  = (claims["ver"]  as? String) ?? "?"
            DebugLog.write("[AzureOAuth] JWT claims: iss=\(iss) aud=\(aud) appid=\(appid) tid=\(tid) ver=\(ver)")
        } else {
            DebugLog.write("[AzureOAuth] JWT claims: <decode failed>")
        }

        return AccessToken(
            accessToken: access,
            username: username,
            refreshToken: refresh,
            expiresAt: Date().addingTimeInterval(expiresIn)
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static func decodeJWTUsername(_ jwt: String) -> String? {
        guard let obj = decodeJWTClaims(jwt) else { return nil }
        // `upn` first — corporate tenants populate this with the
        // user's actual sign-in name. `preferred_username` is the
        // consumer-account fallback. Order matters; production
        // code in supermgrd/src/vpn/azure.rs uses this exact
        // priority.
        return (obj["upn"] as? String)
            ?? (obj["preferred_username"] as? String)
            ?? (obj["email"] as? String)
    }

    /// Decode a JWT's payload (the middle segment, base64url-encoded
    /// JSON) into a claims dict. Returns `nil` if the token shape
    /// is malformed — caller should handle that gracefully rather
    /// than aborting the connect, since the gateway might still
    /// accept the raw token even when we can't introspect it.
    private static func decodeJWTClaims(_ jwt: String) -> [String: Any]? {
        let segments = jwt.split(separator: ".")
        guard segments.count >= 2 else { return nil }
        var b64 = String(segments[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        guard let data = Data(base64Encoded: b64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj
    }

    private static func formEncode(_ pairs: [(String, String)]) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+")
        return pairs.map { "\($0.0)=\($0.1.addingPercentEncoding(withAllowedCharacters: allowed) ?? $0.1)" }
            .joined(separator: "&")
    }

    static func randomURLSafe(length: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncoded
    }

    // ---------------------------------------------------------------
    // Keychain-backed refresh-token + login-hint cache
    // ---------------------------------------------------------------

    private static let keychainService = "com.sybr.supermanager.azure-vpn"

    private static func keychainAccount(audience: String, tenant: String, suffix: String) -> String {
        let raw = "\(audience):\(tenant):\(suffix)"
        let digest = SHA256.hash(data: Data(raw.utf8))
        return Data(digest).map { String(format: "%02x", $0) }.joined().prefix(32).description
    }

    private static func saveRefreshToken(audience: String, tenant: String, token: String) {
        keychainSet(account: keychainAccount(audience: audience, tenant: tenant, suffix: "refresh"), value: token)
    }

    static func loadRefreshToken(audience: String, tenant: String) -> String? {
        keychainGet(account: keychainAccount(audience: audience, tenant: tenant, suffix: "refresh"))
    }

    private static func saveLoginHint(audience: String, tenant: String, hint: String) {
        keychainSet(account: keychainAccount(audience: audience, tenant: tenant, suffix: "hint"), value: hint)
    }

    static func loadLoginHint(audience: String, tenant: String) -> String? {
        keychainGet(account: keychainAccount(audience: audience, tenant: tenant, suffix: "hint"))
    }

    private static func keychainSet(account: String, value: String) {
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: account,
        ]
        SecItemDelete(attrs as CFDictionary)
        var add = attrs
        add[kSecValueData] = Data(value.utf8)
        _ = SecItemAdd(add as CFDictionary, nil)
    }

    private static func keychainGet(account: String) -> String? {
        let q: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let str = String(data: data, encoding: .utf8)
        else { return nil }
        return str
    }
}

// MARK: - PKCE

private struct PKCE {
    let verifier: String
    let challenge: String

    static func generate() -> PKCE {
        // 32 random bytes → 43 base64url chars (within the
        // RFC 7636 §4.1 43-128 char range).
        let verifier = AzureOAuth.randomURLSafe(length: 32)
        let digest = SHA256.hash(data: Data(verifier.utf8))
        let challenge = Data(digest).base64URLEncoded
        return PKCE(verifier: verifier, challenge: challenge)
    }
}

// MARK: - Loopback HTTP listener

/// One-shot HTTP listener for the OAuth callback on
/// `http://127.0.0.1:2023` — same fixed port the production
/// SuperManager Linux backend uses
/// (`tokio::net::TcpListener::bind("127.0.0.1:2023")` in
/// `supermgrd/src/vpn/azure.rs`). We use plain POSIX sockets
/// instead of `Network.framework` because the latter's
/// `NWListener(using:, on:)` rejects bind-to-loopback with
/// `EINVAL` in some macOS configurations — POSIX sockets are
/// what the production code uses, and they Just Work.
///
/// Lifecycle: bind on `start()`; `awaitCode()` accepts one
/// connection on a background queue and resolves with the
/// `?code=…` query parameter; `cancel()` closes the socket
/// (idempotent).
private final class LoopbackOAuthListener: @unchecked Sendable {
    /// Production-validated port. If 2023 is busy we walk up
    /// through 2024..=2032 before giving up.
    static let preferredPort: UInt16 = 2023
    static let portWindow: ClosedRange<UInt16> = 2023...2032

    let redirectURI: String
    private let listenSocket: Int32
    private let expectedState: String
    private var continuation: CheckedContinuation<String, Error>?
    /// Lock around `continuation` + `acceptedSocket` since the
    /// accept loop runs on a background queue.
    private let lock = NSLock()
    private var acceptedSocket: Int32 = -1
    private var cancelled = false

    private init(listenSocket: Int32, port: UInt16, expectedState: String) {
        self.listenSocket = listenSocket
        // Match the audience client's registered redirect URI
        // exactly: `http://localhost:2023` — no trailing slash,
        // hostname `localhost` (NOT `127.0.0.1`). AAD does
        // case-sensitive string equality on the redirect_uri,
        // so any variation gets `AADSTS50011`. We still bind
        // the socket to `127.0.0.1` (IP literal, since bind()
        // doesn't resolve hostnames); only the *string* AAD
        // sees needs to be `localhost`.
        self.redirectURI = "http://localhost:\(port)"
        self.expectedState = expectedState
    }

    /// Bind a fresh socket. Tries `preferredPort` first, falls
    /// back through `portWindow` on `EADDRINUSE`. Throws
    /// `listenerFailed` with the syscall error string when
    /// every port is taken.
    static func start(expectedState: String) throws -> LoopbackOAuthListener {
        var lastErr: String = "no port in \(portWindow) available"
        for portNum in portWindow {
            do {
                let listener = try bind(port: portNum, expectedState: expectedState)
                listener.startAcceptLoop()
                DebugLog.write("[AzureOAuth.Listener] bound 127.0.0.1:\(portNum), redirect_uri=\(listener.redirectURI)")
                return listener
            } catch let AzureOAuth.AuthError.listenerFailed(msg) {
                DebugLog.write("[AzureOAuth.Listener] port \(portNum) unavailable: \(msg)")
                lastErr = msg
                continue
            }
        }
        DebugLog.write("[AzureOAuth.Listener] all ports in \(portWindow) failed: \(lastErr)")
        throw AzureOAuth.AuthError.listenerFailed(lastErr)
    }

    private static func bind(port portNum: UInt16, expectedState: String) throws -> LoopbackOAuthListener {
        let sock = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw AzureOAuth.AuthError.listenerFailed("socket(): \(String(cString: strerror(errno)))")
        }
        // SO_REUSEADDR so a leftover TIME_WAIT from a previous
        // sign-in attempt doesn't block us.
        var yes: Int32 = 1
        _ = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = portNum.bigEndian   // network byte order
        // 127.0.0.1 in network byte order: the four octets
        // packed as a UInt32 with the high byte first.
        addr.sin_addr.s_addr = UInt32(127) << 24
                             | UInt32(0)   << 16
                             | UInt32(0)   << 8
                             | UInt32(1)
        addr.sin_addr.s_addr = addr.sin_addr.s_addr.bigEndian

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(sock, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bindResult != 0 {
            let msg = String(cString: strerror(errno))
            close(sock)
            throw AzureOAuth.AuthError.listenerFailed("bind(127.0.0.1:\(portNum)): \(msg)")
        }
        if Darwin.listen(sock, 1) != 0 {
            let msg = String(cString: strerror(errno))
            close(sock)
            throw AzureOAuth.AuthError.listenerFailed("listen(): \(msg)")
        }

        return LoopbackOAuthListener(
            listenSocket: sock,
            port: portNum,
            expectedState: expectedState
        )
    }

    /// Spin a background queue waiting for the OAuth redirect.
    /// Resolves the awaiting `awaitCode()` Task on the first
    /// well-formed connection.
    private func startAcceptLoop() {
        let listenSock = self.listenSocket
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            DebugLog.write("[AzureOAuth.Listener] accept() blocking on fd=\(listenSock)")
            // Block in accept(); the kernel hands us one client.
            var clientAddr = sockaddr()
            var clientLen = socklen_t(MemoryLayout<sockaddr>.size)
            let conn = Darwin.accept(listenSock, &clientAddr, &clientLen)
            DebugLog.write("[AzureOAuth.Listener] accept() returned fd=\(conn) errno=\(conn < 0 ? errno : 0)")
            guard let self else {
                DebugLog.write("[AzureOAuth.Listener] self deallocated, dropping connection")
                if conn >= 0 { close(conn) }
                return
            }
            self.lock.lock()
            self.acceptedSocket = conn
            let cancelled = self.cancelled
            self.lock.unlock()

            if cancelled || conn < 0 {
                if conn >= 0 { close(conn) }
                return
            }

            // Read the request — a single `recv` of up to 8 KiB
            // catches the full GET line + headers in practice.
            // We only care about the request line.
            var buffer = [UInt8](repeating: 0, count: 8192)
            let n = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
                Darwin.recv(conn, ptr.baseAddress, 8192, 0)
            }
            guard n > 0 else {
                close(conn)
                self.resolveContinuation(.failure(AzureOAuth.AuthError.missingCode))
                return
            }
            let request = String(decoding: buffer[..<Int(n)], as: UTF8.self)

            // Parse `GET /?code=…&state=… HTTP/1.1` — first line.
            let firstLine = request.split(separator: "\r\n").first ?? ""
            let parts = firstLine.split(separator: " ")
            guard parts.count >= 2, parts[0] == "GET" else {
                close(conn)
                self.resolveContinuation(.failure(AzureOAuth.AuthError.missingCode))
                return
            }
            let path = String(parts[1])
            guard let comps = URLComponents(string: "http://localhost\(path)") else {
                close(conn)
                self.resolveContinuation(.failure(AzureOAuth.AuthError.missingCode))
                return
            }
            let query = Dictionary(uniqueKeysWithValues:
                (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") })

            // Always reply with the close-page so the browser
            // shows a friendly result.
            let body = self.htmlClosingPage(success: query["error"] == nil)
            let header = """
            HTTP/1.1 200 OK\r
            Content-Type: text/html; charset=utf-8\r
            Content-Length: \(body.utf8.count)\r
            Connection: close\r
            \r

            """
            let response = (header + body)
            response.withCString { cstr in
                _ = Darwin.send(conn, cstr, strlen(cstr), 0)
            }
            close(conn)

            DebugLog.write("[AzureOAuth.Listener] received \(n) bytes; query keys: \(query.keys.sorted())")
            // Now resolve the continuation with the parsed result.
            if let err = query["error"] {
                let desc = query["error_description"] ?? err
                DebugLog.write("[AzureOAuth.Listener] AAD returned error: \(desc)")
                self.resolveContinuation(.failure(AzureOAuth.AuthError.authorizationDenied(desc)))
            } else if query["state"] != self.expectedState {
                DebugLog.write("[AzureOAuth.Listener] state mismatch: got \(query["state"] ?? "nil"), expected \(self.expectedState.prefix(8))…")
                self.resolveContinuation(.failure(AzureOAuth.AuthError.authorizationDenied(
                    "state mismatch — possible CSRF, refusing the response"
                )))
            } else if let code = query["code"], !code.isEmpty {
                DebugLog.write("[AzureOAuth.Listener] resolving with auth code (\(code.count) chars)")
                self.resolveContinuation(.success(code))
            } else {
                DebugLog.write("[AzureOAuth.Listener] no code in query; resolving with missingCode")
                self.resolveContinuation(.failure(AzureOAuth.AuthError.missingCode))
            }
        }
    }

    func awaitCode() async throws -> String {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            self.lock.lock()
            self.continuation = cont
            self.lock.unlock()
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let cont = continuation
        continuation = nil
        let accepted = acceptedSocket
        acceptedSocket = -1
        lock.unlock()

        // Closing the listening socket aborts any blocked
        // `accept()` call with EBADF — the loop exits cleanly.
        Darwin.close(listenSocket)
        if accepted >= 0 {
            Darwin.close(accepted)
        }
        cont?.resume(throwing: AzureOAuth.AuthError.userCancelled)
    }

    private func resolveContinuation(_ result: Result<String, Error>) {
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        switch result {
        case .success(let s): cont?.resume(returning: s)
        case .failure(let e): cont?.resume(throwing: e)
        }
    }

    private func htmlClosingPage(success: Bool) -> String {
        let title = success ? "Sign-in complete" : "Sign-in failed"
        let body = success
            ? "You're signed in. You can close this tab and return to SuperManager."
            : "The sign-in didn't complete. Return to SuperManager for the error message."
        return """
        <!doctype html>
        <html><head><meta charset="utf-8"><title>\(title)</title>
        <style>
        body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:520px;
        margin:60px auto;padding:0 24px;color:#222;text-align:center}
        h1{font-size:22px;margin:0 0 12px}
        p{font-size:15px;color:#555;line-height:1.5}
        </style></head>
        <body><h1>\(title)</h1><p>\(body)</p></body></html>
        """
    }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
