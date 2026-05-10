import AppKit
import SwiftUI

/// Microsoft Entra ID PKCE sign-in for an Azure VPN profile.
/// Two phases the user moves through:
///
///   1. **Awaiting browser** — `AzureOAuth.signIn` opens the
///      system browser to AAD's authorize endpoint. The user
///      signs in (and clears any MFA / consent prompts) over
///      there. Our loopback listener catches the redirect and
///      we exchange the auth code for an access token.
///   2. **Bringing up tunnel** — daemon renders the OpenVPN body,
///      Mac writes it to disk, helper spawns `openvpn3
///      session-start` with the token piped in via stdin.
///
/// Cancel-safe: closing the sheet cancels the awaiting Task,
/// which tears down the loopback listener.
struct AzureSignInSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let profileId: String
    let summary: AzureVpnSummary
    var onConnected: () -> Void = {}

    private enum Phase {
        case awaitingBrowser
        case bringingUpTunnel
        case error(String)
    }

    @State private var phase: Phase = .awaitingBrowser
    @State private var task: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.tint)
                    .font(.title2)
                Text("Sign in with Microsoft")
                    .font(.headline)
                Spacer()
            }

            switch phase {
            case .awaitingBrowser:
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Browser opened — sign in to Microsoft")
                            .font(.callout)
                    }
                    Text("Once you've signed in, this sheet will continue automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Tenant: \(summary.tenantId)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                        .padding(.top, 4)
                }

            case .bringingUpTunnel:
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Signed in — bringing up the OpenVPN tunnel…")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

            case .error(let message):
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 12)

            HStack {
                if case .error = phase {
                    Button("Try again") {
                        Task { await begin() }
                    }
                    .keyboardShortcut(.defaultAction)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(22)
        .frame(width: 480)
        .task { await begin() }
        .onDisappear { task?.cancel() }
    }

    /// Run the auth + tunnel-up flow. Tries silent refresh first;
    /// falls back to the full PKCE browser flow if no fresh
    /// refresh-token is cached.
    private func begin() async {
        DebugLog.write("[AzureSignIn] BEGIN profileId=\(profileId) tenant=\(summary.tenantId.prefix(8))… audience=\(summary.clientId.prefix(8))…")
        phase = .awaitingBrowser
        task?.cancel()
        // Record the start of the connect attempt so the
        // detail-view's Recent activity row reflects it even if
        // the user closes the sheet before it completes.
        ActivityLog.shared.record(
            profileId: profileId,
            kind: .connectStarted,
            message: "Azure VPN: sign-in started"
        )

        let token: AzureOAuth.AccessToken
        do {
            token = try await AzureOAuth.acquireToken(
                tenant: summary.tenantId,
                audience: summary.clientId
            )
            DebugLog.write("[AzureSignIn] auth OK, got token for \(token.username)")
        } catch let err as AzureOAuth.AuthError {
            DebugLog.write("[AzureSignIn] auth FAILED: \(err.errorDescription ?? "unknown")")
            if case .userCancelled = err {
                dismiss()
                return
            }
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: sign-in failed — \(err.errorDescription ?? "unknown")"
            )
            phase = .error(err.errorDescription ?? "Sign-in failed.")
            return
        } catch {
            DebugLog.write("[AzureSignIn] auth FAILED (untyped): \(error)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: sign-in failed — \(error.localizedDescription)"
            )
            phase = .error(error.localizedDescription)
            return
        }

        phase = .bringingUpTunnel
        await bringUpTunnel(token: token)
    }

    /// Render the .ovpn via the daemon, write to disk, hand off
    /// to the privileged helper.
    private func bringUpTunnel(token: AzureOAuth.AccessToken) async {
        struct RenderResponse: Decodable {
            let ovpnBody: String
            enum CodingKeys: String, CodingKey { case ovpnBody = "ovpn_body" }
        }

        DebugLog.write("[AzureSignIn] requesting daemon to render Azure .ovpn body")
        let render: RenderResponse
        do {
            render = try await appState.client.call(
                "vpn_render_azure_ovpn",
                params: ["profile_id": profileId]
            )
            DebugLog.write("[AzureSignIn] daemon rendered .ovpn (\(render.ovpnBody.count) chars, has_ca=\(render.ovpnBody.contains("<ca>")), has_tls_auth=\(render.ovpnBody.contains("<tls-auth>")))")
        } catch {
            DebugLog.write("[AzureSignIn] vpn_render_azure_ovpn RPC FAILED: \(error)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: render failed — \(error.localizedDescription)"
            )
            phase = .error("Couldn't render the OpenVPN config: \(error.localizedDescription)")
            return
        }

        // /tmp instead of ~/Library/Caches: the privileged
        // helper runs as root, but macOS TCC can block root
        // processes from traversing user-Library paths
        // (especially under privacy-protected directories), and
        // the resulting `EPERM` when openvpn tries to read the
        // config surfaces as a generic "openvpn refused to
        // start" with an empty stderr — exactly what we just
        // saw. /tmp is mode-1777 world-readable; both Mac (as
        // user) and helper (as root) can read it without TCC
        // friction. Same pattern production SuperManager Linux
        // uses with /run/supermgrd/azure-<uuid>/.
        let ovpnPath = URL(fileURLWithPath: "/tmp/supermgr-azure-\(profileId).ovpn")
        do {
            try render.ovpnBody.write(to: ovpnPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: ovpnPath.path)
            DebugLog.write("[AzureSignIn] wrote .ovpn to \(ovpnPath.path) (mode 0644)")
        } catch {
            DebugLog.write("[AzureSignIn] failed to write \(ovpnPath.path): \(error)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: stage .ovpn failed — \(error.localizedDescription)"
            )
            phase = .error("Couldn't stage the OpenVPN config on disk: \(error.localizedDescription)")
            return
        }

        let reachable = await HelperClient.shared.isReachable()
        guard reachable else {
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: privileged helper unreachable"
            )
            phase = .error("The privileged helper isn't reachable. Approve it in System Settings → General → Login Items, then try again.")
            return
        }

        // Username = UPN extracted from the access_token JWT
        // (`upn` claim or `preferred_username`), with `AzureAD`
        // as a last-resort fallback. The Azure VPN gateway
        // accepts any non-empty username when the password is a
        // valid bearer token — the real authentication happens
        // via token validation. Production SuperManager Linux
        // uses this exact policy.
        DebugLog.write("[AzureSignIn] calling helper.ovpnConnect with username=\(token.username), token=\(token.accessToken.count) chars")
        let connectResult: [String: Any]
        do {
            connectResult = try await HelperClient.shared.ovpnConnect(
                profileId: profileId,
                configFile: ovpnPath.path,
                username: token.username,
                password: token.accessToken
            )
            DebugLog.write("[AzureSignIn] helper.ovpnConnect returned: success=\(connectResult["success"] ?? "?"), message=\(connectResult["message"] ?? "?"), log_path=\(connectResult["log_path"] ?? "?")")
        } catch {
            DebugLog.write("[AzureSignIn] helper.ovpnConnect RPC threw: \(error)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: helper RPC failed — \(error.localizedDescription)"
            )
            phase = .error("Helper RPC failed: \(error.localizedDescription)")
            return
        }

        // Helper returns `{success: bool, message: string,
        // log_path?: string}` — `success: false` means openvpn's
        // initial fork+exec returned non-zero (config error,
        // missing binary, etc). Surface the helper's message
        // verbatim so the user sees what openvpn actually said.
        if let ok = connectResult["success"] as? Bool, !ok {
            let msg = (connectResult["message"] as? String) ?? "openvpn refused to start"
            DebugLog.write("[AzureSignIn] helper reported success=false: \(msg)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: openvpn refused to start"
            )
            phase = .error(msg)
            return
        }

        // openvpn 2.x daemonises immediately after fork — the
        // helper's `cmd.output()` returns success the moment the
        // child detaches, NOT when the tunnel is actually up.
        // Poll `ovpn_status` for up to 30 seconds to confirm the
        // process is still alive and reporting `connected`. The
        // window is generous because Azure gateways frequently
        // RST the first TCP attempt and the openvpn daemon's
        // retry loop only succeeds on the second or third pass —
        // a 5-second budget would miss those. Production Linux
        // (`supermgrd/src/vpn/azure.rs`) waits 60s for the same
        // reason; we use 30s here because the Mac UI feels
        // unresponsive past that and we'd rather surface a
        // "still trying" error the user can retry than freeze.
        let logPath = connectResult["log_path"] as? String
        DebugLog.write("[AzureSignIn] polling ovpn_status for tunnel-up confirmation (log_path=\(logPath ?? "<none>"))")
        var connected = false
        var lastStatus: String = "unknown"
        for attempt in 0..<30 {              // up to ~30 seconds at 1s/poll
            try? await Task.sleep(for: .milliseconds(1000))
            if let status = try? await HelperClient.shared.ovpnStatus(profileId: profileId) {
                lastStatus = (status["state"] as? String) ?? "?"
                DebugLog.write("[AzureSignIn] poll #\(attempt + 1): state=\(lastStatus), pid=\(status["pid"] ?? "?")")
                if lastStatus == "connected" {
                    connected = true
                    break
                }
            } else {
                DebugLog.write("[AzureSignIn] poll #\(attempt + 1): ovpn_status RPC threw")
            }
        }
        guard connected else {
            // Read log file for the actual openvpn error so the
            // user sees AUTH_FAILED / Cannot load CA / whatever.
            var logTail = ""
            if let p = logPath, let body = try? String(contentsOfFile: p) {
                let lines = body.split(separator: "\n").suffix(15).joined(separator: "\n")
                logTail = "\n\nLast 15 lines of \(p):\n\(lines)"
            }
            DebugLog.write("[AzureSignIn] tunnel never reached connected (last status=\(lastStatus))\(logTail)")
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Azure VPN: tunnel never reached connected (last: \(lastStatus))"
            )
            phase = .error("openvpn started but the tunnel never reached `connected` (last status: \(lastStatus)).\(logTail)")
            return
        }

        DebugLog.write("[AzureSignIn] SUCCESS — tunnel up as \(token.username)")
        ActivityLog.shared.record(
            profileId: profileId,
            kind: .connectSucceeded,
            message: "Azure VPN: tunnel up as \(token.username)"
        )
        onConnected()
        dismiss()
    }
}
