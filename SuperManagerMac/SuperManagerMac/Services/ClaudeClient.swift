import Foundation

/// Thin Anthropic Messages API client. We don't pull in the
/// official SDK — the surface area we need is a single POST,
/// and shipping a Swift package dependency for that would be
/// disproportionate. Streaming would be nice but adds 200 lines
/// of SSE parsing for marginal UX gain on the kind of prompts
/// we send (config explanations max out around 4 KB output).
///
/// The API key never leaves the GUI process. Going through the
/// daemon would have been cleaner architecturally but means
/// every Claude call adds an RPC roundtrip, and the daemon
/// currently has no API-key storage. For v1 the GUI hits the
/// Anthropic endpoint directly with the key from AppSettings.
enum ClaudeClient {
    static let endpoint = URL(string: "https://api.anthropic.com/v1/messages")!
    static let model = "claude-sonnet-4-5-20250929"
    static let apiVersion = "2023-06-01"
    static let maxTokens = 4096

    /// One-shot call. `system` is optional — pass nil to use
    /// only the user's message. Returns the assistant's text
    /// reply or throws on transport / API errors.
    ///
    /// Errors include:
    ///   - .missingApiKey if AppSettings has no key
    ///   - .httpError(status, body) on 4xx/5xx
    ///   - .decode if Anthropic returns a shape we don't
    ///     understand (defensive — they version their API)
    static func send(
        system: String?,
        userMessage: String,
        apiKey: String
    ) async throws -> String {
        guard !apiKey.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ClaudeError.missingApiKey
        }
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        req.setValue(apiVersion, forHTTPHeaderField: "anthropic-version")

        var body: [String: Any] = [
            "model": model,
            "max_tokens": maxTokens,
            "messages": [
                ["role": "user", "content": userMessage],
            ],
        ]
        if let system = system, !system.isEmpty {
            body["system"] = system
        }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw ClaudeError.transport("not an HTTP response")
        }
        if http.statusCode >= 400 {
            let bodyText = String(data: data, encoding: .utf8) ?? ""
            throw ClaudeError.httpError(http.statusCode, bodyText)
        }

        // Anthropic's response shape:
        // { "content": [ {"type": "text", "text": "..."} ], "stop_reason": "...", ... }
        struct Reply: Decodable {
            struct Block: Decodable {
                let type: String
                let text: String?
            }
            let content: [Block]
        }
        let reply = try JSONDecoder().decode(Reply.self, from: data)
        let text = reply.content
            .compactMap { $0.type == "text" ? $0.text : nil }
            .joined(separator: "\n")
        return text
    }
}

enum ClaudeError: LocalizedError {
    case missingApiKey
    case transport(String)
    case httpError(Int, String)
    case decode(String)

    var errorDescription: String? {
        switch self {
        case .missingApiKey:
            return "No Anthropic API key configured. Set one under Settings → Claude AI."
        case .transport(let msg):
            return "Network error: \(msg)"
        case .httpError(let status, let body):
            // Anthropic returns errors as JSON: {"type":"error","error":{"type":"...","message":"..."}}
            // Try to surface the human-readable message.
            if let data = body.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let err = json["error"] as? [String: Any],
               let msg = err["message"] as? String {
                return "Anthropic API \(status): \(msg)"
            }
            return "Anthropic API \(status): \(body.prefix(200))"
        case .decode(let msg):
            return "Could not parse Anthropic response: \(msg)"
        }
    }
}
