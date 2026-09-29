import Foundation

/// What an OpenVPN configuration expects from the user at connect time.
enum OpenVPNCredentials {
    /// Whether `config` asks for a username and password: an
    /// `auth-user-pass` directive without a file, and no inline
    /// `<auth-user-pass>` block to answer it. OpenVPN runs without a
    /// terminal, so on such a profile it can only give up ("can't ask for
    /// 'Enter Auth Username:'"); the app says what is missing instead.
    ///
    /// Read the way OpenVPN reads it, as far as this one directive needs:
    /// `#` and `;` start comments, a leading `--` is dropped, and the text
    /// of other inline blocks (keys, certificates) is not configuration.
    static func areAsked(in config: String) -> Bool {
        var asked = false
        var openBlock: String?
        for line in config.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let text = line.trimmingCharacters(in: .whitespaces)
            if let block = openBlock {
                if text == "</\(block)>" { openBlock = nil }
                continue
            }
            if text.hasPrefix("<"), text.hasSuffix(">"), !text.hasPrefix("</") {
                let name = String(text.dropFirst().dropLast())
                if name == "auth-user-pass" { return false }
                openBlock = name
                continue
            }
            let words = text.split(whereSeparator: \.isWhitespace)
                .prefix { !$0.hasPrefix("#") && !$0.hasPrefix(";") }
            guard var directive = words.first else { continue }
            if directive.hasPrefix("--") { directive = directive.dropFirst(2) }
            if directive == "auth-user-pass" {
                // `auth-user-pass [inline]` is answered by the block; a file
                // name is not something the helper runs with at all.
                asked = words.count == 1
            }
        }
        return asked
    }
}
