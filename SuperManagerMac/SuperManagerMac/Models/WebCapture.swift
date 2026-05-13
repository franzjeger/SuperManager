import Foundation

/// Snapshot of a piece of equipment the operator discovered out
/// of band — typically by clicking a `supermgr://addhost?...`
/// bookmarklet on a vendor admin page (UniFi, FortiGate, etc.),
/// but also constructible from a plain pasted IP / URL / banner
/// string.
///
/// The whole point is to skip retyping. The user has the info on
/// screen in their browser; the capture parses what it can and
/// pre-fills the sheet, leaving the operator to confirm + pick
/// an action ("add SSH host", "scan this", …).
struct WebCapture: Equatable, Identifiable {
    /// Stable identity so SwiftUI's `.sheet(item:)` can drive
    /// the presentation off `appState.pendingWebCapture`. Default
    /// `UUID()` means each new capture triggers a fresh sheet.
    let id: UUID
    /// IP or DNS name of the device. Required.
    var hostname: String
    /// Port if the bookmarklet picked one up from the page's URL
    /// (e.g. `https://10.0.0.1:8443/admin/`). nil → SSH default
    /// (22) will be used.
    var port: UInt16?
    /// Suggested display name. Pulled from the page title, or
    /// falls back to the hostname.
    var label: String
    /// Best-guess device type from the URL host / page title /
    /// explicit `vendor=` parameter.
    var deviceType: DeviceType
    /// Default username for the device class. Operator can edit.
    var username: String
    /// The original page URL, kept for context display ("captured
    /// from https://1.2.3.4:8443/admin/").
    var sourceUrl: URL?
    /// Original page title, kept for context display.
    var pageTitle: String?

    init(
        id: UUID = UUID(),
        hostname: String,
        port: UInt16? = nil,
        label: String,
        deviceType: DeviceType,
        username: String,
        sourceUrl: URL? = nil,
        pageTitle: String? = nil
    ) {
        self.id = id
        self.hostname = hostname
        self.port = port
        self.label = label
        self.deviceType = deviceType
        self.username = username
        self.sourceUrl = sourceUrl
        self.pageTitle = pageTitle
    }

    /// Parse a `supermgr://addhost?…` URL the OS handed us via
    /// `.onOpenURL`. Returns nil if no usable host can be
    /// recovered — the caller decides whether to surface that as
    /// an error or silently ignore.
    ///
    /// Accepted query parameters (all optional except at least
    /// one of `ip` / `hostname` / `source`):
    ///   - `ip` / `hostname`   — explicit device address
    ///   - `port`              — explicit port (16-bit decimal)
    ///   - `vendor` / `type`   — device-type hint
    ///   - `label`             — display name
    ///   - `title`             — page title (used for label
    ///                            fallback + vendor sniffing)
    ///   - `username`          — pre-fill for the SSH username
    ///   - `source`            — the page URL (used to fall back
    ///                            for host/port + vendor
    ///                            sniffing if the above are
    ///                            missing)
    static func from(url: URL) -> WebCapture? {
        guard url.scheme?.lowercased() == "supermgr" else { return nil }
        let qs = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems ?? []
        let q: (String) -> String? = { name in
            qs.first(where: { $0.name == name })?
                .value?
                .removingPercentEncoding
        }

        // The source URL is the strongest fallback signal because
        // bookmarklets typically pass `source=` even when they
        // can't sniff the IP themselves.
        let source = q("source").flatMap(URL.init(string:))

        let rawHost = q("ip")
            ?? q("hostname")
            ?? source?.host
            ?? ""
        guard !rawHost.isEmpty else { return nil }

        var port: UInt16? = nil
        if let s = q("port"), let v = UInt16(s) {
            port = v
        } else if let p = source?.port,
                  let v = UInt16(exactly: p) {
            port = v
        }

        let vendorHint = q("vendor") ?? q("type")
        let title = q("title")
        let label = q("label") ?? title ?? rawHost
        let dt = Self.sniffDeviceType(
            hint: vendorHint,
            host: rawHost,
            sourceUrl: source,
            title: title
        )

        return WebCapture(
            hostname: rawHost,
            port: port,
            label: label,
            deviceType: dt,
            username: q("username") ?? Self.defaultUsername(for: dt),
            sourceUrl: source,
            pageTitle: title
        )
    }

    /// Smart-parse pasted text. Accepts a bare IP, a `host:port`,
    /// a full URL, or arbitrary text containing an IPv4. Returns
    /// nil if nothing host-shaped can be extracted.
    static func from(pastedText raw: String) -> WebCapture? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        // 1. Full URL with scheme.
        if let url = URL(string: text),
           let scheme = url.scheme, !scheme.isEmpty,
           let host = url.host, !host.isEmpty
        {
            let p = url.port.flatMap { UInt16(exactly: $0) }
            let dt = sniffDeviceType(
                hint: nil, host: host,
                sourceUrl: url, title: nil
            )
            return WebCapture(
                hostname: host, port: p, label: host,
                deviceType: dt,
                username: Self.defaultUsername(for: dt),
                sourceUrl: url, pageTitle: nil
            )
        }

        // 2. host:port form (last colon — IPv6 wouldn't survive
        //    this without brackets anyway).
        if let colon = text.lastIndex(of: ":") {
            let host = String(text[..<colon])
            let portStr = String(text[text.index(after: colon)...])
            if let p = UInt16(portStr), isValidHostOrIp(host) {
                let dt = sniffDeviceType(
                    hint: nil, host: host,
                    sourceUrl: nil, title: nil
                )
                return WebCapture(
                    hostname: host, port: p, label: host,
                    deviceType: dt,
                    username: Self.defaultUsername(for: dt),
                    sourceUrl: nil, pageTitle: nil
                )
            }
        }

        // 3. Bare host / IP.
        if isValidHostOrIp(text) {
            let dt = sniffDeviceType(
                hint: nil, host: text,
                sourceUrl: nil, title: nil
            )
            return WebCapture(
                hostname: text, port: nil, label: text,
                deviceType: dt,
                username: Self.defaultUsername(for: dt),
                sourceUrl: nil, pageTitle: nil
            )
        }

        // 4. Last resort — scan the blob for the first IPv4 and
        //    treat that as the host. The blob itself becomes the
        //    "page title" so device-type sniffing has more signal
        //    (e.g. a banner string like "FortiGate-100F v7.4.1
        //    192.0.2.5").
        if let ip = firstIPv4(in: text) {
            let dt = sniffDeviceType(
                hint: nil, host: ip,
                sourceUrl: nil, title: text
            )
            return WebCapture(
                hostname: ip, port: nil, label: ip,
                deviceType: dt,
                username: Self.defaultUsername(for: dt),
                sourceUrl: nil, pageTitle: text
            )
        }

        return nil
    }

    // MARK: - Heuristics

    /// Guess the device type from any combination of: explicit
    /// vendor hint, hostname, source-URL host, page title. The
    /// hint always wins if it parses cleanly.
    static func sniffDeviceType(
        hint: String?,
        host: String,
        sourceUrl: URL?,
        title: String?
    ) -> DeviceType {
        // Explicit hint — exact match against the enum's raw
        // values + a couple of friendly aliases.
        if let hint = hint?.lowercased(), !hint.isEmpty {
            switch hint {
            case "linux": return .linux
            case "unifi", "ubiquiti", "uni_fi", "ui": return .unifi
            case "pfsense", "pf_sense", "netgate": return .pfSense
            case "openwrt", "open_wrt", "lede": return .openWrt
            case "fortigate", "fortinet": return .fortigate
            case "windows", "win": return .windows
            default: break
            }
        }
        // Fall back to scanning host / source URL / title for
        // vendor strings.
        let blob = [
            host,
            sourceUrl?.host ?? "",
            sourceUrl?.absoluteString ?? "",
            title ?? "",
        ].joined(separator: " ").lowercased()

        if blob.contains("fortigate") || blob.contains("fortinet") {
            return .fortigate
        }
        if blob.contains("unifi") || blob.contains("ui.com")
            || blob.contains("ubiquiti") || blob.contains("ubnt")
        {
            return .unifi
        }
        if blob.contains("pfsense") || blob.contains("netgate") {
            return .pfSense
        }
        if blob.contains("openwrt") || blob.contains("lede") {
            return .openWrt
        }
        if blob.contains("win-") || blob.contains("windows") {
            return .windows
        }
        return .linux
    }

    /// Default SSH username for a freshly-captured device based
    /// on its vendor. Operator can override before submitting.
    static func defaultUsername(for type: DeviceType) -> String {
        switch type {
        case .unifi: return "ubnt"
        case .fortigate: return "admin"
        case .pfSense: return "root"
        case .openWrt: return "root"
        case .windows: return "Administrator"
        case .linux, .custom: return "root"
        }
    }

    private static func isValidHostOrIp(_ s: String) -> Bool {
        guard !s.isEmpty, !s.contains(" "), !s.contains("/")
        else { return false }
        let allowed = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "-._:"))
        return s.unicodeScalars.allSatisfy(allowed.contains)
    }

    private static func firstIPv4(in s: String) -> String? {
        let pattern = #"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"#
        guard let re = try? NSRegularExpression(pattern: pattern),
              let match = re.firstMatch(
                in: s,
                range: NSRange(s.startIndex..., in: s)
              ),
              let range = Range(match.range, in: s)
        else { return nil }
        return String(s[range])
    }
}
