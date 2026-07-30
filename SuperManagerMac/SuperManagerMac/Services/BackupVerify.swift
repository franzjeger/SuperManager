import Foundation

/// Dress rehearsal for a backup archive.
///
/// The point is to find out that an archive is broken on the day it is
/// *taken*, not the day it is needed. `verify` extracts the archive into
/// a private temp directory and runs the checks a restore would care
/// about, without touching the live data directory at all.
///
/// The checks are deliberately restore-shaped rather than exhaustive:
/// does the tar extract, are the stores parseable, and does every secret
/// a profile references actually exist in the archived secret store.
/// That last one is the check with teeth — this codebase has already
/// shipped delete paths that leaked secrets and enrolments with empty
/// args, so "the reference and the referent are both present" is exactly
/// the invariant worth rehearsing. (Keychain-held credentials — IKEv2,
/// OpenVPN/Azure — are expected to be absent and are NOT flagged; the
/// archive never contains them, see `Backup`'s doc.)
enum BackupVerify {

    struct Check: Identifiable {
        enum Status { case pass, warn, fail }
        let title: String
        let status: Status
        let detail: String
        var id: String { title }
    }

    struct Report {
        var checks: [Check]
        /// Worst status across the checks — drives the summary line.
        var worst: Check.Status {
            if checks.contains(where: { $0.status == .fail }) { return .fail }
            if checks.contains(where: { $0.status == .warn }) { return .warn }
            return .pass
        }
    }

    /// Extract `archive` to a temp dir and inspect it. Blocking; call it
    /// off the main actor. The temp dir is removed before returning —
    /// including on throw — so extracted secrets never outlive the call.
    static func verify(archive: URL) -> Report {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("supermgr-verify-\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: scratch, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            return Report(checks: [Check(
                title: "Prepare scratch directory", status: .fail,
                detail: error.localizedDescription)])
        }
        defer { try? fm.removeItem(at: scratch) }

        var checks: [Check] = []

        // 1. Does the archive extract at all?
        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-xzf", archive.path, "-C", scratch.path]
        let stderr = Pipe()
        tar.standardError = stderr
        do {
            try tar.run()
            tar.waitUntilExit()
        } catch {
            return Report(checks: [Check(
                title: "Extract archive", status: .fail,
                detail: error.localizedDescription)])
        }
        guard tar.terminationStatus == 0 else {
            let msg = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8) ?? "unknown"
            return Report(checks: [Check(
                title: "Extract archive", status: .fail,
                detail: "tar exited \(tar.terminationStatus): \(msg.trimmingCharacters(in: .whitespacesAndNewlines))")])
        }
        checks.append(Check(title: "Extract archive", status: .pass,
                            detail: "tar extracted cleanly"))

        checks.append(contentsOf: inspect(extracted: scratch))
        return Report(checks: checks)
    }

    /// The content checks, split from the tar plumbing so tests can run
    /// them against a plain directory without building an archive first.
    static func inspect(extracted dir: URL) -> [Check] {
        let fm = FileManager.default
        var checks: [Check] = []

        // 2. Secret store parses, and how big is it.
        let secretsURL = dir.appendingPathComponent("secrets.json")
        var secrets: [String: String] = [:]
        if let data = fm.contents(atPath: secretsURL.path) {
            if let parsed = try? JSONDecoder().decode([String: String].self, from: data) {
                secrets = parsed
                checks.append(Check(
                    title: "Secret store", status: .pass,
                    detail: "secrets.json parses — \(parsed.count) entries"))
            } else {
                checks.append(Check(
                    title: "Secret store", status: .fail,
                    detail: "secrets.json exists but does not parse as a string map"))
            }
        } else {
            // Legitimate on a machine that never stored a secret, but worth
            // a warning since a restore of THIS archive silently has none.
            checks.append(Check(
                title: "Secret store", status: .warn,
                detail: "no secrets.json in the archive"))
        }

        // 3. VPN profiles are present and readable.
        let profilesDir = dir.appendingPathComponent("profiles")
        let profileFiles = (try? fm.contentsOfDirectory(at: profilesDir, includingPropertiesForKeys: nil))?
            .filter { $0.pathExtension == "toml" } ?? []
        var profileTexts: [String: String] = [:]
        var unreadable: [String] = []
        for f in profileFiles {
            if let text = try? String(contentsOf: f, encoding: .utf8), text.contains("id = ") {
                profileTexts[f.deletingPathExtension().lastPathComponent] = text
            } else {
                unreadable.append(f.lastPathComponent)
            }
        }
        if profileFiles.isEmpty {
            checks.append(Check(title: "VPN profiles", status: .warn,
                                detail: "no profiles/ in the archive"))
        } else if unreadable.isEmpty {
            checks.append(Check(title: "VPN profiles", status: .pass,
                                detail: "\(profileTexts.count) profile files readable"))
        } else {
            checks.append(Check(
                title: "VPN profiles", status: .fail,
                detail: "unreadable or empty: \(unreadable.joined(separator: ", "))"))
        }

        // 4. The check with teeth: every daemon-store secret a profile
        // references must exist in the archived store. Keychain-held
        // labels (password/psk/ovpn-*) are expected to be absent on
        // macOS and are not flagged — only labels the daemon store OWNS
        // (WireGuard key material) count as missing.
        var missing: [String] = []
        for (profileId, text) in profileTexts {
            for label in referencedLabels(inProfileToml: text)
            where daemonStoreOwns(label: label) && secrets[label] == nil {
                missing.append("\(profileId.prefix(8)): \(label)")
            }
        }
        if profileTexts.isEmpty {
            // Nothing to cross-reference; say nothing rather than a
            // vacuous pass.
        } else if missing.isEmpty {
            checks.append(Check(
                title: "Secret cross-reference", status: .pass,
                detail: "every daemon-store secret referenced by a profile is present"))
        } else {
            checks.append(Check(
                title: "Secret cross-reference", status: .fail,
                detail: "referenced but absent — a restore breaks these: "
                    + missing.sorted().joined(separator: "; ")))
        }

        // 5. The .ovpn files OpenVPN profiles point at.
        let ovpnDir = dir.appendingPathComponent("ovpn")
        let ovpnFiles = (try? fm.contentsOfDirectory(at: ovpnDir, includingPropertiesForKeys: nil))?
            .filter { $0.pathExtension == "ovpn" } ?? []
        let emptyOvpn = ovpnFiles.filter {
            ((try? $0.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0) == 0
        }
        if !ovpnFiles.isEmpty {
            checks.append(emptyOvpn.isEmpty
                ? Check(title: "OpenVPN configs", status: .pass,
                        detail: "\(ovpnFiles.count) .ovpn files, none empty")
                : Check(title: "OpenVPN configs", status: .fail,
                        detail: "zero-byte: \(emptyOvpn.map(\.lastPathComponent).joined(separator: ", "))"))
        }

        return checks
    }

    /// Secret labels referenced from a profile TOML. The daemon writes
    /// refs as quoted strings like `"vpn/<uuid>/wg-private-key"`; keying
    /// on the `vpn/` prefix inside quotes keeps this independent of
    /// which field name carries the ref.
    static func referencedLabels(inProfileToml text: String) -> [String] {
        var labels: [String] = []
        var rest = Substring(text)
        while let start = rest.range(of: "\"vpn/") {
            let after = rest[start.upperBound...]
            guard let end = after.firstIndex(of: "\"") else { break }
            labels.append("vpn/" + after[..<end])
            rest = after[after.index(after: end)...]
        }
        return labels
    }

    /// Which referenced labels live in the daemon's file store on macOS
    /// (as opposed to the Keychain, which the GUI owns). Must stay in
    /// step with where the engine actually mints secrets — see
    /// `handlers/vpn.rs`.
    static func daemonStoreOwns(label: String) -> Bool {
        label.contains("/wg-private-key") || label.contains("/wg-psk-")
    }
}
