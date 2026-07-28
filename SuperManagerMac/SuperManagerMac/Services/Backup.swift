import Foundation

/// Full-config backup / restore.
///
/// Backs up the daemon's data dir
/// (`~/Library/Application Support/SuperManager/`) as a single
/// `tar -czf` archive. That covers:
///   • SSH hosts (`ssh/hosts/*.toml`)
///   • SSH key metadata (`ssh/keys/*.toml`) — note: private key
///     material is in here, since `ssh-keygen` produces files we
///     persist alongside metadata. This is intentional — restoring on
///     a new Mac without the private keys would leave hosts orphaned.
///   • VPN profile metadata (`profiles/*.toml`)
///   • Daemon secret store (`secrets.json`, mode 0600). On macOS the
///     daemon runs the file-backed store — see the comment at
///     `supermgrd-mac`'s `FileSecretStore::default_path()` for why it
///     can't hold the keychain-access-groups entitlement — so this
///     file carries, as plain base64, everything the engine calls
///     `secrets.store()` on: SSH private keys and host passwords
///     (`handlers/ssh.rs`), FortiGate API tokens (same file),
///     UniFi controller passwords (`handlers/unifi.rs`), and
///     **WireGuard private keys and peer PSKs** (`handlers/vpn.rs`).
///   • Audit log (`ssh-audit.log`)
///
/// What's *not* in the archive — everything the GUI routes through
/// `VPNKeychain`/`MasterPassword` into the macOS Data Protection
/// Keychain, which is scoped to this Mac's hardware and so can't be
/// exported without breaking the security model (it would refuse to
/// import on another Mac anyway):
///   • **IKEv2 credentials** — EAP passwords and PSKs.
///   • **OpenVPN and Azure VPN credentials** — `vpn/<id>/ovpn-username`
///     and `vpn/<id>/ovpn-password`, read back at connect time in
///     `AppState+VPN.openVPNConnect`. Note the engine mints matching
///     `SecretRef` labels for these, but on macOS the GUI supplies the
///     values over RPC, so nothing lands in the file store.
///   • **Master-password hash**.
///
/// Restoring on a new Mac means re-entering each of those.
///
/// WireGuard is deliberately NOT in that list: its keys are minted by
/// the engine straight into the secret store above, so they travel
/// with the archive.
///
/// Because the data dir contains private SSH keys and possibly
/// password material, the produced archive is just as sensitive as
/// the original directory. We preserve mode 0600 on the file.
@MainActor
enum Backup {
    enum BackupError: Error, LocalizedError {
        case dataDirMissing
        case tarFailed(Int32, String)
        case restoreFailed(String)

        var errorDescription: String? {
            switch self {
            case .dataDirMissing:
                return "SuperManager's data directory doesn't exist yet — there's nothing to back up."
            case .tarFailed(let code, let msg):
                return "tar exited with code \(code): \(msg)"
            case .restoreFailed(let msg):
                return "Restore failed: \(msg)"
            }
        }
    }

    /// Path to SuperManager's data directory. Single source of truth —
    /// matches `supermgr_engine::secrets::default_data_dir()` on macOS.
    static var dataDir: URL {
        let support = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("SuperManager", isDirectory: true)
    }

    /// Suggested filename for a fresh backup, including a timestamp so
    /// successive backups don't overwrite each other when the user
    /// accepts the default name.
    static func suggestedFilename() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return "supermanager-backup-\(formatter.string(from: Date())).tar.gz"
    }

    /// Create a `.tar.gz` archive of the data directory at `destination`.
    /// `destination` must include a filename (use `suggestedFilename()`
    /// or whatever the user picked from `NSSavePanel`).
    static func export(to destination: URL) throws {
        let dir = dataDir
        guard FileManager.default.fileExists(atPath: dir.path) else {
            throw BackupError.dataDirMissing
        }

        // tar's `-C <dir>` followed by `.` means "archive the contents of
        // <dir>, with paths relative to <dir>" — restoring then drops
        // them straight back into the data dir without an extra level
        // of nesting.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = [
            "-czf", destination.path,
            "-C", dir.path,
            ".",
        ]
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errBytes = stderr.fileHandleForReading.readDataToEndOfFile()
            let errStr = String(data: errBytes, encoding: .utf8) ?? "unknown"
            throw BackupError.tarFailed(process.terminationStatus, errStr)
        }

        // Tighten file mode — the archive contains private SSH keys.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: destination.path
        )
    }

    /// Restore a `.tar.gz` archive into the data directory.
    ///
    /// The user is responsible for stopping the running app + daemon
    /// first; otherwise the daemon will keep stale state in memory and
    /// won't see the restored files until restart. We document this in
    /// the UI rather than silently killing the daemon.
    ///
    /// Backs up the existing data dir to
    /// `<data_dir>.before-restore-<timestamp>` before extracting, so
    /// a botched restore can be reverted with a `mv`.
    static func restore(from archive: URL) throws {
        let dir = dataDir

        // Quarantine the current data dir (never delete during restore;
        // user might have overlooked something they wanted).
        if FileManager.default.fileExists(atPath: dir.path) {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd-HHmmss"
            let backupName = "SuperManager.before-restore-\(formatter.string(from: Date()))"
            let quarantine = dir.deletingLastPathComponent()
                .appendingPathComponent(backupName, isDirectory: true)
            do {
                try FileManager.default.moveItem(at: dir, to: quarantine)
            } catch {
                throw BackupError.restoreFailed(
                    "Couldn't quarantine existing data dir: \(error.localizedDescription)"
                )
            }
        }

        // Recreate the data dir, then extract into it.
        do {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true
            )
        } catch {
            throw BackupError.restoreFailed(
                "Couldn't create data dir: \(error.localizedDescription)"
            )
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = [
            "-xzf", archive.path,
            "-C", dir.path,
        ]
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            throw BackupError.restoreFailed("tar launch: \(error.localizedDescription)")
        }
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errBytes = stderr.fileHandleForReading.readDataToEndOfFile()
            let errStr = String(data: errBytes, encoding: .utf8) ?? "unknown"
            throw BackupError.tarFailed(process.terminationStatus, errStr)
        }
    }
}
