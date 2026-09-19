import Foundation
import Darwin

/// Build identity reported by both `--version` and `helper_version`.
/// The helper's Cargo version is independent of the GUI's bundle version.
struct HelperBuildInfo: Sendable {
    let version: String
    let timestamp: UInt64
    let methods: Set<String>
    let devRPC: Bool

    init?(json: [String: Any]) {
        guard let version = json["version"] as? String, !version.isEmpty,
              let rawTimestamp = json["build_timestamp"] as? String,
              let timestamp = UInt64(rawTimestamp), timestamp > 0,
              let methods = json["methods"] as? [String],
              methods.contains("helper_version"),
              let devRPC = json["dev_rpc"] as? Bool else { return nil }
        self.version = version
        self.timestamp = timestamp
        self.methods = Set(methods)
        self.devRPC = devRPC
    }

    /// A newer timestamp alone says nothing about protocol compatibility.
    /// Pinning to the bundled build also supports intentional app rollbacks.
    func matches(_ bundled: HelperBuildInfo) -> Bool {
        version == bundled.version && timestamp == bundled.timestamp
            && devRPC == bundled.devRPC && methods.isSuperset(of: bundled.methods)
    }

    enum ProbeError: Error { case timedOut, invalidMetadata }

    /// Old helpers may ignore `--version` and start a daemon instead.
    /// Probe off the main actor with a deadline and force termination if
    /// necessary. Redirect output to a private file so even a noisy child
    /// cannot fill a pipe and deadlock the readiness check.
    static func read(from binary: URL) async throws -> HelperBuildInfo {
        try await Task.detached(priority: .userInitiated) {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("helper-version-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: directory) }
            let output = directory.appendingPathComponent("version.json")
            guard FileManager.default.createFile(
                atPath: output.path, contents: nil,
                attributes: [.posixPermissions: 0o600]) else {
                throw ProbeError.invalidMetadata
            }
            let handle = try FileHandle(forWritingTo: output)
            defer { try? handle.close() }
            let process = Process()
            process.executableURL = binary
            process.arguments = ["--version"]
            process.standardOutput = handle
            process.standardError = FileHandle.nullDevice
            try process.run()
            let deadline = ProcessInfo.processInfo.systemUptime + 2
            while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
                try? await Task.sleep(for: .milliseconds(20))
            }
            if process.isRunning {
                process.terminate()
                try? await Task.sleep(for: .milliseconds(100))
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                throw ProbeError.timedOut
            }
            guard process.terminationStatus == 0 else { throw ProbeError.invalidMetadata }
            let reader = try FileHandle(forReadingFrom: output)
            defer { try? reader.close() }
            // Metadata is a few KB. Reject oversized or partial output.
            let data = try reader.read(upToCount: 65_537) ?? Data()
            guard data.count <= 65_536,
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let info = HelperBuildInfo(json: json) else { throw ProbeError.invalidMetadata }
            return info
        }.value
    }
}
