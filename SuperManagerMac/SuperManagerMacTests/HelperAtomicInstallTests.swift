import XCTest
@testable import SuperManagerMac

@MainActor
final class HelperAtomicInstallTests: XCTestCase {
    private func run(_ path: String, _ arguments: [String] = []) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    func testReplacingPreviouslyExecutedSignedFileUsesNewInode() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let destination = dir.appendingPathComponent("helper with ' quote")
        try FileManager.default.copyItem(atPath: "/usr/bin/false", toPath: destination.path)
        XCTAssertEqual(try run("/usr/bin/codesign", ["--force", "--sign", "-", destination.path]), 0)
        XCTAssertEqual(try run(destination.path), 1)
        let previousInode = try FileManager.default.attributesOfItem(atPath: destination.path)[.systemFileNumber] as? NSNumber
        let script = HelperInstaller.atomicReplacementScript(
            source: "/usr/bin/true",
            destination: destination.path,
            requirement: "anchor apple"
        )
        XCTAssertEqual(try run("/bin/sh", ["-ec", script]), 0)
        let newInode = try FileManager.default.attributesOfItem(atPath: destination.path)[.systemFileNumber] as? NSNumber
        XCTAssertNotEqual(previousInode, newInode)
        XCTAssertEqual(try run(destination.path), 0)
        XCTAssertEqual(try run("/usr/bin/codesign", ["--verify", "--strict", destination.path]), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).count, 1)
    }

    func testDefaultRequirementRejectsNonSuperManagerSignedBinary() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let destination = dir.appendingPathComponent("helper")
        try FileManager.default.copyItem(atPath: "/usr/bin/false", toPath: destination.path)
        let original = try Data(contentsOf: destination)
        // `/usr/bin/true` is validly Apple-signed, but not signed by Team LY6LJ395B8
        // as `com.sybr.supermanager.helper` — default requirement must reject it.
        let script = HelperInstaller.atomicReplacementScript(
            source: "/usr/bin/true",
            destination: destination.path
        )
        XCTAssertNotEqual(try run("/bin/sh", ["-ec", script]), 0)
        XCTAssertEqual(try Data(contentsOf: destination), original)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).count, 1)
    }

    func testOpenVPN3TerminalCommandUsesBundledScriptsOnly() throws {
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }

        // Without bundled scripts, `terminalBuildCommand` returns nil rather than
        // curling mutable scripts from GitHub.
        XCTAssertNil(Dependencies.terminalBuildCommand(for: "openvpn3", resourceURL: empty))

        let builderRoot = empty.appendingPathComponent("openvpn3-builder", isDirectory: true)
        let scriptsDir = builderRoot.appendingPathComponent("scripts", isDirectory: true)
        let contribDir = builderRoot.appendingPathComponent("contrib", isDirectory: true)
        try FileManager.default.createDirectory(at: scriptsDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: contribDir, withIntermediateDirectories: true)
        try Data("#!/bin/bash\n".utf8).write(to: scriptsDir.appendingPathComponent("install.sh"))
        try Data("#!/bin/bash\n".utf8).write(to: contribDir.appendingPathComponent("build-openvpn3-mac.sh"))

        let cmd = try XCTUnwrap(Dependencies.terminalBuildCommand(for: "openvpn3", resourceURL: empty))
        XCTAssertFalse(cmd.contains("curl"))
        XCTAssertFalse(cmd.contains("raw.githubusercontent.com"))
        XCTAssertTrue(cmd.contains("openvpn3-builder/scripts/install.sh"))
        XCTAssertTrue(cmd.contains("--deps-only --with-openvpn3"))
    }

    func testInvalidReplacementLeavesInstalledExecutableUntouched() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let destination = dir.appendingPathComponent("helper")
        let invalid = dir.appendingPathComponent("invalid")
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: destination.path)
        try Data("not a signed executable".utf8).write(to: invalid)
        let original = try Data(contentsOf: destination)
        let script = HelperInstaller.atomicReplacementScript(source: invalid.path, destination: destination.path)
        XCTAssertNotEqual(try run("/bin/sh", ["-ec", script]), 0)
        XCTAssertEqual(try Data(contentsOf: destination), original)
        XCTAssertEqual(try run(destination.path), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).count, 2)
    }
}
