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
        let script = HelperInstaller.atomicReplacementScript(source: "/usr/bin/true", destination: destination.path)
        XCTAssertEqual(try run("/bin/sh", ["-ec", script]), 0)
        let newInode = try FileManager.default.attributesOfItem(atPath: destination.path)[.systemFileNumber] as? NSNumber
        XCTAssertNotEqual(previousInode, newInode)
        XCTAssertEqual(try run(destination.path), 0)
        XCTAssertEqual(try run("/usr/bin/codesign", ["--verify", "--strict", destination.path]), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).count, 1)
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
