import XCTest

@testable import SuperManagerMac

final class HelperBuildInfoTests: XCTestCase {
    private func metadata(
        version: String = "0.1.0", timestamp: String = "2000",
        methods: [String] = ["helper_version", "vpn_connect"], devRPC: Bool = false
    ) -> [String: Any] {
        ["version": version, "build_timestamp": timestamp, "methods": methods, "dev_rpc": devRPC]
    }

    func testMatchingHelperBuildDoesNotDependOnAppBundleVersion() throws {
        let bundled = try XCTUnwrap(HelperBuildInfo(json: metadata()))
        XCTAssertTrue(bundled.matches(bundled))
    }

    func testOldAndNewerBuildsBothRequireInstallingBundledBuild() throws {
        let bundled = try XCTUnwrap(HelperBuildInfo(json: metadata()))
        for timestamp in ["1000", "3000"] {
            let deployed = try XCTUnwrap(HelperBuildInfo(json: metadata(timestamp: timestamp)))
            XCTAssertFalse(deployed.matches(bundled))
        }
    }

    func testVersionCapabilitiesAndBuildModeMustMatch() throws {
        let bundled = try XCTUnwrap(HelperBuildInfo(json: metadata()))
        for changed in [metadata(version: "0.2.0"), metadata(methods: ["helper_version"]),
                        metadata(devRPC: true)] {
            XCTAssertFalse(try XCTUnwrap(HelperBuildInfo(json: changed)).matches(bundled))
        }
    }

    func testUnknownAndInvalidMetadataCannotPassReadiness() {
        XCTAssertNil(HelperBuildInfo(json: [:]))
        for timestamp in ["0", "", "unknown", "-1"] {
            XCTAssertNil(HelperBuildInfo(json: metadata(timestamp: timestamp)))
        }
        XCTAssertNil(HelperBuildInfo(json: metadata(methods: [])))
        XCTAssertNil(HelperBuildInfo(json: metadata(version: "")))
    }

    func testProbeReadsHelperMetadata() async throws {
        let file = try makeExecutable("#!/bin/sh\necho '{\"version\":\"0.1.0\",\"build_timestamp\":\"2000\",\"methods\":[\"helper_version\"],\"dev_rpc\":false}'\n")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let info = try await HelperBuildInfo.read(from: file)
        XCTAssertEqual(info.timestamp, 2000)
    }

    func testProbeTimesOutWhenLegacyHelperNeverExits() async throws {
        let file = try makeExecutable("#!/bin/sh\ntrap '' TERM\nwhile :; do :; done\n")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let start = ProcessInfo.processInfo.systemUptime
        do {
            _ = try await HelperBuildInfo.read(from: file)
            XCTFail("An old daemon must not be mistaken for a version response")
        } catch HelperBuildInfo.ProbeError.timedOut {
            XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 5)
        }
    }

    func testNoisyProbeCannotFillAPipeAndHangReadiness() async throws {
        let file = try makeExecutable("#!/bin/sh\n/usr/bin/head -c 131072 /dev/zero\n")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        do {
            _ = try await HelperBuildInfo.read(from: file)
            XCTFail("Oversized output must not be accepted as metadata")
        } catch HelperBuildInfo.ProbeError.invalidMetadata { }
    }

    private func makeExecutable(_ script: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let file = directory.appendingPathComponent("helper")
        try script.write(to: file, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: file.path)
        return file
    }
}
