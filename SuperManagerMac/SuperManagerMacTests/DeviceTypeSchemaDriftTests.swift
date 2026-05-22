import XCTest
@testable import SuperManagerMac

/// Tests for the Swift/Rust `DeviceType` schema-drift fix.
///
/// Background (schema-drift gate): Rust's `DeviceType` had 9 cases;
/// Swift had 7. The two missing cases — `OpnSense` (`"opn_sense"`)
/// and `Sophos` (`"sophos"`) — caused those hosts to:
///   1. Decode silently as `.custom`, mis-rendering everywhere
///      `DeviceType.displayName` or case-equality is used.
///   2. **Write-amplify** on first edit: `updateHost` serialised
///      `deviceType.rawValue = "custom"` back to the engine, which
///      persisted `Custom`, permanently destroying the host's true
///      type. This is the dominant harm — "mis-render until fixed"
///      becomes "silently corrupted on first save."
///   3. Surface a second silent default: the outer
///      `(try? c.decode(DeviceType.self, ..)) ?? .linux` in
///      `SshHostSummary.init(from:)` would swallow any throw and
///      produce `.linux` (worse than `.custom` for firewall hosts).
///
/// The fix: add `.opnSense` / `.sophos` cases, carry
/// `unrecognizedDeviceTypeRawValue` for future unknowns,
/// and prefer that raw string over `rawValue` in `updateHost`.
///
/// These tests verify all three objectives.
final class DeviceTypeSchemaDriftTests: XCTestCase {

    // MARK: - Helpers

    private func decode(_ deviceTypeWireValue: String) throws -> SshHostSummary {
        let json = """
        {
            "id": "test-host",
            "label": "Test",
            "hostname": "10.0.0.1",
            "port": 22,
            "username": "admin",
            "group": "",
            "device_type": "\(deviceTypeWireValue)",
            "auth_method": "key",
            "pinned": false,
            "has_api": false,
            "has_unifi_controller": false
        }
        """
        return try JSONDecoder().decode(SshHostSummary.self, from: Data(json.utf8))
    }

    // MARK: - Round-trip tests for the two newly-added cases

    func testOpnSenseWireValueDecodesAsOpnSense() throws {
        let host = try decode("opn_sense")
        XCTAssertEqual(host.deviceType, .opnSense,
            "'opn_sense' must decode to .opnSense, not .custom — " +
            "the schema-drift regression that write-amplified to Custom")
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue,
            ".opnSense is a known case; unrecognizedDeviceTypeRawValue must be nil")
    }

    func testOpnSenseAliasCaseInsensitive() throws {
        // Engine might send various spellings — verify the alias
        // matching in DeviceType.map(rawValue:) covers them.
        let host = try decode("opnsense")
        XCTAssertEqual(host.deviceType, .opnSense)
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue)
    }

    func testSophosWireValueDecodesAsSophos() throws {
        let host = try decode("sophos")
        XCTAssertEqual(host.deviceType, .sophos,
            "'sophos' must decode to .sophos, not .custom")
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue)
    }

    func testSophosAliasSfos() throws {
        let host = try decode("sfos")
        XCTAssertEqual(host.deviceType, .sophos)
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue)
    }

    // MARK: - Unrecognised-value preservation (future schema drift)

    func testUnrecognisedWireValueDecodesAsCustomWithRawPreserved() throws {
        // A future Rust DeviceType case not-yet-in-Swift should still
        // decode without throwing, but must carry the original string
        // so the write path can round-trip it without data loss.
        let host = try decode("future_vendor")
        XCTAssertEqual(host.deviceType, .custom,
            "Unrecognised wire value should decode as .custom")
        XCTAssertEqual(host.unrecognizedDeviceTypeRawValue, "future_vendor",
            "The original wire string must be preserved for the write path")
    }

    func testGenuinelyCustomHostCarriesNoRaw() throws {
        // A host explicitly typed as "custom" by the operator is a
        // genuinely-custom host — unrecognizedDeviceTypeRawValue must
        // be nil so the distinction holds.
        let host = try decode("custom")
        XCTAssertEqual(host.deviceType, .custom)
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue,
            "Genuinely-custom hosts must not set unrecognizedDeviceTypeRawValue")
    }

    // MARK: - Write-amplification regression

    /// This is the gate's load-bearing test.
    ///
    /// Before the fix: an OpnSense or Sophos host decodes as
    /// `.custom`; the first call to `updateHost` sends
    /// `device_type: "custom"` on the wire; the engine persists
    /// `Custom`, permanently destroying the original type.
    ///
    /// After the fix: `SshHostSummary.deviceTypeWireValue` prefers
    /// `unrecognizedDeviceTypeRawValue` over `deviceType.rawValue`,
    /// so the original string round-trips unchanged as long as the
    /// operator hasn't explicitly changed the picker.
    func testWriteAmplificationRegression_unrecognisedHostRoundTripsOriginalWireValue() throws {
        let host = try decode("future_vendor")
        XCTAssertEqual(host.deviceType, .custom)
        XCTAssertEqual(host.unrecognizedDeviceTypeRawValue, "future_vendor")

        // Simulate updateHost serialisation — should use the raw,
        // not deviceType.rawValue = "custom".
        let wireValue = host.deviceTypeWireValue
        XCTAssertEqual(wireValue, "future_vendor",
            "deviceTypeWireValue must return the original wire string, " +
            "not 'custom' — this is what prevented the write-amplification " +
            "data-loss bug: engine receives 'future_vendor' back, not 'custom'")
    }

    func testWriteAmplificationRegression_knownTypeRoundTripsRawValue() throws {
        // For all known types, deviceTypeWireValue must equal
        // deviceType.rawValue — the fix must not change behaviour for
        // the common (non-drifted) case.
        let host = try decode("fortigate")
        XCTAssertEqual(host.deviceType, .fortigate)
        XCTAssertNil(host.unrecognizedDeviceTypeRawValue)
        XCTAssertEqual(host.deviceTypeWireValue, "fortigate",
            "Known types must still round-trip via their rawValue")
    }

    func testWriteAmplificationRegression_newlyAddedCasesNeverLeaveUnrecognised() throws {
        // Once .opnSense and .sophos are in the Swift enum,
        // hosts of those types must not leave unrecognizedDeviceTypeRawValue
        // set — that would cause them to be written back as the raw
        // instead of the normalised rawValue (which is fine, but
        // confirms no latent confusion between the two paths).
        let opnSense = try decode("opn_sense")
        XCTAssertNil(opnSense.unrecognizedDeviceTypeRawValue,
            ".opnSense is now a known case; raw should not be preserved")
        XCTAssertEqual(opnSense.deviceTypeWireValue, "opn_sense",
            ".opnSense.rawValue is 'opn_sense' — wire should match")

        let sophos = try decode("sophos")
        XCTAssertNil(sophos.unrecognizedDeviceTypeRawValue)
        XCTAssertEqual(sophos.deviceTypeWireValue, "sophos")
    }

    // MARK: - effectiveDeviceTypeDisplayName

    func testEffectiveDisplayNameForKnownTypeIsDisplayName() throws {
        let host = try decode("fortigate")
        XCTAssertEqual(host.effectiveDeviceTypeDisplayName, "FortiGate")
    }

    func testEffectiveDisplayNameForUnrecognisedTypeShowsRaw() throws {
        let host = try decode("future_vendor")
        XCTAssertEqual(host.effectiveDeviceTypeDisplayName, "Unrecognized: future_vendor",
            "Host-detail surfaces must show the original type, " +
            "not 'Custom', for unrecognised wire values")
    }

    func testEffectiveDisplayNameForGenuineCustomIsCustom() throws {
        let host = try decode("custom")
        XCTAssertEqual(host.effectiveDeviceTypeDisplayName, "Custom",
            "Genuinely-custom hosts must still show 'Custom'")
    }
}
