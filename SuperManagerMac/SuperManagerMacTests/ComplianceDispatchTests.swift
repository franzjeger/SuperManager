import XCTest
@testable import SuperManagerMac

/// 1.12b allowlist guardrail.
///
/// `DeviceType.complianceDispatch` is the single source of truth
/// for which compliance baseline runner a host routes to. Every
/// call site (the Compliance host view's body switch, the Run-scan
/// button dispatch, the export-button gate, the
/// ComplianceListColumn allowlist filter) reads through this
/// extension — never on a bare `if deviceType == .fortigate` or
/// an open `else` catch-all.
///
/// **The failure mode this guards against:** silently routing a
/// non-baseline-able device type to `compliance_run_linux`. The
/// Linux runner shells out for `sshd -T`, `systemctl`, `sysctl`,
/// `journalctl`, `ufw` / `firewalld` — every one of those breaks
/// on pfSense (FreeBSD), OpenWrt (busybox / no-systemd), UniFi
/// controllers, or anything else not in the allowlist. The result
/// would be a screen of false failures with no diagnostic value.
///
/// This was the trap that gated the original 1.12 work, and the
/// third test case below (a non-allowlisted DeviceType) is the
/// guardrail against a future careless `else` re-introducing it.
final class ComplianceDispatchTests: XCTestCase {

    // -- Allowlisted: FortiGate ----------------------------------------

    func testFortigateDispatchesToFortigateBaseline() {
        XCTAssertEqual(
            DeviceType.fortigate.complianceDispatch,
            .fortigateBaseline,
            "FortiGate hosts must route to the FortiGate REST-API baseline runner."
        )
    }

    // -- Allowlisted: Linux --------------------------------------------

    func testLinuxDispatchesToLinuxBaseline() {
        XCTAssertEqual(
            DeviceType.linux.complianceDispatch,
            .linuxBaseline,
            "Linux hosts must route to the Linux SSH baseline runner."
        )
    }

    // -- Non-allowlisted: every other DeviceType -----------------------
    //
    // Each non-allowlisted case asserted individually — a future
    // engineer accidentally re-widening one of these into a baseline
    // bucket will see exactly which case broke.

    func testUniFiIsNotApplicable() {
        XCTAssertEqual(
            DeviceType.unifi.complianceDispatch,
            .notApplicable,
            "UniFi controllers have no baseline; routing to compliance_run_linux would produce false failures."
        )
    }

    func testPfSenseIsNotApplicable() {
        XCTAssertEqual(
            DeviceType.pfSense.complianceDispatch,
            .notApplicable,
            "pfSense runs FreeBSD — every Linux check (sshd -T, systemctl, sysctl) fails on builtins not present."
        )
    }

    func testOpenWrtIsNotApplicable() {
        XCTAssertEqual(
            DeviceType.openWrt.complianceDispatch,
            .notApplicable,
            "OpenWrt is busybox / no systemd; Linux baseline checks would fail their service-check assumptions."
        )
    }

    func testWindowsIsNotApplicable() {
        XCTAssertEqual(
            DeviceType.windows.complianceDispatch,
            .notApplicable,
            "Windows has no SSH-baseline coverage in this engine — routing to a Linux runner is wrong by construction."
        )
    }

    func testCustomIsNotApplicable() {
        XCTAssertEqual(
            DeviceType.custom.complianceDispatch,
            .notApplicable,
            "Custom device types are unclassified — defaulting to a baseline runner would be silent fall-through."
        )
    }

    // -- Exhaustiveness sweep ------------------------------------------

    /// Iterates over `DeviceType.allCases` and asserts every case is
    /// classified into exactly one bucket. If a future
    /// `DeviceType` case is added without being explicitly mapped
    /// in `complianceDispatch`, the Swift compiler's switch
    /// exhaustiveness check fails to compile — but this test is
    /// the runtime backstop in case someone adds a default branch
    /// to silence the compiler.
    func testEveryDeviceTypeIsClassified() {
        let allowlisted: Set<DeviceType> = [.fortigate, .linux]
        for dt in DeviceType.allCases {
            let dispatch = dt.complianceDispatch
            if allowlisted.contains(dt) {
                XCTAssertNotEqual(
                    dispatch, .notApplicable,
                    "DeviceType \(dt) is on the allowlist but mapped to .notApplicable — should route to a baseline runner."
                )
            } else {
                XCTAssertEqual(
                    dispatch, .notApplicable,
                    "DeviceType \(dt) is NOT on the allowlist but mapped to \(dispatch) — a non-baseline-able device routed to a baseline runner is the failure mode 1.12 was created to prevent."
                )
            }
        }
    }
}
