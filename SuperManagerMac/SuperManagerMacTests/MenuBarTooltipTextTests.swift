import XCTest

@testable import SuperManagerMac

/// Wording rules for the menu bar hover tooltip.
///
/// The tooltip is the only place the menu bar says WHICH tunnel is up —
/// the icon only says whether one is. These pin the shape so a later
/// edit doesn't quietly turn it back into a single opaque word.
final class MenuBarTooltipTextTests: XCTestCase {

    func testIdleMachineSaysNoVpn() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true, tunnels: [], tailscale: nil)
        XCTAssertEqual(text, "No VPN connected")
    }

    func testDisconnectedTunnelsDoNotCountAsConnected() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [MenuBarTunnel(name: "Aarsleff", state: "disconnected")],
            tailscale: nil)
        XCTAssertEqual(text, "No VPN connected")
    }

    func testNamesEveryConnectedTunnel() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [
                MenuBarTunnel(name: "Aarsleff", state: "connected"),
                MenuBarTunnel(name: "Novita", state: "connected"),
                MenuBarTunnel(name: "Ferro", state: "disconnected"),
            ],
            tailscale: nil)
        XCTAssertEqual(text, "VPN: Aarsleff, Novita")
    }

    /// Connecting is its own line, so a tunnel that is still negotiating
    /// is never reported as if traffic were already flowing through it.
    func testConnectingIsReportedSeparately() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [
                MenuBarTunnel(name: "Aarsleff", state: "connected"),
                MenuBarTunnel(name: "Novita", state: "connecting"),
            ],
            tailscale: nil)
        XCTAssertEqual(text, "VPN: Aarsleff\nConnecting: Novita")
    }

    func testReconnectingCountsAsConnecting() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [MenuBarTunnel(name: "Ferro", state: "reconnecting")],
            tailscale: nil)
        XCTAssertEqual(text, "Connecting: Ferro")
    }

    func testTailscaleLineAppendedWhenPresent() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [],
            tailscale: "Tailscale: exit via franz-cachyos")
        XCTAssertEqual(text, "No VPN connected\nTailscale: exit via franz-cachyos")
    }

    /// Tailscale is omitted entirely when it isn't running — a tooltip
    /// listing everything that is off is noise.
    func testTailscaleOmittedWhenNil() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true, tunnels: [], tailscale: nil)
        XCTAssertFalse(text.contains("Tailscale"))
    }

    /// A dead daemon means every other line is a stale cache, so it
    /// leads and says so.
    func testDaemonOfflineLeadsAndWarnsOfStaleness() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: false,
            tunnels: [MenuBarTunnel(name: "Aarsleff", state: "connected")],
            tailscale: nil)
        XCTAssertEqual(
            text, "Daemon offline — status may be stale\nVPN: Aarsleff")
    }

    func testHealthyOneTunnelMachineIsTwoLines() {
        let text = MenuBarTooltipText.build(
            daemonAvailable: true,
            tunnels: [MenuBarTunnel(name: "Aarsleff", state: "connected")],
            tailscale: "Tailscale: connected (12 peers)")
        XCTAssertEqual(text.components(separatedBy: "\n").count, 2)
    }
}
