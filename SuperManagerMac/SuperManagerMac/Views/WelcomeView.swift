import SwiftUI

/// First-run welcome / onboarding step. Shown by the detail
/// column ONLY when:
///   - no SSH hosts
///   - no VPN profiles
///   - Tailscale daemon not yet installed
///
/// Once the user does any of these (imports a config, adds a host,
/// installs the daemon), the welcome dismisses naturally because
/// the detail column reverts to either an empty selection
/// placeholder or a real detail view.
///
/// Three large action cards, one per common first-step. Each card
/// triggers the same flow the toolbar buttons do — we deliberately
/// don't introduce new code paths, just surface the existing ones
/// in a more discoverable place for new users.
struct WelcomeView: View {
    @Environment(AppState.self) private var appState
    /// Bindings for the existing sheets in ContentView. Passed in
    /// so clicks here flip the same state ContentView's toolbar
    /// uses — no parallel paths.
    @Binding var showingAddHost: Bool
    @Binding var showingImportVpn: Bool

    var body: some View {
        ScrollView {
            VStack(spacing: 28) {
                heroBlock
                cardsGrid
                quickTip
            }
            .padding(40)
            .frame(maxWidth: 720)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Big top-of-page block introducing the app's purpose.
    private var heroBlock: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Welcome to SuperManager")
                .font(.system(size: 28, weight: .semibold))
            Text("MSP toolbox: scan customer networks, track findings over time, manage SSH + VPN, deploy FortiGate configs — all from one Mac app.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Four action cards covering each "first thing you'd do".
    /// Customer + Engagement is the lead because that's what
    /// drives the product's biggest value (offensive scanning +
    /// findings tracking) — SSH/VPN/Tailscale are supporting
    /// utilities for the same workflow.
    private var cardsGrid: some View {
        LazyVGrid(
            columns: [
                GridItem(.adaptive(minimum: 280, maximum: 360), spacing: 16)
            ],
            spacing: 16
        ) {
            scanCard
            tailscaleCard
            vpnCard
            sshCard
        }
    }

    /// Lead card — directs users to add a customer + engagement
    /// and run their first scan. Without this card, new users
    /// learn SSH/VPN setup but miss the product's selling point.
    private var scanCard: some View {
        OnboardingCard(
            icon: "shield.lefthalf.filled.badge.checkmark",
            tint: .red,
            title: "Add customer & start scanning",
            subtitle: "Define a customer + engagement (scope CIDRs), then run passive + active scans. Findings track CVEs, weak TLS, exposed paths, and default creds over time.",
            primary: "Open Provisioning",
            primaryAction: { appState.selectedSection = .provisioning }
        )
    }

    private var tailscaleCard: some View {
        OnboardingCard(
            icon: "globe.americas.fill",
            tint: .blue,
            title: "Tailscale",
            subtitle: tailscaleSubtitle,
            primary: tailscalePrimary,
            primaryAction: tailscalePrimaryAction
        )
    }

    private var vpnCard: some View {
        OnboardingCard(
            icon: "lock.shield.fill",
            tint: .green,
            title: "VPN Profile",
            subtitle: "Import a `.conf` (WireGuard) or `.ovpn` (OpenVPN) — also drop one anywhere in the window.",
            primary: "Import file…",
            primaryAction: { showingImportVpn = true }
        )
    }

    private var sshCard: some View {
        OnboardingCard(
            icon: "terminal.fill",
            tint: .orange,
            title: "SSH Host",
            subtitle: "Save host details + push keys with one click. Connect via ssh:// from the host detail view.",
            primary: "Add host…",
            primaryAction: { showingAddHost = true }
        )
    }

    /// Helpful quick-tip footer summarising the safety story.
    /// Reinforces the "always-on with auto-recovery" angle.
    private var quickTip: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lightbulb.fill")
                .foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 4) {
                Text("All connections come with safety nets.")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text("Auto-reconnect after sleep, kill-switch when enabled, and a connectivity watchdog that auto-recovers within 10 seconds if anything goes wrong.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(14)
        .background(Color(nsColor: .windowBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(.quaternary)
        )
    }

    // ----- Tailscale-card state machine -----

    private var tailscaleSubtitle: String {
        if (appState.tailscaledInstalled ?? false) {
            return "Your daemon is installed and ready. Click Tailscale in the sidebar to authenticate."
        }
        if appState.tailscaleIsBundled {
            return "Install our bundled tailscaled as a system service — auto-starts at boot, auto-reconnects after sleep."
        }
        return "Tailscale binaries aren't bundled in this build."
    }

    private var tailscalePrimary: String {
        if (appState.tailscaledInstalled ?? false) {
            return "Open Tailscale"
        }
        if appState.tailscaleIsBundled {
            return "Install daemon"
        }
        return "Unavailable"
    }

    private var tailscalePrimaryAction: () -> Void {
        if (appState.tailscaledInstalled ?? false) {
            return { appState.selectedSection = .tailscale }
        }
        if appState.tailscaleIsBundled {
            return {
                Task { await appState.installTailscaled() }
            }
        }
        return {}
    }
}

/// One card in the welcome grid. Centred icon + title + subtitle +
/// primary action button.
private struct OnboardingCard: View {
    let icon: String
    let tint: Color
    let title: String
    let subtitle: String
    let primary: String
    let primaryAction: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 28))
                .foregroundStyle(tint)
            Text(title)
                .font(.headline)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(4)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            Button(primary, action: primaryAction)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(.quaternary, lineWidth: 1)
        )
    }
}
