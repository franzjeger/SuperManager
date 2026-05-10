import AppKit
import SwiftUI

extension Notification.Name {
    /// Fired by the custom "About SuperManager" menu item. The
    /// active ContentView listens for this and flips its
    /// `showingAbout` state. Using a notification (instead of a
    /// shared @State) keeps SuperManagerApp from owning view-level
    /// presentation state.
    static let superManagerShowAbout = Notification.Name("com.sybr.supermanager.showAbout")

    /// Fired by the Help → Explain Configuration… menu item.
    static let superManagerShowExplain = Notification.Name("com.sybr.supermanager.showExplain")
}

@main
struct SuperManagerApp: App {
    @State private var appState = AppState()
    /// Drives the auto-lock timer. SwiftUI doesn't fire `task` for the
    /// app itself, so we run a polling timer for now — cheap, runs
    /// once per second, only does work when the lock is *enabled* and
    /// the user has been idle past the threshold.
    @State private var autoLockTask: Task<Void, Never>? = nil

    var body: some Scene {
        WindowGroup {
            // Lock-aware root. When `LockState.isLocked` is true the
            // window contains *only* `LockScreenView` — no
            // `ContentView`, no toolbar, no search field. That's the
            // only way to truly prevent locked-state UI bleed-through:
            // an overlay can't fully hide content behind it because
            // SwiftUI's materials are translucent by design, but if
            // there's no content to bleed through there's nothing to
            // hide.
            //
            // ContentView is rebuilt fresh when we unlock — selection
            // state and search text reset to defaults. That's the
            // expected behaviour for a re-entry from locked: users
            // don't want to come back to a stale search filter from
            // before they walked away.
            RootView(appState: appState) {
                Task {
                    await startDaemon()
                    await appState.connectToDaemon()
                    startAutoLockTimer()
                }
            }
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1100, height: 700)
        .commands {
            // Keep the standard `File → New Window` (⌘N) — without it,
            // closing the app's only window with ⌘W leaves the process
            // running with no UI and no way to summon it back. The
            // command-group default behaviour for `WindowGroup` is to
            // open a new instance of the scene's view, which is exactly
            // what we want for a single-window app like this one.
            CommandMenu("Navigation") {
                Button("Fleet") { appState.selectedSection = .fleet }
                    .keyboardShortcut("0", modifiers: .command)
                Divider()
                Button("SSH") { appState.selectedSection = .ssh }
                    .keyboardShortcut("1", modifiers: .command)
                Button("VPN") { appState.selectedSection = .vpn }
                    .keyboardShortcut("2", modifiers: .command)
                Button("Tailscale") { appState.selectedSection = .tailscale }
                    .keyboardShortcut("3", modifiers: .command)
                Button("Compliance") { appState.selectedSection = .compliance }
                    .keyboardShortcut("4", modifiers: .command)
                Button("Provisioning") { appState.selectedSection = .provisioning }
                    .keyboardShortcut("5", modifiers: .command)
                Button("Security") { appState.selectedSection = .security }
                    .keyboardShortcut("6", modifiers: .command)
            }
            // Replace the default "About SuperManager" with one
            // that posts a notification ContentView listens for —
            // gives us a richer about window with helper /
            // tailscaled versions and a "Copy diagnostics" button.
            CommandGroup(replacing: .appInfo) {
                Button("About SuperManager") {
                    NotificationCenter.default.post(
                        name: .superManagerShowAbout,
                        object: nil
                    )
                }
            }
            // Help menu — replaces the default "SuperManager Help"
            // (which points to a Help Book we don't ship) with a
            // small set of useful links. Opens in the user's
            // default browser via NSWorkspace.
            CommandGroup(replacing: .help) {
                Button("Open Source Repository") {
                    if let url = URL(string: "https://github.com/franzjeger/SuperManager") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Button("Report an Issue…") {
                    if let url = URL(string: "https://github.com/franzjeger/SuperManager/issues/new") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Divider()
                Button("Tailscale Documentation") {
                    if let url = URL(string: "https://tailscale.com/kb/") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Button("WireGuard Documentation") {
                    if let url = URL(string: "https://www.wireguard.com/quickstart/") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Divider()
                Button("Explain Configuration…") {
                    NotificationCenter.default.post(
                        name: .superManagerShowExplain,
                        object: nil
                    )
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                Divider()
                Button("Reveal Helper Log in Finder") {
                    let url = URL(fileURLWithPath: "/var/log/supermanager-helper.log")
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                }
                Button("Reveal App Debug Log in Finder") {
                    let dir = FileManager.default
                        .urls(for: .applicationSupportDirectory, in: .userDomainMask)
                        .first?
                        .appendingPathComponent("SuperManager")
                    if let dir {
                        NSWorkspace.shared.activateFileViewerSelecting([dir])
                    }
                }
                Divider()
                // Surface the support bundle from a top-level menu
                // so it's reachable when the user is reporting an
                // issue, not buried inside the Tailscale overflow
                // menu (where it currently is the only entry-point).
                Button("Save Support Bundle…") {
                    Task { _ = await SupportBundle.saveInteractive(appState: appState) }
                }
            }
        }

        // Status-bar icon reflects current connectivity state so
        // the user can glance at the menu bar to know if Tailscale
        // is up, an exit node is active, or a VPN profile is
        // connected. Computed in `menuBarSymbol(for:)`.
        MenuBarExtra("SuperManager", systemImage: menuBarSymbol(for: appState)) {
            MenuBarView()
                .environment(appState)
        }

        // `Settings { }` is the SwiftUI scene that wires up the
        // SuperManager → Settings… menu item and Cmd+, automatically.
        // The window's content size is driven by the TabView inside.
        Settings {
            SettingsView()
                .environment(appState)
        }
    }

    /// Start the daemon process. **Always** kills any pre-existing
    /// `supermgrd-mac` first and respawns from the bundle's embedded
    /// binary, so the running daemon's code is *guaranteed* to match
    /// the GUI's. This is the simplest cure for the stale-daemon
    /// hazard: if you rebuild the app and the old daemon was still
    /// running with last-week's RPC table, an "unknown method" error
    /// pops up the moment you exercise a new feature.
    ///
    /// Cost of the kill-and-respawn: a ~300 ms gap on every launch
    /// while the new daemon binds the socket. SSH state and VPN
    /// profiles are persisted on disk, so nothing is lost — the new
    /// daemon reads them right back during its `DaemonState::load_*`.
    private func startDaemon() async {
        // 1. Kill any existing daemon — fire-and-forget, but wait for
        //    the process to actually exit before continuing so the
        //    socket file isn't held by a zombie.
        await Task.detached(priority: .userInitiated) {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            task.arguments = ["-f", "supermgrd-mac"]
            task.standardOutput = FileHandle.nullDevice
            task.standardError = FileHandle.nullDevice
            do {
                try task.run()
                task.waitUntilExit()
            } catch {
                // pkill not available, or no matching process — both fine.
            }
        }.value
        // pkill is asynchronous w.r.t. the kernel — give the OS a
        // moment to reap before we try to bind the same socket.
        try? await Task.sleep(for: .milliseconds(300))

        // 2. Remove any stale socket file. The new daemon would
        //    overwrite it on `bind()` anyway, but cleaning up here
        //    makes the `isDaemonAlive()` probe immediately accurate.
        let sockPath = ServiceClient.socketPath
        try? FileManager.default.removeItem(atPath: sockPath)

        // 3. Spawn fresh from the first available binary path. In
        //    a packaged build that's `Contents/MacOS/supermgrd-mac`;
        //    in dev (running the binary out of DerivedData with cargo
        //    rebuilds in `target/`) the fallbacks let us pick up the
        //    just-rebuilt binary without re-bundling.
        for path in daemonBinaryCandidates() {
            guard FileManager.default.isExecutableFile(atPath: path) else { continue }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                continue
            }
            // Poll for the socket to come up (up to ~5 s). The daemon
            // does its `DaemonState::load_*` here, which can take a
            // moment with lots of profiles.
            for _ in 0..<50 {
                try? await Task.sleep(for: .milliseconds(100))
                if isDaemonAlive() { return }
            }
            return
        }
    }

    /// Candidate locations for the daemon binary, in priority order.
    private func daemonBinaryCandidates() -> [String] {
        let bundleURL = URL(fileURLWithPath: Bundle.main.bundlePath)
        // In dev the .app lives at <project>/SuperManagerMac/build/SuperManager.app,
        // so the cargo output is three directories above the bundle.
        let projectRoot = bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            bundleURL.path + "/Contents/MacOS/supermgrd-mac",
            projectRoot.appendingPathComponent("target/debug/supermgrd-mac").path,
            projectRoot.appendingPathComponent("target/release/supermgrd-mac").path,
            "\(home)/.cargo/bin/supermgrd-mac",
            "/usr/local/bin/supermgrd-mac",
        ]
    }

    /// Start the auto-lock timer + activity observer.
    ///
    /// Idle detection: an `NSEvent.addLocalMonitorForEvents` hook fires
    /// on every keystroke / mouse click / scroll inside our app's
    /// windows; on each one we update `LockState.lastActivity`. We
    /// don't watch system-wide events — that would require
    /// Accessibility permission, and "while my own window is focused"
    /// is the right semantic anyway.
    ///
    /// Lock trigger: a 1-Hz polling task locks the app when
    /// (now - lastActivity) crosses the configured threshold. Cheap;
    /// short-circuits when auto-lock is off or no password is set.
    private func startAutoLockTimer() {
        // Activity observer — feed every relevant NSEvent into
        // `noteActivity()`. The closure must return the event so the
        // app continues to receive it normally.
        let _ = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown,
                       .otherMouseDown, .scrollWheel, .mouseMoved]
        ) { event in
            LockState.shared.noteActivity()
            return event
        }

        autoLockTask?.cancel()
        autoLockTask = Task { @MainActor in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                let settings = AppSettings.shared
                guard settings.autoLockMinutes > 0,
                      settings.requireMasterPassword,
                      MasterPassword.isSet,
                      !LockState.shared.isLocked
                else { continue }
                let elapsed = Date().timeIntervalSince(LockState.shared.lastActivity)
                if elapsed >= Double(settings.autoLockMinutes) * 60 {
                    LockState.shared.lock()
                }
            }
        }
    }

    /// Pick the menu-bar SF Symbol that reflects the most
    /// noteworthy state right now. Priority: Tailscale exit-node
    /// active > any VPN connected > Tailscale connected > nothing.
    /// macOS tints the icon for the active state automatically;
    /// no need to vary colour here.
    private func menuBarSymbol(for appState: AppState) -> String {
        // Tailscale exit-node is the most "loud" state — all
        // user traffic is being relayed through a peer.
        if let prefs = appState.tailscalePrefs,
           let peers = appState.tailscaleStatus?.peers,
           prefs.currentExitNode(in: peers) != nil {
            return "arrow.up.forward.circle.fill"
        }
        // Any VPN profile in connected state.
        let anyVpnUp = appState.vpnConnectionStates.values.contains("connected")
        if anyVpnUp {
            return "lock.shield.fill"
        }
        // Tailscale is up but no exit-node — quietly connected.
        if appState.tailscaleStatus?.backendState == "Running" {
            return "globe.americas.fill"
        }
        // Nothing is up. Use a soft default that doesn't scream
        // for attention.
        return "shield"
    }

    /// Probe the daemon socket — `connect()` fails fast with ECONNREFUSED
    /// when the file exists but no daemon is listening.
    private func isDaemonAlive() -> Bool {
        let path = ServiceClient.socketPath
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cstr in
                _ = memcpy(ptr, cstr, min(path.utf8.count, 104))
            }
        }
        let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        return result == 0
    }
}
