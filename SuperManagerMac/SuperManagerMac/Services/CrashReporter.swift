import Foundation
import CrashReporter

/// Crash-reporting facade over Microsoft's PLCrashReporter.
///
/// ## What it does
///
/// On every launch we ask PLCrashReporter to install its Mach
/// exception handler + signal handlers. From that moment on, any
/// uncaught Objective-C exception, Swift trap, or unhandled signal
/// (SIGSEGV, SIGBUS, SIGABRT, …) is captured to an internal queue
/// before the process is terminated.
///
/// On the *next* launch we check that queue. If a crash is sitting
/// there:
///   1. Load it and convert to a plain-text crash report
///   2. Save it under
///      `~/Library/Application Support/SuperManager/crashes/`
///      with an ISO-8601-named filename
///   3. Tell PLCrashReporter to purge its queue so we don't
///      re-save the same report on every launch
///
/// The Support Bundle (Help → Save Support Bundle…) already
/// globs that directory, so an operator reporting a bug just
/// attaches the bundle and we get a symbolicated stack trace.
///
/// ## Why this instead of a hosted service (Sentry / Crashlytics)
///
///   - **Privacy.** Nothing leaves the operator's Mac unless they
///     explicitly export a Support Bundle.
///   - **MSP context.** Customer infrastructure may be sensitive;
///     auto-sending crash dumps that could include hostnames /
///     IPs to a third-party service is a non-starter for many
///     environments.
///   - **No dependency.** No external service to monitor, no
///     monthly cost, no upgrade treadmill.
///
/// Trade-off: developer has to wait for the operator to manually
/// send a bundle. For an MSP tool with a few dozen installs this
/// is fine. If we ever ship to hundreds we can layer a hosted
/// service on top — the PLCrashReporter queue is preserved either
/// way.
///
/// ## When to enable
///
/// We call `start()` from `SuperManagerApp` *before* the SwiftUI
/// scene phase begins. That window — between `@main` struct init
/// and SwiftUI taking over — is the only place to install the
/// handlers and still catch crashes that happen during app
/// startup (e.g. a malformed preference dict triggering a Swift
/// trap in `AppState.init`).
enum CrashReporting {
    /// Directory where extracted crash reports get written. Matches
    /// the path SupportBundle.swift globs.
    static var crashDir: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first!
            .appendingPathComponent("SuperManager")
            .appendingPathComponent("crashes")
        return base
    }

    /// Initialise the reporter + drain any pending crash from the
    /// previous run. Idempotent — calling twice does nothing on
    /// the second call (PLCrashReporter enforces singleton).
    static func start() {
        let config = PLCrashReporterConfig(
            // Mach exceptions are more reliable than signal-only on
            // macOS — they catch crashes the kernel surfaces via
            // EXC_BAD_ACCESS before they're delivered as signals.
            signalHandlerType: .mach,
            symbolicationStrategy: []
        )
        guard let reporter = PLCrashReporter(configuration: config) else {
            DebugLog.write("[crash] PLCrashReporter init returned nil")
            return
        }

        // Drain any pending crash from the previous run BEFORE
        // installing the new handler — otherwise the act of
        // installing might overwrite the pending file.
        drainPendingCrash(from: reporter)

        // Install handlers. After this returns, signals + Mach
        // exceptions land in PLCrashReporter's queue.
        do {
            try reporter.enableAndReturnError()
        } catch {
            DebugLog.write("[crash] enable failed: \(error.localizedDescription)")
        }
    }

    /// If a crash was captured in the previous run, write a
    /// human-readable report to disk and purge it from the
    /// reporter's internal queue.
    private static func drainPendingCrash(from reporter: PLCrashReporter) {
        guard reporter.hasPendingCrashReport() else { return }

        guard let data = try? reporter.loadPendingCrashReportDataAndReturnError() else {
            DebugLog.write("[crash] hasPendingCrashReport=true but load failed")
            // Purge anyway so we don't try forever on a corrupt entry.
            reporter.purgePendingCrashReport()
            return
        }

        do {
            let report = try PLCrashReport(data: data)
            // .textFormat is the Apple-style crash log that's
            // immediately readable in any editor and matches the
            // format the OS generates in
            // ~/Library/Logs/DiagnosticReports/.
            let text = PLCrashReportTextFormatter.stringValue(
                for: report,
                with: PLCrashReportTextFormatiOS
            ) ?? "(empty)"

            try FileManager.default.createDirectory(
                at: crashDir,
                withIntermediateDirectories: true
            )
            let filename = ISO8601DateFormatter().string(from: Date())
                .replacingOccurrences(of: ":", with: "-")
                + ".crash"
            let path = crashDir.appendingPathComponent(filename)
            try text.write(to: path, atomically: true, encoding: .utf8)
            DebugLog.write("[crash] saved pending report to \(path.path)")
        } catch {
            DebugLog.write("[crash] failed to render/save report: \(error.localizedDescription)")
        }

        reporter.purgePendingCrashReport()
    }
}
