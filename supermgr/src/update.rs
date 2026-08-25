//! Update check + updater plumbing for the Settings → Updates page.
//!
//! Linux installs are built from a git checkout of `main`, so "is there a
//! newer version" is a question about commits, not release tags. The check
//! asks GitHub's compare API how `origin/main` relates to the commit this
//! binary was built from (embedded by `build.rs`); the answer is exact —
//! identical / behind / ahead / diverged — and costs one unauthenticated
//! request.
//!
//! The update itself is *not* done in-process: `supermgr-update`
//! (scripts/update-linux.sh, installed by install-linux.sh) owns the
//! pull → rebuild → reinstall sequence, and this module only spawns it and
//! streams its output back to the dialog. One updater, whichever door it is
//! entered through. Run from the GUI there is no terminal, so the script's
//! install phase elevates through polkit (pkexec) rather than sudo.

use std::sync::mpsc::Sender;

use tokio::io::{AsyncBufReadExt as _, BufReader};

/// Crate version, for display next to the commit.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Full hash of the commit this binary was built from, or `unknown` when
/// the build happened outside a git checkout.
pub const GIT_COMMIT: &str = env!("SUPERMGR_GIT_COMMIT");

/// Short (7-char) form of [`GIT_COMMIT`] for display.
pub fn short_commit() -> &'static str {
    if GIT_COMMIT == "unknown" {
        GIT_COMMIT
    } else {
        &GIT_COMMIT[..7.min(GIT_COMMIT.len())]
    }
}

/// What the GitHub compare said about this build.
pub enum CheckOutcome {
    /// The build matches the tip of `origin/main` (or is ahead of it).
    UpToDate,
    /// `origin/main` has moved on: `commits` new commit(s), the newest
    /// summarised in `latest`.
    UpdateAvailable {
        /// How many commits behind this build is.
        commits: u64,
        /// First line of the newest commit's message.
        latest: String,
    },
    /// The question could not be answered — no git info in the build, no
    /// network, or a local-only commit GitHub has never seen.
    Unknown(String),
}

/// Ask GitHub how `main` relates to the commit this binary was built from.
pub async fn check() -> CheckOutcome {
    if GIT_COMMIT == "unknown" {
        return CheckOutcome::Unknown(
            "this build carries no git information — run supermgr-update to check from a checkout"
                .into(),
        );
    }

    let url = format!(
        "https://api.github.com/repos/franzjeger/SuperManager/compare/{GIT_COMMIT}...main"
    );
    let resp = match reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "SuperManager-Update-Check")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return CheckOutcome::Unknown(format!("could not reach GitHub: {e}")),
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // GitHub has never seen this commit — a local commit that was never
        // pushed. Diverged as far as updating is concerned.
        return CheckOutcome::Unknown(
            "this build's commit is not on GitHub — the checkout has local commits".into(),
        );
    }
    if !resp.status().is_success() {
        return CheckOutcome::Unknown(format!("GitHub answered {}", resp.status()));
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return CheckOutcome::Unknown(format!("unreadable GitHub response: {e}")),
    };

    // compare/<built>...main: "ahead" means main is ahead of the build.
    match body.get("status").and_then(|s| s.as_str()) {
        Some("identical" | "behind") => CheckOutcome::UpToDate,
        Some("ahead") => {
            let commits = body
                .get("ahead_by")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let latest = body
                .get("commits")
                .and_then(|c| c.as_array())
                .and_then(|c| c.last())
                .and_then(|c| c.pointer("/commit/message"))
                .and_then(|m| m.as_str())
                .map(|m| m.lines().next().unwrap_or("").to_owned())
                .unwrap_or_default();
            CheckOutcome::UpdateAvailable { commits, latest }
        }
        Some("diverged") => CheckOutcome::Unknown(
            "the checkout has local commits that are not on GitHub — update it by hand".into(),
        ),
        _ => CheckOutcome::Unknown("GitHub's answer had no comparison status".into()),
    }
}

/// One event out of a running `supermgr-update`.
pub enum UpdaterEvent {
    /// A line of combined stdout/stderr output.
    Line(String),
    /// The updater exited; `true` on success.
    Done(bool),
}

/// Spawn `supermgr-update --yes` and stream its output as [`UpdaterEvent`]s.
///
/// Events go over a std `mpsc` channel because the receiving end is a
/// `glib::timeout_add_local` drain on the GTK thread — the same bridge the
/// rest of the app uses (see the threading-model note in `main.rs`).
pub fn run_updater(rt: &tokio::runtime::Handle, tx: Sender<UpdaterEvent>) {
    rt.spawn(async move {
        let child = tokio::process::Command::new("supermgr-update")
            .arg("--yes")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(UpdaterEvent::Line(format!(
                    "could not start supermgr-update: {e}\n\
                     (is SuperManager installed via scripts/install-linux.sh?)"
                )));
                let _ = tx.send(UpdaterEvent::Done(false));
                return;
            }
        };

        // Forward both streams line by line. The script writes progress to
        // stdout and warnings to stderr; the dialog shows them interleaved,
        // which is exactly what a terminal would have shown.
        let mut out = child.stdout.take().map(|s| BufReader::new(s).lines());
        let mut err = child.stderr.take().map(|s| BufReader::new(s).lines());
        let tx_err = tx.clone();
        let err_task = tokio::spawn(async move {
            if let Some(lines) = err.as_mut() {
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = tx_err.send(UpdaterEvent::Line(line));
                }
            }
        });
        if let Some(lines) = out.as_mut() {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(UpdaterEvent::Line(line));
            }
        }
        let _ = err_task.await;

        let ok = matches!(child.wait().await, Ok(status) if status.success());
        let _ = tx.send(UpdaterEvent::Done(ok));
    });
}
