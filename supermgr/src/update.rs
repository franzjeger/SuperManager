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
//! entered through.
//!
//! The GUI gives the script a terminal of its own (a pseudo-terminal), so it
//! takes the same path as in a terminal: the install phase asks `sudo`, and
//! the dialog answers sudo's password prompt. It used to run without one and
//! elevate through pkexec, which needs a polkit authentication agent in the
//! session. A session without a working one (a compositor started from a tty,
//! xrdp, a bare window manager) could build every update and install none.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::mpsc::Sender;

/// Nearest Git tag plus commit distance, or the crate version outside Git.
pub const VERSION: &str = env!("SUPERMGR_BUILD_VERSION");
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

    let url =
        format!("https://api.github.com/repos/franzjeger/SuperManager/compare/{GIT_COMMIT}...main");
    let resp = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default()
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
#[derive(Debug, PartialEq, Eq)]
pub enum UpdaterEvent {
    /// A line of the updater's terminal output.
    Line(String),
    /// `sudo` is waiting for the user's password on the updater's terminal.
    PasswordPrompt,
    /// The updater exited; `true` on success.
    Done(bool),
}

/// sudo's prompt in the updater's terminal, set through `SUDO_PROMPT` so the
/// dialog recognises it whatever the locale or sudoers say.
const SUDO_PROMPT: &str = "[supermgr-update] password: ";

/// The writing end of the updater's terminal: what the user types, sent the
/// way a terminal sends keystrokes.
pub struct UpdaterInput(std::fs::File);

impl UpdaterInput {
    /// Answer sudo's prompt. Echo is off on the terminal while sudo reads,
    /// so the password never comes back as output.
    pub fn send_password(&self, password: &str) -> std::io::Result<()> {
        let mut line = Vec::with_capacity(password.len() + 1);
        line.extend_from_slice(password.as_bytes());
        line.push(b'\n');
        (&self.0).write_all(&line)
    }

    /// Ctrl-C on the terminal: the line discipline turns it into SIGINT for
    /// the updater and whatever it is running, exactly as in a shell.
    pub fn interrupt(&self) -> std::io::Result<()> {
        (&self.0).write_all(b"\x03")
    }
}

/// Spawn `supermgr-update --yes` on a pseudo-terminal and stream its output
/// as [`UpdaterEvent`]s. Returns the terminal's input, or `None` when the
/// updater could not be started (the reason has then been sent as events).
///
/// Events go over a std `mpsc` channel because the receiving end is a
/// `glib::timeout_add_local` drain on the GTK thread — the same bridge the
/// rest of the app uses (see the threading-model note in `main.rs`).
pub fn run_updater(tx: Sender<UpdaterEvent>) -> Option<UpdaterInput> {
    let mut args = vec!["--yes".to_owned()];
    if GIT_COMMIT != "unknown" {
        // The checkout may already have been pulled without rebuilding.
        // Tell the script what is actually running so it can still detect
        // and install that pending rebuild.
        args.extend(["--installed-commit".to_owned(), GIT_COMMIT.to_owned()]);
    }
    match spawn_on_pty(Path::new("supermgr-update"), &args, tx.clone()) {
        Ok(input) => Some(input),
        Err(e) => {
            let _ = tx.send(UpdaterEvent::Line(format!(
                "could not start supermgr-update: {e}\n\
                 (is SuperManager installed via scripts/install-linux.sh?)"
            )));
            let _ = tx.send(UpdaterEvent::Done(false));
            None
        }
    }
}

/// Run `program` as the session leader of a new pseudo-terminal, which
/// becomes its controlling terminal: sudo reads passwords from `/dev/tty`,
/// not from stdin, so a pty on the standard streams alone is not enough.
/// util-linux `setsid --ctty` makes that switch in the child; doing it here
/// would take `pre_exec`, which `unsafe_code = "forbid"` rules out.
fn spawn_on_pty(
    program: &Path,
    args: &[String],
    tx: Sender<UpdaterEvent>,
) -> std::io::Result<UpdaterInput> {
    use nix::fcntl::OFlag;
    use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};

    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let slave_path = ptsname_r(&master)?;
    let master = std::fs::File::from(std::os::fd::OwnedFd::from(master));
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OFlag::O_NOCTTY.bits())
        .open(&slave_path)?;

    let mut command = std::process::Command::new("setsid");
    command
        .args(["--ctty", "--wait"])
        .arg(program)
        .args(args)
        .stdin(slave.try_clone()?)
        .stdout(slave.try_clone()?)
        .stderr(slave)
        // Plain output for a text view: no colour, no redrawn progress
        // bars, no pager waiting for a key nobody can press.
        .env("TERM", "dumb")
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("SUDO_PROMPT", SUDO_PROMPT);
    let mut child = command.spawn()?;
    // The command held the parent's copies of the slave. Once they are gone
    // the child's are the last, so reading the master ends (EIO) exactly
    // when the updater and everything it started have exited.
    drop(command);

    let reader = master.try_clone()?;
    std::thread::spawn(move || {
        let mut reader = reader;
        let mut pending = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    pending.extend_from_slice(&chunk[..n]);
                    for event in drain_terminal_output(&mut pending) {
                        let _ = tx.send(event);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // EIO: the last process holding the terminal has exited.
                Err(_) => break,
            }
        }
        if !pending.is_empty() {
            let _ = tx.send(UpdaterEvent::Line(terminal_line(&pending)));
        }
        let ok = matches!(child.wait(), Ok(status) if status.success());
        let _ = tx.send(UpdaterEvent::Done(ok));
    });

    Ok(UpdaterInput(master))
}

/// Take the complete lines out of `pending`, and sudo's prompt if that is
/// what the unfinished rest is. Anything else unfinished stays for the next
/// read: a prompt is the only output that waits without a newline.
fn drain_terminal_output(pending: &mut Vec<u8>) -> Vec<UpdaterEvent> {
    let mut events = Vec::new();
    while let Some(end) = pending.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = pending.drain(..=end).collect();
        events.push(UpdaterEvent::Line(terminal_line(&line[..end])));
    }
    if pending.ends_with(SUDO_PROMPT.as_bytes()) {
        pending.clear();
        events.push(UpdaterEvent::PasswordPrompt);
    }
    events
}

/// One terminal line as it would look on screen: the terminal ends lines
/// with `\r\n`, and a `\r` inside a line means the text after it was drawn
/// over the text before it.
fn terminal_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim_end_matches('\r');
    text.rsplit('\r').next().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn complete_lines_come_out_and_partial_ones_wait() {
        let mut pending = b"one\r\ntwo\r\nthr".to_vec();
        assert_eq!(
            drain_terminal_output(&mut pending),
            [
                UpdaterEvent::Line("one".into()),
                UpdaterEvent::Line("two".into())
            ]
        );
        assert_eq!(pending, b"thr");
    }

    #[test]
    fn sudos_prompt_is_recognised_without_a_newline() {
        let mut pending = format!("Installing\r\n{SUDO_PROMPT}").into_bytes();
        assert_eq!(
            drain_terminal_output(&mut pending),
            [
                UpdaterEvent::Line("Installing".into()),
                UpdaterEvent::PasswordPrompt
            ]
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn a_redrawn_line_shows_what_was_drawn_last() {
        assert_eq!(
            terminal_line(b"Building 1/9\rBuilding 9/9\r"),
            "Building 9/9"
        );
    }

    /// A stand-in for `supermgr-update` that asks for a password the way sudo
    /// does: on `/dev/tty`, which only exists with a controlling terminal.
    fn fake_updater(dir: &Path) -> std::path::PathBuf {
        let script = dir.join("fake-update");
        std::fs::write(
            &script,
            "#!/bin/bash\n\
             set -euo pipefail\n\
             echo building\n\
             IFS= read -rs -p \"$SUDO_PROMPT\" pw </dev/tty\n\
             echo\n\
             [ \"$pw\" = hunter2 ] && echo installed || { echo wrong; exit 1; }\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        script
    }

    fn next(rx: &mpsc::Receiver<UpdaterEvent>) -> UpdaterEvent {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("updater went quiet")
    }

    #[test]
    fn a_password_typed_into_the_dialog_reaches_a_dev_tty_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let input = spawn_on_pty(&fake_updater(dir.path()), &[], tx).unwrap();

        assert_eq!(next(&rx), UpdaterEvent::Line("building".into()));
        assert_eq!(next(&rx), UpdaterEvent::PasswordPrompt);
        input.send_password("hunter2").unwrap();
        // The newline sudo prints after the hidden input, then the result;
        // never the password itself.
        assert_eq!(next(&rx), UpdaterEvent::Line(String::new()));
        assert_eq!(next(&rx), UpdaterEvent::Line("installed".into()));
        assert_eq!(next(&rx), UpdaterEvent::Done(true));
    }

    #[test]
    fn cancelling_at_the_prompt_stops_the_updater() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let input = spawn_on_pty(&fake_updater(dir.path()), &[], tx).unwrap();

        assert_eq!(next(&rx), UpdaterEvent::Line("building".into()));
        assert_eq!(next(&rx), UpdaterEvent::PasswordPrompt);
        input.interrupt().unwrap();
        loop {
            match next(&rx) {
                UpdaterEvent::Done(ok) => break assert!(!ok),
                UpdaterEvent::Line(line) => assert_ne!(line, "installed"),
                UpdaterEvent::PasswordPrompt => panic!("asked again after Ctrl-C"),
            }
        }
    }
}
