//! Bounded external-command execution.
//!
//! Every external binary the helper drives is a potential hang, and a hang
//! here is never local: the helper runs its self-healing loops on long-lived
//! std threads and its RPCs on tokio workers, so one command that never
//! returns permanently retires whichever thread called it. Enough of those and
//! the route guardian stops snapshotting, the connectivity watchdog stops
//! probing, and — once the workers are gone — `accept()` stops running, so the
//! socket still accepts connections at the kernel level while nothing ever
//! answers them. The GUI then sits on an RPC that never completes and shows
//! state that stopped being true hours ago.
//!
//! That is not hypothetical. `/sbin/route -n get <dest>` blocks *forever* when
//! the route it is asked about points at a utun that has been torn down — the
//! exact kernel state a VPN peer reboot (firewall restart) produces. One such
//! call took out the route guardian for three days (visible afterwards as
//! `force_restore_now failed: no snapshots available`), two more took out the
//! connectivity watchdog and the RPC workers, and the app froze.
//!
//! So: every external command the helper runs to completion is bounded —
//! synchronous ones through `bounded()` / [`Bounded`], async ones through
//! [`bounded_async`]; strongSwan's `run` applies its own deadline. The only
//! unbounded children are the long-lived processes the helper supervises and
//! kills through their handles (charon, ovpncli, tcpdump). `bounded()`
//! replaces `.output()` and keeps the same `io::Result<Output>` shape, so a
//! call site changes by one wrapper and all of its existing Ok/Err handling
//! still applies. A command that overruns its budget is SIGKILLed rather than
//! abandoned, which reaps the child *and* lets the waiter thread finish — the
//! previous "spawn a thread and walk away on timeout" pattern leaked both.
//!
//! Budgets are per call site and deliberately tight for probes (a route or
//! status lookup that needs more than a few seconds has already failed) and
//! generous for genuine work (bringing a tunnel up, bootstrapping a daemon).

use std::io;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A read-only probe of local state: routing table, interface list, DNS
/// config, process list. These answer from kernel state or not at all, so a
/// few seconds is already pathological.
pub const PROBE: u64 = 5;

/// A mutating local operation — installing a route, loading a pf anchor,
/// writing DNS state. Still local, but may contend on a kernel lock.
pub const MUTATE: u64 = 10;

/// Something that legitimately talks to the network or spins up a daemon
/// (`tailscale up`, `launchctl bootstrap`). Slow is normal here; never
/// returning is not.
pub const SLOW: u64 = 60;

/// Run `cmd` to completion, or SIGKILL it after `secs` seconds.
///
/// Drop-in for `Command::output()`: same return type, and a timeout surfaces
/// as `io::ErrorKind::TimedOut` so call sites that already treat an `Err` as
/// "couldn't determine" keep working unchanged. stdin is closed so a command
/// that unexpectedly prompts fails instead of waiting for input that will
/// never come.
pub fn bounded(cmd: &mut Command, secs: u64) -> io::Result<Output> {
    let label = describe(cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    // Capture the pid before the Child moves into the waiter thread — after
    // the move we have no handle to kill through.
    let pid = child.id() as libc::pid_t;

    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("bounded-cmd".into())
        .spawn(move || {
            // wait_with_output drains both pipes while waiting, so a chatty
            // child can't deadlock on a full pipe buffer. After a SIGKILL it
            // returns promptly and this thread exits — no leak, no zombie.
            let _ = tx.send(child.wait_with_output());
        })?;

    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(result) => result,
        Err(_) => {
            // SIGKILL, not SIGTERM: the commands that hang here are stuck in
            // a kernel read that ignores polite signals.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            tracing::warn!(
                command = %label,
                budget_secs = secs,
                "external command exceeded its budget — SIGKILLed"
            );
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("`{label}` timed out after {secs}s"),
            ))
        }
    }
}

/// Default budget for the drop-in [`Bounded`] wrapper. Generous enough that a
/// local command doing real work is never cut off, short enough that a wedged
/// one frees its thread while the loop that called it still matters.
pub const DEFAULT: u64 = 15;

/// Drop-in replacement for `std::process::Command` that cannot hang.
///
/// The modules that drive routing, DNS, pf and the tailscale CLI call out to
/// external binaries in ~90 places, every one of them on either a watchdog
/// thread or a tokio worker. Rather than wrap each call and leave the next one
/// added to the file unbounded by default, those modules import this as
/// `Command` — so the safe thing is what you get by writing ordinary code, and
/// the budget is the only thing left to think about.
///
/// `output()` and `status()` are bounded. Commands that have to be fed on
/// stdin (`scutil`) spawn a `std::process::Command` directly and bound the wait
/// with [`wait_bounded`] instead.
pub struct Bounded {
    inner: Command,
    budget: u64,
}

impl Bounded {
    pub fn new(program: impl AsRef<std::ffi::OsStr>) -> Self {
        Self {
            inner: Command::new(program),
            budget: DEFAULT,
        }
    }

    /// Override the default budget — larger for commands that legitimately
    /// take their time (daemon bootstrap, DHCP renew, a network probe).
    pub fn budget(&mut self, secs: u64) -> &mut Self {
        self.budget = secs;
        self
    }

    pub fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.inner.args(args);
        self
    }

    /// Bounded. Note that stdout/stderr are captured (as `Command::output`
    /// does) even when the caller only wanted the exit code.
    pub fn output(&mut self) -> io::Result<Output> {
        bounded(&mut self.inner, self.budget)
    }

    /// Bounded, via `output()`. Unlike `Command::status` the child's output is
    /// captured rather than inherited — worth knowing, but every caller here
    /// discards it anyway.
    pub fn status(&mut self) -> io::Result<std::process::ExitStatus> {
        self.output().map(|o| o.status)
    }
}

/// Bounded `wait_with_output` for a child the caller spawned itself.
///
/// For the commands we have to drive through stdin — `scutil` takes its edits
/// as a script on stdin, so it can't go through [`bounded`] — the spawn is the
/// caller's but the waiting is still a hang risk: a wedged `configd` leaves
/// `scutil` alive and silent, and `child.wait()` then never returns. Same
/// contract as [`bounded`]: SIGKILL on overrun, `TimedOut` to the caller.
pub fn wait_bounded(child: std::process::Child, secs: u64, label: &str) -> io::Result<Output> {
    let pid = child.id() as libc::pid_t;
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("bounded-wait".into())
        .spawn(move || {
            let _ = tx.send(child.wait_with_output());
        })?;
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(result) => result,
        Err(_) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            tracing::warn!(
                command = %label,
                budget_secs = secs,
                "external command exceeded its budget while being waited on — SIGKILLed"
            );
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("`{label}` timed out after {secs}s"),
            ))
        }
    }
}

/// [`bounded`] for tokio commands on the async RPC paths. The child is
/// `SIGKILLed` through `kill_on_drop` when the budget runs out, and the timeout
/// surfaces as `io::ErrorKind::TimedOut`, like the sync version.
pub async fn bounded_async(cmd: &mut tokio::process::Command, secs: u64) -> io::Result<Output> {
    let label = describe(cmd.as_std());
    cmd.kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(secs), cmd.output()).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                command = %label,
                budget_secs = secs,
                "external command exceeded its budget — killed"
            );
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("`{label}` timed out after {secs}s"),
            ))
        }
    }
}

/// Program + args, for the timeout log line. `Command`'s own `Debug` includes
/// the env deltas and quoting noise; this stays readable in a log.
fn describe(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().into_owned();
    for arg in cmd.get_args() {
        s.push(' ');
        s.push_str(&arg.to_string_lossy());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_output_for_a_fast_command() {
        let out = bounded(Command::new("/bin/echo").arg("hi"), PROBE).expect("echo ran");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    }

    #[test]
    fn kills_and_reports_timeout_for_a_hanging_command() {
        let started = std::time::Instant::now();
        let err = bounded(Command::new("/bin/sleep").arg("30"), 1).expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        // The point of the fix: the caller gets its thread back in ~1s
        // instead of 30 (or never).
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn propagates_spawn_failure_instead_of_hanging() {
        let err =
            bounded(&mut Command::new("/nonexistent/binary"), PROBE).expect_err("no such binary");
        assert_ne!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn async_variant_kills_and_reports_timeout() {
        let started = std::time::Instant::now();
        let err = bounded_async(tokio::process::Command::new("/bin/sleep").arg("30"), 1)
            .await
            .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        let out = bounded_async(tokio::process::Command::new("/bin/echo").arg("hi"), PROBE)
            .await
            .expect("echo ran");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    }

    #[test]
    fn preserves_nonzero_exit_status() {
        let out = bounded(Command::new("/bin/sh").args(["-c", "exit 3"]), PROBE).expect("ran");
        assert_eq!(out.status.code(), Some(3));
    }
}
