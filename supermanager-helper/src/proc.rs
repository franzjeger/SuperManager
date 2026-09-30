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
//! still applies. A command that overruns its budget is killed together with
//! its process group — nothing it started can keep its pipes, and the call,
//! alive — and then reaped. Everything runs on the calling thread, and the
//! child is reaped last, so a kill can never land on a recycled pid.
//!
//! Budgets are per call site and deliberately tight for probes (a route or
//! status lookup that needs more than a few seconds has already failed) and
//! generous for genuine work (bringing a tunnel up, bootstrapping a daemon).

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

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

/// Run `cmd` to completion, or kill it after `secs` seconds.
///
/// Drop-in for `Command::output()`: same return type, and a timeout surfaces
/// as `io::ErrorKind::TimedOut` so call sites that already treat an `Err` as
/// "couldn't determine" keep working unchanged.
pub fn bounded(cmd: &mut Command, secs: u64) -> io::Result<Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    run(cmd, secs)
}

/// Spawn `cmd` as the leader of a new process group and [`finish`] it.
/// stdin is closed, so a command that unexpectedly prompts fails instead of
/// waiting for input that will never come.
fn run(cmd: &mut Command, secs: u64) -> io::Result<Output> {
    let label = describe(cmd);
    cmd.stdin(Stdio::null()).process_group(0);
    let child = cmd.spawn()?;
    finish(child, Scope::Group, secs, &label)
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

    /// Bounded `Command::output`.
    pub fn output(&mut self) -> io::Result<Output> {
        bounded(&mut self.inner, self.budget)
    }

    /// Bounded `Command::status`. The child's stdout and stderr go where the
    /// helper's own do — its log — so a failing launchctl or pfctl still says
    /// why, as it did before this wrapper existed.
    pub fn status(&mut self) -> io::Result<std::process::ExitStatus> {
        self.inner.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        run(&mut self.inner, self.budget).map(|o| o.status)
    }
}

/// Bounded `wait_with_output` for a child the caller spawned itself.
///
/// For the commands we have to drive through stdin — `scutil` takes its edits
/// as a script on stdin, so it can't go through [`bounded`] — the spawn is the
/// caller's but the waiting is still a hang risk: a wedged `configd` leaves
/// `scutil` alive and silent, and `child.wait()` then never returns. Same
/// contract as [`bounded`], except that only the child itself is killed: the
/// caller spawned it into the helper's own process group.
pub fn wait_bounded(child: Child, secs: u64, label: &str) -> io::Result<Output> {
    finish(child, Scope::Child, secs, label)
}

/// What an overrun kills.
#[derive(Clone, Copy)]
enum Scope {
    /// The child leads its own process group (`run` spawned it that way).
    Group,
    /// The child shares the helper's process group.
    Child,
}

/// Collect `child`'s output and exit status within `secs`, or kill it.
///
/// Nothing is reaped until the end, so the pid — and the process group a
/// [`Scope::Group`] child leads — stay reserved for as long as we might
/// signal them. Killing the group on overrun also takes out anything the
/// command started that inherited its pipes, which would otherwise keep them
/// open, and this call waiting, for as long as it lives.
fn finish(mut child: Child, scope: Scope, secs: u64, label: &str) -> io::Result<Output> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let outcome = match read_to_eof(&mut child, deadline) {
        Ok(Some(output)) => wait_for_exit(&child, deadline).map(|exited| exited.then_some(output)),
        other => other,
    };
    match outcome {
        Ok(Some((stdout, stderr))) => Ok(Output {
            status: child.wait()?,
            stdout,
            stderr,
        }),
        Ok(None) => {
            kill(&mut child, scope);
            let _ = child.wait();
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
        Err(e) => {
            kill(&mut child, scope);
            let _ = child.wait();
            Err(e)
        }
    }
}

/// Read the child's stdout and stderr to EOF by `deadline`, on this thread.
/// Both pipes are non-blocking and waited on together with poll(2), so a
/// child blocked on one full pipe cannot deadlock against a read of the
/// other. `Ok(None)` if a pipe is still open at the deadline.
fn read_to_eof(child: &mut Child, deadline: Instant) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut pipes = [
        child.stdout.take().map(|p| File::from(OwnedFd::from(p))),
        child.stderr.take().map(|p| File::from(OwnedFd::from(p))),
    ];
    for pipe in pipes.iter().flatten() {
        set_nonblocking(pipe)?;
    }
    let mut bufs = [Vec::new(), Vec::new()];
    loop {
        for (pipe, buf) in pipes.iter_mut().zip(bufs.iter_mut()) {
            if let Some(file) = pipe {
                if read_available(file, buf)? {
                    *pipe = None;
                }
            }
        }
        let mut open: Vec<libc::pollfd> = pipes
            .iter()
            .flatten()
            .map(|file| libc::pollfd {
                fd: file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if open.is_empty() {
            let [stdout, stderr] = bufs;
            return Ok(Some((stdout, stderr)));
        }
        if !poll_until(&mut open, deadline)? {
            return Ok(None);
        }
    }
}

/// Read what `file` has right now. Returns whether it reached EOF.
fn read_available(file: &mut File, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0u8; 8192];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// poll(2) until one of `fds` is ready (`true`) or `deadline` passes.
fn poll_until(fds: &mut [libc::pollfd], deadline: Instant) -> io::Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `fds` is a valid, exclusively borrowed pollfd array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms.max(1)) };
        if n > 0 {
            return Ok(true);
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

fn set_nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait until `child` exits or `deadline` passes, without reaping it.
fn wait_for_exit(child: &Child, deadline: Instant) -> io::Result<bool> {
    let pid = child.id() as libc::pid_t;
    // SAFETY: kqueue() returns a new descriptor, owned from here on.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `kq` is a valid descriptor that nothing else owns.
    let kq = unsafe { OwnedFd::from_raw_fd(kq) };
    let watch = libc::kevent {
        ident: pid as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: one change, no events; all pointers are to live locals.
    if unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            &raw const watch,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        // A process that has already exited can no longer be watched.
        return if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(true)
        } else {
            Err(err)
        };
    }
    // From here on an exit is an event; one just before the registration
    // shows up as a waitable child instead.
    if exited_unreaped(pid)? {
        return Ok(true);
    }
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let timeout = libc::timespec {
            tv_sec: left.as_secs() as libc::time_t,
            tv_nsec: libc::c_long::from(left.subsec_nanos()),
        };
        // SAFETY: an all-zero kevent is a valid value to be overwritten.
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: no changes, one event slot, all pointers to live locals.
        let n = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                std::ptr::null(),
                0,
                &raw mut event,
                1,
                &raw const timeout,
            )
        };
        if n > 0 {
            return Ok(true);
        }
        if n == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Whether our child `pid` has exited, leaving it waitable (WNOWAIT).
fn exited_unreaped(pid: libc::pid_t) -> io::Result<bool> {
    // SAFETY: an all-zero siginfo_t is a valid value to be overwritten.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a live local; WNOHANG | WNOWAIT neither block nor reap.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.si_pid != 0)
}

/// SIGKILL, not SIGTERM: the commands that overrun are stuck in a kernel
/// wait that ignores polite signals. Only called while `child` is unreaped,
/// so its pid, and the group it leads, are still its own.
fn kill(child: &mut Child, scope: Scope) {
    match scope {
        // SAFETY: plain syscall on a process group the unreaped leader reserves.
        Scope::Group => unsafe {
            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
        },
        Scope::Child => {
            let _ = child.kill();
        }
    }
}

/// Whether process `pid` runs the executable at `path`. A pid written down
/// can outlive its process, and the pid be reused by something else.
pub fn process_is(pid: i32, path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable for the length passed.
    let len = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast(),
            u32::try_from(buf.len()).unwrap_or(0),
        )
    };
    let Ok(len) = usize::try_from(len) else {
        return false;
    };
    if len == 0 || pid <= 0 {
        return false;
    }
    let running = std::path::Path::new(std::ffi::OsStr::from_bytes(&buf[..len]));
    std::fs::canonicalize(path).is_ok_and(|expected| expected == running)
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
    fn a_grandchild_holding_the_pipes_dies_with_the_command() {
        let marker = std::env::temp_dir().join(format!("proc-grandchild-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > '{}'; exit 0", marker.display());
        let started = std::time::Instant::now();
        let err = bounded(Command::new("/bin/sh").args(["-c", &script]), 1)
            .expect_err("the grandchild keeps stdout open, so output never completes");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid: libc::pid_t = std::fs::read_to_string(&marker)
            .expect("marker written")
            .trim()
            .parse()
            .expect("pid");
        let _ = std::fs::remove_file(&marker);
        // Killed with its process group rather than left holding the pipes
        // (and a waiter) for its full 30 s. Give launchd a moment to reap it.
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: signal 0 only checks for existence.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "grandchild {pid} survived"
        );
    }

    #[test]
    fn a_chatty_command_cannot_deadlock_on_a_full_pipe() {
        // Far more than a pipe buffer on both streams at once.
        let out = bounded(
            Command::new("/bin/sh").args([
                "-c",
                "head -c 3000000 /dev/zero; head -c 2000000 /dev/zero >&2",
            ]),
            PROBE,
        )
        .expect("ran");
        assert_eq!(out.stdout.len(), 3_000_000);
        assert_eq!(out.stderr.len(), 2_000_000);
    }

    #[test]
    fn waits_for_a_caller_spawned_child() {
        use std::io::Write as _;
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cat");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"hi")
            .expect("write");
        let out = wait_bounded(child, PROBE, "cat").expect("cat ran");
        assert_eq!(out.stdout, b"hi");
    }

    #[test]
    fn status_reports_the_exit_code() {
        let status = Bounded::new("/bin/sh")
            .args(["-c", "exit 4"])
            .status()
            .expect("ran");
        assert_eq!(status.code(), Some(4));
    }

    #[test]
    fn preserves_nonzero_exit_status() {
        let out = bounded(Command::new("/bin/sh").args(["-c", "exit 3"]), PROBE).expect("ran");
        assert_eq!(out.status.code(), Some(3));
    }
}
