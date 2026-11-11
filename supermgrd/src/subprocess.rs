//! Bounded execution of trusted root system binaries.
//!
//! All external privileged helpers (`nft`, `ip`, `resolvectl`, `swanctl`,
//! `modprobe`, `nmcli`, `systemctl`, `tailscale`) are resolved exclusively
//! from root-owned system directories (`/usr/sbin`, `/sbin`, `/usr/bin`,
//! `/bin`), never from an inherited `PATH`.  Every invocation runs under a
//! mandatory wall-clock timeout with `kill_on_drop(true)` and per-stream
//! output caps so a hung or runaway child process can never wedge a tokio task
//! or exhaust daemon memory.

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

/// Trusted system binary directories searched in order.
const TRUSTED_SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// Safe `PATH` passed to spawned system binaries so any child helper they
/// invoke is likewise restricted to root system directories.
const SAFE_SYSTEM_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

/// Maximum bytes captured from `stdout` or `stderr` of a system command (4 MiB).
pub const MAX_SUBPROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Resolve the first executable binary matching `bin_candidates` inside
/// `/usr/sbin`, `/sbin`, `/usr/bin`, or `/bin`.
///
/// Candidate names must be bare filenames without path separators.
///
/// # Errors
///
/// - [`io::ErrorKind::InvalidInput`] if `bin_candidates` is empty or contains
///   path separators or NUL bytes.
/// - [`io::ErrorKind::NotFound`] if none of the candidates exist as an
///   executable file in the trusted system directories.
pub fn resolve_system_bin(bin_candidates: &[&str]) -> io::Result<PathBuf> {
    if bin_candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bin_candidates must not be empty",
        ));
    }

    for &name in bin_candidates {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\0')
            || name == "."
            || name == ".."
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid system binary candidate name '{name}'"),
            ));
        }

        for &dir in TRUSTED_SYSTEM_DIRS {
            let candidate = Path::new(dir).join(name);
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "executable not found in trusted system directories ({}): [{}]",
            TRUSTED_SYSTEM_DIRS.join(", "),
            bin_candidates.join(", ")
        ),
    ))
}

/// Execute a trusted system binary with bounded runtime and bounded output.
///
/// Resolves `bin_candidates` strictly within `/usr/sbin`, `/sbin`, `/usr/bin`,
/// and `/bin`, spawns the process with `stdin` closed and `kill_on_drop(true)`,
/// caps `stdout` and `stderr` at [`MAX_SUBPROCESS_OUTPUT_BYTES`] each, and
/// aborts the process if `timeout` elapses.
///
/// Callers **must not** hold the `DaemonState` mutex across `.await`ing this
/// function.
///
/// # Errors
///
/// - [`io::ErrorKind::NotFound`] if no candidate binary is installed.
/// - [`io::ErrorKind::TimedOut`] if execution exceeds `timeout`.
/// - [`io::ErrorKind::InvalidData`] if `stdout` or `stderr` exceeds
///   [`MAX_SUBPROCESS_OUTPUT_BYTES`].
pub async fn run_system_cmd(
    bin_candidates: &[&str],
    args: &[&str],
    timeout: Duration,
) -> io::Result<Output> {
    let bin = resolve_system_bin(bin_candidates)?;
    run_bounded_command(&bin, args, None, timeout).await
}

/// Like [`run_system_cmd`], but pipes `stdin_bytes` into the child's standard
/// input before closing `stdin` (used for atomic `nft -f -` transactions).
///
/// # Errors
///
/// Returns the same error kinds as [`run_system_cmd`], plus any pipe write
/// failure if the child exits before reading `stdin_bytes` and exits non-zero.
pub async fn run_system_cmd_stdin(
    bin_candidates: &[&str],
    args: &[&str],
    stdin_bytes: &[u8],
    timeout: Duration,
) -> io::Result<Output> {
    let bin = resolve_system_bin(bin_candidates)?;
    run_bounded_command(&bin, args, Some(stdin_bytes), timeout).await
}

/// Execute an already-resolved binary path with the same timeout, `kill_on_drop`,
/// and output bounds as [`run_system_cmd`].
pub(crate) async fn run_exact_bin(
    bin: &Path,
    args: &[String],
    timeout: Duration,
) -> io::Result<Output> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_bounded_command(bin, &borrowed, None, timeout).await
}

async fn read_stream_bounded<R>(
    mut reader: R,
    limit: usize,
    stream_name: &str,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let max_plus_one = u64::try_from(limit)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    (&mut reader)
        .take(max_plus_one)
        .read_to_end(&mut buf)
        .await?;
    if buf.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subprocess {stream_name} exceeded {limit} byte limit"),
        ));
    }
    Ok(buf)
}

async fn run_bounded_command(
    bin: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Output> {
    let effective_timeout = if timeout.is_zero() {
        Duration::from_millis(1)
    } else {
        timeout
    };

    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .env("PATH", SAFE_SYSTEM_PATH)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn()?;

    let io_fut = async {
        if let Some(bytes) = stdin_bytes {
            if let Some(mut stdin) = child.stdin.take() {
                // Ignore BrokenPipe here so we still read stderr and report the
                // child's diagnostic message when it rejects input early.
                if let Err(e) = stdin.write_all(bytes).await {
                    if e.kind() != io::ErrorKind::BrokenPipe {
                        return Err(e);
                    }
                }
                drop(stdin);
            }
        }

        let stdout_pipe = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("subprocess stdout pipe unavailable"))?;
        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("subprocess stderr pipe unavailable"))?;

        let (stdout, stderr) = tokio::try_join!(
            read_stream_bounded(stdout_pipe, MAX_SUBPROCESS_OUTPUT_BYTES, "stdout"),
            read_stream_bounded(stderr_pipe, MAX_SUBPROCESS_OUTPUT_BYTES, "stderr"),
        )?;

        let status = child.wait().await?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    };

    match tokio::time::timeout(effective_timeout, io_fut).await {
        Ok(result) => result,
        Err(_) => {
            // `child` was moved into `io_fut`, which was just dropped by
            // `tokio::time::timeout`, triggering `kill_on_drop(true)`.
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "'{}' timed out after {:.1}s",
                    bin.display(),
                    effective_timeout.as_secs_f64()
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_trusted_binaries_and_rejects_untrusted_names() {
        let sh = resolve_system_bin(&["sh"]).expect("sh exists in /bin or /usr/bin");
        assert!(sh.is_absolute());

        assert_eq!(
            resolve_system_bin(&["definitely-not-installed-binary-xyz"])
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        for bad in ["", "/bin/sh", "../sh", "foo/bar", "sh\0"] {
            assert_eq!(
                resolve_system_bin(&[bad]).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "accepted unsafe candidate {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn enforces_timeout_stdin_and_output_bounds() {
        let sh = resolve_system_bin(&["sh"]).unwrap();
        let exact_out = run_exact_bin(
            &sh,
            &["-c".to_owned(), "printf ok".to_owned()],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(exact_out.status.success());
        assert_eq!(exact_out.stdout, b"ok");

        let out = run_system_cmd_stdin(&["cat"], &[], b"hello world", Duration::from_secs(2))
            .await
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello world");

        let timed_out = run_system_cmd(&["sh"], &["-c", "exec sleep 5"], Duration::from_millis(40))
            .await
            .unwrap_err();
        assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);

        let too_large = read_stream_bounded(std::io::Cursor::new(vec![b'x'; 1025]), 1024, "stdout")
            .await
            .unwrap_err();
        assert_eq!(too_large.kind(), io::ErrorKind::InvalidData);
    }
}
