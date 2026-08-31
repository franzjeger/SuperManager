//! Root-side traffic capture for the engine's cleartext-audit
//! pipeline. Shells out to `tcpdump` (already on every macOS box)
//! with a BPF filter built by the engine. The helper's value-add
//! here is: it runs as root, so `tcpdump` opens `/dev/bpf*`
//! without an admin prompt or a ChmodBPF dance.
//!
//! # Security
//!
//! This RPC is one of the more dangerous ones the helper exposes
//! — arbitrary BPF + arbitrary output path could be abused to
//! sniff every packet on the segment and dump it wherever. We
//! defend with:
//!
//!   - **Output-path lockdown**: the path MUST be inside the
//!     caller's `~/Library/Application Support/SuperManager/`
//!     directory. The helper resolves the authenticated Unix-socket peer's
//!     home through the system account database. No path containing `..` is
//!     accepted, and `tcpdump` receives a pre-opened no-follow descriptor.
//!   - **BPF filter sanity check**: length-capped, no shell
//!     metacharacters (we pass it as a separate argv anyway,
//!     but layered defence is cheap).
//!   - **Duration cap**: 600 seconds. Longer captures should be
//!     done with Wireshark by hand — we're a recon tool, not a
//!     long-haul collector.
//!   - **Interface validation**: accepts only short alphanumeric BSD interface
//!     names and logs names outside the common macOS set.

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Params {
    /// BSD interface name. `en0` / `en1` / `utun0` / `lo0` / …
    interface: String,
    /// Absolute pcap path under the user's data dir.
    output_path: String,
    /// BPF expression. Must be non-empty, ≤ 512 chars, no shell
    /// metacharacters.
    bpf_filter: String,
    /// Capture duration in seconds. Clamped to [1, 600].
    duration_secs: u32,
}

#[derive(Debug, Serialize)]
pub struct CaptureReport {
    pub pcap_path: String,
    pub size_bytes: u64,
    pub duration_secs: u32,
    pub interface: String,
    /// Whether tcpdump's "N packets captured" line was seen.
    /// Useful for the GUI to distinguish "ran but saw nothing"
    /// from "didn't run at all".
    pub completed_cleanly: bool,
    pub packet_count_estimate: u64,
}

pub async fn run(raw_params: serde_json::Value, peer_uid: libc::uid_t) -> Result<CaptureReport> {
    let p: Params = serde_json::from_value(raw_params).map_err(|e| anyhow!("bad params: {e}"))?;
    let duration = p.duration_secs.clamp(1, 600);

    validate_interface(&p.interface)?;
    validate_bpf(&p.bpf_filter)?;
    let user_home = home_dir_for_uid(peer_uid)?;
    let output_path = validate_output_path(&p.output_path, &user_home)?;
    let output_file = create_capture_file(&output_path)?;
    std::os::unix::fs::fchown(&output_file, Some(peer_uid), None)
        .map_err(|e| anyhow!("assign capture to uid {peer_uid}: {e}"))?;
    let capture_fd = output_file
        .try_clone()
        .map_err(|e| anyhow!("clone capture descriptor: {e}"))?;

    // Run tcpdump. The `-G <duration> -W 1` combo tells tcpdump
    // to rotate the capture file every `duration` seconds and
    // keep only 1 file — effectively, "run for N seconds then
    // exit cleanly". This is more reliable than spawn+sleep+
    // SIGTERM, especially when the helper is killed mid-capture.
    //
    // We don't use `-Z root` (drop privileges to user "root" for
    // the pcap writer) because we ARE root and the writer's
    // setuid-as-root is a no-op. The fd is owned by the helper
    // and inherited fine.
    //
    // `-q` keeps the parsed-protocol stdout quiet; we only care
    // about the binary pcap on disk.
    let bpf_filter = p.bpf_filter.clone();
    let mut child = tokio::process::Command::new("tcpdump")
        .args([
            "-i",
            &p.interface,
            // Stream through the descriptor opened above. Giving tcpdump the
            // pathname would let a symlink swap redirect this root process.
            "-w",
            "-",
            "-G",
            &duration.to_string(),
            "-W",
            "1",
            "-q",
            // Snap length — limit per-packet capture to 1600
            // bytes. Enough for any reasonable ASCII protocol
            // exchange. Bigger captures bloat the pcap without
            // value for cleartext-credential audit.
            "-s",
            "1600",
            // Pass the BPF as a single argv string. tcpdump
            // joins multiple bare args internally; the explicit
            // single-string form means we never need to worry
            // about shell quoting.
            &bpf_filter,
        ])
        .stdout(Stdio::from(capture_fd))
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("spawn tcpdump: {e}"))?;

    // Wait up to `duration + 10s` for tcpdump to finish. The
    // +10s gives it time to flush the pcap and exit after the
    // rotation marker hits.
    let wait = Duration::from_secs(duration as u64 + 10);
    let status = match tokio::time::timeout(wait, child.wait()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(anyhow!("tcpdump wait: {e}")),
        Err(_) => {
            // Hard-stop tcpdump.
            let _ = child.kill().await;
            return Err(anyhow!("tcpdump exceeded {}s wall-clock", wait.as_secs()));
        }
    };

    if !status.success() {
        // Even on non-zero exit (signal, error) the pcap may
        // contain partial data; surface to caller.
        let exit = status.code().unwrap_or(-1);
        tracing::warn!(exit, "tcpdump exited non-zero");
    }

    output_file
        .sync_all()
        .map_err(|e| anyhow!("flush capture {}: {e}", output_path.display()))?;
    let meta = output_file
        .metadata()
        .map_err(|e| anyhow!("stat pcap {}: {e}", output_path.display()))?;
    let size_bytes = meta.len();

    Ok(CaptureReport {
        pcap_path: output_path.to_string_lossy().into_owned(),
        size_bytes,
        duration_secs: duration,
        interface: p.interface,
        completed_cleanly: status.success(),
        packet_count_estimate: estimate_packet_count(size_bytes),
    })
}

fn create_capture_file(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| anyhow!("securely create capture {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("empty interface name"));
    }
    if name.len() > 16 {
        return Err(anyhow!("interface name too long"));
    }
    // Allow [a-z0-9]+ plus the BSD numeric suffix. Reject paths,
    // shell metas.
    let ok = name.chars().all(|c| c.is_ascii_alphanumeric());
    if !ok {
        return Err(anyhow!("interface name must be [a-z0-9]+"));
    }
    // Soft allowlist of common Mac interfaces. This is a sanity
    // check, not a hard restriction — the caller already filtered
    // via the BSD-name regex above. Anything matching the regex
    // but not in this list will still run, but tracing logs it.
    let recognised = [
        "en0",
        "en1",
        "en2",
        "en3",
        "en4",
        "en5",
        "lo0",
        "bridge0",
        "bridge100",
        "bridge101",
        "utun0",
        "utun1",
        "utun2",
        "utun3",
        "utun4",
        "utun5",
        "utun6",
        "utun7",
        "utun8",
        "utun9",
        "awdl0",
        "llw0",
        "vmnet1",
        "vmnet8",
    ];
    if !recognised.contains(&name) {
        tracing::info!("traffic_capture: unrecognised interface {name} (running anyway)");
    }
    Ok(())
}

fn validate_bpf(expr: &str) -> Result<()> {
    if expr.is_empty() {
        return Err(anyhow!("empty BPF filter"));
    }
    if expr.len() > 512 {
        return Err(anyhow!("BPF filter > 512 chars"));
    }
    // Reject characters that aren't part of standard BPF syntax.
    // Allowed: alphanumerics, whitespace, dots, slashes, parens,
    // colons, square brackets (for tcp[12] etc.), ampersands +
    // pipes (and/or), arithmetic + comparison operators.
    let allowed: &[char] = &[
        ' ', '\t', '.', '/', '(', ')', ':', '[', ']', '&', '|', '<', '>', '=', '-', '!', '+', '*',
        '%',
    ];
    for c in expr.chars() {
        if !c.is_ascii_alphanumeric() && !allowed.contains(&c) {
            return Err(anyhow!("BPF filter contains disallowed char: {c:?}"));
        }
    }
    Ok(())
}

/// Confirm the output path is under the caller's data directory
/// and contains no `..`. Returns the canonical path.
fn validate_output_path(raw: &str, user_home: &Path) -> Result<PathBuf> {
    if raw.is_empty() {
        return Err(anyhow!("empty output path"));
    }
    let p = Path::new(raw);
    if !p.is_absolute() {
        return Err(anyhow!("output path must be absolute"));
    }
    // No traversal.
    if raw.contains("..") {
        return Err(anyhow!("output path must not contain `..`"));
    }
    // Resolve both the allowed root and the destination parent before opening.
    // This rejects existing symlink components that escape the user's data dir.
    let allowed_prefix = user_home.join("Library/Application Support/SuperManager");
    let allowed_prefix = allowed_prefix
        .canonicalize()
        .map_err(|e| anyhow!("resolve allowed capture directory: {e}"))?;
    let parent = p
        .parent()
        .ok_or_else(|| anyhow!("output path has no parent"))?;
    let parent = parent
        .canonicalize()
        .map_err(|e| anyhow!("capture parent must already exist: {e}"))?;
    if !parent.starts_with(&allowed_prefix) {
        return Err(anyhow!(
            "output path must be under {}",
            allowed_prefix.display()
        ));
    }
    // The basename must end with .pcap or .pcapng (no .sh, no
    // .plist, no executable extensions).
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "pcap" && ext != "pcapng" {
        return Err(anyhow!("output path must end in .pcap or .pcapng"));
    }
    let filename = p
        .file_name()
        .ok_or_else(|| anyhow!("output path has no filename"))?;
    Ok(parent.join(filename))
}

/// Resolve the authenticated socket peer's home directory without consulting
/// daemon-wide environment variables or guessing among `/Users` entries.
fn home_dir_for_uid(uid: libc::uid_t) -> Result<PathBuf> {
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buffer_len = usize::try_from(suggested).unwrap_or(16_384).max(1024);
    let mut buffer = vec![0_u8; buffer_len];
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "getpwuid_r({uid}) failed: {}",
            std::io::Error::from_raw_os_error(rc)
        ));
    }
    if result.is_null() {
        return Err(anyhow!("no account exists for socket peer uid {uid}"));
    }
    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_dir.is_null() {
        return Err(anyhow!("account for uid {uid} has no home directory"));
    }
    let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
    Ok(PathBuf::from(home.to_string_lossy().into_owned()))
}

/// Very rough pcap-size → packet-count estimate. A pcap file has
/// a 24-byte global header plus 16-byte per-packet header. With
/// average TCP payload + headers ~80 bytes, that's ~96 bytes per
/// captured packet at our snap length. Used only as a GUI hint.
fn estimate_packet_count(bytes: u64) -> u64 {
    if bytes <= 24 {
        return 0;
    }
    (bytes - 24) / 96
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_tree() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(
            home.path()
                .join("Library/Application Support/SuperManager/captures"),
        )
        .unwrap();
        home
    }

    #[test]
    fn rejects_empty_interface() {
        assert!(validate_interface("").is_err());
    }

    #[test]
    fn rejects_interface_with_shell_meta() {
        assert!(validate_interface("en0;rm -rf /").is_err());
        assert!(validate_interface("en0 && curl evil.com").is_err());
        assert!(validate_interface("../en0").is_err());
    }

    #[test]
    fn accepts_standard_macos_interfaces() {
        for iface in &["en0", "en1", "utun0", "utun7", "lo0", "bridge100", "awdl0"] {
            assert!(validate_interface(iface).is_ok(), "{iface} should pass");
        }
    }

    #[test]
    fn rejects_empty_bpf() {
        assert!(validate_bpf("").is_err());
    }

    #[test]
    fn rejects_bpf_with_shell_meta() {
        assert!(validate_bpf("tcp port 80; rm -rf /").is_err());
        assert!(validate_bpf("$(curl evil)").is_err());
        assert!(validate_bpf("tcp `id`").is_err());
        assert!(validate_bpf("tcp\"or 1=1").is_err());
    }

    #[test]
    fn accepts_realistic_bpf() {
        let ok = [
            "tcp port 80",
            "tcp port 21 or tcp port 23",
            "(tcp port 80 or tcp port 8080) and net 192.168.1.0/24",
            "tcp[((tcp[12]>>4)*4)+0:4] = 0x47455420",
        ];
        for expr in &ok {
            assert!(validate_bpf(expr).is_ok(), "{expr} should pass");
        }
    }

    #[test]
    fn rejects_bpf_too_long() {
        let too_long = "tcp port 80 or ".repeat(50);
        assert!(validate_bpf(&too_long).is_err());
    }

    #[test]
    fn rejects_relative_output_path() {
        let home = capture_tree();
        assert!(validate_output_path("captures/x.pcap", home.path()).is_err());
    }

    #[test]
    fn rejects_path_with_dotdot() {
        // Must be absolute AND no `..` AND must start with the
        // user's SuperManager dir. The dotdot rule alone fails it.
        let p =
            "/Users/somebody/Library/Application Support/SuperManager/captures/../../etc/x.pcap";
        let home = capture_tree();
        assert!(validate_output_path(p, home.path()).is_err());
    }

    #[test]
    fn rejects_non_pcap_extension() {
        let home = capture_tree();
        let bad_ext = home
            .path()
            .join("Library/Application Support/SuperManager/captures/x.sh");
        let res = validate_output_path(bad_ext.to_str().unwrap(), home.path());
        assert!(res.is_err(), "must reject .sh extension: got {res:?}");
    }

    #[test]
    fn rejects_parent_symlink_that_escapes_capture_root() {
        let home = capture_tree();
        let outside = tempfile::tempdir().unwrap();
        let link = home
            .path()
            .join("Library/Application Support/SuperManager/escape");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let requested = link.join("capture.pcap");
        assert!(validate_output_path(requested.to_str().unwrap(), home.path()).is_err());
    }

    #[test]
    fn secure_create_refuses_a_final_symlink() {
        let home = capture_tree();
        let victim = home.path().join("victim");
        std::fs::write(&victim, b"do not overwrite").unwrap();
        let planted = home
            .path()
            .join("Library/Application Support/SuperManager/captures/planted.pcap");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        assert!(create_capture_file(&planted).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not overwrite");
    }

    #[test]
    fn estimate_packet_count_sanity() {
        assert_eq!(estimate_packet_count(0), 0);
        assert_eq!(estimate_packet_count(24), 0);
        // 24 + 96 = 120 bytes → 1 packet estimate
        assert_eq!(estimate_packet_count(120), 1);
        assert!(estimate_packet_count(10_000) > 50);
    }
}
