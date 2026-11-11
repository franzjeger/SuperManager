//! In-app updater: GitHub Releases → download → lock → verify → run the installer.
//!
//! The Mac app gets this from Sparkle; Windows has no platform updater for
//! MSI-distributed apps, so this is the equivalent by hand:
//!
//! 1. Ask the GitHub API for the newest release and compare its tag with
//!    the version this binary was built as (`SUPERMGR_VERSION`, stamped
//!    from the release tag by CI — see `build.rs`).
//! 2. Download the `SuperManager-Setup-<v>.exe` Burn bundle (preferred —
//!    it carries the WireGuard/OpenVPN driver prerequisites), falling back
//!    to the bare `SuperManager-<v>.msi`, into a fresh `%TEMP%` staging
//!    directory created with `create_new`.
//! 3. Reopen the downloaded installer with `FILE_SHARE_READ` only (no write
//!    or delete sharing) and hold that kernel handle open across:
//!    a) SHA-256 verification read directly from the locked file handle,
//!    b) Authenticode signature verification (`Get-AuthenticodeSignature`
//!       `Status -eq 'Valid'` + optional publisher subject pin), and
//!    c) `Command::spawn()` (`CreateProcessW`), eliminating any `%TEMP%`
//!       TOCTOU swap window between verification and execution (`P1-6`).
//! 4. Start the installer and let the caller quit the GUI — the MSI's
//!    MajorUpgrade replaces the old install and restarts the service in
//!    the same transaction.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use futures_util::StreamExt as _;
use sha2::Digest as _;

/// The version this binary was built as. From the release tag in CI
/// builds, `CARGO_PKG_VERSION` in dev builds.
pub const CURRENT_VERSION: &str = env!("SUPERMGR_VERSION");

/// Win32 `FILE_SHARE_READ`: permits concurrent read/execute access
/// (`Get-AuthenticodeSignature`, `CreateProcessW`, `msiexec`) while blocking
/// any concurrent write, append, rename, or delete for as long as the handle
/// remains open.
const FILE_SHARE_READ: u32 = 0x0000_0001;

/// Win32 `CREATE_NO_WINDOW`: prevents a console window from flashing when the
/// GUI invokes `powershell.exe` for Authenticode verification.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Optional compile-time Authenticode publisher subject substring pin
/// (e.g. `CN=SuperManager`).
const EXPECTED_PUBLISHER: Option<&str> = option_env!("SUPERMGR_WINDOWS_PUBLISHER");

const AUTHENTICODE_VERIFY_SCRIPT: &str = "\
$ErrorActionPreference = 'Stop'; \
$sig = Get-AuthenticodeSignature -LiteralPath $env:SM_INSTALLER_PATH; \
if ($null -eq $sig -or $sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) { \
    $st = if ($null -ne $sig) { \"$($sig.Status): $($sig.StatusMessage)\" } else { 'NoSignature' }; \
    [Console]::Error.WriteLine(\"Authenticode signature invalid ($st)\"); \
    exit 1; \
} \
$expected = $env:SM_EXPECTED_PUBLISHER; \
if (-not [string]::IsNullOrWhiteSpace($expected)) { \
    if ($sig.SignerCertificate.Subject.IndexOf($expected, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { \
        [Console]::Error.WriteLine(\"Unexpected Authenticode signer '$($sig.SignerCertificate.Subject)'; expected '$expected'\"); \
        exit 2; \
    } \
} \
exit 0";

const RELEASES_LATEST: &str =
    "https://api.github.com/repos/franzjeger/SuperManager/releases/latest";

/// A newer release, ready to download.
pub struct UpdateInfo {
    /// Version string without the `v` prefix, e.g. `1.8.0`.
    pub version: String,
    /// Installer asset filename, e.g. `SuperManager-Setup-1.8.0.exe`.
    pub name: String,
    /// Direct download URL of the installer asset.
    pub url: String,
    /// Download URL of the `.sha256` sidecar.
    pub sha256_url: String,
    /// Asset size in bytes, for progress reporting.
    pub size: u64,
}

fn http() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("SuperManager-Updater")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
        .context("build HTTP client")
}

/// `"1.7.0"` → comparable numeric form; non-numeric fragments count as 0.
fn parse_version(v: &str) -> (u64, u64, u64) {
    let mut nums = v
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.trim().parse::<u64>().unwrap_or(0));
    (
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
    )
}

/// Ask GitHub for the newest release. `Ok(None)` means up to date.
pub async fn check() -> anyhow::Result<Option<UpdateInfo>> {
    let client = http()?;
    let release: serde_json::Value = client
        .get(RELEASES_LATEST)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("could not reach GitHub")?
        .error_for_status()
        .context("GitHub releases API")?
        .json()
        .await
        .context("unreadable GitHub response")?;

    let tag = release
        .get("tag_name")
        .and_then(|t| t.as_str())
        .context("release has no tag_name")?;
    let latest = tag.trim_start_matches('v').to_owned();
    if parse_version(&latest) <= parse_version(CURRENT_VERSION) {
        return Ok(None);
    }

    let assets = release
        .get("assets")
        .and_then(|a| a.as_array())
        .context("release has no assets")?;
    let find = |pred: &dyn Fn(&str) -> bool| {
        assets
            .iter()
            .find(|a| a.get("name").and_then(|n| n.as_str()).is_some_and(pred))
    };
    // Setup bundle first: it chain-installs the WireGuardNT + OpenVPN
    // driver prerequisites. Bare MSI as fallback for releases that only
    // shipped one artifact.
    let installer = find(&|n| n.starts_with("SuperManager-Setup-") && n.ends_with(".exe"))
        .or_else(|| find(&|n| n.starts_with("SuperManager-") && n.ends_with(".msi")))
        .with_context(|| format!("release v{latest} has no Windows installer asset"))?;

    let raw_name = installer["name"].as_str().unwrap_or_default();
    let name = crate::model::sanitize_installer_filename(raw_name)
        .map_err(anyhow::Error::msg)?
        .to_owned();
    let url = installer
        .get("browser_download_url")
        .and_then(|u| u.as_str())
        .context("installer asset has no download URL")?
        .to_owned();
    let sha_name = format!("{name}.sha256");
    let sha256_url = find(&|n| n == sha_name.as_str())
        .and_then(|a| a.get("browser_download_url"))
        .and_then(|u| u.as_str())
        // Unsigned installer with no published hash: nothing to verify
        // against, so refuse now instead of downloading something we
        // would refuse to run anyway.
        .with_context(|| format!("release v{latest} has no {sha_name} to verify against"))?
        .to_owned();
    let size = installer
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Ok(Some(UpdateInfo {
        version: latest,
        name,
        url,
        sha256_url,
        size,
    }))
}

/// A downloaded installer verified against both its `.sha256` sidecar and
/// Windows Authenticode while holding a `FILE_SHARE_READ`-only kernel handle.
///
/// Keeping `_lock` open across verification and `Command::spawn()` prevents
/// any local process from modifying, replacing, or deleting the file between
/// verification and process creation (`P1-6`).
pub struct VerifiedInstaller {
    path: PathBuf,
    _lock: std::fs::File,
}

fn system32_executable(relative: &str) -> PathBuf {
    let canonical = PathBuf::from(r"C:\Windows\System32").join(relative);
    if canonical.is_file() {
        return canonical;
    }
    std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(relative)
}

fn open_read_locked(path: &Path) -> anyhow::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .with_context(|| format!("opening {} with read-only sharing lock", path.display()))
}

fn verify_sha256_from_handle(
    file: &mut std::fs::File,
    expected_hex: &str,
    display_name: &str,
) -> anyhow::Result<()> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewinding {display_name} for SHA-256 verification"))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {display_name} for SHA-256 verification"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewinding {display_name} after SHA-256 verification"))?;

    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != expected_hex {
        anyhow::bail!(
            "SHA-256 mismatch on {display_name} — the download does not match what CI published. \
             Not running it."
        );
    }
    Ok(())
}

fn verify_authenticode_powershell(path: &Path, display_name: &str) -> anyhow::Result<()> {
    let powershell = system32_executable(r"WindowsPowerShell\v1.0\powershell.exe");
    let mut cmd = std::process::Command::new(&powershell);
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        AUTHENTICODE_VERIFY_SCRIPT,
    ])
    .env("SM_INSTALLER_PATH", path)
    .stdin(std::process::Stdio::null())
    .creation_flags(CREATE_NO_WINDOW);

    if let Some(publisher) = EXPECTED_PUBLISHER {
        cmd.env("SM_EXPECTED_PUBLISHER", publisher);
    } else {
        cmd.env_remove("SM_EXPECTED_PUBLISHER");
    }

    let output = cmd
        .output()
        .with_context(|| format!("invoking {} for Authenticode check", powershell.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let detail = if detail.is_empty() {
            format!("exit status {}", output.status)
        } else {
            detail
        };
        anyhow::bail!(
            "Authenticode signature verification failed on {display_name} ({detail}). \
             Refusing to execute an unsigned or untrusted installer."
        );
    }
    Ok(())
}

fn lock_and_verify_installer(
    path: PathBuf,
    expected_sha256: &str,
    display_name: &str,
) -> anyhow::Result<VerifiedInstaller> {
    let mut locked = open_read_locked(&path)?;
    if let Err(err) = verify_sha256_from_handle(&mut locked, expected_sha256, display_name)
        .and_then(|()| verify_authenticode_powershell(&path, display_name))
    {
        drop(locked);
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        return Err(err);
    }
    Ok(VerifiedInstaller {
        path,
        _lock: locked,
    })
}

/// Download the installer to an isolated `%TEMP%` directory, lock it with
/// `FILE_SHARE_READ`, verify its SHA-256 from the locked handle plus its
/// Authenticode signature, and return the locked [`VerifiedInstaller`].
/// `progress` is called with `(bytes so far, total)` as chunks arrive.
pub async fn download(
    info: &UpdateInfo,
    mut progress: impl FnMut(u64, u64),
) -> anyhow::Result<VerifiedInstaller> {
    use tokio::io::AsyncWriteExt as _;

    let safe_name = crate::model::sanitize_installer_filename(&info.name)
        .map_err(anyhow::Error::msg)?
        .to_owned();
    let client = http()?;

    let sidecar_raw = client
        .get(&info.sha256_url)
        .send()
        .await
        .context("fetching the .sha256 sidecar")?
        .error_for_status()?
        .text()
        .await?;
    let expected = crate::model::parse_sha256_sidecar(&sidecar_raw).map_err(anyhow::Error::msg)?;

    let stage_dir = std::env::temp_dir().join(format!("supermgr-update-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir(&stage_dir)
        .await
        .with_context(|| format!("creating staging directory {}", stage_dir.display()))?;
    let path = stage_dir.join(&safe_name);

    let resp = match client
        .get(&info.url)
        .send()
        .await
        .context("starting the download")
        .and_then(|r| {
            r.error_for_status()
                .context("installer download HTTP status")
        }) {
        Ok(r) => r,
        Err(e) => {
            let _ = tokio::fs::remove_dir(&stage_dir).await;
            return Err(e);
        }
    };
    let total = resp.content_length().unwrap_or(info.size);

    let write_result: anyhow::Result<()> = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .with_context(|| format!("creating {}", path.display()))?;
        let mut got: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("download interrupted")?;
            file.write_all(&chunk).await?;
            got += chunk.len() as u64;
            progress(got, total);
        }
        file.flush().await?;
        file.sync_all().await?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&path).await;
        let _ = tokio::fs::remove_dir(&stage_dir).await;
        return Err(e);
    }

    let display_name = info.name.clone();
    tokio::task::spawn_blocking(move || lock_and_verify_installer(path, &expected, &display_name))
        .await
        .context("installer verification task panicked")?
}

/// Start the verified installer while still holding its `FILE_SHARE_READ`
/// lock handle across `Command::spawn()`. The caller quits the GUI right
/// after — the installer stops the service, replaces the files, and starts
/// the new service itself.
pub fn launch(installer: VerifiedInstaller) -> anyhow::Result<PathBuf> {
    let is_msi = installer
        .path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("msi"));
    let spawned = if is_msi {
        std::process::Command::new(system32_executable("msiexec.exe"))
            .arg("/i")
            .arg(&installer.path)
            .spawn()
    } else {
        std::process::Command::new(&installer.path).spawn()
    };
    let _child = spawned.with_context(|| format!("starting {}", installer.path.display()))?;
    // Keep `_lock` alive until `CreateProcessW` has mapped the image / spawned `msiexec`.
    let VerifiedInstaller { path, _lock } = installer;
    drop(_lock);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{
        lock_and_verify_installer, open_read_locked, parse_version, verify_sha256_from_handle,
    };
    use sha2::Digest as _;

    #[test]
    fn version_ordering() {
        assert!(parse_version("1.7.0") > parse_version("1.0.0"));
        assert!(parse_version("v1.10.0") > parse_version("1.9.9"));
        assert!(parse_version("1.7.0") == parse_version("v1.7"));
        assert!(parse_version("2.0.0") > parse_version("1.99.99"));
    }

    #[test]
    fn read_lock_blocks_writers_verifies_sha256_and_rejects_unsigned_installer() {
        let dir = std::env::temp_dir().join(format!("sm-update-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("SuperManager-Setup-9.9.9.exe");
        let payload = b"MZ-unsigned-test-payload";
        std::fs::write(&path, payload).unwrap();

        let expected_hex: String = sha2::Sha256::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        {
            let mut locked = open_read_locked(&path).unwrap();
            // Concurrent write open MUST be denied while FILE_SHARE_READ lock is held.
            assert!(
                std::fs::OpenOptions::new().write(true).open(&path).is_err(),
                "writer should be blocked while FILE_SHARE_READ handle is open"
            );
            verify_sha256_from_handle(&mut locked, &expected_hex, "test.exe").unwrap();
            assert!(
                verify_sha256_from_handle(&mut locked, &"0".repeat(64), "test.exe").is_err(),
                "tampered digest must fail verification"
            );
        }

        // Full lock_and_verify_installer must reject the unsigned payload and clean up.
        let err = match lock_and_verify_installer(
            path.clone(),
            &expected_hex,
            "SuperManager-Setup-9.9.9.exe",
        ) {
            Ok(_) => panic!("unsigned installer must be rejected"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("Authenticode"),
            "unexpected error: {err:#}"
        );
        assert!(!path.exists(), "rejected installer should be deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// The Settings page's Updates card
// ---------------------------------------------------------------------------

/// Answer the Updates card's buttons. `Updates.busy` doubles as the guard
/// against a second check or download starting while one runs.
pub(super) fn bind(window: &super::AppWindow, ctx: &super::Ctx) {
    use slint::ComponentHandle as _;

    use super::Updates;

    fn status(ctx: &super::Ctx, msg: String) {
        ctx.ui(move |w| w.global::<Updates>().set_status(msg.into()));
    }

    let updates = window.global::<Updates>();

    updates.on_check({
        let ctx = ctx.clone();
        move || {
            let Some(w) = ctx.weak.upgrade() else {
                return;
            };
            let u = w.global::<Updates>();
            if u.get_busy() {
                return;
            }
            u.set_busy(true);
            u.set_status("Checking GitHub releases\u{2026}".into());
            let ctx2 = ctx.clone();
            ctx.spawn(async move {
                let result = check().await;
                ctx2.ui(move |w| {
                    let u = w.global::<Updates>();
                    u.set_busy(false);
                    match result {
                        Ok(Some(info)) => {
                            u.set_available(true);
                            u.set_status(
                                format!(
                                    "Version {} is available. You have {CURRENT_VERSION}.",
                                    info.version
                                )
                                .into(),
                            );
                        }
                        Ok(None) => {
                            u.set_available(false);
                            u.set_status(
                                format!("You have the latest version ({CURRENT_VERSION}).").into(),
                            );
                        }
                        Err(e) => u.set_status(format!("Couldn't check for updates: {e:#}").into()),
                    }
                });
            });
        }
    });

    // Re-check (the offered version can be minutes old), download to
    // %TEMP%, verify against the published SHA-256, start the installer,
    // and quit — the MSI's MajorUpgrade replaces this install and restarts
    // the service in its own transaction.
    updates.on_install({
        let ctx = ctx.clone();
        move || {
            let Some(w) = ctx.weak.upgrade() else {
                return;
            };
            let u = w.global::<Updates>();
            if u.get_busy() {
                return;
            }
            u.set_busy(true);
            let ctx2 = ctx.clone();
            ctx.spawn(async move {
                let done = |ctx: &super::Ctx| ctx.ui(|w| w.global::<Updates>().set_busy(false));
                let info = match check().await {
                    Ok(Some(i)) => i,
                    Ok(None) => {
                        ctx2.ui(|w| w.global::<Updates>().set_available(false));
                        status(
                            &ctx2,
                            format!("You already have the latest version ({CURRENT_VERSION})."),
                        );
                        done(&ctx2);
                        return;
                    }
                    Err(e) => {
                        status(&ctx2, format!("Couldn't check for updates: {e:#}"));
                        done(&ctx2);
                        return;
                    }
                };

                // Progress at ~5 MB steps; every chunk would flood the
                // event loop for nothing visible.
                let name = info.name.clone();
                let mut last_step = u64::MAX;
                let progress_ctx = ctx2.clone();
                let downloaded = download(&info, |got, total| {
                    let step = got / (5 * 1024 * 1024);
                    if step != last_step {
                        last_step = step;
                        let msg = if total > 0 {
                            format!(
                                "Downloading {name}\u{2026} {} of {} MB",
                                got / (1024 * 1024),
                                total / (1024 * 1024)
                            )
                        } else {
                            format!("Downloading {name}\u{2026} {} MB", got / (1024 * 1024))
                        };
                        status(&progress_ctx, msg);
                    }
                })
                .await;

                match downloaded.and_then(launch) {
                    Ok(path) => {
                        tracing::info!("update installer started: {}", path.display());
                        status(
                            &ctx2,
                            "Installer verified and started \u{2014} SuperManager closes now."
                                .into(),
                        );
                        // A moment for the message, then out of the
                        // installer's way: it replaces this binary.
                        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                        let _ = slint::invoke_from_event_loop(|| {
                            slint::quit_event_loop().ok();
                        });
                    }
                    Err(e) => {
                        status(&ctx2, format!("The update failed: {e:#}"));
                        done(&ctx2);
                    }
                }
            });
        }
    });
}
