//! In-app updater: GitHub Releases → download → verify → run the installer.
//!
//! The Mac app gets this from Sparkle; Windows has no platform updater for
//! MSI-distributed apps, so this is the equivalent by hand:
//!
//! 1. Ask the GitHub API for the newest release and compare its tag with
//!    the version this binary was built as (`SUPERMGR_VERSION`, stamped
//!    from the release tag by CI — see `build.rs`).
//! 2. Download the `SuperManager-Setup-<v>.exe` Burn bundle (preferred —
//!    it carries the WireGuard/OpenVPN driver prerequisites), falling back
//!    to the bare `SuperManager-<v>.msi`.
//! 3. Verify it against the `.sha256` sidecar CI published next to it.
//!    Both artifacts are unsigned today (no EV cert — see
//!    release-windows.yml), which makes this check the only integrity
//!    check there is; a download that has no sidecar is refused rather
//!    than run unverified.
//! 4. Start the installer and let the caller quit the GUI — the MSI's
//!    MajorUpgrade replaces the old install and restarts the service in
//!    the same transaction.

use std::path::PathBuf;

use anyhow::Context as _;
use futures_util::StreamExt as _;
use sha2::Digest as _;

/// The version this binary was built as. From the release tag in CI
/// builds, `CARGO_PKG_VERSION` in dev builds.
pub const CURRENT_VERSION: &str = env!("SUPERMGR_VERSION");

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

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("SuperManager-Updater")
        .build()
        .expect("reqwest client")
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
    let release: serde_json::Value = http()
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
        assets.iter().find(|a| {
            a.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(pred)
        })
    };
    // Setup bundle first: it chain-installs the WireGuardNT + OpenVPN
    // driver prerequisites. Bare MSI as fallback for releases that only
    // shipped one artifact.
    let installer = find(&|n| n.starts_with("SuperManager-Setup-") && n.ends_with(".exe"))
        .or_else(|| find(&|n| n.starts_with("SuperManager-") && n.ends_with(".msi")))
        .with_context(|| format!("release v{latest} has no Windows installer asset"))?;

    let name = installer["name"].as_str().unwrap_or_default().to_owned();
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

    Ok(Some(UpdateInfo { version: latest, name, url, sha256_url, size }))
}

/// Download the installer to `%TEMP%`, verify its SHA-256 against the
/// published sidecar, and return the verified path. `progress` is called
/// with (bytes so far, total) as chunks arrive.
pub async fn download(
    info: &UpdateInfo,
    mut progress: impl FnMut(u64, u64),
) -> anyhow::Result<PathBuf> {
    use tokio::io::AsyncWriteExt as _;

    let expected = http()
        .get(&info.sha256_url)
        .send()
        .await
        .context("fetching the .sha256 sidecar")?
        .error_for_status()?
        .text()
        .await?;
    // Sidecar format is `<hex>  <filename>` (see release-windows.yml).
    let expected = expected
        .split_whitespace()
        .next()
        .context("empty .sha256 sidecar")?
        .to_ascii_lowercase();

    let path = std::env::temp_dir().join(&info.name);
    let resp = http()
        .get(&info.url)
        .send()
        .await
        .context("starting the download")?
        .error_for_status()?;
    let total = resp.content_length().unwrap_or(info.size);

    let mut file = tokio::fs::File::create(&path)
        .await
        .with_context(|| format!("creating {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut got: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("download interrupted")?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        got += chunk.len() as u64;
        progress(got, total);
    }
    file.flush().await?;
    drop(file);

    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != expected {
        let _ = tokio::fs::remove_file(&path).await;
        anyhow::bail!(
            "SHA-256 mismatch on {} — the download does not match what CI published. \
             Not running it.",
            info.name
        );
    }
    Ok(path)
}

/// Start the verified installer. The caller quits the GUI right after —
/// the installer stops the service, replaces the files, and starts the
/// new service itself.
pub fn launch(path: &std::path::Path) -> anyhow::Result<()> {
    let is_msi = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("msi"));
    let spawned = if is_msi {
        std::process::Command::new("msiexec").arg("/i").arg(path).spawn()
    } else {
        std::process::Command::new(path).spawn()
    };
    spawned
        .map(drop)
        .with_context(|| format!("starting {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn version_ordering() {
        assert!(parse_version("1.7.0") > parse_version("1.0.0"));
        assert!(parse_version("v1.10.0") > parse_version("1.9.9"));
        assert!(parse_version("1.7.0") == parse_version("v1.7"));
        assert!(parse_version("2.0.0") > parse_version("1.99.99"));
    }
}
