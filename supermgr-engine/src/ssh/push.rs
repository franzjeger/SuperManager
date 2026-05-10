//! Push public keys to remote hosts' `authorized_keys`.
//!
//! Mirrors the strategy used by the Python SSH Manager:
//!
//! 1. **SFTP** (preferred) — read the file, check for duplicates, append.
//! 2. **Exec fallback** — base64-encode the key to avoid shell-quoting issues;
//!    compatible with BusyBox (UniFi, OpenWRT, pfSense, etc.).
//! 3. **Sudo** — write to `/root/.ssh/authorized_keys` via `sudo` exec commands.

use base64::Engine;
use supermgr_core::error::SshError;

use crate::ssh::connection::SshSession;

/// Result of a push operation for a single host.
#[derive(Debug, serde::Serialize)]
pub struct PushResult {
    pub host_id: String,
    pub host_label: String,
    pub success: bool,
    pub message: String,
}

/// Push a public key to a remote host's `authorized_keys`.
///
/// If `use_sudo` is true the key is written to `/root/.ssh/authorized_keys`
/// using `sudo` exec commands. Otherwise SFTP is attempted first, falling
/// back to exec if the SFTP subsystem is unavailable.
pub async fn push_public_key(
    session: &SshSession,
    public_key: &str,
    use_sudo: bool,
) -> Result<(), SshError> {
    let pub_line = public_key.trim();

    if use_sudo {
        push_with_sudo(session, pub_line).await
    } else {
        match push_via_sftp(session, pub_line).await {
            Ok(()) => Ok(()),
            Err(_) => push_via_exec(session, pub_line).await,
        }
    }
}

// ---------------------------------------------------------------------------
// SFTP strategy
// ---------------------------------------------------------------------------

/// Push using SFTP: read authorized_keys, check for duplicates, append.
async fn push_via_sftp(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    // Discover the remote home directory.
    let (_, home_out, _) = session.exec("echo $HOME").await?;
    let home = home_out.trim();
    let home = if home.is_empty() { "/root" } else { home };

    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    let sftp = session.sftp().await.map_err(|e| {
        SshError::PushFailed(format!("SFTP not available: {e}"))
    })?;

    // Ensure ~/.ssh exists.
    if sftp.metadata(&ssh_dir).await.is_err() {
        sftp.create_dir(&ssh_dir).await.map_err(|e| {
            SshError::PushFailed(format!("failed to create {ssh_dir}: {e}"))
        })?;
    }

    // Read existing authorized_keys (empty if absent).
    let existing = match sftp.read(&ak_path).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    };

    // Check for duplicate — match on the key data portion.
    if existing.contains(pub_line) {
        return Ok(()); // Already present.
    }

    // Build the new file content.
    let mut updated = existing.trim_end_matches('\n').to_owned();
    if !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(pub_line);
    updated.push('\n');

    // Write back.
    sftp.write(&ak_path, updated.as_bytes()).await.map_err(|e| {
        SshError::PushFailed(format!("failed to write {ak_path}: {e}"))
    })?;

    // Set permissions (best-effort, ignore errors from broken SFTP servers).
    let _ = set_permissions_via_exec(session, &ssh_dir, "700").await;
    let _ = set_permissions_via_exec(session, &ak_path, "600").await;

    Ok(())
}

/// Helper: chmod via exec (since russh-sftp metadata API may not support
/// permissions on all servers).
async fn set_permissions_via_exec(
    session: &SshSession,
    path: &str,
    mode: &str,
) -> Result<(), SshError> {
    session.exec(&format!("chmod {mode} {path}")).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Exec fallback strategy
// ---------------------------------------------------------------------------

/// Push using shell commands only — no SFTP required.
///
/// Uses base64 encoding to safely transfer the key without shell-quoting
/// issues. Compatible with BusyBox (UniFi, OpenWRT, pfSense, etc.).
async fn push_via_exec(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    let (_, home_out, _) = session.exec("echo $HOME").await?;
    let home = home_out.trim();
    let home = if home.is_empty() { "/root" } else { home };

    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    // Ensure directory and file exist with correct permissions.
    let _ = session
        .exec(&format!("mkdir -p {ssh_dir} && chmod 700 {ssh_dir}"))
        .await;
    let _ = session
        .exec(&format!("touch {ak_path} && chmod 600 {ak_path}"))
        .await;

    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_line.as_bytes());

    // Check for duplicate.
    let check_cmd = format!(
        "grep -qF \"$(printf '%s' {b64} | base64 -d)\" {ak_path} 2>/dev/null"
    );
    let (rc, _, _) = session.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(()); // Already present.
    }

    // Append via base64 decode.
    let append_cmd = format!("printf '%s\\n' {b64} | base64 -d >> {ak_path}");
    let (rc, _, stderr) = session.exec(&append_cmd).await?;
    if rc != 0 {
        return Err(SshError::PushFailed(format!(
            "append failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sudo strategy
// ---------------------------------------------------------------------------

/// Push to `/root/.ssh/authorized_keys` using `sudo` exec commands.
async fn push_with_sudo(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    let target_dir = "/root/.ssh";
    let target_file = "/root/.ssh/authorized_keys";

    // Ensure directory and file.
    let _ = session
        .exec(&format!(
            "sudo mkdir -p {target_dir} && sudo chmod 700 {target_dir}"
        ))
        .await;
    let _ = session
        .exec(&format!(
            "sudo touch {target_file} && sudo chmod 600 {target_file}"
        ))
        .await;

    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_line.as_bytes());

    // Check for duplicate.
    let check_cmd = format!(
        "sudo grep -qF \"$(echo {b64} | base64 -d)\" {target_file} 2>/dev/null"
    );
    let (rc, _, _) = session.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(()); // Already present.
    }

    // Append via base64.
    let append_cmd = format!(
        "echo {b64} | base64 -d | sudo tee -a {target_file} > /dev/null"
    );
    let (rc, _, stderr) = session.exec(&append_cmd).await?;
    if rc != 0 {
        return Err(SshError::PushFailed(format!(
            "sudo append failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}
