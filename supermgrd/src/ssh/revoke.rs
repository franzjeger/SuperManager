//! Revoke public keys from remote hosts' `authorized_keys`.
//!
//! Mirrors the strategy used by the Python SSH Manager:
//!
//! 1. **SFTP** (preferred) — read the file, filter out matching lines, rewrite.
//! 2. **Exec fallback** — use `grep -vF` with base64-encoded key; compatible
//!    with BusyBox (UniFi, OpenWRT, pfSense, etc.).
//! 3. **Sudo** — operate on `/root/.ssh/authorized_keys` via `sudo`.

use base64::Engine;
use supermgr_core::error::SshError;

use crate::ssh::connection::SshSession;

/// Revoke a public key from a remote host's `authorized_keys`.
///
/// Returns `Ok(())` even if the key was not present (idempotent).
///
/// If `use_sudo` is true, operates on `/root/.ssh/authorized_keys` using
/// `sudo` exec commands. Otherwise SFTP is attempted first, falling back
/// to exec if the SFTP subsystem is unavailable.
pub async fn revoke_public_key(
    session: &SshSession,
    public_key: &str,
    use_sudo: bool,
) -> Result<(), SshError> {
    let pub_line = public_key.trim();

    if use_sudo {
        revoke_with_sudo(session, pub_line).await
    } else {
        match revoke_via_sftp(session, pub_line).await {
            Ok(()) => Ok(()),
            Err(_) => revoke_via_exec(session, pub_line).await,
        }
    }
}

// ---------------------------------------------------------------------------
// SFTP strategy
// ---------------------------------------------------------------------------

/// Revoke using SFTP: read authorized_keys, filter out matching lines, rewrite.
async fn revoke_via_sftp(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    let (_, home_out, _) = session.exec("echo $HOME").await?;
    let home = home_out.trim();
    let home = if home.is_empty() { "/root" } else { home };

    let ak_path = format!("{home}/.ssh/authorized_keys");

    let sftp = session.sftp().await.map_err(|e| {
        SshError::RevokeFailed(format!("SFTP not available: {e}"))
    })?;

    // Read existing authorized_keys.
    let existing = match sftp.read(&ak_path).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => return Ok(()), // File absent — nothing to revoke.
    };

    // Filter out lines containing the public key.
    let filtered: String = existing
        .lines()
        .filter(|line| !line.contains(pub_line))
        .map(|line| format!("{line}\n"))
        .collect();

    let original_count = existing.lines().count();
    let filtered_count = filtered.lines().count();

    if original_count == filtered_count {
        return Ok(()); // Key was not present.
    }

    // Write back.
    sftp.write(&ak_path, filtered.as_bytes()).await.map_err(|e| {
        SshError::RevokeFailed(format!("failed to write {ak_path}: {e}"))
    })?;

    // Fix permissions (best-effort).
    let _ = session.exec(&format!("chmod 600 {ak_path}")).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Exec fallback strategy
// ---------------------------------------------------------------------------

/// Revoke using shell commands only — BusyBox/Dropbear compatible.
///
/// Uses `grep -vF` with base64-encoded key to avoid shell-quoting issues.
async fn revoke_via_exec(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    let (_, home_out, _) = session.exec("echo $HOME").await?;
    let home = home_out.trim();
    let home = if home.is_empty() { "/root" } else { home };

    let ak_path = format!("{home}/.ssh/authorized_keys");

    // Check if file exists.
    let (rc, _, _) = session.exec(&format!("test -f {ak_path}")).await?;
    if rc != 0 {
        return Ok(()); // File absent — nothing to revoke.
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_line.as_bytes());

    // Use a temporary file to atomically replace the authorized_keys.
    let cmd = format!(
        "tmp=$(mktemp /tmp/.ak_revoke_XXXXXX) && \
         grep -vF \"$(printf '%s' {b64} | base64 -d)\" {ak_path} > \"$tmp\" \
         && mv \"$tmp\" {ak_path} && chmod 600 {ak_path}"
    );
    let (rc, _, stderr) = session.exec(&cmd).await?;
    if rc != 0 {
        return Err(SshError::RevokeFailed(format!(
            "revoke failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sudo strategy
// ---------------------------------------------------------------------------

/// Revoke from `/root/.ssh/authorized_keys` via `sudo`.
async fn revoke_with_sudo(session: &SshSession, pub_line: &str) -> Result<(), SshError> {
    let target_file = "/root/.ssh/authorized_keys";

    // Check if file exists.
    let (rc, _, _) = session.exec(&format!("sudo test -f {target_file}")).await?;
    if rc != 0 {
        return Ok(()); // File absent — nothing to revoke.
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_line.as_bytes());

    // Use a temporary file to atomically replace the authorized_keys.
    let cmd = format!(
        "tmp=$(mktemp /tmp/.ak_revoke_XXXXXX) && \
         sudo grep -vF \"$(printf '%s' {b64} | base64 -d)\" {target_file} > \"$tmp\" \
         && sudo mv \"$tmp\" {target_file} && sudo chmod 600 {target_file}"
    );
    let (rc, _, stderr) = session.exec(&cmd).await?;
    if rc != 0 {
        return Err(SshError::RevokeFailed(format!(
            "sudo revoke failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}
