//! Push and revoke public keys in a remote host's `authorized_keys`.
//!
//! Both operations use the same three strategies, in the same order:
//!
//! 1. **SFTP** (preferred) — read `authorized_keys` (treating *only*
//!    `NoSuchFile` as empty), stage in `~/.ssh/.authorized_keys.tmp.<id>`,
//!    and atomically rename into place.
//! 2. **Exec fallback** — used only when the SFTP subsystem itself is
//!    unavailable; base64-encodes key material to avoid shell-quoting issues
//!    and stays compatible with `BusyBox` (`UniFi`, `OpenWRT`, pfSense, etc.).
//! 3. **Sudo** — operates on `/root/.ssh/authorized_keys` entirely inside a
//!    root `sudo sh -c` subshell so `/root/.ssh/authorized_keys` stays owned
//!    by `0:0` with mode `0600` (`StrictModes`-safe).
//!
//! Keys are matched by `(key_type, base64_blob)` ignoring leading
//! `authorized_keys` options and trailing comments.

use base64::Engine;

use crate::error::SshError;
use crate::ssh::remote::{RemoteFiles, RemoteShell};

/// Result of a push or revoke operation against a single host.
#[derive(Debug, serde::Serialize)]
pub struct PushResult {
    /// UUID string of the host the operation targeted.
    pub host_id: String,
    /// Human-readable host label, for display in results.
    pub host_label: String,
    /// Whether the operation completed successfully.
    pub success: bool,
    /// Success detail or failure reason.
    pub message: String,
}

/// Outcome of revoking a public key from a remote `authorized_keys` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeOutcome {
    /// At least one matching key entry was removed from `authorized_keys`.
    Removed,
    /// No matching key entry (or `authorized_keys` file) was present on the host.
    NotPresent,
}

/// Ask the remote for `$HOME`, falling back to `/root` when it's empty.
///
/// Validates that the returned path is a clean absolute Unix path containing
/// no shell metacharacters or control bytes.
async fn remote_home(shell: &dyn RemoteShell) -> Result<String, SshError> {
    let (_, home_out, _) = shell.exec("echo $HOME").await?;
    let home = home_out.trim().trim_end_matches('/');
    let resolved = if home.is_empty() { "/root" } else { home };
    if !resolved.starts_with('/')
        || resolved.contains("..")
        || !resolved
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return Err(SshError::ConnectionFailed {
            host: String::new(),
            reason: format!("unsafe remote $HOME path: {resolved:?}"),
        });
    }
    Ok(resolved.to_owned())
}

fn encode(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn is_ssh_key_type(token: &str) -> bool {
    !token.is_empty()
        && !token.contains(['=', ',', '"', '\''])
        && (token.starts_with("ssh-")
            || token.starts_with("ecdsa-sha2-")
            || token.starts_with("sk-ssh-")
            || token.starts_with("sk-ecdsa-"))
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '@' | '_'))
}

fn is_valid_base64_blob(blob: &str) -> bool {
    blob.len() >= 16
        && blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

/// Skip leading OpenSSH `authorized_keys` options (supporting quoted strings
/// with `\"` escapes) and return the remainder starting at the key type.
fn skip_authorized_keys_options(line: &str) -> Option<&str> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes {
            match ch {
                '\\' => escaped = true,
                '"' => in_quotes = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_quotes = true,
            ' ' | '\t' => return Some(line[idx..].trim_start_matches([' ', '\t'])),
            _ => {}
        }
    }
    None
}

/// Extract `(key_type, base64_blob)` from either a bare public key or an
/// `authorized_keys` line (ignoring comments and leading options).
pub fn parse_public_key_core(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let first_end = trimmed.find([' ', '\t']).unwrap_or(trimmed.len());
    let first_tok = &trimmed[..first_end];

    let key_part = if is_ssh_key_type(first_tok) {
        trimmed
    } else {
        skip_authorized_keys_options(trimmed)?
    };

    let mut fields = key_part.split([' ', '\t']).filter(|s| !s.is_empty());
    let key_type = fields.next()?;
    let blob = fields.next()?;
    if !is_ssh_key_type(key_type) || !is_valid_base64_blob(blob) {
        return None;
    }
    Some((key_type, blob))
}

fn validate_input_public_key(raw: &str) -> Result<(&str, &str, &str), String> {
    let pub_line = raw.trim();
    if pub_line.contains(['\n', '\r', '\0']) {
        return Err("public key must be a single line without control characters".into());
    }
    let (key_type, blob) = parse_public_key_core(pub_line).ok_or_else(|| {
        "invalid SSH public key format (expected '<type> <base64> [comment]')".to_owned()
    })?;
    // Ensure caller input starts directly with `<key_type> <blob>`, not attacker-injected options.
    if !pub_line.starts_with(key_type) {
        return Err("public key must not include authorized_keys options".into());
    }
    Ok((pub_line, key_type, blob))
}

fn line_matches_key(line: &str, key_type: &str, blob: &str) -> bool {
    parse_public_key_core(line).is_some_and(|(kt, kb)| kt == key_type && kb == blob)
}

async fn stage_and_replace_sftp(
    shell: &dyn RemoteShell,
    files: &dyn RemoteFiles,
    ssh_dir: &str,
    ak_path: &str,
    contents: &[u8],
) -> Result<(), String> {
    let tmp_path = format!(
        "{ssh_dir}/.authorized_keys.tmp.{}",
        uuid::Uuid::new_v4().simple()
    );
    files
        .write(&tmp_path, contents)
        .await
        .map_err(|e| format!("failed to stage {tmp_path}: {e}"))?;

    // Try SFTP rename first (works when authorized_keys does not yet exist or
    // server supports overwrite); fall back to POSIX `mv -f` so existing
    // `authorized_keys` files on standard SFTP v3 servers are atomically
    // replaced via rename(2) with mode 0600.
    if files.rename(&tmp_path, ak_path).await.is_err() {
        let cmd = format!("chmod 600 {tmp_path} && mv -f {tmp_path} {ak_path}");
        match shell.exec(&cmd).await {
            Ok((0, _, _)) => {}
            Ok((rc, _, stderr)) => {
                let _ = files.remove_file(&tmp_path).await;
                return Err(format!(
                    "atomic replace of {ak_path} failed (rc={rc}): {stderr}"
                ));
            }
            Err(e) => {
                let _ = files.remove_file(&tmp_path).await;
                return Err(format!("atomic replace of {ak_path} failed: {e}"));
            }
        }
    }

    let _ = shell.exec(&format!("chmod 700 {ssh_dir}")).await;
    let _ = shell.exec(&format!("chmod 600 {ak_path}")).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

/// Push a public key to a remote host's `authorized_keys`.
///
/// If `use_sudo` is true the key is written to `/root/.ssh/authorized_keys`
/// using `sudo` exec commands. Otherwise SFTP is attempted first, falling
/// back to exec **only** if the SFTP subsystem is unavailable.
///
/// Idempotent: a key whose `(key_type, base64_blob)` is already present is
/// left alone even if its comment differs.
pub async fn push_public_key(
    shell: &dyn RemoteShell,
    public_key: &str,
    use_sudo: bool,
) -> Result<(), SshError> {
    let (pub_line, key_type, blob) =
        validate_input_public_key(public_key).map_err(SshError::PushFailed)?;

    if use_sudo {
        push_with_sudo(shell, pub_line, key_type, blob).await
    } else {
        match shell.files().await {
            Ok(files) => push_via_sftp(shell, files.as_ref(), pub_line, key_type, blob).await,
            Err(_) => push_via_exec(shell, pub_line, key_type, blob).await,
        }
    }
}

/// Push using SFTP: read `authorized_keys` (`NoSuchFile` -> empty, other errors
/// abort), check for duplicates by key material, stage and atomically rename.
async fn push_via_sftp(
    shell: &dyn RemoteShell,
    files: &dyn RemoteFiles,
    pub_line: &str,
    key_type: &str,
    blob: &str,
) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    if !files.exists(&ssh_dir).await {
        files
            .create_dir(&ssh_dir)
            .await
            .map_err(|e| SshError::PushFailed(format!("failed to create {ssh_dir}: {e}")))?;
    }

    let existing = match files
        .read_optional(&ak_path)
        .await
        .map_err(|e| SshError::PushFailed(format!("failed to read {ak_path}: {e}")))?
    {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => String::new(),
    };

    if existing
        .lines()
        .any(|line| line_matches_key(line, key_type, blob))
    {
        return Ok(());
    }

    let mut updated = existing.trim_end_matches('\n').to_owned();
    if !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(pub_line);
    updated.push('\n');

    stage_and_replace_sftp(shell, files, &ssh_dir, &ak_path, updated.as_bytes())
        .await
        .map_err(SshError::PushFailed)
}

/// Push using shell commands only — no SFTP required.
///
/// Uses base64 encoding to safely transfer the key without shell-quoting
/// issues. Compatible with `BusyBox` (`UniFi`, `OpenWRT`, pfSense, etc.).
async fn push_via_exec(
    shell: &dyn RemoteShell,
    pub_line: &str,
    key_type: &str,
    blob: &str,
) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    let _ = shell
        .exec(&format!("mkdir -p {ssh_dir} && chmod 700 {ssh_dir}"))
        .await;
    let _ = shell
        .exec(&format!("touch {ak_path} && chmod 600 {ak_path}"))
        .await;

    let key_core_b64 = encode(&format!("{key_type} {blob}"));
    let check_cmd =
        format!("grep -qF \"$(printf '%s' {key_core_b64} | base64 -d)\" {ak_path} 2>/dev/null");
    let (rc, _, _) = shell.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(());
    }

    let full_b64 = encode(pub_line);
    let append_cmd =
        format!("printf '%s' {full_b64} | base64 -d >> {ak_path} && printf '\\n' >> {ak_path}");
    let (rc, _, stderr) = shell.exec(&append_cmd).await?;
    if rc != 0 {
        return Err(SshError::PushFailed(format!(
            "append failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

/// Push to `/root/.ssh/authorized_keys` using `sudo` exec commands.
async fn push_with_sudo(
    shell: &dyn RemoteShell,
    pub_line: &str,
    key_type: &str,
    blob: &str,
) -> Result<(), SshError> {
    let target_dir = "/root/.ssh";
    let target_file = "/root/.ssh/authorized_keys";

    let _ = shell
        .exec(&format!(
            "sudo mkdir -p {target_dir} && sudo chmod 700 {target_dir}"
        ))
        .await;
    let _ = shell
        .exec(&format!(
            "sudo touch {target_file} && sudo chmod 600 {target_file} && sudo chown 0:0 {target_file}"
        ))
        .await;

    let key_core_b64 = encode(&format!("{key_type} {blob}"));
    let check_cmd = format!(
        "sudo grep -qF \"$(printf '%s' {key_core_b64} | base64 -d)\" {target_file} 2>/dev/null"
    );
    let (rc, _, _) = shell.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(());
    }

    let full_b64 = encode(pub_line);
    let append_cmd = format!(
        "printf '%s\\n' \"$(printf '%s' {full_b64} | base64 -d)\" | sudo tee -a {target_file} > /dev/null"
    );
    let (rc, _, stderr) = shell.exec(&append_cmd).await?;
    if rc != 0 {
        return Err(SshError::PushFailed(format!(
            "sudo append failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

/// Revoke a public key from a remote host's `authorized_keys`.
///
/// Matches by `(key_type, base64_blob)` ignoring trailing comments and leading
/// `authorized_keys` options, and reports whether a matching key was actually
/// removed ([`RevokeOutcome::Removed`]) or already absent
/// ([`RevokeOutcome::NotPresent`]).
pub async fn revoke_public_key(
    shell: &dyn RemoteShell,
    public_key: &str,
    use_sudo: bool,
) -> Result<RevokeOutcome, SshError> {
    let (_pub_line, key_type, blob) =
        validate_input_public_key(public_key).map_err(SshError::RevokeFailed)?;

    if use_sudo {
        revoke_with_sudo(shell, key_type, blob).await
    } else {
        match shell.files().await {
            Ok(files) => revoke_via_sftp(shell, files.as_ref(), key_type, blob).await,
            Err(_) => revoke_via_exec(shell, key_type, blob).await,
        }
    }
}

/// Revoke using SFTP: read `authorized_keys`, filter matching keys, stage and
/// atomically rename.
async fn revoke_via_sftp(
    shell: &dyn RemoteShell,
    files: &dyn RemoteFiles,
    key_type: &str,
    blob: &str,
) -> Result<RevokeOutcome, SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    let Some(bytes) = files
        .read_optional(&ak_path)
        .await
        .map_err(|e| SshError::RevokeFailed(format!("failed to read {ak_path}: {e}")))?
    else {
        return Ok(RevokeOutcome::NotPresent);
    };
    let existing = String::from_utf8_lossy(&bytes).into_owned();

    let mut removed = false;
    let mut filtered = String::with_capacity(existing.len());
    for line in existing.lines() {
        if line_matches_key(line, key_type, blob) {
            removed = true;
        } else {
            filtered.push_str(line);
            filtered.push('\n');
        }
    }

    if !removed {
        return Ok(RevokeOutcome::NotPresent);
    }

    stage_and_replace_sftp(shell, files, &ssh_dir, &ak_path, filtered.as_bytes())
        .await
        .map_err(SshError::RevokeFailed)?;

    Ok(RevokeOutcome::Removed)
}

/// Revoke using shell commands only — `BusyBox`/Dropbear compatible.
///
/// Stages the filtered file inside `~/.ssh` (same filesystem, user-owned `0600`)
/// and treats `grep -vF` exit status `1` (last key removed -> 0 output lines)
/// as success.
async fn revoke_via_exec(
    shell: &dyn RemoteShell,
    key_type: &str,
    blob: &str,
) -> Result<RevokeOutcome, SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    let (rc, _, _) = shell.exec(&format!("test -f {ak_path}")).await?;
    if rc != 0 {
        return Ok(RevokeOutcome::NotPresent);
    }

    let b64 = encode(&format!("{key_type} {blob}"));

    let cmd = format!(
        "sh -c 'target=\"{ak_path}\"; \
         key=$(printf \"%s\" \"{b64}\" | base64 -d) || exit 2; \
         grep -F \"$key\" \"$target\" >/dev/null 2>&1 || exit 3; \
         umask 077; \
         tmp=$(mktemp \"{ssh_dir}/.ak_revoke_XXXXXX\") || exit 2; \
         trap \"rm -f \\\"$tmp\\\"\" EXIT; \
         {{ grep -vF \"$key\" \"$target\" > \"$tmp\" || [ $? -eq 1 ]; }} \
         && chmod 600 \"$tmp\" \
         && mv -f \"$tmp\" \"$target\"'"
    );
    let (rc, _, stderr) = shell.exec(&cmd).await?;
    match rc {
        0 => Ok(RevokeOutcome::Removed),
        3 => Ok(RevokeOutcome::NotPresent),
        _ => Err(SshError::RevokeFailed(format!(
            "revoke failed (rc={rc}): {stderr}"
        ))),
    }
}

/// Revoke from `/root/.ssh/authorized_keys` inside a single `sudo sh -c`
/// pipeline so the staged file is created in `/root/.ssh`, owned by `0:0`,
/// `chmod 600`'d before `mv`, and removing the final key (`grep` exit 1)
/// succeeds cleanly.
async fn revoke_with_sudo(
    shell: &dyn RemoteShell,
    key_type: &str,
    blob: &str,
) -> Result<RevokeOutcome, SshError> {
    let target_dir = "/root/.ssh";
    let target_file = "/root/.ssh/authorized_keys";

    let (rc, _, _) = shell.exec(&format!("sudo test -f {target_file}")).await?;
    if rc != 0 {
        return Ok(RevokeOutcome::NotPresent);
    }

    let b64 = encode(&format!("{key_type} {blob}"));

    let cmd = format!(
        "sudo sh -c 'target=\"{target_file}\"; \
         key=$(printf \"%s\" \"{b64}\" | base64 -d) || exit 2; \
         grep -F \"$key\" \"$target\" >/dev/null 2>&1 || exit 3; \
         umask 077; \
         tmp=$(mktemp \"{target_dir}/.ak_revoke_XXXXXX\") || exit 2; \
         trap \"rm -f \\\"$tmp\\\"\" EXIT; \
         {{ grep -vF \"$key\" \"$target\" > \"$tmp\" || [ $? -eq 1 ]; }} \
         && chown 0:0 \"$tmp\" \
         && chmod 600 \"$tmp\" \
         && mv -f \"$tmp\" \"$target\"'"
    );
    let (rc, _, stderr) = shell.exec(&cmd).await?;
    match rc {
        0 => Ok(RevokeOutcome::Removed),
        3 => Ok(RevokeOutcome::NotPresent),
        _ => Err(SshError::RevokeFailed(format!(
            "sudo revoke failed (rc={rc}): {stderr}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleKeyMaterial12345 admin@laptop";
    const KEY_CORE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleKeyMaterial12345";

    struct FakeShell {
        commands: Mutex<Vec<String>>,
        home: String,
        /// `Some` when the host offers a working SFTP subsystem.
        files: Option<FakeFiles>,
        /// Exit code for `grep -qF` duplicate checks (0 = key already there).
        grep_rc: u32,
        /// Exit code for `test -f` existence checks (0 = present).
        test_rc: u32,
        /// Exit code for revoke `sudo sh -c` / `sh -c` pipelines (0 = removed, 3 = absent).
        revoke_rc: u32,
    }

    impl FakeShell {
        fn exec_only() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                home: "/home/admin".to_owned(),
                files: None,
                grep_rc: 1,
                test_rc: 0,
                revoke_rc: 0,
            }
        }

        fn with_sftp(contents: &[(&str, &str)]) -> Self {
            let map = contents
                .iter()
                .map(|(p, c)| ((*p).to_owned(), (*c).as_bytes().to_vec()))
                .collect();
            Self {
                commands: Mutex::new(Vec::new()),
                home: "/home/admin".to_owned(),
                files: Some(FakeFiles {
                    files: Mutex::new(map),
                    fail_read: false,
                }),
                grep_rc: 1,
                test_rc: 0,
                revoke_rc: 0,
            }
        }

        fn issued(&self) -> Vec<String> {
            self.commands.lock().unwrap().clone()
        }

        fn issued_any(&self, needle: &str) -> bool {
            self.issued().iter().any(|c| c.contains(needle))
        }

        fn file(&self, path: &str) -> Option<String> {
            self.files
                .as_ref()
                .and_then(|f| f.files.lock().unwrap().get(path).cloned())
                .map(|b| String::from_utf8(b).unwrap())
        }
    }

    struct FakeFiles {
        files: Mutex<HashMap<String, Vec<u8>>>,
        fail_read: bool,
    }

    #[async_trait]
    impl RemoteFiles for &FakeFiles {
        async fn read(&self, path: &str) -> Result<Vec<u8>, SshError> {
            if self.fail_read {
                return Err(SshError::PushFailed("permission denied".into()));
            }
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| SshError::PushFailed("no such file".into()))
        }

        async fn read_optional(&self, path: &str) -> Result<Option<Vec<u8>>, SshError> {
            if self.fail_read {
                return Err(SshError::PushFailed("permission denied".into()));
            }
            Ok(self.files.lock().unwrap().get(path).cloned())
        }

        async fn write(&self, path: &str, contents: &[u8]) -> Result<(), SshError> {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), contents.to_vec());
            Ok(())
        }

        async fn rename(&self, from: &str, to: &str) -> Result<(), SshError> {
            let mut guard = self.files.lock().unwrap();
            let bytes = guard
                .remove(from)
                .ok_or_else(|| SshError::PushFailed("temp file missing".into()))?;
            guard.insert(to.to_owned(), bytes);
            Ok(())
        }

        async fn remove_file(&self, path: &str) -> Result<(), SshError> {
            self.files.lock().unwrap().remove(path);
            Ok(())
        }

        async fn create_dir(&self, path: &str) -> Result<(), SshError> {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), Vec::new());
            Ok(())
        }

        async fn exists(&self, path: &str) -> bool {
            self.files.lock().unwrap().contains_key(path)
        }
    }

    #[async_trait]
    impl RemoteShell for FakeShell {
        async fn exec(&self, command: &str) -> Result<(u32, String, String), SshError> {
            self.commands.lock().unwrap().push(command.to_owned());
            if command == "echo $HOME" {
                return Ok((0, format!("{}\n", self.home), String::new()));
            }
            if command.contains("grep -qF") {
                return Ok((self.grep_rc, String::new(), String::new()));
            }
            if command.contains("test -f") {
                return Ok((self.test_rc, String::new(), String::new()));
            }
            if command.contains("grep -vF") {
                return Ok((self.revoke_rc, String::new(), String::new()));
            }
            Ok((0, String::new(), String::new()))
        }

        async fn files(&self) -> Result<Box<dyn RemoteFiles + Send + Sync + '_>, SshError> {
            match self.files.as_ref() {
                Some(f) => Ok(Box::new(f)),
                None => Err(SshError::PushFailed("no sftp subsystem".into())),
            }
        }
    }

    // -- push ---------------------------------------------------------------

    #[tokio::test]
    async fn push_falls_back_to_exec_when_the_host_has_no_sftp() {
        let shell = FakeShell::exec_only();
        push_public_key(&shell, KEY, false).await.unwrap();
        assert!(shell.issued_any("base64 -d >>"), "expected an exec append");
    }

    #[tokio::test]
    async fn push_via_exec_never_puts_the_raw_key_in_a_shell_command() {
        let shell = FakeShell::exec_only();
        push_public_key(&shell, KEY, false).await.unwrap();
        for cmd in shell.issued() {
            assert!(
                !cmd.contains("ssh-ed25519 AAAA"),
                "raw key text leaked into a shell command: {cmd}"
            );
        }
        let full_b64 = encode(KEY);
        let core_b64 = encode(KEY_CORE);
        assert!(
            shell.issued_any(&full_b64) && shell.issued_any(&core_b64),
            "key should travel base64-encoded"
        );
    }

    #[tokio::test]
    async fn push_via_exec_skips_the_append_when_the_key_is_already_there() {
        let mut shell = FakeShell::exec_only();
        shell.grep_rc = 0;
        push_public_key(&shell, KEY, false).await.unwrap();
        assert!(
            !shell.issued_any("base64 -d >>"),
            "must not append a key that is already present"
        );
    }

    #[tokio::test]
    async fn push_via_sftp_appends_to_the_existing_file() {
        let shell = FakeShell::with_sftp(&[
            ("/home/admin/.ssh", ""),
            (
                "/home/admin/.ssh/authorized_keys",
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQother other@host\n",
            ),
        ]);
        push_public_key(&shell, KEY, false).await.unwrap();
        let written = shell.file("/home/admin/.ssh/authorized_keys").unwrap();
        assert_eq!(
            written,
            format!("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQother other@host\n{KEY}\n")
        );
    }

    #[tokio::test]
    async fn push_via_sftp_aborts_on_read_error_instead_of_truncating() {
        let mut shell = FakeShell::with_sftp(&[(
            "/home/admin/.ssh/authorized_keys",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQexisting keep@me\n",
        )]);
        shell.files.as_mut().unwrap().fail_read = true;
        let err = push_public_key(&shell, KEY, false).await.unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "SFTP read error must abort instead of wiping authorized_keys or falling back: {err}"
        );
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQexisting keep@me\n"
        );
        assert!(
            !shell.issued_any("base64 -d >>"),
            "must not fall back to exec when SFTP read fails"
        );
    }

    #[tokio::test]
    async fn push_via_sftp_is_idempotent_even_with_different_comment() {
        let existing = format!("{KEY_CORE} different-comment@workstation\n");
        let shell = FakeShell::with_sftp(&[
            ("/home/admin/.ssh", ""),
            ("/home/admin/.ssh/authorized_keys", &existing),
        ]);
        push_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            existing
        );
    }

    #[tokio::test]
    async fn push_via_sftp_creates_the_ssh_dir_when_missing() {
        let shell = FakeShell::with_sftp(&[]);
        push_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            format!("{KEY}\n")
        );
        assert!(shell.issued_any("chmod 700 /home/admin/.ssh"));
        assert!(shell.issued_any("chmod 600 /home/admin/.ssh/authorized_keys"));
    }

    #[tokio::test]
    async fn push_with_sudo_targets_root_not_the_login_user() {
        let shell = FakeShell::exec_only();
        push_public_key(&shell, KEY, true).await.unwrap();
        assert!(shell.issued_any("sudo mkdir -p /root/.ssh"));
        assert!(shell.issued_any("sudo tee -a /root/.ssh/authorized_keys"));
        assert!(
            !shell.issued_any("/home/admin"),
            "sudo mode must not touch the login user's authorized_keys"
        );
    }

    #[tokio::test]
    async fn empty_remote_home_falls_back_to_root() {
        let mut shell = FakeShell::exec_only();
        shell.home = String::new();
        push_public_key(&shell, KEY, false).await.unwrap();
        assert!(shell.issued_any("/root/.ssh/authorized_keys"));
    }

    #[tokio::test]
    async fn push_surfaces_a_failing_append() {
        struct Failing;
        #[async_trait]
        impl RemoteShell for Failing {
            async fn exec(&self, command: &str) -> Result<(u32, String, String), SshError> {
                if command.contains("base64 -d >>") {
                    return Ok((1, String::new(), "Read-only file system".into()));
                }
                if command.contains("grep -qF") {
                    return Ok((1, String::new(), String::new()));
                }
                Ok((0, "/home/admin\n".into(), String::new()))
            }
            async fn files(&self) -> Result<Box<dyn RemoteFiles + Send + Sync + '_>, SshError> {
                Err(SshError::PushFailed("no sftp".into()))
            }
        }
        let err = push_public_key(&Failing, KEY, false).await.unwrap_err();
        assert!(
            err.to_string().contains("Read-only file system"),
            "the remote's stderr should reach the operator, got: {err}"
        );
    }

    // -- revoke -------------------------------------------------------------

    #[tokio::test]
    async fn revoke_via_sftp_removes_matching_key_regardless_of_comment_or_options() {
        let existing = format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQkeep1 keep@me\n\
             from=\"10.0.0.0/8\",command=\"/bin/true\" {KEY_CORE} renamed@host\n\
             ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQkeep2 keep@too\n"
        );
        let shell = FakeShell::with_sftp(&[("/home/admin/.ssh/authorized_keys", &existing)]);
        let outcome = revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(outcome, RevokeOutcome::Removed);
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQkeep1 keep@me\n\
             ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQkeep2 keep@too\n"
        );
    }

    #[tokio::test]
    async fn revoke_via_sftp_reports_not_present_when_key_is_absent() {
        let existing = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQother someone@else\n";
        let shell = FakeShell::with_sftp(&[("/home/admin/.ssh/authorized_keys", existing)]);
        let outcome = revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(outcome, RevokeOutcome::NotPresent);
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            existing
        );
    }

    #[tokio::test]
    async fn revoke_reports_not_present_when_authorized_keys_does_not_exist() {
        let mut shell = FakeShell::exec_only();
        shell.test_rc = 1;
        let outcome = revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(outcome, RevokeOutcome::NotPresent);
        assert!(!shell.issued_any("mktemp"), "nothing to rewrite");
    }

    #[tokio::test]
    async fn revoke_via_exec_stages_in_ssh_dir_and_tolerates_last_key_removal() {
        let shell = FakeShell::exec_only();
        let outcome = revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(outcome, RevokeOutcome::Removed);
        let rewrite = shell
            .issued()
            .into_iter()
            .find(|c| c.contains("grep -vF"))
            .expect("expected a filtering rewrite");
        assert!(
            rewrite.contains("mktemp \"/home/admin/.ssh/.ak_revoke_XXXXXX\""),
            "should stage inside ~/.ssh: {rewrite}"
        );
        assert!(
            rewrite.contains("|| [ $? -eq 1 ]"),
            "removing the final key makes grep exit 1 and must still succeed: {rewrite}"
        );
        assert!(
            rewrite.contains("&& mv -f "),
            "should move over the original"
        );
    }

    #[tokio::test]
    async fn revoke_with_sudo_runs_inside_root_shell_and_chowns_before_mv() {
        let shell = FakeShell::exec_only();
        let outcome = revoke_public_key(&shell, KEY, true).await.unwrap();
        assert_eq!(outcome, RevokeOutcome::Removed);
        let rewrite = shell
            .issued()
            .into_iter()
            .find(|c| c.contains("grep -vF"))
            .expect("expected a filtering rewrite");
        assert!(
            rewrite.starts_with("sudo sh -c "),
            "entire pipeline must run as root: {rewrite}"
        );
        assert!(
            rewrite.contains("mktemp \"/root/.ssh/.ak_revoke_XXXXXX\""),
            "temp file must be created in /root/.ssh, never /tmp: {rewrite}"
        );
        assert!(
            rewrite.contains("chown 0:0 \"$tmp\" && chmod 600 \"$tmp\" && mv -f"),
            "must enforce root ownership + 0600 before mv for StrictModes: {rewrite}"
        );
        assert!(rewrite.contains("|| [ $? -eq 1 ]"));
    }

    #[tokio::test]
    async fn revoke_via_exec_never_puts_the_raw_key_in_a_shell_command() {
        let shell = FakeShell::exec_only();
        revoke_public_key(&shell, KEY, false).await.unwrap();
        for cmd in shell.issued() {
            assert!(
                !cmd.contains("ssh-ed25519 AAAA"),
                "raw key text leaked into a shell command: {cmd}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_or_multiline_public_key_is_rejected() {
        let shell = FakeShell::exec_only();
        assert!(push_public_key(&shell, "", false).await.is_err());
        assert!(revoke_public_key(&shell, "", true).await.is_err());
        assert!(
            push_public_key(&shell, &format!("{KEY}\nssh-ed25519 AAAAB3extra"), false)
                .await
                .is_err()
        );
    }
}
