//! Push and revoke public keys in a remote host's `authorized_keys`.
//!
//! Both operations use the same three strategies, in the same order:
//!
//! 1. **SFTP** (preferred) — read the file, edit it, write it back.
//! 2. **Exec fallback** — base64-encode the key to avoid shell-quoting
//!    issues; compatible with BusyBox (UniFi, OpenWRT, pfSense, etc.).
//! 3. **Sudo** — operate on `/root/.ssh/authorized_keys` via `sudo`.
//!
//! Everything here runs against the [`RemoteShell`] trait rather than a
//! concrete session type, so `supermgrd` and `supermgr-engine` share one
//! copy — they previously carried identical files that had no test coverage
//! between them and only luck keeping them in step.

use base64::Engine;

use crate::error::SshError;
use crate::ssh::remote::RemoteShell;

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

/// Ask the remote for `$HOME`, falling back to `/root` when it's empty.
///
/// Appliance shells sometimes return nothing here; `/root` is the right
/// guess for the network gear this tool manages.
async fn remote_home(shell: &dyn RemoteShell) -> Result<String, SshError> {
    let (_, home_out, _) = shell.exec("echo $HOME").await?;
    let home = home_out.trim();
    Ok(if home.is_empty() {
        "/root".to_owned()
    } else {
        home.to_owned()
    })
}

fn encode(pub_line: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(pub_line.as_bytes())
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

/// Push a public key to a remote host's `authorized_keys`.
///
/// If `use_sudo` is true the key is written to `/root/.ssh/authorized_keys`
/// using `sudo` exec commands. Otherwise SFTP is attempted first, falling
/// back to exec if the SFTP subsystem is unavailable.
///
/// Idempotent: a key already present is left alone.
pub async fn push_public_key(
    shell: &dyn RemoteShell,
    public_key: &str,
    use_sudo: bool,
) -> Result<(), SshError> {
    let pub_line = public_key.trim();

    if use_sudo {
        push_with_sudo(shell, pub_line).await
    } else {
        match push_via_sftp(shell, pub_line).await {
            Ok(()) => Ok(()),
            Err(_) => push_via_exec(shell, pub_line).await,
        }
    }
}

/// Push using SFTP: read `authorized_keys`, check for duplicates, append.
async fn push_via_sftp(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    let files = shell
        .files()
        .await
        .map_err(|e| SshError::PushFailed(format!("SFTP not available: {e}")))?;

    // Ensure ~/.ssh exists.
    if !files.exists(&ssh_dir).await {
        files
            .create_dir(&ssh_dir)
            .await
            .map_err(|e| SshError::PushFailed(format!("failed to create {ssh_dir}: {e}")))?;
    }

    // Read existing authorized_keys (empty if absent).
    let existing = match files.read(&ak_path).await {
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

    files
        .write(&ak_path, updated.as_bytes())
        .await
        .map_err(|e| SshError::PushFailed(format!("failed to write {ak_path}: {e}")))?;

    // Set permissions (best-effort, ignore errors from broken SFTP servers).
    let _ = shell.exec(&format!("chmod 700 {ssh_dir}")).await;
    let _ = shell.exec(&format!("chmod 600 {ak_path}")).await;

    Ok(())
}

/// Push using shell commands only — no SFTP required.
///
/// Uses base64 encoding to safely transfer the key without shell-quoting
/// issues. Compatible with BusyBox (UniFi, OpenWRT, pfSense, etc.).
async fn push_via_exec(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ssh_dir = format!("{home}/.ssh");
    let ak_path = format!("{ssh_dir}/authorized_keys");

    // Ensure directory and file exist with correct permissions.
    let _ = shell
        .exec(&format!("mkdir -p {ssh_dir} && chmod 700 {ssh_dir}"))
        .await;
    let _ = shell
        .exec(&format!("touch {ak_path} && chmod 600 {ak_path}"))
        .await;

    let b64 = encode(pub_line);

    // Check for duplicate.
    let check_cmd =
        format!("grep -qF \"$(printf '%s' {b64} | base64 -d)\" {ak_path} 2>/dev/null");
    let (rc, _, _) = shell.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(()); // Already present.
    }

    // Append via base64 decode.
    let append_cmd = format!("printf '%s\\n' {b64} | base64 -d >> {ak_path}");
    let (rc, _, stderr) = shell.exec(&append_cmd).await?;
    if rc != 0 {
        return Err(SshError::PushFailed(format!(
            "append failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

/// Push to `/root/.ssh/authorized_keys` using `sudo` exec commands.
async fn push_with_sudo(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let target_dir = "/root/.ssh";
    let target_file = "/root/.ssh/authorized_keys";

    // Ensure directory and file.
    let _ = shell
        .exec(&format!(
            "sudo mkdir -p {target_dir} && sudo chmod 700 {target_dir}"
        ))
        .await;
    let _ = shell
        .exec(&format!(
            "sudo touch {target_file} && sudo chmod 600 {target_file}"
        ))
        .await;

    let b64 = encode(pub_line);

    // Check for duplicate.
    let check_cmd =
        format!("sudo grep -qF \"$(echo {b64} | base64 -d)\" {target_file} 2>/dev/null");
    let (rc, _, _) = shell.exec(&check_cmd).await?;
    if rc == 0 {
        return Ok(()); // Already present.
    }

    // Append via base64.
    let append_cmd = format!("echo {b64} | base64 -d | sudo tee -a {target_file} > /dev/null");
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
/// Returns `Ok(())` even if the key was not present (idempotent).
///
/// If `use_sudo` is true, operates on `/root/.ssh/authorized_keys` using
/// `sudo` exec commands. Otherwise SFTP is attempted first, falling back
/// to exec if the SFTP subsystem is unavailable.
pub async fn revoke_public_key(
    shell: &dyn RemoteShell,
    public_key: &str,
    use_sudo: bool,
) -> Result<(), SshError> {
    let pub_line = public_key.trim();

    if use_sudo {
        revoke_with_sudo(shell, pub_line).await
    } else {
        match revoke_via_sftp(shell, pub_line).await {
            Ok(()) => Ok(()),
            Err(_) => revoke_via_exec(shell, pub_line).await,
        }
    }
}

/// Revoke using SFTP: read `authorized_keys`, filter matching lines, rewrite.
async fn revoke_via_sftp(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ak_path = format!("{home}/.ssh/authorized_keys");

    let files = shell
        .files()
        .await
        .map_err(|e| SshError::RevokeFailed(format!("SFTP not available: {e}")))?;

    // Read existing authorized_keys.
    let existing = match files.read(&ak_path).await {
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

    files
        .write(&ak_path, filtered.as_bytes())
        .await
        .map_err(|e| SshError::RevokeFailed(format!("failed to write {ak_path}: {e}")))?;

    // Fix permissions (best-effort).
    let _ = shell.exec(&format!("chmod 600 {ak_path}")).await;

    Ok(())
}

/// Revoke using shell commands only — `BusyBox`/Dropbear compatible.
///
/// Uses `grep -vF` with a base64-encoded key to avoid shell-quoting issues.
async fn revoke_via_exec(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let home = remote_home(shell).await?;
    let ak_path = format!("{home}/.ssh/authorized_keys");

    // Check if file exists.
    let (rc, _, _) = shell.exec(&format!("test -f {ak_path}")).await?;
    if rc != 0 {
        return Ok(()); // File absent — nothing to revoke.
    }

    let b64 = encode(pub_line);

    // Use a temporary file to atomically replace the authorized_keys.
    let cmd = format!(
        "tmp=$(mktemp /tmp/.ak_revoke_XXXXXX) && \
         grep -vF \"$(printf '%s' {b64} | base64 -d)\" {ak_path} > \"$tmp\" \
         && mv \"$tmp\" {ak_path} && chmod 600 {ak_path}"
    );
    let (rc, _, stderr) = shell.exec(&cmd).await?;
    if rc != 0 {
        return Err(SshError::RevokeFailed(format!(
            "revoke failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
}

/// Revoke from `/root/.ssh/authorized_keys` via `sudo`.
async fn revoke_with_sudo(shell: &dyn RemoteShell, pub_line: &str) -> Result<(), SshError> {
    let target_file = "/root/.ssh/authorized_keys";

    // Check if file exists.
    let (rc, _, _) = shell.exec(&format!("sudo test -f {target_file}")).await?;
    if rc != 0 {
        return Ok(()); // File absent — nothing to revoke.
    }

    let b64 = encode(pub_line);

    // Use a temporary file to atomically replace the authorized_keys.
    let cmd = format!(
        "tmp=$(mktemp /tmp/.ak_revoke_XXXXXX) && \
         sudo grep -vF \"$(printf '%s' {b64} | base64 -d)\" {target_file} > \"$tmp\" \
         && sudo mv \"$tmp\" {target_file} && sudo chmod 600 {target_file}"
    );
    let (rc, _, stderr) = shell.exec(&cmd).await?;
    if rc != 0 {
        return Err(SshError::RevokeFailed(format!(
            "sudo revoke failed (rc={rc}): {stderr}"
        )));
    }

    Ok(())
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
    use crate::ssh::remote::RemoteFiles;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample admin@laptop";

    /// A remote host that records every command it is asked to run.
    ///
    /// These tests are about the *wire behaviour*: which commands go to a
    /// customer's firewall, in what order, with the key encoded how. That
    /// is the part that breaks appliances when it changes, and it was
    /// entirely uncovered before this module was shared.
    struct FakeShell {
        commands: Mutex<Vec<String>>,
        home: String,
        /// `Some` when the host offers a working SFTP subsystem.
        files: Option<FakeFiles>,
        /// Exit code for `grep -qF` duplicate checks (0 = key already there).
        grep_rc: u32,
        /// Exit code for `test -f` existence checks (0 = present).
        test_rc: u32,
    }

    impl FakeShell {
        fn exec_only() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                home: "/home/admin".to_owned(),
                files: None,
                grep_rc: 1,
                test_rc: 0,
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
                }),
                grep_rc: 1,
                test_rc: 0,
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
    }

    #[async_trait]
    impl RemoteFiles for &FakeFiles {
        async fn read(&self, path: &str) -> Result<Vec<u8>, SshError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| SshError::PushFailed("no such file".into()))
        }
        async fn write(&self, path: &str, contents: &[u8]) -> Result<(), SshError> {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), contents.to_vec());
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
        // Dropbear on a switch: SFTP unavailable, and giving up would mean
        // the whole feature fails on exactly the devices it was built for.
        let shell = FakeShell::exec_only();
        push_public_key(&shell, KEY, false).await.unwrap();
        assert!(shell.issued_any("base64 -d >>"), "expected an exec append");
    }

    #[tokio::test]
    async fn push_via_exec_never_puts_the_raw_key_in_a_shell_command() {
        // The whole point of the base64 round-trip: a key comment
        // containing a quote or a backtick must not reach the remote
        // shell as syntax.
        let shell = FakeShell::exec_only();
        push_public_key(&shell, KEY, false).await.unwrap();
        for cmd in shell.issued() {
            assert!(
                !cmd.contains("ssh-ed25519 AAAA"),
                "raw key text leaked into a shell command: {cmd}"
            );
        }
        let b64 = encode(KEY);
        assert!(shell.issued_any(&b64), "key should travel base64-encoded");
    }

    #[tokio::test]
    async fn push_via_exec_skips_the_append_when_the_key_is_already_there() {
        let mut shell = FakeShell::exec_only();
        shell.grep_rc = 0; // grep found it
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
            ("/home/admin/.ssh/authorized_keys", "ssh-rsa AAAAB3 other@host\n"),
        ]);
        push_public_key(&shell, KEY, false).await.unwrap();
        let written = shell.file("/home/admin/.ssh/authorized_keys").unwrap();
        assert_eq!(written, format!("ssh-rsa AAAAB3 other@host\n{KEY}\n"));
    }

    #[tokio::test]
    async fn push_via_sftp_is_idempotent() {
        let existing = format!("{KEY}\n");
        let shell = FakeShell::with_sftp(&[
            ("/home/admin/.ssh", ""),
            ("/home/admin/.ssh/authorized_keys", &existing),
        ]);
        push_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(shell.file("/home/admin/.ssh/authorized_keys").unwrap(), existing);
    }

    #[tokio::test]
    async fn push_via_sftp_creates_the_ssh_dir_when_missing() {
        let shell = FakeShell::with_sftp(&[]);
        push_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(shell.file("/home/admin/.ssh/authorized_keys").unwrap(), format!("{KEY}\n"));
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
        // Appliance shells that print nothing for $HOME must not produce
        // paths like "/.ssh/authorized_keys".
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
    async fn revoke_via_sftp_removes_only_the_matching_line() {
        let existing = format!("ssh-rsa AAAAB3 keep@me\n{KEY}\nssh-rsa AAAAB3 keep@too\n");
        let shell = FakeShell::with_sftp(&[("/home/admin/.ssh/authorized_keys", &existing)]);
        revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(
            shell.file("/home/admin/.ssh/authorized_keys").unwrap(),
            "ssh-rsa AAAAB3 keep@me\nssh-rsa AAAAB3 keep@too\n"
        );
    }

    #[tokio::test]
    async fn revoke_via_sftp_leaves_the_file_alone_when_the_key_is_absent() {
        let existing = "ssh-rsa AAAAB3 someone@else\n";
        let shell = FakeShell::with_sftp(&[("/home/admin/.ssh/authorized_keys", existing)]);
        revoke_public_key(&shell, KEY, false).await.unwrap();
        assert_eq!(shell.file("/home/admin/.ssh/authorized_keys").unwrap(), existing);
    }

    #[tokio::test]
    async fn revoke_is_ok_when_authorized_keys_does_not_exist() {
        // Revoking from a host that never had the key is a no-op, not a
        // failure — batch revoke across a fleet depends on this.
        let mut shell = FakeShell::exec_only();
        shell.test_rc = 1; // test -f says no
        revoke_public_key(&shell, KEY, false).await.unwrap();
        assert!(!shell.issued_any("mktemp"), "nothing to rewrite");
    }

    #[tokio::test]
    async fn revoke_via_exec_rewrites_through_a_temp_file() {
        // Writing authorized_keys in place would leave a host with a
        // truncated file — and no way in — if the link drops mid-write.
        let shell = FakeShell::exec_only();
        revoke_public_key(&shell, KEY, false).await.unwrap();
        let rewrite = shell
            .issued()
            .into_iter()
            .find(|c| c.contains("grep -vF"))
            .expect("expected a filtering rewrite");
        assert!(rewrite.contains("mktemp"), "should stage in a temp file");
        assert!(rewrite.contains("&& mv "), "should move over the original");
    }

    #[tokio::test]
    async fn revoke_with_sudo_targets_root_and_stages_in_a_temp_file() {
        let shell = FakeShell::exec_only();
        revoke_public_key(&shell, KEY, true).await.unwrap();
        let rewrite = shell
            .issued()
            .into_iter()
            .find(|c| c.contains("grep -vF"))
            .expect("expected a filtering rewrite");
        assert!(rewrite.contains("sudo mv "));
        assert!(rewrite.contains("/root/.ssh/authorized_keys"));
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
}
