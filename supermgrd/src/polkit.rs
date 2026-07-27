//! Caller authorization for the D-Bus interface.
//!
//! # Why this exists
//!
//! `supermgrd` runs as root on the **system** bus, and its bus policy lets
//! any local user send it messages — that is the normal arrangement for a
//! system service, because the unprivileged GUI has to be able to reach it.
//! What was missing is the other half: the daemon never asked *who* was
//! calling. Every method was reachable by every local account, including
//! the ones that hand back SSH private keys, stored host passwords, and a
//! full secret export.
//!
//! Polkit is the mechanism Linux provides for exactly this shape of
//! problem — a privileged service deciding whether an unprivileged caller
//! may perform a named action, with the desktop's authentication agent
//! prompting when a decision needs a human. It is what NetworkManager,
//! systemd and PackageKit use for the same reason.
//!
//! # Failure posture
//!
//! Authorization **fails closed**. If polkit is not installed, not running,
//! or cannot be reached, the call is denied rather than allowed. A security
//! check that evaporates when its dependency is missing is not a security
//! check. This makes polkit a runtime dependency of the guarded methods —
//! see `contrib/polkit/org.supermgr.Daemon.policy` and the install steps in
//! the README.

use std::collections::HashMap;

use zbus::message::Header;
use zbus::zvariant::Value;
use zbus::{fdo, Connection};

/// Read secret material: private keys, stored passwords, full backups.
///
/// Held at `auth_admin` in the shipped policy — administrator
/// authentication every time, with no "remember this" grace period,
/// because each grant discloses long-lived credentials.
pub const ACTION_SECRETS: &str = "org.supermgr.daemon.secrets";

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority",
    gen_blocking = false
)]
trait Authority {
    /// `CheckAuthorization(subject, action_id, details, flags, cancellation_id)`
    /// returns `(is_authorized, is_challenge, details)`.
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

/// Let polkit's authentication agent prompt the user if the action needs it.
const ALLOW_USER_INTERACTION: u32 = 1;

/// Authorize the sender of `header` for `action`, or return `AccessDenied`.
///
/// # Errors
///
/// `AccessDenied` when the caller is not authorized, when the message has
/// no sender to identify, or when polkit cannot be consulted at all.
pub async fn authorize(
    connection: &Connection,
    header: &Header<'_>,
    action: &str,
) -> fdo::Result<()> {
    let Some(sender) = header.sender() else {
        // Every message on a bus connection carries a sender; one that
        // doesn't is not something to guess about.
        return Err(fdo::Error::AccessDenied(
            "refusing an unidentified caller".to_owned(),
        ));
    };

    let authority = AuthorityProxy::new(connection).await.map_err(|e| {
        tracing::error!(error = %e, "polkit unreachable — denying");
        fdo::Error::AccessDenied(format!(
            "cannot reach polkit to authorize '{action}': {e}. \
             This operation requires polkit; install it and retry."
        ))
    })?;

    // Identify the caller by its unique bus name. Polkit resolves that to
    // a uid itself, so we never trust a caller's claim about who it is.
    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("name", Value::from(sender.as_str()));
    let subject = ("system-bus-name", subject_details);

    let (authorized, challenge, _details) = authority
        .check_authorization(
            &subject,
            action,
            HashMap::new(),
            ALLOW_USER_INTERACTION,
            "",
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, action, "polkit check failed — denying");
            fdo::Error::AccessDenied(format!("polkit refused to decide '{action}': {e}"))
        })?;

    if authorized {
        tracing::info!(caller = %sender, action, "authorized");
        return Ok(());
    }

    // `challenge` means the user could have authenticated but didn't —
    // dismissed the prompt, or no agent was running to show one. Worth
    // distinguishing in the message, because the remedies differ.
    tracing::warn!(caller = %sender, action, challenge, "denied");
    Err(fdo::Error::AccessDenied(if challenge {
        format!("'{action}' needs administrator authentication, which was not completed")
    } else {
        format!("'{action}' is not permitted for this user")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_action_matches_the_shipped_policy_file() {
        // The daemon and the .policy file have to agree on the action id
        // or polkit silently has no rule to apply — and a missing rule is
        // an implicit deny that looks like a bug, not a policy.
        let policy = include_str!("../../contrib/polkit/org.supermgr.Daemon.policy");
        assert!(
            policy.contains(&format!("action id=\"{ACTION_SECRETS}\"")),
            "{ACTION_SECRETS} is not declared in the polkit policy file"
        );
    }

    /// The `<defaults>` block for `action`, with surrounding prose and
    /// XML comments excluded — the comments discuss the very strings
    /// these assertions look for, so slicing to `</action>` would match
    /// documentation instead of policy.
    fn defaults_block(policy: &str, action: &str) -> String {
        let after_action = policy
            .split(&format!("action id=\"{action}\""))
            .nth(1)
            .expect("action present in policy file");
        after_action
            .split("<defaults>")
            .nth(1)
            .expect("action has a defaults block")
            .split("</defaults>")
            .next()
            .expect("defaults block is closed")
            .to_owned()
    }

    #[test]
    fn secret_action_requires_auth_every_time() {
        // `auth_admin_keep` would cache the grant for the rest of the
        // session. For credential disclosure we want a prompt each time,
        // so a single authorization can't be replayed silently.
        let policy = include_str!("../../contrib/polkit/org.supermgr.Daemon.policy");
        let defaults = defaults_block(policy, ACTION_SECRETS);
        assert!(
            defaults.contains("<allow_active>auth_admin</allow_active>"),
            "expected auth_admin for the secrets action, got: {defaults}"
        );
        assert!(
            !defaults.contains("auth_admin_keep"),
            "auth_admin_keep would let one grant cover later secret reads"
        );
    }

    #[test]
    fn inactive_and_remote_sessions_are_refused_outright() {
        let policy = include_str!("../../contrib/polkit/org.supermgr.Daemon.policy");
        let defaults = defaults_block(policy, ACTION_SECRETS);
        assert!(
            defaults.contains("<allow_any>no</allow_any>"),
            "a remote or inactive session must not be able to read secrets"
        );
        assert!(defaults.contains("<allow_inactive>no</allow_inactive>"));
    }
}
