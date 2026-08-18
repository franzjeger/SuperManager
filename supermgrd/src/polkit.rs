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
//! prompting when a decision needs a human. It is what `NetworkManager`,
//! systemd and `PackageKit` use for the same reason.
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

/// Open an SSH session to a managed host.
///
/// Held at `auth_admin_keep`: one authentication, then a grace period
/// covering the rest of the session.
///
/// # Why not `ACTION_SECRETS`
///
/// `SshConnectCommand` discloses the same material `SshExportPrivateKey`
/// does — it stages the host's password or private key on disk for the
/// caller's `ssh` to read. By that measure it belongs behind the same
/// action, and for a while it was behind nothing at all, which is how a
/// caller refused by `SshExportPrivateKey` could get the key anyway.
///
/// But it is also the Connect button. `auth_admin` means a password
/// prompt for every SSH session an operator opens, all day. A control
/// that makes the tool unusable gets switched off, and a policy file
/// deleted in irritation protects nothing — so the honest classification
/// by disclosure loses to the one people will actually keep.
///
/// `auth_admin_keep` is the compromise, and it is a real one: within the
/// grace period a second caller on the same session is not asked again.
/// What it buys is that an unprivileged account cannot silently harvest
/// credentials for every managed host — somebody has to authenticate
/// once, and the prompt names what is being asked for.
pub const ACTION_SSH_CONNECT: &str = "org.supermgr.daemon.ssh-connect";

/// Selecting or clearing a Tailscale exit node.
///
/// Gated, even though `connect` (bring up a VPN profile) is not, and the
/// difference is worth stating rather than leaving as an inconsistency.
///
/// The bus policy lets **any** local account talk to this daemon —
/// `context="default"` with a bare `allow send_destination`. An exit node
/// routes every packet this machine sends through a host of the caller's
/// choosing, so ungated it would let any local user silently redirect
/// another user's traffic through a machine they control. That is a
/// different shape of problem from starting a VPN the admin already
/// configured, and the direction this daemon has been moving is to gate
/// exactly that kind of surface once it is noticed rather than to match the
/// loosest existing precedent.
///
/// `auth_admin_keep` for the same reason as SSH connect: the operator
/// comparing two exit nodes would otherwise authenticate on every attempt,
/// and a control that irritating gets worked around.
pub const ACTION_TAILSCALE_EXIT_NODE: &str = "org.supermgr.daemon.tailscale-exit-node";

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

    const POLICY: &str = include_str!("../../contrib/polkit/org.supermgr.Daemon.policy");

    /// Every action the daemon can ask polkit about.
    ///
    /// Adding a constant above without adding it here leaves the new action
    /// unchecked, so keep the two in step — the assertions below are the
    /// only thing standing between a typo and a method that denies
    /// everybody for a reason nobody can see.
    const ALL_ACTIONS: &[&str] =
        &[ACTION_SECRETS, ACTION_SSH_CONNECT, ACTION_TAILSCALE_EXIT_NODE];

    #[test]
    fn every_action_the_daemon_uses_is_declared_in_the_policy_file() {
        // The daemon and the .policy file have to agree on the action id
        // or polkit silently has no rule to apply — and a missing rule is
        // an implicit deny that looks like a bug, not a policy.
        for action in ALL_ACTIONS {
            assert!(
                POLICY.contains(&format!("action id=\"{action}\"")),
                "{action} is not declared in the polkit policy file"
            );
        }
    }

    #[test]
    fn the_actions_are_distinct() {
        // Two constants resolving to one id would silently apply one
        // action's authentication level to the other's methods.
        let mut seen = std::collections::HashSet::new();
        for action in ALL_ACTIONS {
            assert!(seen.insert(*action), "duplicate action id: {action}");
        }
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
        let defaults = defaults_block(POLICY, ACTION_SECRETS);
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
    fn ssh_connect_asks_once_per_session_rather_than_never_or_every_time() {
        // The deliberate compromise, so it should fail if someone drifts it
        // either way: `yes` would be no authentication at all, `auth_admin`
        // would put a password prompt on the Connect button and get the
        // policy file deleted.
        let defaults = defaults_block(POLICY, ACTION_SSH_CONNECT);
        assert!(
            defaults.contains("<allow_active>auth_admin_keep</allow_active>"),
            "expected auth_admin_keep for the ssh-connect action, got: {defaults}"
        );
    }

    #[test]
    fn no_action_is_granted_without_authentication() {
        // `yes` anywhere in a defaults block means that method is open to
        // whoever can reach the bus, which is every local account.
        for action in ALL_ACTIONS {
            let defaults = defaults_block(POLICY, action);
            for line in defaults.lines() {
                let line = line.trim();
                assert!(
                    !line.contains(">yes<"),
                    "{action} grants without authentication: {line}"
                );
            }
        }
    }

    #[test]
    fn inactive_and_remote_sessions_are_refused_outright() {
        // Neither reading a stored credential nor opening a session with
        // one is for a remote or switched-away seat.
        for action in ALL_ACTIONS {
            let defaults = defaults_block(POLICY, action);
            assert!(
                defaults.contains("<allow_any>no</allow_any>"),
                "{action} is reachable from a remote session: {defaults}"
            );
            assert!(
                defaults.contains("<allow_inactive>no</allow_inactive>"),
                "{action} is reachable from an inactive session: {defaults}"
            );
        }
    }

    /// `ssh_connect_command` consults polkit.
    ///
    /// The policy file being right is no use if the method never asks — and
    /// "the rule exists but the call site ignores it" is the shape of the
    /// bug this whole action was added to fix. There is no way to exercise
    /// the real path here: it needs a system bus, a polkit daemon, and a
    /// host to connect to. So this reads the source, bounded to the
    /// function, and checks the guard is still in it.
    ///
    /// Comments are stripped before searching. The guard carries a comment
    /// naming the action, so a search over the raw text passes just as
    /// happily with the code deleted and the explanation left behind —
    /// verified by removing the line and watching the first version of this
    /// test stay green.
    #[test]
    fn ssh_connect_command_is_gated() {
        let daemon = include_str!("daemon.rs");
        let body: String = daemon
            .split("async fn ssh_connect_command")
            .nth(1)
            .expect("ssh_connect_command exists")
            // The next method's doc comment ends this one's body. Bounding
            // it matters: without it the search would happily find some
            // other method's guard and pass.
            .split("\n    /// ")
            .next()
            .expect("something follows ssh_connect_command")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            body.contains("authorize(conn, &hdr, crate::polkit::ACTION_SSH_CONNECT)"),
            "ssh_connect_command no longer authorizes against {ACTION_SSH_CONNECT}. \
             It stages the host's password or private key on disk; ungated, a caller \
             refused by {ACTION_SECRETS} can come here for the same material instead."
        );
    }

    /// Same shape as the test above, and the same reason for the shape:
    /// comments are stripped so a deleted guard with its explanation left
    /// behind still fails.
    #[test]
    fn tailscale_set_exit_node_is_gated() {
        let daemon = include_str!("daemon.rs");
        let body: String = daemon
            .split("async fn tailscale_set_exit_node")
            .nth(1)
            .expect("tailscale_set_exit_node exists")
            .split("\n    /// ")
            .next()
            .expect("something follows tailscale_set_exit_node")
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            body.contains("authorize(conn, &hdr, crate::polkit::ACTION_TAILSCALE_EXIT_NODE)"),
            "tailscale_set_exit_node no longer authorizes against \
             {ACTION_TAILSCALE_EXIT_NODE}. This bus accepts every local account, and \
             the method decides which host every packet from this machine leaves \
             through — ungated, one local user can redirect another's traffic."
        );
    }

    /// The guard runs before anything with a side effect.
    ///
    /// `ssh_connect_command` brings up a mapped VPN profile before building
    /// the command. If the authorization check sat after that, an
    /// unauthorised caller could still raise a tunnel on its way to being
    /// refused — a denial that changes the state of the machine is not much
    /// of a denial.
    #[test]
    fn ssh_connect_authorizes_before_the_auto_vpn_connect() {
        let daemon = include_str!("daemon.rs");
        let body = daemon
            .split("async fn ssh_connect_command")
            .nth(1)
            .expect("ssh_connect_command exists");

        let guard = body
            .find("authorize(conn, &hdr, crate::polkit::ACTION_SSH_CONNECT)")
            .expect("the guard is present");
        let auto_vpn = body
            .find("connect_profile(")
            .expect("the auto-VPN connect is present");

        assert!(
            guard < auto_vpn,
            "the polkit check runs after the auto-VPN connect, so an \
             unauthorised caller can bring up a tunnel before being refused"
        );
    }
}
