//! On-demand diagnostics. No polling, network probes or changes to VPN state.

use std::fmt::Write as _;
use std::time::Duration;

const LIMIT: usize = 64 * 1024;

/// Collect a local support report. Credentials and configuration files are
/// never read. Logs are optional because arbitrary driver output can contain
/// sensitive data even after common credential lines have been filtered.
pub async fn collect(include_logs: bool) -> String {
    let mut report = format!(
        "SuperManager support report\nGenerated: {}\nVersion: {}\nCommit: {}\n\nContains network addresses and hostnames. Review before sharing.\nNo configuration or credential files are included.\n",
        chrono::Utc::now().to_rfc3339(), crate::update::VERSION, crate::update::GIT_COMMIT,
    );
    let commands: &[(&str, &str, &[&str])] = &[
        ("Kernel", "uname", &["-srmo"]),
        (
            "Daemon",
            "systemctl",
            &[
                "show",
                "supermgrd.service",
                "--property=ActiveState,SubState,ExecMainStatus,ActiveEnterTimestamp",
                "--no-pager",
            ],
        ),
        ("Interfaces", "ip", &["-brief", "address"]),
        (
            "IPv4 routes",
            "ip",
            &["-4", "route", "show", "table", "all"],
        ),
        (
            "IPv6 routes",
            "ip",
            &["-6", "route", "show", "table", "all"],
        ),
        ("DNS", "resolvectl", &["status", "--no-pager"]),
        (
            "NetworkManager",
            "nmcli",
            &["-t", "-f", "STATE,CONNECTIVITY", "general"],
        ),
    ];
    // Independent commands run together; the slowest missing service adds at
    // most three seconds. kill_on_drop also stops timed-out child processes.
    let outputs =
        futures_util::future::join_all(commands.iter().map(|(_, program, args)| async move {
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(*args).env("LC_ALL", "C").kill_on_drop(true);
            match tokio::time::timeout(Duration::from_secs(3), cmd.output()).await {
                Ok(Ok(output)) => {
                    let bytes = if output.status.success() {
                        &output.stdout
                    } else {
                        &output.stderr
                    };
                    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(LIMIT)]);
                    format!("Exit status: {}\n{text}", output.status)
                }
                Ok(Err(_)) => "Unavailable on this system.\n".into(),
                Err(_) => "Timed out after 3 seconds.\n".into(),
            }
        }))
        .await;
    for ((title, _, _), output) in commands.iter().zip(outputs) {
        let _ = write!(report, "\n--- {title} ---\n{output}");
    }
    if include_logs {
        report.push_str("\n--- Recent daemon logs (common credential lines omitted) ---\n");
        match tokio::time::timeout(Duration::from_secs(3), crate::dbus_client::dbus_get_logs())
            .await
        {
            Ok(Ok(lines)) => {
                let first = lines.len().saturating_sub(100);
                let mut budget = LIMIT;
                for line in &lines[first..] {
                    let safe = redact_log(line);
                    if safe.len() > budget {
                        break;
                    }
                    budget -= safe.len();
                    report.push_str(&safe);
                    report.push('\n');
                }
            }
            _ => report.push_str("Daemon logs unavailable.\n"),
        }
    }
    report
}

fn redact_log(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "private",
        "preshared",
        "psk",
        "user_code",
        "auth_challenge",
        "credential",
        "begin ",
        "https://",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        "[potentially sensitive log line omitted]".into()
    } else {
        line.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_and_login_lines_are_omitted() {
        for line in [
            "PASSWORD=secret",
            "auth_challenge user_code=ABC",
            "Authorization: Bearer abc",
            "open https://login.example/?code=abc",
            "PrivateKey=abc",
        ] {
            assert_eq!(redact_log(line), "[potentially sensitive log line omitted]");
        }
        assert_eq!(redact_log("VPN disconnected"), "VPN disconnected");
    }
}
