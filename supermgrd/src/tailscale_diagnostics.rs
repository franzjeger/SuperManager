//! On-demand comparison of Tailscale's DNS resolver and the system resolver.
use crate::tailscale_management::{cli, require_profile};
use std::time::Duration;
use supermgr_core::tailscale::{TailscaleDiagnosticCheck as Check, TailscaleDnsReport};

fn check(name: &str, status: &str, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

fn dns_reply(raw: &str, expected: &[String]) -> Result<bool, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "Unsupported DNS response format")?;
    let code = value["ResponseCode"]
        .as_str()
        .ok_or("DNS response code was not reported")?;
    if code != "RCodeSuccess" && code != "NOERROR" {
        return Err(format!("Tailscale DNS returned {code}"));
    }
    let answers = value["Answers"]
        .as_array()
        .ok_or("DNS response has no answers")?;
    Ok(answers.iter().any(|answer| {
        let body = &answer["Body"];
        // Current CLI represents A records as an IP string; accept an
        // object containing IP as well, without treating any answer as success.
        body.as_str()
            .or_else(|| body["IP"].as_str())
            .is_some_and(|ip| expected.iter().any(|known| known == ip))
    }))
}

pub async fn diagnose(profile: &str) -> Result<TailscaleDnsReport, String> {
    require_profile(profile).await?;
    let mut checks = Vec::new();
    let nodes = crate::tailscale::list_nodes().await?;
    let node = nodes
        .iter()
        .find(|n| n.is_self && !n.dns_name.is_empty())
        .ok_or("No local MagicDNS name is reported. Sign in and refresh first.")?;
    let name = node.dns_name.trim_end_matches('.');
    if name.len() > 253
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
    {
        return Err("The reported MagicDNS name is invalid".into());
    }
    let query = vec![
        "dns".into(),
        "query".into(),
        "--json".into(),
        name.into(),
        "A".into(),
    ];
    let config_args = vec!["dns".into(), "status".into()];
    let (direct, system, configuration) = tokio::join!(
        cli(&query),
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((name, 0))),
        cli(&config_args),
    );
    let direct = direct.and_then(|raw| dns_reply(&raw, &node.tailscale_ips));
    let system = match system {
        Ok(Ok(addresses)) => Ok(addresses.map(|a| a.ip().to_string()).collect::<Vec<_>>()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("System lookup timed out after five seconds".into()),
    };
    let system_matches = system
        .as_ref()
        .is_ok_and(|addresses| addresses.iter().any(|ip| node.tailscale_ips.contains(ip)));
    checks.push(match &direct {
        Ok(true) => check(
            "Tailscale DNS",
            "pass",
            format!("{name} resolves to this device's Tailscale address."),
        ),
        Ok(false) => check(
            "Tailscale DNS",
            "fail",
            "DNS replied, but not with this device's reported address.",
        ),
        Err(e) => check(
            "Tailscale DNS",
            "unknown",
            format!("{e}. Check whether this CLI supports 'tailscale dns query'."),
        ),
    });
    checks.push(check(
        "System DNS",
        if system_matches { "pass" } else { "fail" },
        match system {
            Ok(addresses) => format!("{name} → {}", addresses.join(", ")),
            Err(e) => e,
        },
    ));
    if direct == Ok(true) && !system_matches {
        checks.push(check("Suggested repair", "warning", "Tailscale resolves the name, but the system resolver does not. Check Use tailnet DNS in Settings, then inspect the system resolver details below. Connect using the device's Tailscale IP while resolving the DNS issue."));
    }
    let health = crate::tailscale::health().await;
    checks.push(check(
        "Backend",
        if health.is_running() {
            "pass"
        } else {
            "warning"
        },
        health.backend_state,
    ));
    if require_profile(profile).await.is_err() {
        checks.push(check("Account changed", "warning", "The active account changed during diagnostics. Refresh and run again; these results may refer to the previous account."));
    }
    let resolver = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            ["nameserver", "search", "options"]
                .iter()
                .any(|prefix| line.trim_start().starts_with(prefix))
        })
        .take(32)
        .collect::<Vec<_>>()
        .join("\n");
    let config = configuration.unwrap_or_else(|e| format!("DNS configuration unavailable: {e}"));
    Ok(TailscaleDnsReport {
        checked_at: chrono::Utc::now().to_rfc3339(),
        profile_id: profile.into(),
        checks,
        details: format!(
            "Tailscale DNS configuration\n{}\n\nSystem resolver (/etc/resolv.conf)\n{resolver}",
            config.chars().take(16000).collect::<String>()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_success_requires_the_expected_address_not_just_a_successful_process() {
        let expected = vec!["100.100.1.2".into()];
        assert_eq!(
            dns_reply(
                r#"{"ResponseCode":"RCodeSuccess","Answers":[{"Body":"100.100.1.2"}]}"#,
                &expected
            ),
            Ok(true)
        );
        assert_eq!(
            dns_reply(
                r#"{"ResponseCode":"RCodeSuccess","Answers":[{"Body":"203.0.113.1"}]}"#,
                &expected
            ),
            Ok(false)
        );
        assert!(dns_reply(
            r#"{"ResponseCode":"RCodeNameError","Answers":[]}"#,
            &expected
        )
        .is_err());
        assert!(dns_reply("{}", &expected).is_err());
    }
}
