//! Per-customer Markdown documentation export.
//!
//! Aggregates the data the daemon already has (VPN profiles, SSH hosts,
//! their `customer` tags) into a single Markdown document suitable for
//! pasting into a customer-handover note, an audit binder, or a wiki page.
//!
//! Live API queries against FortiGate / OPNsense / UniFi appliances are
//! intentionally NOT performed here — this module produces a pure-data
//! report from on-disk state, which is what makes it scriptable, fast,
//! and offline-safe. If you want a richer report that also fetches live
//! status (firmware version, sessions, etc.), wire that into the GUI
//! calling layer where the existing `*_get_status` D-Bus methods live.

use std::fmt::Write as _;

use chrono::Utc;

use supermgr_core::{
    ssh::host::SshHost, vpn::profile::Profile, vpn::profile::ProfileConfig,
};

/// Render a Markdown document for `customer` summarising every profile and
/// SSH host tagged with that customer name. The match is case-insensitive
/// on the trimmed input — `"Sybr"`, `"sybr"`, and `"  sybr  "` all hit the
/// same group.
///
/// Pass `""` to render an "ungrouped" report covering every profile/host
/// whose `customer` field is empty.
///
/// The output is plain Markdown; no external rendering deps. Field
/// ordering is stable so consecutive exports diff cleanly.
pub fn render_customer_doc(
    customer: &str,
    profiles: &[Profile],
    hosts: &[SshHost],
) -> String {
    let needle = customer.trim().to_lowercase();
    let title = if needle.is_empty() {
        "Ungrouped".to_owned()
    } else {
        customer.trim().to_owned()
    };

    let mut out = String::new();

    // ── Header ────────────────────────────────────────────────────────
    let _ = writeln!(out, "# {title} — SuperManager export");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "_Generated: {}_",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = writeln!(out);

    // ── VPN profiles ──────────────────────────────────────────────────
    let mut matched_profiles: Vec<&Profile> = profiles
        .iter()
        .filter(|p| p.customer.trim().eq_ignore_ascii_case(&needle))
        .collect();
    matched_profiles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let _ = writeln!(out, "## VPN profiles ({})", matched_profiles.len());
    let _ = writeln!(out);
    if matched_profiles.is_empty() {
        let _ = writeln!(out, "_None._");
        let _ = writeln!(out);
    } else {
        let _ = writeln!(
            out,
            "| Name | Backend | Host | Username | Full-tunnel | Auto | Kill switch | Last connected |"
        );
        let _ = writeln!(
            out,
            "|------|---------|------|----------|-------------|------|-------------|----------------|"
        );
        for p in &matched_profiles {
            let backend = p.config.backend_name();
            let host = match &p.config {
                ProfileConfig::FortiGate(fg) => fg.host.clone(),
                _ => "—".to_owned(),
            };
            let user = match &p.config {
                ProfileConfig::FortiGate(fg) => fg.username.clone(),
                ProfileConfig::OpenVpn(ov) => ov.username.clone().unwrap_or_default(),
                _ => String::new(),
            };
            let last = p
                .last_connected_at
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "never".to_owned());
            let _ = writeln!(
                out,
                "| {name} | {backend} | {host} | {user} | {ft} | {ac} | {ks} | {last} |",
                name = md_escape(&p.name),
                backend = md_escape(backend),
                host = md_escape(&host),
                user = md_escape(&user),
                ft = if p.full_tunnel { "yes" } else { "no" },
                ac = if p.auto_connect { "yes" } else { "no" },
                ks = if p.kill_switch { "yes" } else { "no" },
                last = last,
            );
        }
        let _ = writeln!(out);
    }

    // ── SSH hosts ─────────────────────────────────────────────────────
    let mut matched_hosts: Vec<&SshHost> = hosts
        .iter()
        .filter(|h| h.customer.trim().eq_ignore_ascii_case(&needle))
        .collect();
    matched_hosts.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));

    let _ = writeln!(out, "## SSH hosts ({})", matched_hosts.len());
    let _ = writeln!(out);
    if matched_hosts.is_empty() {
        let _ = writeln!(out, "_None._");
        let _ = writeln!(out);
    } else {
        let _ = writeln!(
            out,
            "| Label | Hostname | Port | User | Type | Group | API | Pinned |"
        );
        let _ = writeln!(
            out,
            "|-------|----------|------|------|------|-------|-----|--------|"
        );
        for h in &matched_hosts {
            let api = if h.api_token_ref.is_some() { "yes" } else { "—" };
            let _ = writeln!(
                out,
                "| {label} | {host} | {port} | {user} | {dt} | {grp} | {api} | {pin} |",
                label = md_escape(&h.label),
                host = md_escape(&h.hostname),
                port = h.port,
                user = md_escape(&h.username),
                dt = h.device_type,
                grp = md_escape(&h.group),
                api = api,
                pin = if h.pinned { "★" } else { "—" },
            );
        }
        let _ = writeln!(out);
    }

    // ── Device-type counts (handy for audit summaries) ────────────────
    if !matched_hosts.is_empty() {
        let _ = writeln!(out, "## Host type breakdown");
        let _ = writeln!(out);
        let mut counts = std::collections::BTreeMap::<String, usize>::new();
        for h in &matched_hosts {
            *counts.entry(format!("{}", h.device_type)).or_default() += 1;
        }
        for (kind, n) in &counts {
            let _ = writeln!(out, "- **{kind}**: {n}");
        }
        let _ = writeln!(out);
    }

    // ── Footer ────────────────────────────────────────────────────────
    let _ = writeln!(
        out,
        "---\n_Source: SuperManager — VPN profiles + SSH host registry on this daemon._"
    );

    out
}

/// Return the list of distinct, non-empty customer tags across the merged
/// profile + host registries. Sorted case-insensitively for stable display.
pub fn list_customers(profiles: &[Profile], hosts: &[SshHost]) -> Vec<String> {
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    for p in profiles {
        let trimmed = p.customer.trim();
        if !trimmed.is_empty() {
            seen.entry(trimmed.to_lowercase())
                .or_insert_with(|| trimmed.to_owned());
        }
    }
    for h in hosts {
        let trimmed = h.customer.trim();
        if !trimmed.is_empty() {
            seen.entry(trimmed.to_lowercase())
                .or_insert_with(|| trimmed.to_owned());
        }
    }
    seen.into_values().collect()
}

/// Escape Markdown table-cell metacharacters that would break the layout.
///
/// Pipe is the row separator; backslash is the escape itself; backtick
/// would start an inline code span. Newlines must be replaced with a space
/// because Markdown table cells cannot span multiple lines.
fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '\\' => out.push_str("\\\\"),
            '`' => out.push_str("\\`"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::IpAddr;
    use supermgr_core::{
        ssh::host::AuthMethod, ssh::DeviceType,
        vpn::profile::{FortiGateConfig, SecretRef},
    };
    use uuid::Uuid;

    fn sample_fortigate_profile(name: &str, customer: &str) -> Profile {
        Profile {
            id: Uuid::new_v4(),
            name: name.into(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: customer.into(),
            config: ProfileConfig::FortiGate(FortiGateConfig {
                host: "fw.example.com".into(),
                username: "sybr_admin".into(),
                password: SecretRef::new("p"),
                psk: SecretRef::new("k"),
                dns_servers: Vec::<IpAddr>::new(),
                routes: Vec::new(),
            }),
            updated_at: Utc::now(),
        }
    }

    fn sample_host(label: &str, customer: &str, dt: DeviceType) -> SshHost {
        SshHost {
            id: Uuid::new_v4(),
            label: label.into(),
            hostname: "10.0.0.1".into(),
            port: 22,
            username: "admin".into(),
            group: "edge".into(),
            device_type: dt,
            auth_method: AuthMethod::Key,
            auth_key_id: None,
            auth_password_ref: None,
            auth_cert_ref: None,
            vpn_profile_id: None,
            api_port: None,
            api_token_ref: None,
            api_verify_tls: false,
            unifi_controller_url: None,
            unifi_api_token_ref: None,
            rdp_port: None,
            vnc_port: None,
            port_forwards: Vec::new(),
            proxy_jump: None,
            pinned: false,
            customer: customer.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn list_customers_dedupes_case_insensitively() {
        let profiles = vec![
            sample_fortigate_profile("a", "Sybr"),
            sample_fortigate_profile("b", "sybr"),
            sample_fortigate_profile("c", "Elteco"),
            sample_fortigate_profile("d", ""),
        ];
        let hosts = vec![
            sample_host("h1", "  Sybr  ", DeviceType::Linux),
            sample_host("h2", "Autostrada", DeviceType::Fortigate),
        ];
        let cs = list_customers(&profiles, &hosts);
        // First-seen casing wins, but lowercase dedup means only one Sybr.
        assert!(cs.contains(&"Sybr".to_owned()));
        assert!(cs.contains(&"Elteco".to_owned()));
        assert!(cs.contains(&"Autostrada".to_owned()));
        assert_eq!(cs.len(), 3, "got {cs:?}");
    }

    #[test]
    fn render_picks_only_matching_customer() {
        let profiles = vec![
            sample_fortigate_profile("p_sybr", "Sybr"),
            sample_fortigate_profile("p_elteco", "Elteco"),
        ];
        let hosts = vec![
            sample_host("h_sybr", "Sybr", DeviceType::Fortigate),
            sample_host("h_elteco", "Elteco", DeviceType::Linux),
        ];
        let md = render_customer_doc("Sybr", &profiles, &hosts);
        assert!(md.contains("# Sybr"));
        assert!(md.contains("p_sybr"));
        assert!(md.contains("h_sybr"));
        assert!(!md.contains("p_elteco"));
        assert!(!md.contains("h_elteco"));
    }

    #[test]
    fn render_match_is_case_insensitive_and_trims() {
        let profiles = vec![sample_fortigate_profile("p", "Sybr")];
        let md = render_customer_doc("  sYbR  ", &profiles, &[]);
        assert!(md.contains("p"));
    }

    #[test]
    fn render_handles_empty_input_gracefully() {
        let md = render_customer_doc("nobody", &[], &[]);
        assert!(md.contains("# nobody"));
        assert!(md.contains("_None._"));
    }

    #[test]
    fn render_empty_customer_string_means_ungrouped() {
        let profiles = vec![
            sample_fortigate_profile("a", ""),
            sample_fortigate_profile("b", "Sybr"),
        ];
        let md = render_customer_doc("", &profiles, &[]);
        assert!(md.contains("# Ungrouped"));
        assert!(md.contains("a"));
        assert!(!md.contains("| b "));
    }

    #[test]
    fn md_escape_neutralises_table_breakers() {
        assert_eq!(md_escape("a|b"), "a\\|b");
        assert_eq!(md_escape("c`d"), "c\\`d");
        assert_eq!(md_escape("e\nf"), "e f");
        assert_eq!(md_escape(r"g\h"), r"g\\h");
    }
}
