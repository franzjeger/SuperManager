//! Customer + Site model for provisioning.
//!
//! A *Customer* groups one or more *Sites*. A Site corresponds
//! to a physical location (HQ, branch office, datacenter rack)
//! and pins down everything a deployment template needs that
//! varies between locations: VLAN map, WAN type, subnet
//! addressing, DNS preferences, contact details for compliance
//! reports.
//!
//! # Persistence
//!
//! Each customer is one TOML file under
//! `~/Library/Application Support/SuperManager/customers/<slug>.toml`.
//! Slugs are derived from the display name on creation and never
//! change (renaming the display name keeps the same slug). This
//! is what gives us a stable referrer for compliance runs and
//! deployment history that can survive a customer being renamed
//! "Acme Corp" → "Acme International Holdings Ltd".
//!
//! # Why TOML files (not a database)
//!
//! - Same rationale as compliance runs: append-friendly, plain-text,
//!   gits cleanly. The whole customer library is a directory you
//!   can copy onto a new Mac to migrate setup.
//! - Templates need to read customer values at render time. TOML
//!   parses to `serde_json::Value` cheaply via toml's serde
//!   integration; we hand that map straight to Tera's context.
//! - First-class export/import without translation layers.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    /// URL-safe identifier, derived from `display_name` at create
    /// time. Stable across renames.
    pub slug: String,

    pub display_name: String,

    /// Free-form contact / billing info. Surfaces on PDF report
    /// covers in later phases. Empty is fine.
    #[serde(default)]
    pub contact_name: String,
    #[serde(default)]
    pub contact_email: String,
    #[serde(default)]
    pub notes: String,

    /// Default template suggested when the user opens a render
    /// dialog without explicitly picking one. Optional — if
    /// unset the GUI defaults to "branch_office".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_template: Option<String>,

    /// Domains that must be allowed past FortiGuard's
    /// Newly-Observed-Domains (NOD) / Newly-Registered-Domains
    /// (NRD) categories on management VLANs. Typical entries:
    ///
    ///   - `*.unifi.<customer-domain>`     (their UniFi controller)
    ///   - `*.ui.com`                      (Ubiquiti's cloud)
    ///   - `*.ubnt.com`
    ///   - `*.synology.<customer-domain>`  (NAS / surveillance)
    ///
    /// The template engine merges these with a hardcoded set of
    /// universally-required infrastructure domains (Ubiquiti
    /// cloud, FortiGuard, Microsoft updates) when generating
    /// the MGMT-VLAN DNS filter profile.
    #[serde(default)]
    pub mgmt_allowlist_domains: Vec<String>,

    /// Primary public domain for the customer — drives the DNS
    /// health audit (SPF/DKIM/DMARC/DNSSEC). When empty, the
    /// audit falls back to extracting the domain from
    /// `contact_email`.
    #[serde(default)]
    pub primary_domain: String,

    pub sites: Vec<Site>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// Stable id within the customer. Used as the lookup key when
    /// a deployment is recorded against a specific site.
    pub id: String,

    pub display_name: String,

    /// Postal address — appears on PDF reports.
    #[serde(default)]
    pub address: String,

    /// FortiGate hostnames at this site. The provisioning view
    /// uses these to filter the host picker, and compliance can
    /// roll up scores per-site.
    #[serde(default)]
    pub host_ids: Vec<String>,

    /// "fiber" / "dhcp" / "pppoe" / "static". Free-form for now;
    /// templates branch on it. Future enhancement: enum.
    #[serde(default)]
    pub wan_type: String,

    /// Public WAN IP if static. Empty for DHCP / PPPoE / unknown.
    #[serde(default)]
    pub wan_static_ip: String,

    /// Default LAN subnet — the CIDR that VLAN 1 / native sits on.
    /// Templates use this as the base for derived VLAN subnets
    /// (`set ip {{ site.lan_base | nth_subnet(n) }}`).
    #[serde(default)]
    pub lan_base: String,

    /// Custom VLAN map. Each entry produces a `config system
    /// interface` block in the rendered template.
    #[serde(default)]
    pub vlans: Vec<Vlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub subnet: String,
    /// "wan" | "internal" | "iot" | "guest" | "voice" — drives
    /// which firewall policy class the template generates.
    #[serde(default)]
    pub purpose: String,
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Root directory for customer TOML files. Created on first save.
fn customers_dir() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("customers");
    p
}

/// Convert a display name to a URL-safe slug. Lowercase, ASCII
/// alphanumerics + hyphens only, collapsing runs of separators.
/// Stable across re-runs: same input always produces same slug.
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_dash = true; // suppress leading dashes
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("customer");
    }
    out
}

/// List all customers on disk, sorted by display name. Errors on
/// the IO layer bubble up; per-file parse errors are logged and
/// the file is skipped (one bad file shouldn't blank the whole
/// library).
pub fn list_all() -> Result<Vec<Customer>> {
    let dir = customers_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Customer> = Vec::new();
    for entry in std::fs::read_dir(&dir).context("read customers dir")? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("customer listing entry error: {e}");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match load_path(&path) {
            Ok(c) => out.push(c),
            Err(e) => tracing::warn!("customer load failed for {path:?}: {e:#}"),
        }
    }
    out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(out)
}

pub fn load(slug: &str) -> Result<Customer> {
    let mut path = customers_dir();
    path.push(format!("{slug}.toml"));
    load_path(&path)
}

fn load_path(path: &Path) -> Result<Customer> {
    let bytes = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
    toml::from_str(&bytes).with_context(|| format!("parse {path:?}"))
}

/// Validate that a customer / engagement slug is filesystem-safe.
/// Accepts ASCII alphanumeric + hyphens only — same character set
/// `slugify()` produces. Rejects path traversal (`..`, `/`),
/// hidden-file prefix (`.`), and empty input.
///
/// Centralized here because every save / load / delete path
/// (customer, engagement, findings_store, notify) interpolates
/// the slug into a filename. Unvalidated slugs were the
/// path-traversal vector flagged in the security review.
pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        anyhow::bail!("slug must not be empty");
    }
    if slug.len() > 64 {
        anyhow::bail!("slug must be ≤64 chars");
    }
    if slug.starts_with('.') || slug.starts_with('-') {
        anyhow::bail!("slug must not start with '.' or '-'");
    }
    for ch in slug.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
            anyhow::bail!("slug contains illegal character: {ch:?}");
        }
    }
    Ok(())
}

/// Per-customer save mutex. Mirrors the engagement lock pattern:
/// stops two concurrent saves (e.g. provisioning sheet save +
/// discovery host-link append) from racing on the TOML file.
fn customer_lock(slug: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("customer lock map poisoned");
    guard
        .entry(slug.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Persist a customer. Creates the directory if needed. Slug is
/// the only thing that pins the file path — renames are safe.
pub fn save(customer: &Customer) -> Result<()> {
    validate_slug(&customer.slug).context("invalid customer slug")?;
    let lock = customer_lock(&customer.slug);
    let _guard = lock.lock().expect("customer lock poisoned");

    let dir = customers_dir();
    std::fs::create_dir_all(&dir).context("create customers dir")?;
    let mut path = dir;
    path.push(format!("{}.toml", customer.slug));
    let tmp = path.with_extension("toml.tmp");
    let serialized = toml::to_string_pretty(customer).context("serialize customer")?;
    std::fs::write(&tmp, serialized).with_context(|| format!("write {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {path:?}"))?;
    Ok(())
}

pub fn delete(slug: &str) -> Result<()> {
    validate_slug(slug).context("invalid slug")?;
    let mut path = customers_dir();
    path.push(format!("{slug}.toml"));
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("delete {path:?}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Customer report
// ---------------------------------------------------------------------------

/// Aggregate everything we know about a customer into a Markdown
/// deliverable suitable for client handoff: compliance scores
/// per site, recent deployments, contact info, site addresses.
///
/// The report is the artifact that turns "we managed your gear"
/// into something a customer can put in a binder. We deliberately
/// produce Markdown rather than HTML/PDF directly — Markdown
/// renders consistently in Notion / GitHub / Marked, and macOS
/// Preview's "Print → Save as PDF" finishes the conversion to
/// PDF when the customer wants paper.
///
/// Aggregation is read-only: walk customer file, walk each site's
/// host_ids, look up each host's compliance history + deployment
/// history. The engine doesn't need a database join — the
/// per-host JSON stores already partition cleanly.
pub async fn render_customer_report(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    customer_slug: &str,
) -> Result<String> {
    let customer = load(customer_slug)?;
    let host_lookup: std::collections::HashMap<uuid::Uuid, supermgr_core::host::Host> = {
        let st = state.lock().await;
        st.ssh_hosts
            .values()
            .cloned()
            .map(|h| (h.id, h))
            .collect()
    };

    let mut out = String::with_capacity(8192);
    use std::fmt::Write;

    // ============= Cover =============
    writeln!(out, "# {} — Network Operations Report", customer.display_name).unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_Generated by SuperManager on {}_",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
    .unwrap();
    writeln!(out).unwrap();

    if !customer.contact_name.is_empty() || !customer.contact_email.is_empty() {
        writeln!(out, "**Contact:** {} ({})", customer.contact_name, customer.contact_email)
            .unwrap();
        writeln!(out).unwrap();
    }
    if !customer.notes.is_empty() {
        writeln!(out, "## Notes").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "{}", customer.notes).unwrap();
        writeln!(out).unwrap();
    }

    // ============= Executive summary =============
    let mut total_hosts = 0usize;
    let mut total_compliant = 0usize;
    let mut total_runs = 0usize;
    let mut total_deployments = 0usize;
    let mut score_sum: u32 = 0;
    let mut score_count: u32 = 0;

    for site in &customer.sites {
        for host_id_str in &site.host_ids {
            if let Ok(host_id) = uuid::Uuid::parse_str(host_id_str) {
                if host_lookup.contains_key(&host_id) {
                    total_hosts += 1;
                }
                let host_id_simple = host_id.simple().to_string();
                if let Ok(history) = crate::compliance::load_history(&host_id_simple, 1) {
                    if let Some(latest) = history.first() {
                        total_runs += 1;
                        score_sum += u32::from(latest.score);
                        score_count += 1;
                        if latest.score >= 90 {
                            total_compliant += 1;
                        }
                    }
                }
                if let Ok(deps) = crate::provisioning::list_deployments(&host_id_simple, 100) {
                    total_deployments += deps.len();
                }
            }
        }
    }

    writeln!(out, "## Executive Summary").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Metric | Value |").unwrap();
    writeln!(out, "|---|---|").unwrap();
    writeln!(out, "| Sites managed | {} |", customer.sites.len()).unwrap();
    writeln!(out, "| Devices | {total_hosts} |").unwrap();
    writeln!(out, "| Devices currently CIS-L1 compliant (score ≥ 90) | {total_compliant} of {total_hosts} |").unwrap();
    writeln!(out, "| Total compliance scans recorded | {total_runs} |").unwrap();
    if score_count > 0 {
        writeln!(
            out,
            "| Average compliance score | {} / 100 |",
            score_sum / score_count
        )
        .unwrap();
    }
    writeln!(out, "| Total deployments performed | {total_deployments} |").unwrap();
    writeln!(out).unwrap();

    // ============= Per-site detail =============
    for site in &customer.sites {
        writeln!(out, "## Site — {}", site.display_name).unwrap();
        writeln!(out).unwrap();
        if !site.address.is_empty() {
            writeln!(out, "**Address:** {}", site.address).unwrap();
            writeln!(out).unwrap();
        }
        writeln!(out, "**WAN:** {} · **LAN base:** {} · **VLANs:** {}",
            if site.wan_type.is_empty() { "unknown" } else { &site.wan_type },
            if site.lan_base.is_empty() { "—" } else { &site.lan_base },
            site.vlans.len()
        ).unwrap();
        writeln!(out).unwrap();

        if !site.vlans.is_empty() {
            writeln!(out, "### VLAN map").unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| VLAN ID | Name | Subnet | Purpose |").unwrap();
            writeln!(out, "|---|---|---|---|").unwrap();
            for vlan in &site.vlans {
                writeln!(out, "| {} | {} | `{}` | {} |",
                    vlan.id,
                    vlan.name,
                    vlan.subnet,
                    if vlan.purpose.is_empty() { "—" } else { &vlan.purpose }
                ).unwrap();
            }
            writeln!(out).unwrap();
        }

        if site.host_ids.is_empty() {
            writeln!(out, "_No devices attached to this site._").unwrap();
            writeln!(out).unwrap();
        } else {
            writeln!(out, "### Devices").unwrap();
            writeln!(out).unwrap();
            for host_id_str in &site.host_ids {
                let host_id = match uuid::Uuid::parse_str(host_id_str) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let host = match host_lookup.get(&host_id) {
                    Some(h) => h,
                    None => {
                        writeln!(out, "- _(host {host_id_str} no longer exists in inventory)_").unwrap();
                        continue;
                    }
                };
                writeln!(out, "#### {} ({})", host.label, format_device_type(host.device_type)).unwrap();
                writeln!(out).unwrap();
                writeln!(out, "- **SSH endpoint:** `{}@{}:{}`", host.username, host.hostname, host.port).unwrap();
                writeln!(out, "- **Auth method:** {}", format_auth_method(host.auth_method)).unwrap();
                writeln!(out).unwrap();

                // Latest compliance run.
                let host_simple = host_id.simple().to_string();
                if let Ok(history) = crate::compliance::load_history(&host_simple, 5) {
                    if let Some(latest) = history.first() {
                        writeln!(
                            out,
                            "**Latest compliance scan:** {} on {} — score **{}/100**, {} passed, {} failed{}.",
                            latest.firmware.as_deref().unwrap_or("unknown firmware"),
                            latest.started_at.format("%Y-%m-%d"),
                            latest.score,
                            latest.passed,
                            latest.failed,
                            if latest.errored > 0 { format!(", {} errored", latest.errored) } else { String::new() }
                        ).unwrap();
                        writeln!(out).unwrap();
                        if history.len() > 1 {
                            writeln!(out, "**Score history (most recent {} runs):** {}",
                                history.len(),
                                history.iter().take(10).map(|r| r.score.to_string()).collect::<Vec<_>>().join(" → ")
                            ).unwrap();
                            writeln!(out).unwrap();
                        }
                    } else {
                        writeln!(out, "_No compliance scans on record._").unwrap();
                        writeln!(out).unwrap();
                    }
                }

                // Recent deployments.
                if let Ok(deps) = crate::provisioning::list_deployments(&host_simple, 5) {
                    if !deps.is_empty() {
                        writeln!(out, "**Recent deployments:**").unwrap();
                        writeln!(out).unwrap();
                        for dep in &deps {
                            let status = match dep.status {
                                crate::provisioning::DeploymentStatus::Succeeded => "✅ succeeded",
                                crate::provisioning::DeploymentStatus::Failed => "❌ failed",
                                crate::provisioning::DeploymentStatus::RolledBack => "↩ rolled back",
                                crate::provisioning::DeploymentStatus::Running => "⏱ running",
                            };
                            writeln!(
                                out,
                                "- {} — `{}` — {} ({} lines pushed)",
                                dep.started_at.format("%Y-%m-%d %H:%M"),
                                dep.template_id,
                                status,
                                dep.lines_pushed
                            ).unwrap();
                        }
                        writeln!(out).unwrap();
                    }
                }
            }
        }
    }

    // ============= Footer =============
    writeln!(out, "---").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_This report aggregates data from `~/Library/Application Support/SuperManager/`. \
         Compliance baselines are CIS-FortiOS-7.4 Level 1. Per-host scan and deployment \
         records are retained on this Mac._"
    )
    .unwrap();
    Ok(out)
}

fn format_device_type(t: supermgr_core::ssh::DeviceType) -> &'static str {
    use supermgr_core::ssh::DeviceType;
    match t {
        DeviceType::Linux => "Linux",
        DeviceType::UniFi => "UniFi",
        DeviceType::PfSense => "pfSense",
        DeviceType::OpnSense => "OPNsense",
        DeviceType::OpenWrt => "OpenWrt",
        DeviceType::Fortigate => "FortiGate",
        DeviceType::Sophos => "Sophos",
        DeviceType::Windows => "Windows",
        DeviceType::Custom => "Custom",
    }
}

fn format_auth_method(m: supermgr_core::ssh::AuthMethod) -> &'static str {
    use supermgr_core::ssh::AuthMethod;
    match m {
        AuthMethod::Key => "SSH key",
        AuthMethod::Password => "Password",
        AuthMethod::Certificate => "SSH certificate",
    }
}

#[cfg(test)]
mod slug_tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(validate_slug("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_slug("../etc").is_err());
        assert!(validate_slug("..").is_err());
        assert!(validate_slug("a/b").is_err());
        assert!(validate_slug("a\\b").is_err());
    }

    #[test]
    fn rejects_dot_or_dash_prefix() {
        assert!(validate_slug(".hidden").is_err());
        assert!(validate_slug("-leading").is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!(validate_slug(&"a".repeat(65)).is_err());
    }

    #[test]
    fn accepts_normal_slugs() {
        assert!(validate_slug("acme-corp").is_ok());
        assert!(validate_slug("customer_a").is_ok());
        assert!(validate_slug("ABC123").is_ok());
        assert!(validate_slug("a").is_ok()); // single char OK
    }

    proptest::proptest! {
        /// Property: validate_slug must never panic on any input.
        /// Some inputs reject (Err); some accept; none crash.
        #[test]
        fn prop_validate_slug_never_panics(s in ".{0,128}") {
            let _ = validate_slug(&s);
        }

        /// Property: any accepted slug, when interpolated into
        /// "<dir>/<slug>.toml", must NOT escape `<dir>`. The
        /// canonical form's last component must equal `slug.toml`.
        #[test]
        fn prop_accepted_slug_is_filesystem_safe(s in "[a-zA-Z0-9_-]{1,64}") {
            // Reject leading dot/dash up front (validate_slug rule).
            if s.starts_with('.') || s.starts_with('-') {
                return Ok(());
            }
            let validated = validate_slug(&s);
            if validated.is_err() {
                return Ok(());
            }
            let path = format!("/tmp/customers/{s}.toml");
            let pb = std::path::PathBuf::from(&path);
            // Final component must be exactly "<slug>.toml". Bind
            // the expected name to a `let` first so the &str
            // borrow outlives the macro's temporary creation.
            let expected = format!("{s}.toml");
            proptest::prop_assert_eq!(
                pb.file_name().and_then(|f| f.to_str()),
                Some(expected.as_str())
            );
            // Parent must be /tmp/customers — validation didn't
            // let any "/" sneak through to escape the dir.
            proptest::prop_assert_eq!(
                pb.parent().and_then(|p| p.to_str()),
                Some("/tmp/customers")
            );
        }
    }
}
