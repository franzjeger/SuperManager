//! Template engine for FortiGate / UniFi configuration generation.
//!
//! # Architecture
//!
//! Linux's `supermgr/src/ui/provisioning/wizard.rs` is 4400 lines of
//! GTK code that calls Claude with a 70-line system prompt at the
//! end. The output is a wall of CLI commands you push to the device
//! and pray. We replace this with three layers:
//!
//! 1. **Templates** — Tera-rendered strings. Templates are plain
//!    `.tera` files shipped in this binary as defaults, plus
//!    user-supplied files in
//!    `~/Library/Application Support/SuperManager/templates/`.
//!    Tera supports loops, conditionals, includes, and filters,
//!    so a template can iterate VLANs, branch on WAN type, and
//!    expand subnet notations without escaping into Rust code.
//!
//! 2. **Render context** — built from a `(Customer, Site, extras)`
//!    triple via serde. Template authors reference `{{ customer.display_name }}`,
//!    `{{ site.lan_base }}`, `{{ vlans | length }}`, and so on.
//!
//! 3. **Render result** — text + a manifest of the variables
//!    consumed (so the GUI can render a "missing required field"
//!    pre-flight) and the templates included.
//!
//! # Deployment approval
//!
//! Diff preview validates customer/site membership and retains a single-use
//! plan with rendered commands and a host snapshot. Deploy never re-renders;
//! it checks for changed host/customer/live configuration before pushing.
//! This is not a device transaction: automatic timed rollback and reliable
//! per-command acknowledgment remain separate requirements.
//!

pub(crate) mod plans;

use std::path::PathBuf;

use anyhow::{bail, anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tera::{Context as TeraContext, Tera};

use crate::customer::{Customer, Site};

// ---------------------------------------------------------------------------
// Template metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    /// Stable id, dot-namespaced. `vendor.purpose.tier` form keeps
    /// the directory structure flat while still supporting future
    /// growth without renames.
    pub id: String,
    /// Human-readable label for the picker.
    pub display_name: String,
    /// 1-2 sentence summary surfaced in the picker.
    pub description: String,
    /// "fortigate" / "unifi" / "switch". The GUI uses this to
    /// filter the picker by device type.
    pub vendor: String,
    /// "branch_office" / "hq" / "retail" / "datacenter" / "custom".
    pub category: String,
    /// True when the template is shipped in the binary; false for
    /// user-supplied templates in the support directory. The GUI
    /// renders a "Built-in" badge for built-ins.
    pub built_in: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderRequest {
    pub template_id: String,
    pub customer_slug: String,
    pub site_id: String,
    /// Free-form extras. Templates reference `{{ extras.foo }}` —
    /// useful for one-off variables that don't belong on the
    /// permanent customer record (e.g. a one-time S2S peer IP).
    #[serde(default)]
    pub extras: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderResult {
    pub template_id: String,
    /// The rendered config (FortiOS CLI for FortiGate templates,
    /// JSON for UniFi controller calls).
    pub output: String,
    /// Variables Tera reported as accessed during rendering.
    /// Used by the GUI to surface "you referenced extras.foo
    /// which is unset, here's what got substituted as empty".
    /// Tera doesn't expose a clean API for this; we approximate
    /// by tracking which `extras` keys we passed in.
    pub extras_used: Vec<String>,
}

// ---------------------------------------------------------------------------
// Template discovery
// ---------------------------------------------------------------------------

fn templates_dir() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("templates");
    p
}

/// Built-in templates. Each (id, display_name, description,
/// vendor, category, body). Body is the Tera source.
///
/// Why hardcoded: a v1 template needs to ship with the binary so
/// users see something useful immediately; once the engine is
/// stable, we'll move these to bundled `.tera` files in the app's
/// resources and load them like the user-supplied set.
fn built_in_templates() -> Vec<(TemplateInfo, &'static str)> {
    vec![
        (
            TemplateInfo {
                id: "fortigate.branch_office".into(),
                display_name: "FortiGate — Branch Office".into(),
                description: "Standard branch-office hardening: CIS Level 1 baseline, single WAN, address objects per VLAN, NTP, web/DNS filtering, FortiGuard auto-update.".into(),
                vendor: "fortigate".into(),
                category: "branch_office".into(),
                built_in: true,
            },
            include_str!("templates/fortigate_branch_office.tera"),
        ),
        (
            TemplateInfo {
                id: "fortigate.hq".into(),
                display_name: "FortiGate — Headquarters".into(),
                description: "HQ-grade hardening: CIS L1+L2, dual-WAN with SD-WAN failover, RADIUS auth via FortiAuthenticator, S2S VPN scaffold, comprehensive policy + DoS + IPv6.".into(),
                vendor: "fortigate".into(),
                category: "hq".into(),
                built_in: true,
            },
            include_str!("templates/fortigate_hq.tera"),
        ),
        (
            TemplateInfo {
                id: "unifi.wifi_basic".into(),
                display_name: "UniFi — Basic WiFi network".into(),
                description: "JSON for UniFi controller's REST API: creates networks (one per VLAN) and a WPA3-Personal SSID per network. Deploy via the UniFi Controller integration.".into(),
                vendor: "unifi".into(),
                category: "wifi".into(),
                built_in: true,
            },
            include_str!("templates/unifi_wifi_basic.tera"),
        ),
    ]
}

/// All templates: built-in + user-supplied. User templates with
/// the same id as a built-in override the built-in (last write
/// wins, matching the compliance check overlay pattern).
pub fn list_templates() -> Result<Vec<TemplateInfo>> {
    let mut out: Vec<TemplateInfo> = built_in_templates()
        .into_iter()
        .map(|(info, _)| info)
        .collect();
    let dir = templates_dir();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir).context("read templates dir")? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("templates listing error: {e}");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match load_user_template_meta(&path) {
                Ok(info) => {
                    // Override built-in if same id; else append.
                    if let Some(idx) = out.iter().position(|t| t.id == info.id) {
                        out[idx] = info;
                    } else {
                        out.push(info);
                    }
                }
                Err(e) => tracing::warn!("template metadata load failed for {path:?}: {e:#}"),
            }
        }
    }
    out.sort_by(|a, b| {
        a.vendor
            .cmp(&b.vendor)
            .then(a.category.cmp(&b.category))
            .then(a.display_name.cmp(&b.display_name))
    });
    Ok(out)
}

/// User templates are split across two files: `<id>.toml`
/// holds metadata, `<id>.tera` holds the body. Same convention
/// as compliance overlays — keeps things browseable / git-able.
#[derive(Deserialize)]
struct UserTemplateToml {
    id: String,
    display_name: String,
    description: String,
    vendor: String,
    #[serde(default = "default_category")]
    category: String,
}

fn default_category() -> String {
    "custom".into()
}

fn load_user_template_meta(toml_path: &std::path::Path) -> Result<TemplateInfo> {
    let bytes =
        std::fs::read_to_string(toml_path).with_context(|| format!("read {toml_path:?}"))?;
    let parsed: UserTemplateToml = toml::from_str(&bytes)?;
    Ok(TemplateInfo {
        id: parsed.id,
        display_name: parsed.display_name,
        description: parsed.description,
        vendor: parsed.vendor,
        category: parsed.category,
        built_in: false,
    })
}

fn template_body(template_id: &str) -> Result<String> {
    // Built-in?
    for (info, body) in built_in_templates() {
        if info.id == template_id {
            return Ok(body.to_owned());
        }
    }
    // User?
    let mut path = templates_dir();
    path.push(format!("{template_id}.tera"));
    if path.exists() {
        return std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"));
    }
    Err(anyhow!("template not found: {template_id}"))
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Render a template against a (customer, site) pair. Returns
/// `RenderResult` with the output string. Errors propagate from
/// Tera's parser/renderer with full diagnostic — the GUI surfaces
/// them so the template author knows exactly which line is wrong.
pub fn render(req: &RenderRequest) -> Result<RenderResult> {
    let customer = crate::customer::load(&req.customer_slug).with_context(|| {
        format!("load customer {}", req.customer_slug)
    })?;
    let site = customer
        .sites
        .iter()
        .find(|s| s.id == req.site_id)
        .ok_or_else(|| anyhow!("site '{}' not found in customer '{}'", req.site_id, req.customer_slug))?;
    let body = template_body(&req.template_id)?;

    let mut tera = Tera::default();
    tera.add_raw_template(&req.template_id, &body)
        .with_context(|| format!("parse template {}", req.template_id))?;
    register_filters(&mut tera);

    let context = build_context(&customer, site, &req.extras)?;
    let output = tera
        .render(&req.template_id, &context)
        .with_context(|| format!("render template {}", req.template_id))?;

    let extras_used: Vec<String> = req.extras.keys().cloned().collect();
    Ok(RenderResult {
        template_id: req.template_id.clone(),
        output,
        extras_used,
    })
}

/// Render and return the rendered text directly without re-fetching
/// the customer (used by future pre-flight / diff paths). Public
/// for callers that already have a customer object loaded.
pub fn render_with_customer(
    customer: &Customer,
    site: &Site,
    template_id: &str,
    extras: &serde_json::Map<String, serde_json::Value>,
) -> Result<RenderResult> {
    let body = template_body(template_id)?;
    let mut tera = Tera::default();
    tera.add_raw_template(template_id, &body)
        .with_context(|| format!("parse template {template_id}"))?;
    register_filters(&mut tera);

    let context = build_context(customer, site, extras)?;
    let output = tera
        .render(template_id, &context)
        .with_context(|| format!("render template {template_id}"))?;
    let extras_used: Vec<String> = extras.keys().cloned().collect();
    Ok(RenderResult {
        template_id: template_id.to_owned(),
        output,
        extras_used,
    })
}

/// Build the Tera context object. Customer + site are passed
/// straight through via serde, plus a `meta` block with the
/// rendered-at timestamp + framework name (used in template
/// banner comments).
fn build_context(
    customer: &Customer,
    site: &Site,
    extras: &serde_json::Map<String, serde_json::Value>,
) -> Result<TeraContext> {
    let mut ctx = TeraContext::new();
    ctx.insert("customer", customer);
    ctx.insert("site", site);
    ctx.insert("vlans", &site.vlans);
    ctx.insert("extras", extras);
    ctx.insert(
        "meta",
        &serde_json::json!({
            "rendered_at": chrono::Utc::now().to_rfc3339(),
            "framework": "SuperManager Provisioning v1",
        }),
    );
    Ok(ctx)
}

// ---------------------------------------------------------------------------
// Custom Tera filters
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Section parsing & diff
// ---------------------------------------------------------------------------

/// FortiOS configs are blocks of the form:
///
/// ```text
/// config <path with spaces>
///     <body lines>
///     edit "..."
///         set foo bar
///     next
/// end
/// ```
///
/// `config / end` blocks may nest (`edit / next` is one level
/// down, but those don't count as separate top-level sections).
/// We only care about top-level sections for diffing. The path
/// is the entire string after `config` up to end-of-line, used
/// verbatim as the section identifier.
#[derive(Debug, Clone)]
pub struct ConfigSection {
    pub path: String,
    pub body: String,
}

/// Parse a FortiOS config dump (or rendered template) into
/// top-level `config X / end` sections. Comments (`#` / `{#`)
/// and blank lines outside any section are ignored. Lines
/// inside a section are kept verbatim — order matters for
/// `edit` blocks.
pub fn parse_sections(text: &str) -> Vec<ConfigSection> {
    let mut out: Vec<ConfigSection> = Vec::new();
    let mut depth: usize = 0; // 0 = outside any section
    let mut current_path: Option<String> = None;
    let mut current_body = String::new();

    for raw_line in text.lines() {
        let trimmed = raw_line.trim_start();
        if depth == 0 {
            if let Some(rest) = trimmed.strip_prefix("config ") {
                depth = 1;
                current_path = Some(rest.trim().to_owned());
                current_body.clear();
                continue;
            }
            // Skip non-config content at top level (banner
            // comments, blank lines).
            continue;
        }

        // Inside a section. `config` on its own line (only `edit`
        // sub-blocks here) increments depth; `end` decrements;
        // the outermost `end` closes the section.
        if trimmed == "end" {
            depth -= 1;
            if depth == 0 {
                if let Some(path) = current_path.take() {
                    out.push(ConfigSection {
                        path,
                        body: current_body.trim_end().to_owned(),
                    });
                }
                current_body.clear();
                continue;
            }
        } else if trimmed.starts_with("config ") {
            depth += 1;
        }
        // Within a section — keep the line.
        current_body.push_str(raw_line);
        current_body.push('\n');
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionStatus {
    /// Section in template but not on device — would create.
    Added,
    /// Section on device but not in template — template doesn't touch it.
    /// Most common case; we don't surface these in the headline diff
    /// to avoid overwhelming the user with the device's full config.
    DeviceOnly,
    /// Section bodies match (after normalisation).
    Equal,
    /// Both have it but bodies differ — would update.
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDiff {
    pub path: String,
    pub status: SectionStatus,
    pub template_body: Option<String>,
    pub device_body: Option<String>,
    /// Unified diff (template-as-newer, device-as-older). Empty
    /// when status is Equal or DeviceOnly.
    pub unified_diff: String,
}

/// Compute section-level diffs between a rendered template and
/// the live device config. Both are passed as raw text — the
/// daemon fetches the device side via SSH `show full-configuration`
/// before calling this.
pub fn diff_sections(template: &str, device: &str) -> Vec<SectionDiff> {
    let tmpl_sections = parse_sections(template);
    let dev_sections = parse_sections(device);

    // Build maps for O(1) lookup. FortiOS path strings are stable;
    // we don't need fuzzy matching.
    let mut dev_map: std::collections::HashMap<String, String> = dev_sections
        .into_iter()
        .map(|s| (s.path, s.body))
        .collect();

    let mut out: Vec<SectionDiff> = Vec::new();

    for tmpl in tmpl_sections {
        if let Some(dev_body) = dev_map.remove(&tmpl.path) {
            let normalised_tmpl = normalise(&tmpl.body);
            let normalised_dev = normalise(&dev_body);
            if normalised_tmpl == normalised_dev {
                out.push(SectionDiff {
                    path: tmpl.path,
                    status: SectionStatus::Equal,
                    template_body: Some(tmpl.body),
                    device_body: Some(dev_body),
                    unified_diff: String::new(),
                });
            } else {
                let diff = unified_diff(&dev_body, &tmpl.body, &tmpl.path);
                out.push(SectionDiff {
                    path: tmpl.path,
                    status: SectionStatus::Modified,
                    template_body: Some(tmpl.body),
                    device_body: Some(dev_body),
                    unified_diff: diff,
                });
            }
        } else {
            // Template would create this section.
            let diff = unified_diff("", &tmpl.body, &tmpl.path);
            out.push(SectionDiff {
                path: tmpl.path,
                status: SectionStatus::Added,
                template_body: Some(tmpl.body),
                device_body: None,
                unified_diff: diff,
            });
        }
    }

    // Remaining device sections — not touched by template. We
    // report them as `DeviceOnly` only if the user opts into
    // verbose mode; for v1 we simply omit them. This keeps the
    // diff scope to "what the template would change", not "every
    // setting on the device".

    out
}

/// Normalise a section body for comparison: trim trailing
/// whitespace per line, collapse runs of blank lines, strip
/// leading indentation. FortiOS config dumps come back with 4-
/// space indents while template output uses tabs or different
/// indent — without normalisation every section would diff just
/// for whitespace.
fn normalise(body: &str) -> String {
    let mut out = String::new();
    let mut last_blank = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !last_blank {
                out.push('\n');
                last_blank = true;
            }
            continue;
        }
        last_blank = false;
        out.push_str(trimmed);
        out.push('\n');
    }
    out
}

/// Tiny unified-diff implementation. We don't pull in the
/// `similar` crate just for this — section bodies are at most a
/// few dozen lines, the simple line-by-line diff is sufficient
/// for the GUI's preview rendering. For larger sections the GUI
/// can fall back to side-by-side view.
fn unified_diff(old: &str, new: &str, path: &str) -> String {
    use std::fmt::Write;
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let lcs = longest_common_subsequence(&old_lines, &new_lines);
    let mut out = String::new();
    let _ = writeln!(out, "--- device: {path}");
    let _ = writeln!(out, "+++ template: {path}");
    let mut oi = 0usize;
    let mut ni = 0usize;
    let mut li = 0usize;
    while oi < old_lines.len() || ni < new_lines.len() {
        // Common line — copy through as context.
        if li < lcs.len()
            && oi < old_lines.len()
            && ni < new_lines.len()
            && old_lines[oi] == lcs[li]
            && new_lines[ni] == lcs[li]
        {
            let _ = writeln!(out, " {}", old_lines[oi]);
            oi += 1;
            ni += 1;
            li += 1;
            continue;
        }
        // Deletion from old.
        if oi < old_lines.len()
            && (li >= lcs.len() || old_lines[oi] != lcs[li])
        {
            let _ = writeln!(out, "-{}", old_lines[oi]);
            oi += 1;
            continue;
        }
        // Addition to new.
        if ni < new_lines.len()
            && (li >= lcs.len() || new_lines[ni] != lcs[li])
        {
            let _ = writeln!(out, "+{}", new_lines[ni]);
            ni += 1;
            continue;
        }
        break;
    }
    out
}

/// LCS via dynamic programming. O(n*m) which is fine for our
/// section sizes (< 200 lines typically).
fn longest_common_subsequence<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<&'a str> {
    let n = a.len();
    let m = b.len();
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            if a[i] == b[j] {
                dp[i + 1][j + 1] = dp[i][j] + 1;
            } else {
                dp[i + 1][j + 1] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }
    let mut out = Vec::with_capacity(dp[n][m]);
    let mut i = n;
    let mut j = m;
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            out.push(a[i - 1]);
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    out.reverse();
    out
}

// ---------------------------------------------------------------------------
// Deployment persistence
// ---------------------------------------------------------------------------

/// One record per attempted deploy. Persisted under
/// `~/Library/Application Support/SuperManager/deployments/<host_id>/<id>.json`.
/// `backup_path` points to the saved pre-deploy snapshot which
/// we restore from on rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub host_id: String,
    pub customer_slug: String,
    pub site_id: String,
    pub template_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: DeploymentStatus,
    /// Path to the saved pre-deploy backup `.conf` file.
    pub backup_path: Option<String>,
    /// The rendered template that we tried (or are about) to push.
    pub rendered_config: String,
    /// When acknowledgment_checked is true, commands followed by a valid prompt.
    /// The next line after a failure may have applied without acknowledgment.
    pub lines_pushed: u64,
    /// Distinguishes measured progress from older records' estimated counts.
    #[serde(default)]
    pub acknowledgment_checked: bool,
    /// Captured target and backup digest are required for automated restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_snapshot: Option<supermgr_core::host::Host>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_from_deployment_id: Option<String>,
    /// Last device error message if status == Failed.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Running,
    Succeeded,
    Failed,
    /// User clicked rollback — the backup_path was restored.
    RolledBack,
}

fn deployments_dir(host_id: &str) -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("deployments");
    p.push(host_id);
    p
}

fn save_deployment(record: &Deployment) -> Result<()> {
    let dir = deployments_dir(&record.host_id);
    std::fs::create_dir_all(&dir).context("create deployments dir")?;
    write_deployment_in(&dir, record)
}

fn write_deployment_in(dir: &std::path::Path, record: &Deployment) -> Result<()> {
    use std::io::Write;
    let id = uuid::Uuid::parse_str(&record.id).context("invalid deployment ID")?;
    let path = dir.join(format!("{}.json", id.simple()));
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(&serde_json::to_vec_pretty(record)?)?;
    file.as_file().sync_all()?;
    file.persist(&path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

pub fn list_deployments(host_id: &str, limit: usize) -> Result<Vec<Deployment>> {
    let expected_host = uuid::Uuid::parse_str(host_id).context("invalid host ID")?;
    let dir = deployments_dir(&expected_host.simple().to_string());
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Deployment> = Vec::new();
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(d) = serde_json::from_slice::<Deployment>(&bytes) {
                if uuid::Uuid::parse_str(&d.host_id).ok() == Some(expected_host) {
                    out.push(d);
                }
            }
        }
    }
    out.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    if out.len() > limit {
        out.truncate(limit);
    }
    Ok(out)
}

pub fn load_deployment(host_id: &str, deployment_id: &str) -> Result<Deployment> {
    let mut path = deployments_dir(host_id);
    path.push(format!("{deployment_id}.json"));
    let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ---------------------------------------------------------------------------
// Backup & deploy
// ---------------------------------------------------------------------------

/// Backup directory — separate from the deployment record JSONs
/// because backups are large (.conf files can be 100s of KB) and
/// we want them on a path the user can browse easily.
fn backups_dir(host_id: &str) -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("backups");
    p.push(host_id);
    p
}

/// Pull `show full-configuration` over SSH, save to disk, return
/// the path. Used both standalone (manual backup) and as the
/// pre-deploy snapshot of safe_deploy.
pub async fn pre_deploy_backup(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    host_id: uuid::Uuid,
) -> Result<String> {
    let (_host, session) = open_session(state, secrets, host_id).await?;
    let cfg = fetch_full_config(&session).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await;
    write_private_backup(&host_id.simple().to_string(), &cfg?)
}

/// Convenience: open SSH to the host, return the session +
/// host record. Splits the session-open from the work so callers
/// can hold the session across multiple FortiOS commands without
/// repeated handshakes.
async fn open_session(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    host_id: uuid::Uuid,
) -> Result<(supermgr_core::host::Host, crate::ssh::connection::SshSession)> {
    crate::server::connect_to_host_owned(state, secrets, host_id)
        .await
        .map_err(|e| anyhow!("ssh connect: {e}"))
}

fn write_private_backup(host_id: &str, config: &str) -> Result<String> {
    let dir = backups_dir(host_id);
    write_private_backup_in(&dir, config)
}

fn write_private_backup_in(dir: &std::path::Path, config: &str) -> Result<String> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("backup-{}.conf", uuid::Uuid::new_v4()));
    let mut file = tempfile::NamedTempFile::new_in(&dir)?;
    file.write_all(config.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&path)?;
    #[cfg(unix)]
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(path.to_string_lossy().into_owned())
}

async fn fetch_full_config(
    session: &crate::ssh::connection::SshSession,
) -> Result<String> {
    let (status, stdout, stderr) = tokio::time::timeout(
        std::time::Duration::from_secs(60), session.exec("show full-configuration")
    ).await.context("configuration read timed out")??;
    validate_config_response(status, &stdout, &stderr)?;
    Ok(stdout)
}

fn validate_config_response(status: u32, stdout: &str, stderr: &str) -> Result<()> {
    if status != 0 || !stderr.trim().is_empty() || !stdout.lines().any(|l| l.trim_start().starts_with("config "))
        || stdout.contains("Command fail") || stdout.contains("Command parse error") {
        bail!("Device did not return a valid full configuration; preview/deploy aborted");
    }
    Ok(())
}

async fn target_snapshot(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    host_id: uuid::Uuid,
    request: &RenderRequest,
) -> Result<(supermgr_core::host::Host, Customer)> {
    crate::customer::validate_slug(&request.customer_slug)?;
    let customers = crate::customer::list_all_strict()?;
    let hosts: Vec<_> = state.lock().await.ssh_hosts.values().cloned().collect();
    let customer = plans::validate_target(&hosts, &customers, host_id, request)?.clone();
    let host = hosts.into_iter().find(|h| h.id == host_id).ok_or_else(|| anyhow!("host not found"))?;
    Ok((host, customer))
}

/// Build a bounded, single-use plan from one target/customer snapshot.
/// Deployment uses these bytes, never a second rendering of mutable inputs.
pub(crate) async fn diff_preview(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    registry: &plans::PlanRegistry,
    host_id: uuid::Uuid,
    request: &RenderRequest,
) -> Result<DiffPreviewResult> {
    let (host, customer) = target_snapshot(state, host_id, request).await?;
    let template = list_templates()?.into_iter().find(|t| t.id == request.template_id)
        .ok_or_else(|| anyhow!("template not found"))?;
    if template.vendor != "fortigate" { bail!("Only FortiGate templates can be deployed over this path"); }
    let site = customer.sites.iter().find(|s| s.id == request.site_id).ok_or_else(|| anyhow!("site not found"))?;
    let render = render_with_customer(&customer, site, &request.template_id, &request.extras)?;
    let (_, session) = crate::server::connect_host_snapshot(state, secrets, host.clone()).await?;
    let live_result = fetch_full_config(&session).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await;
    let live = live_result?;
    let sections = diff_sections(&render.output, &live);
    let summary = summarise_sections(&sections);
    let plan = plans::Plan::new(host, customer, request.clone(), render.output.clone(), &live)?;
    let plan_id = registry.insert(plan)?.to_string();
    Ok(DiffPreviewResult { plan_id, rendered: render.output, sections, summary })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffPreviewResult {
    pub plan_id: String,
    /// The full rendered template — handed back so the GUI's
    /// "deploy this" call can reference what it preview'd
    /// (avoids a re-render race if the customer changes mid-
    /// flight).
    pub rendered: String,
    pub sections: Vec<SectionDiff>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: u32,
    pub modified: u32,
    pub equal: u32,
    pub total: u32,
}

fn summarise_sections(sections: &[SectionDiff]) -> DiffSummary {
    let mut added = 0;
    let mut modified = 0;
    let mut equal = 0;
    for s in sections {
        match s.status {
            SectionStatus::Added => added += 1,
            SectionStatus::Modified => modified += 1,
            SectionStatus::Equal => equal += 1,
            SectionStatus::DeviceOnly => {}
        }
    }
    DiffSummary {
        added,
        modified,
        equal,
        total: sections.len() as u32,
    }
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

/// Consume an approved preview and deploy its immutable bytes to its host snapshot.
/// A failed attempt requires a fresh preview. The target lease prevents overlapping
/// plan deployments, including requests on different RPC connections.
pub(crate) async fn deploy(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    registry: &std::sync::Arc<plans::PlanRegistry>,
    plan_id: uuid::Uuid,
) -> Result<Deployment> {
    let (plan, _lease) = registry.take(plan_id)?;
    let host_id = plan.host.id;
    let request = &plan.request;
    let (host, customer) = target_snapshot(state, host_id, request).await?;
    plan.validate_current(&host, &customer)?;
    let host_str = host_id.simple().to_string();
    let id = uuid::Uuid::new_v4().simple().to_string();

    let mut record = Deployment {
        id: id.clone(),
        host_id: host_str.clone(),
        customer_slug: request.customer_slug.clone(),
        site_id: request.site_id.clone(),
        template_id: request.template_id.clone(),
        started_at: chrono::Utc::now(),
        finished_at: None,
        status: DeploymentStatus::Running,
        backup_path: None,
        rendered_config: plan.rendered.clone(),
        lines_pushed: 0,
        acknowledgment_checked: false,
        target_snapshot: Some(plan.host.clone()),
        backup_sha256: None,
        restored_from_deployment_id: match &plan.operation {
            plans::PlanOperation::DeployTemplate => None,
            plans::PlanOperation::RestoreBackup { source_deployment_id } => Some(source_deployment_id.clone()),
        },
        error: None,
    };
    save_deployment(&record)?;

    // One connection for live-state validation, backup and push. A host edit
    // cannot redirect the second half of the operation to a different endpoint.
    let prepare = async {
        let (_, session) = crate::server::connect_host_snapshot(state, secrets, plan.host.clone()).await?;
        let preparation = async {
            let live = fetch_full_config(&session).await?;
            plan.validate_live(&live)?;
            let (host, customer) = target_snapshot(state, host_id, request).await?;
            plan.validate_current(&host, &customer)?;
            let backup_path = write_private_backup(&host_str, &live)?;
            Ok::<_, anyhow::Error>((backup_path, config_digest(&live)))
        }.await;
        match preparation {
            Ok((path, digest)) => Ok((session, path, digest)),
            Err(e) => { let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await; Err(e) }
        }
    }.await;
    let (session, backup_path, backup_digest) = match prepare {
        Ok(value) => value,
        Err(e) => {
            record.status = DeploymentStatus::Failed;
            record.error = Some(format!("pre-deploy validation/backup failed: {e:#}"));
            record.finished_at = Some(chrono::Utc::now());
            save_deployment(&record)?;
            return Err(e);
        }
    };
    record.backup_path = Some(backup_path);
    record.backup_sha256 = Some(backup_digest);
    if let Err(e) = save_deployment(&record) {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await;
        return Err(e);
    }
    // Send every reviewed line in order; do not re-render or silently filter commands.
    let lines: Vec<&str> = plan.rendered.lines().collect();

    let result = session.shell_config(&lines, 120).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await;
    let status = match plan.operation {
        plans::PlanOperation::DeployTemplate => DeploymentStatus::Succeeded,
        plans::PlanOperation::RestoreBackup { .. } => DeploymentStatus::RolledBack,
    };
    apply_shell_result(&mut record, result, status);
    save_deployment(&record)?;
    Ok(record)
}

/// `lines_pushed` is retained on the wire for compatibility, but now counts
/// acknowledged lines, not attempted writes or an estimate of the entire input.
fn apply_shell_result(
    record: &mut Deployment,
    result: std::result::Result<crate::ssh::shell::ShellOutput, crate::ssh::shell::ShellFailure>,
    success_status: DeploymentStatus,
) {
    record.finished_at = Some(chrono::Utc::now());
    record.acknowledgment_checked = true;
    match result {
        Ok(output) => {
            record.status = success_status;
            record.lines_pushed = output.acknowledged_lines as u64;
            record.error = None;
        }
        Err(error) => {
            record.status = DeploymentStatus::Failed;
            record.lines_pushed = error.acknowledged_lines as u64;
            record.error = Some(error.to_string());
        }
    }
}

fn config_digest(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Open once without following the final symlink. O_NONBLOCK prevents a
/// replaced FIFO from hanging the daemon before we can check the file type.
fn read_restore_file(path: &std::path::Path, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open restore source")?;
    if !file.metadata()?.is_file() { bail!("Restore source must be a regular file"); }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit { bail!("Restore source exceeds size limit"); }
    Ok(text)
}

fn verified_backup(
    record: &Deployment,
    host: &supermgr_core::host::Host,
    request: &RenderRequest,
    expected_dir: &std::path::Path,
) -> Result<String> {
    if uuid::Uuid::parse_str(&record.host_id)? != host.id
        || record.customer_slug != request.customer_slug || record.site_id != request.site_id {
        bail!("Backup belongs to a different host, customer or site");
    }
    let captured = record.target_snapshot.as_ref().ok_or_else(|| anyhow!("Legacy backup has no captured target; automated restore is unavailable"))?;
    if serde_json::to_value(captured)? != serde_json::to_value(host)? {
        bail!("Host changed since backup; automated restore is unavailable");
    }
    let digest = record.backup_sha256.as_ref().ok_or_else(|| anyhow!("Legacy backup has no integrity digest; automated restore is unavailable"))?;
    let path = std::path::Path::new(record.backup_path.as_deref().ok_or_else(|| anyhow!("Deployment has no backup"))?);
    if path.parent() != Some(expected_dir) || path.file_name().is_none() {
        bail!("Backup path is outside this host's backup directory");
    }
    let text = read_restore_file(path, 2 * 1024 * 1024)?;
    if config_digest(&text) != *digest { bail!("Backup changed or is corrupt; restore aborted"); }
    validate_config_response(0, &text, "")?;
    Ok(text)
}

/// Restore is a previewed command replay, not a FortiOS replacement transaction.
/// Input is a deployment ID and explicit scope, never an arbitrary file path.
pub(crate) async fn restore_preview(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    registry: &plans::PlanRegistry,
    host_id: uuid::Uuid,
    deployment_id: uuid::Uuid,
    customer_slug: String,
    site_id: String,
) -> Result<DiffPreviewResult> {
    let record_path = deployments_dir(&host_id.simple().to_string()).join(format!("{}.json", deployment_id.simple()));
    let record: Deployment = serde_json::from_str(&read_restore_file(&record_path, 4 * 1024 * 1024)?)?;
    if uuid::Uuid::parse_str(&record.id)? != deployment_id { bail!("Deployment record ID mismatch"); }
    let request = RenderRequest { template_id: record.template_id.clone(), customer_slug, site_id, extras: Default::default() };
    let (host, customer) = target_snapshot(state, host_id, &request).await?;
    let rendered = verified_backup(&record, &host, &request, &backups_dir(&host_id.simple().to_string()))?;
    let (_, session) = crate::server::connect_host_snapshot(state, secrets, host.clone()).await?;
    let live = fetch_full_config(&session).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session.disconnect()).await;
    let live = live?;
    let sections = diff_sections(&rendered, &live);
    let summary = summarise_sections(&sections);
    let mut plan = plans::Plan::new(host, customer, request, rendered.clone(), &live)?;
    plan.operation = plans::PlanOperation::RestoreBackup { source_deployment_id: deployment_id.simple().to_string() };
    let plan_id = registry.insert(plan)?.to_string();
    Ok(DiffPreviewResult { plan_id, rendered, sections, summary })
}

/// Register filters that templates rely on. We keep these tightly
/// scoped — generic enough to be useful, specific enough that
/// template authors don't need a Tera reference manual to use
/// them.
fn register_filters(tera: &mut Tera) {
    // `slugify` — produce a FortiOS-safe hostname or label. Strips
    // anything that isn't ASCII alphanumeric or hyphen, replaces
    // whitespace + commas + slashes with hyphens, collapses runs of
    // hyphens, lowercases. FortiOS hostnames are limited to
    // [a-zA-Z0-9-] without leading/trailing hyphen — this filter
    // outputs exactly that.
    tera.register_filter(
        "slugify",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let text = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("slugify requires a string"))?;
            let mut out = String::with_capacity(text.len());
            let mut last_dash = true;
            for ch in text.chars() {
                if ch.is_ascii_alphanumeric() {
                    out.push(ch.to_ascii_lowercase());
                    last_dash = false;
                } else if !last_dash {
                    out.push('-');
                    last_dash = true;
                }
            }
            while out.ends_with('-') {
                out.pop();
            }
            if out.is_empty() {
                out.push_str("device");
            }
            // Truncate at 35 chars — FortiOS hostname limit is 35.
            if out.len() > 35 {
                out.truncate(35);
                while out.ends_with('-') {
                    out.pop();
                }
            }
            Ok(tera::Value::String(out))
        },
    );

    // `cidr_first_host` — given "10.0.10.0/24" returns "10.0.10.1"
    // (the first usable host IP). Used for DHCP default-gateway
    // and similar settings. Errors if the input isn't a CIDR.
    tera.register_filter(
        "cidr_first_host",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let cidr = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("cidr_first_host requires a string"))?;
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts.first().copied().unwrap_or("");
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(tera::Error::msg("cidr_first_host: expected dotted-quad"));
            }
            let last: u32 = octets[3].parse().unwrap_or(0);
            Ok(tera::Value::String(format!(
                "{}.{}.{}.{}",
                octets[0], octets[1], octets[2], last + 1
            )))
        },
    );

    // `cidr_dhcp_start` — given "10.0.10.0/24" returns "10.0.10.50"
    // (the first .50 to leave room for static reservations 1-49).
    // Convention chosen so admins have predictable static-block
    // headroom without per-template thought.
    tera.register_filter(
        "cidr_dhcp_start",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let cidr = value.as_str().ok_or_else(|| tera::Error::msg("cidr_dhcp_start requires a string"))?;
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts.first().copied().unwrap_or("");
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(tera::Error::msg("cidr_dhcp_start: expected dotted-quad"));
            }
            Ok(tera::Value::String(format!(
                "{}.{}.{}.50",
                octets[0], octets[1], octets[2]
            )))
        },
    );

    // `cidr_dhcp_end` — last `.250` of a /24 (leaves .251-.254 for
    // statically-assigned servers / printers / APs).
    tera.register_filter(
        "cidr_dhcp_end",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let cidr = value.as_str().ok_or_else(|| tera::Error::msg("cidr_dhcp_end requires a string"))?;
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts.first().copied().unwrap_or("");
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(tera::Error::msg("cidr_dhcp_end: expected dotted-quad"));
            }
            Ok(tera::Value::String(format!(
                "{}.{}.{}.250",
                octets[0], octets[1], octets[2]
            )))
        },
    );

    // `cidr_netmask` — given "10.0.10.0/24" returns "255.255.255.0".
    // Used by FortiOS DHCP server which wants explicit netmask
    // separately from the IP+CIDR.
    tera.register_filter(
        "cidr_netmask",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let cidr = value.as_str().ok_or_else(|| tera::Error::msg("cidr_netmask requires a string"))?;
            let parts: Vec<&str> = cidr.split('/').collect();
            let prefix: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
            let mask = if prefix == 0 { 0u32 } else { (!0u32) << (32 - prefix) };
            Ok(tera::Value::String(format!(
                "{}.{}.{}.{}",
                (mask >> 24) & 0xff,
                (mask >> 16) & 0xff,
                (mask >> 8) & 0xff,
                mask & 0xff,
            )))
        },
    );

    // `comment(width=80, char='-')` filter: format a banner-style
    // CLI comment line. Used for section headers in FortiOS configs.
    tera.register_filter(
        "banner",
        |value: &tera::Value, _args: &std::collections::HashMap<String, tera::Value>| {
            let text = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("banner filter requires a string"))?;
            let width = 60;
            let line = "=".repeat(width);
            let padding = (width.saturating_sub(text.len() + 2)) / 2;
            let pad = " ".repeat(padding);
            Ok(tera::Value::String(format!(
                "# {line}\n# {pad}{text}{pad}\n# {line}"
            )))
        },
    );
    // `replace_octet(prefix='10.0', n)` — derive a /24 from a
    // base CIDR and an octet. Cheap subnet-derivation that works
    // for the common branch-office case without pulling in ipnet
    // into a Tera filter.
    tera.register_filter(
        "third_octet",
        |value: &tera::Value, args: &std::collections::HashMap<String, tera::Value>| {
            let cidr = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("third_octet requires a string CIDR"))?;
            let n = args
                .get("n")
                .and_then(tera::Value::as_u64)
                .ok_or_else(|| tera::Error::msg("third_octet requires arg 'n'"))?;
            // Crude — just splits on dots and rewrites the third
            // octet. "10.0.0.0/24" + n=10 → "10.0.10.0/24".
            let parts: Vec<&str> = cidr.split('.').collect();
            if parts.len() != 4 {
                return Err(tera::Error::msg("third_octet: expected dotted-quad CIDR"));
            }
            let last_with_mask = parts[3];
            Ok(tera::Value::String(format!(
                "{}.{}.{}.{}",
                parts[0], parts[1], n, last_with_mask
            )))
        },
    );
}

#[cfg(test)]
mod approval_io_tests {
    use super::*;
    #[test]
    fn failed_or_empty_config_reads_cannot_be_backups_or_previews() {
        assert!(validate_config_response(0, "config system global\nend\n", "").is_ok());
        for (code, out, err) in [(1, "config system global\nend", ""), (0, "", ""),
            (0, "permission denied", ""), (0, "config x\nCommand fail", ""),
            (0, "config x\nend", "permission denied")] {
            assert!(validate_config_response(code, out, err).is_err());
        }
    }
    #[test]
    fn backups_are_unique_complete_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_private_backup_in(dir.path(), "secret config one").unwrap();
        let second = write_private_backup_in(dir.path(), "secret config two").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "secret config one");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "secret config two");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(first).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}

#[cfg(test)]
mod shell_outcome_tests {
    use super::*;
    fn legacy_record() -> Deployment {
        serde_json::from_value(serde_json::json!({
            "id":"record", "host_id":"host", "customer_slug":"acme", "site_id":"hq",
            "template_id":"test", "started_at":"2026-09-09T00:00:00Z", "status":"succeeded",
            "rendered_config":"first\nsecond\nthird", "lines_pushed":3
        })).unwrap()
    }
    #[test]
    fn legacy_progress_is_not_reinterpreted_as_acknowledged() {
        assert!(!legacy_record().acknowledgment_checked);
    }
    #[test]
    fn partial_failure_is_failed_with_measured_progress_and_uncertain_line() {
        let mut record = legacy_record();
        apply_shell_result(&mut record, Err(crate::ssh::shell::ShellFailure {
            acknowledged_lines:1, line:Some(2), reason:"SSH channel closed before acknowledgment"
        }), DeploymentStatus::Succeeded);
        assert!(matches!(record.status, DeploymentStatus::Failed));
        assert!(record.acknowledgment_checked);
        assert_eq!(record.lines_pushed, 1);
        assert!(record.finished_at.is_some());
        assert!(record.error.unwrap().contains("may have been applied"));
    }
    #[test]
    fn restore_results_only_mark_success_after_all_acknowledgments() {
        let mut record = legacy_record();
        apply_shell_result(&mut record, Ok(crate::ssh::shell::ShellOutput {
            transcript:String::new(), acknowledged_lines:3
        }), DeploymentStatus::RolledBack);
        assert!(matches!(record.status, DeploymentStatus::RolledBack));
        assert!(record.acknowledgment_checked);
        assert_eq!(record.lines_pushed, 3);
        assert!(record.error.is_none());
        apply_shell_result(&mut record, Err(crate::ssh::shell::ShellFailure {
            acknowledged_lines:0, line:None, reason:"SSH shell setup failed"
        }), DeploymentStatus::RolledBack);
        assert!(matches!(record.status, DeploymentStatus::Failed));
        assert_eq!(record.lines_pushed, 0);
    }
}

#[cfg(test)]
mod restore_safety_tests {
    use super::*;
    fn fixture(dir: &std::path::Path) -> (Deployment, supermgr_core::host::Host, RenderRequest) {
        let host: supermgr_core::host::Host = serde_json::from_value(serde_json::json!({
            "id":uuid::Uuid::new_v4(), "label":"FW", "hostname":"10.0.0.1", "username":"admin", "auth_method":"password"
        })).unwrap();
        let text = "config system global\nset hostname reviewed\nend\n";
        let path = dir.join("backup.conf"); std::fs::write(&path, text).unwrap();
        let record: Deployment = serde_json::from_value(serde_json::json!({
            "id":uuid::Uuid::new_v4(), "host_id":host.id, "customer_slug":"acme", "site_id":"hq",
            "template_id":"test", "started_at":"2026-09-09T00:00:00Z", "status":"failed",
            "rendered_config":"", "lines_pushed":0, "backup_path":path,
            "target_snapshot":host, "backup_sha256":config_digest(text)
        })).unwrap();
        let request = RenderRequest {template_id:"test".into(), customer_slug:"acme".into(), site_id:"hq".into(), extras:Default::default()};
        (record, host, request)
    }
    #[test]
    fn restore_requires_exact_host_scope_and_captured_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (record, host, request) = fixture(dir.path());
        assert!(verified_backup(&record, &host, &request, dir.path()).is_ok());
        let mut wrong = request.clone(); wrong.customer_slug = "other".into();
        assert!(verified_backup(&record, &host, &wrong, dir.path()).is_err());
        wrong = request.clone(); wrong.site_id = "other".into();
        assert!(verified_backup(&record, &host, &wrong, dir.path()).is_err());
        let mut moved = host.clone(); moved.hostname = "wrong-device".into();
        assert!(verified_backup(&record, &moved, &request, dir.path()).is_err());
        moved = host.clone(); moved.id = uuid::Uuid::new_v4();
        assert!(verified_backup(&record, &moved, &request, dir.path()).is_err());
    }
    #[test]
    fn changed_legacy_and_other_host_backups_fail_closed() {
        let dir = tempfile::tempdir().unwrap(); let other = tempfile::tempdir().unwrap();
        let (record, host, request) = fixture(dir.path());
        assert!(verified_backup(&record, &host, &request, other.path()).is_err());
        let mut legacy = record.clone(); legacy.target_snapshot = None;
        assert!(verified_backup(&legacy, &host, &request, dir.path()).is_err());
        legacy = record.clone(); legacy.backup_sha256 = None;
        assert!(verified_backup(&legacy, &host, &request, dir.path()).is_err());
        std::fs::write(record.backup_path.as_ref().unwrap(), "config changed\nend").unwrap();
        assert!(verified_backup(&record, &host, &request, dir.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_and_non_regular_files_are_not_restore_sources() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let (record, host, request) = fixture(dir.path());
        let path = std::path::Path::new(record.backup_path.as_ref().unwrap());
        let moved = dir.path().join("actual.conf"); std::fs::rename(path, &moved).unwrap();
        symlink(&moved, path).unwrap();
        assert!(verified_backup(&record, &host, &request, dir.path()).is_err());
        assert!(read_restore_file(dir.path(), 1024).is_err());
        use std::os::unix::ffi::OsStrExt;
        let fifo_path = dir.path().join("pipe.conf");
        let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the C string is NUL terminated and alive for this syscall.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(read_restore_file(&fifo_path, 1024).is_err());
    }
    #[test]
    fn restore_files_are_bounded_and_record_updates_are_private_atomic_replacements() {
        let dir = tempfile::tempdir().unwrap(); let (mut record, _, _) = fixture(dir.path());
        assert!(read_restore_file(std::path::Path::new(record.backup_path.as_ref().unwrap()), 2).is_err());
        write_deployment_in(dir.path(), &record).unwrap();
        let path = dir.path().join(format!("{}.json", uuid::Uuid::parse_str(&record.id).unwrap().simple()));
        record.status = DeploymentStatus::Succeeded;
        write_deployment_in(dir.path(), &record).unwrap();
        let saved: Deployment = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(matches!(saved.status, DeploymentStatus::Succeeded));
        assert_eq!(saved.backup_sha256, record.backup_sha256);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    #[test]
    fn restore_approval_keeps_reviewed_bytes_when_source_file_changes() {
        let dir = tempfile::tempdir().unwrap(); let (record, host, request) = fixture(dir.path());
        let reviewed = verified_backup(&record, &host, &request, dir.path()).unwrap();
        let customer: Customer = serde_json::from_value(serde_json::json!({
            "slug":"acme", "display_name":"Acme", "sites":[{"id":"hq", "display_name":"HQ"}]
        })).unwrap();
        let mut plan = plans::Plan::new(host, customer, request, reviewed.clone(), "live").unwrap();
        plan.operation = plans::PlanOperation::RestoreBackup { source_deployment_id:record.id.clone() };
        let registry = std::sync::Arc::new(plans::PlanRegistry::default());
        let id = registry.insert(plan).unwrap();
        std::fs::write(record.backup_path.unwrap(), "changed after approval").unwrap();
        let (approved, _lease) = registry.take(id).unwrap();
        assert_eq!(approved.rendered, reviewed);
        assert!(matches!(approved.operation, plans::PlanOperation::RestoreBackup { source_deployment_id } if source_deployment_id == record.id));
        assert!(registry.take(id).is_err());
    }

}
