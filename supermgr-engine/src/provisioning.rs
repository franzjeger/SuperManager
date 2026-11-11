//! Template engine for `FortiGate` / `UniFi` configuration generation.
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
//! # Why pure rendering, not pushing
//!
//! Render and Deploy are kept separate so the user always sees
//! what would change before anything hits the device. Phase 6
//! adds a `provisioning_diff_preview` RPC that pulls live config
//! and renders unified-diff against the rendered template; phase
//! 6 also adds `provisioning_safe_deploy` which uses `FortiOS`'s
//! `revert-on-no-confirm` to roll back automatically if the
//! deploy breaks SSH/API connectivity.
//!
//! For now the GUI exposes "Render → Copy" so the user can paste
//! into a `FortiGate` console session manually. That alone replaces
//! the bulk of the Linux wizard's value while keeping the trust
//! model conservative.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tera::{Context as TeraContext, Tera};

use crate::customer::{Customer, Site};
use crate::ssh::connection::ShellInput;
use supermgr_core::error::SshError;

mod plans;
pub use plans::PlanRegistry;

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
    /// "`branch_office`" / "hq" / "retail" / "datacenter" / "custom".
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
    /// The rendered config (`FortiOS` CLI for `FortiGate` templates,
    /// JSON for `UniFi` controller calls).
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

/// Built-in templates. Each (id, `display_name`, description,
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
    supermgr_core::sanitize::validate_safe_ident(template_id, "template_id")
        .map_err(|e| anyhow!("{e}"))?;
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

const SECRET_EXTRA_KEYS: &[&str] = &[
    "vpn_psk",
    "vpn_admin_password",
    "pppoe_password",
    "radius_secret",
    "s2s_psk",
    "wifi_password",
];

fn validate_secret_value(key: &str, raw: &str) -> Result<()> {
    let trimmed = raw.trim();
    if trimmed.len() < 8 {
        return Err(anyhow!(
            "extras.{key} must be at least 8 characters long"
        ));
    }
    if raw.chars().any(|c| c.is_control() || c == '"') {
        return Err(anyhow!(
            "extras.{key} must not contain control characters or double quotes"
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "admin" | "password" | "changeme" | "12345678")
        || lower.starts_with("change-me")
    {
        return Err(anyhow!(
            "extras.{key} must not use a placeholder or default value"
        ));
    }
    Ok(())
}

fn require_secret_extra(
    extras: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    template_id: &str,
) -> Result<()> {
    let val = extras
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow!("template '{template_id}' requires secret parameter 'extras.{key}'")
        })?;
    validate_secret_value(key, val)
}

fn validate_template_secrets(
    template_id: &str,
    site: &Site,
    extras: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    for &key in SECRET_EXTRA_KEYS {
        if let Some(val) = extras.get(key) {
            let s = val
                .as_str()
                .ok_or_else(|| anyhow!("extras.{key} must be a string"))?;
            validate_secret_value(key, s)?;
        }
    }

    match template_id {
        "fortigate.branch_office" => {
            require_secret_extra(extras, "vpn_psk", template_id)?;
            require_secret_extra(extras, "vpn_admin_password", template_id)?;
            if site.wan_type == "pppoe" {
                let user = extras
                    .get("pppoe_user")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .unwrap_or("");
                if user.is_empty()
                    || user.eq_ignore_ascii_case("change-me")
                    || user.chars().any(|c| c.is_control() || c == '"')
                {
                    return Err(anyhow!(
                        "template '{template_id}' with PPPoE WAN requires a valid 'extras.pppoe_user'"
                    ));
                }
                require_secret_extra(extras, "pppoe_password", template_id)?;
            }
        }
        "fortigate.hq" => {
            require_secret_extra(extras, "radius_secret", template_id)?;
            require_secret_extra(extras, "vpn_psk", template_id)?;
            let has_s2s = extras
                .get("s2s_peer_ip")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.trim().is_empty());
            if has_s2s {
                require_secret_extra(extras, "s2s_psk", template_id)?;
            }
        }
        "unifi.wifi_basic" => {
            if site.vlans.iter().any(|v| v.purpose != "iot") {
                require_secret_extra(extras, "wifi_password", template_id)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Render a template against a (customer, site) pair. Returns
/// `RenderResult` with the output string. Errors propagate from
/// Tera's parser/renderer with full diagnostic — the GUI surfaces
/// them so the template author knows exactly which line is wrong.
pub fn render(req: &RenderRequest) -> Result<RenderResult> {
    let customer = crate::customer::load(&req.customer_slug)
        .with_context(|| format!("load customer {}", req.customer_slug))?;
    let site = customer
        .sites
        .iter()
        .find(|s| s.id == req.site_id)
        .ok_or_else(|| {
            anyhow!(
                "site '{}' not found in customer '{}'",
                req.site_id,
                req.customer_slug
            )
        })?;
    render_with_customer(&customer, site, &req.template_id, &req.extras)
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
    validate_template_secrets(template_id, site, extras)?;
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

/// `FortiOS` configs are blocks of the form:
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

/// Parse a `FortiOS` config dump (or rendered template) into
/// top-level `config X / end` sections. Comments (`#` / `{#`)
/// and blank lines outside any section are ignored. Lines
/// inside a section are kept verbatim — order matters for
/// `edit` blocks.
#[must_use]
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
    /// when status is Equal or `DeviceOnly`.
    pub unified_diff: String,
}

/// Compute section-level diffs between a rendered template and
/// the live device config. Both are passed as raw text — the
/// daemon fetches the device side via SSH `show full-configuration`
/// before calling this.
#[must_use]
pub fn diff_sections(template: &str, device: &str) -> Vec<SectionDiff> {
    let tmpl_sections = parse_sections(template);
    let dev_sections = parse_sections(device);

    // Build maps for O(1) lookup. FortiOS path strings are stable;
    // we don't need fuzzy matching.
    let mut dev_map: std::collections::HashMap<String, String> =
        dev_sections.into_iter().map(|s| (s.path, s.body)).collect();

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
/// leading indentation. `FortiOS` config dumps come back with 4-
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
        if oi < old_lines.len() && (li >= lcs.len() || old_lines[oi] != lcs[li]) {
            let _ = writeln!(out, "-{}", old_lines[oi]);
            oi += 1;
            continue;
        }
        // Addition to new.
        if ni < new_lines.len() && (li >= lcs.len() || new_lines[ni] != lcs[li]) {
            let _ = writeln!(out, "+{}", new_lines[ni]);
            ni += 1;
            continue;
        }
        break;
    }
    out
}

/// Linear-space LCS via common prefix/suffix trimming + Hirschberg's
/// divide-and-conquer algorithm on interned `u32` line IDs.
///
/// Diffing two 10,000-line `FortiOS` configurations used to allocate a
/// dense `(n+1) × (m+1)` `usize` matrix (~800 MB). Trimming shared
/// outer lines, interning + filtering unshared middle lines, and using
/// two `Vec<u32>` DP rows keeps peak memory in the tens of kilobytes.
fn longest_common_subsequence<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<&'a str> {
    let mut prefix = 0usize;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < (a.len() - prefix)
        && suffix < (b.len() - prefix)
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let a_mid = &a[prefix..a.len() - suffix];
    let b_mid = &b[prefix..b.len() - suffix];
    if a_mid.is_empty() || b_mid.is_empty() {
        let mut out = Vec::with_capacity(prefix + suffix);
        out.extend_from_slice(&a[..prefix]);
        out.extend_from_slice(&a[a.len() - suffix..]);
        return out;
    }

    // Intern lines appearing in `a_mid` and filter both sides down to lines
    // that appear on BOTH sides — lines unique to one side can never belong
    // to any common subsequence.
    let mut str_to_id: std::collections::HashMap<&'a str, u32> =
        std::collections::HashMap::with_capacity(a_mid.len());
    let mut id_to_str: Vec<&'a str> = Vec::new();
    let mut a_raw_ids: Vec<u32> = Vec::with_capacity(a_mid.len());
    for &line in a_mid {
        let id = match str_to_id.get(line) {
            Some(&existing) => existing,
            None => {
                let next = id_to_str.len() as u32;
                id_to_str.push(line);
                str_to_id.insert(line, next);
                next
            }
        };
        a_raw_ids.push(id);
    }

    let mut seen_in_b = vec![false; id_to_str.len()];
    let mut b_ids: Vec<u32> = Vec::with_capacity(b_mid.len());
    for &line in b_mid {
        if let Some(&id) = str_to_id.get(line) {
            seen_in_b[id as usize] = true;
            b_ids.push(id);
        }
    }
    let a_ids: Vec<u32> = a_raw_ids
        .into_iter()
        .filter(|&id| seen_in_b[id as usize])
        .collect();

    let mut mid_ids: Vec<u32> = Vec::new();
    hirschberg_lcs(&a_ids, &b_ids, &mut mid_ids);

    let mut out = Vec::with_capacity(prefix + mid_ids.len() + suffix);
    out.extend_from_slice(&a[..prefix]);
    for id in mid_ids {
        out.push(id_to_str[id as usize]);
    }
    out.extend_from_slice(&a[a.len() - suffix..]);
    out
}

/// Two-row forward LCS length vector for `x` against `y`.
fn lcs_row_forward(x: &[u32], y: &[u32]) -> Vec<u32> {
    let mut prev = vec![0u32; y.len() + 1];
    let mut curr = vec![0u32; y.len() + 1];
    for &xi in x {
        curr[0] = 0;
        for (j, &yj) in y.iter().enumerate() {
            curr[j + 1] = if xi == yj {
                prev[j] + 1
            } else {
                curr[j].max(prev[j + 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev
}

/// Two-row reverse LCS length vector for `x.rev()` against `y.rev()`.
fn lcs_row_reverse(x: &[u32], y: &[u32]) -> Vec<u32> {
    let mut prev = vec![0u32; y.len() + 1];
    let mut curr = vec![0u32; y.len() + 1];
    for &xi in x.iter().rev() {
        curr[0] = 0;
        for (j, &yj) in y.iter().rev().enumerate() {
            curr[j + 1] = if xi == yj {
                prev[j] + 1
            } else {
                curr[j].max(prev[j + 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev
}

fn hirschberg_lcs(x: &[u32], y: &[u32], out: &mut Vec<u32>) {
    // Cap adversarial O(n*m) CPU work on huge shuffled-duplicate inputs
    // while keeping exact optimal LCS for all realistic config sections.
    const MAX_CELLS: usize = 25_000_000;

    let mut p = 0usize;
    while p < x.len() && p < y.len() && x[p] == y[p] {
        p += 1;
    }
    if p > 0 {
        out.extend_from_slice(&x[..p]);
    }
    let mut s = 0usize;
    while s < (x.len() - p) && s < (y.len() - p) && x[x.len() - 1 - s] == y[y.len() - 1 - s] {
        s += 1;
    }

    let xm = &x[p..x.len() - s];
    let ym = &y[p..y.len() - s];

    if !xm.is_empty() && !ym.is_empty() {
        if xm.len() == 1 {
            if ym.contains(&xm[0]) {
                out.push(xm[0]);
            }
        } else if ym.len() == 1 {
            if xm.contains(&ym[0]) {
                out.push(ym[0]);
            }
        } else if xm.len().saturating_mul(ym.len()) > MAX_CELLS {
            // Bounded linear fallback for pathological inputs.
            let mut j = 0usize;
            for &xi in xm {
                if let Some(rel) = ym[j..].iter().position(|&yj| yj == xi) {
                    out.push(xi);
                    j += rel + 1;
                }
            }
        } else {
            let mid = xm.len() / 2;
            let split_y = {
                let l1 = lcs_row_forward(&xm[..mid], ym);
                let l2 = lcs_row_reverse(&xm[mid..], ym);
                let m = ym.len();
                let mut best_k = 0usize;
                let mut best_score = 0u32;
                for k in 0..=m {
                    let score = l1[k] + l2[m - k];
                    if score >= best_score {
                        best_score = score;
                        best_k = k;
                    }
                }
                best_k
            };
            hirschberg_lcs(&xm[..mid], &ym[..split_y], out);
            hirschberg_lcs(&xm[mid..], &ym[split_y..], out);
        }
    }

    if s > 0 {
        out.extend_from_slice(&x[x.len() - s..]);
    }
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
    /// Lines pushed successfully. On error, the abort line is
    /// the next one in the `rendered_config`.
    pub lines_pushed: u64,
    /// Last device error message if status == Failed.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Running,
    Succeeded,
    Failed,
    /// User clicked rollback — the `backup_path` was restored.
    RolledBack,
}

fn deployments_dir(host_id: &str) -> Result<PathBuf> {
    supermgr_core::sanitize::validate_safe_ident(host_id, "host_id").map_err(|e| anyhow!("{e}"))?;
    let mut p = crate::secrets::default_data_dir();
    p.push("deployments");
    p.push(host_id);
    Ok(p)
}

fn save_deployment(record: &Deployment) -> Result<()> {
    supermgr_core::sanitize::validate_safe_ident(&record.id, "deployment_id")
        .map_err(|e| anyhow!("{e}"))?;
    let dir = deployments_dir(&record.host_id)?;
    std::fs::create_dir_all(&dir).context("create deployments dir")?;
    let mut path = dir;
    path.push(format!("{}.json", record.id));
    let bytes = serde_json::to_vec_pretty(record)?;
    std::fs::write(&path, bytes).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

pub fn list_deployments(host_id: &str, limit: usize) -> Result<Vec<Deployment>> {
    let dir = deployments_dir(host_id)?;
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
                out.push(d);
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
    supermgr_core::sanitize::validate_safe_ident(deployment_id, "deployment_id")
        .map_err(|e| anyhow!("{e}"))?;
    let mut path = deployments_dir(host_id)?;
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
fn backups_dir(host_id: &str) -> Result<PathBuf> {
    supermgr_core::sanitize::validate_safe_ident(host_id, "host_id").map_err(|e| anyhow!("{e}"))?;
    let mut p = crate::secrets::default_data_dir();
    p.push("backups");
    p.push(host_id);
    Ok(p)
}

/// Pull `show full-configuration` over SSH, save to disk, return
/// the path. Used both standalone (manual backup) and as the
/// pre-deploy snapshot of `safe_deploy`.
pub async fn pre_deploy_backup(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    host_id: uuid::Uuid,
) -> Result<String> {
    let (_host, session) = open_session(state, secrets, host_id).await?;
    let cfg = fetch_full_config(&session).await?;
    let _ = session.disconnect().await;

    let dir = backups_dir(&host_id.simple().to_string())?;
    std::fs::create_dir_all(&dir).context("create backups dir")?;
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let mut path = dir;
    path.push(format!("backup-{timestamp}.conf"));
    std::fs::write(&path, cfg.as_bytes()).with_context(|| format!("write {path:?}"))?;
    let path_str = path.to_string_lossy().into_owned();
    tracing::info!("pre_deploy_backup: saved {path_str} ({} bytes)", cfg.len());
    Ok(path_str)
}

/// Convenience: open SSH to the host, return the session +
/// host record. Splits the session-open from the work so callers
/// can hold the session across multiple `FortiOS` commands without
/// repeated handshakes.
async fn open_session(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    host_id: uuid::Uuid,
) -> Result<(
    supermgr_core::host::Host,
    crate::ssh::connection::SshSession,
)> {
    crate::server::connect_to_host_owned(state, secrets, host_id)
        .await
        .map_err(|e| anyhow!("ssh connect: {e}"))
}

/// The unit's running configuration: the backup a deploy rolls back to,
/// and what a preview diffs against. Whatever else comes back is an error.
async fn fetch_full_config(session: &crate::ssh::connection::SshSession) -> Result<String> {
    // The whole config of a large unit can take a while to print; a
    // backup that doesn't finish aborts the deploy, which is the safe way
    // round.
    let (status, stdout, stderr) = session
        .exec(
            "show full-configuration",
            Some(std::time::Duration::from_secs(300)),
        )
        .await
        .map_err(|e| anyhow!("show full-configuration: {e}"))?;
    if !is_full_config(&stdout) {
        let answer = stderr
            .lines()
            .chain(stdout.lines())
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("nothing");
        return Err(anyhow!(
            "show full-configuration returned no configuration (exit status {status}): {answer}"
        ));
    }
    Ok(stdout)
}

/// Whether `text` is a whole `FortiOS` configuration: top-level `config`
/// blocks, the last one closed by `end`. An error line, an empty answer
/// and output cut off inside a block are not.
fn is_full_config(text: &str) -> bool {
    text.lines().any(|line| line.starts_with("config "))
        && text.lines().map(str::trim).rfind(|line| !line.is_empty()) == Some("end")
}

/// Render → fetch live → diff, for the site's own FortiGate. Returns a
/// structured response the GUI can render as a per-section preview, and
/// the plan a deploy of exactly this configuration takes (`plans`).
pub async fn diff_preview(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    registry: &PlanRegistry,
    host_id: uuid::Uuid,
    request: &RenderRequest,
) -> Result<DiffPreviewResult> {
    let (host, customer) = target(state, host_id, request).await?;
    let site = customer
        .sites
        .iter()
        .find(|s| s.id == request.site_id)
        .ok_or_else(|| anyhow!("site '{}' not found", request.site_id))?;
    let render = render_with_customer(&customer, site, &request.template_id, &request.extras)?;
    let (_host, session) = open_session(state, secrets, host_id).await?;
    let live = fetch_full_config(&session).await?;
    let _ = session.disconnect().await;
    let sections = diff_sections(&render.output, &live);
    let summary = summarise_sections(&sections);
    let plan_id = registry.insert(plans::Plan::new(
        host,
        request.clone(),
        render.output.clone(),
    )?)?;
    Ok(DiffPreviewResult {
        plan_id: plan_id.to_string(),
        expires_in_secs: plans::TTL.as_secs(),
        rendered: render.output,
        sections,
        summary,
    })
}

/// The host and customer a preview or deploy is for, if `host_id` is the
/// site's own FortiGate (`plans::validate_target`).
async fn target(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    host_id: uuid::Uuid,
    request: &RenderRequest,
) -> Result<(supermgr_core::host::Host, Customer)> {
    crate::customer::validate_slug(&request.customer_slug)?;
    let customers = crate::customer::list_all()?;
    let hosts: Vec<supermgr_core::host::Host> =
        state.lock().await.ssh_hosts.values().cloned().collect();
    let customer = plans::validate_target(&hosts, &customers, host_id, request)?.clone();
    let host = hosts
        .into_iter()
        .find(|h| h.id == host_id)
        .ok_or_else(|| anyhow!("host not found"))?;
    Ok((host, customer))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffPreviewResult {
    /// What a deploy of exactly this preview takes: single use, and good
    /// for `expires_in_secs`.
    pub plan_id: String,
    pub expires_in_secs: u64,
    /// The full rendered template, as the deploy will push it.
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

/// Deploy a preview's plan: exactly the configuration the preview showed,
/// to the host it was for, which must still be the site's own FortiGate,
/// reached the same way. Nothing is rendered again. The flow is:
///   1. Snapshot pre-deploy config to disk (recoverable rollback).
///   2. Push the rendered config via SSH using `shell_interact`
///      so we can wait for the `FortiOS` prompt between blocks
///      and abort on the first error.
///   3. Persist a Deployment record either way.
///
/// The plan is used up by the attempt, whatever its outcome: a retry
/// starts from a new preview. Errors are surfaced with the line number of
/// the failure so the user can find it in the rendered output.
pub async fn deploy(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    registry: &std::sync::Arc<PlanRegistry>,
    plan_id: uuid::Uuid,
) -> Result<Deployment> {
    let (plan, _lease) = registry.take(plan_id)?;
    let host_id = plan.host.id;
    let request = &plan.request;
    let (host, _) = target(state, host_id, request).await?;
    plan.validate_target_unchanged(&host)?;
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
        error: None,
    };
    save_deployment(&record)?;

    // Step 1: backup. Failures here abort the deploy — no point
    // pushing if we can't recover.
    let backup_path = match pre_deploy_backup(state, secrets, host_id).await {
        Ok(p) => p,
        Err(e) => {
            record.status = DeploymentStatus::Failed;
            record.error = Some(format!("backup failed: {e:#}"));
            record.finished_at = Some(chrono::Utc::now());
            save_deployment(&record)?;
            return Err(anyhow!("backup failed: {e:#}"));
        }
    };
    record.backup_path = Some(backup_path.clone());
    save_deployment(&record)?;

    // Step 2: push. Each line is sent separately via shell_interact
    // so we get prompt-level error checking. Lines starting with
    // `{#` (Tera comments left over) and blank lines are skipped.
    let lines: Vec<String> = plan
        .rendered
        .lines()
        .filter(|l| !l.trim_start().starts_with("{#") && !l.trim().is_empty())
        .map(str::to_owned)
        .collect();

    let (_host, session) = match open_session(state, secrets, host_id).await {
        Ok(p) => p,
        Err(e) => {
            record.status = DeploymentStatus::Failed;
            record.error = Some(format!("ssh connect failed: {e:#}"));
            record.finished_at = Some(chrono::Utc::now());
            save_deployment(&record)?;
            return Err(e);
        }
    };

    // One shell_interact for the whole batch, 120 s for the whole push.
    // This is conservative; FortiOS acks each line in typically <50ms.
    let inputs: Vec<ShellInput<'_>> = lines.iter().map(|l| ShellInput::Command(l)).collect();
    let result = session.shell_interact(&inputs, 120).await;
    let _ = session.disconnect().await;

    match result {
        Ok(transcript) => {
            // Every line was acknowledged. Detect FortiOS's common error
            // markers in the transcript. Real FortiOS errors include
            // "Command fail" or "Command parse error".
            record.lines_pushed = lines.len() as u64;
            if transcript.contains("Command fail") || transcript.contains("Command parse error") {
                record.status = DeploymentStatus::Failed;
                record.error = Some(extract_first_error(&transcript));
            } else {
                record.status = DeploymentStatus::Succeeded;
            }
        }
        Err(e) => record_failed_push(&mut record, &e),
    }
    record.finished_at = Some(chrono::Utc::now());
    save_deployment(&record)?;
    Ok(record)
}

/// Record a push that ended in an error. A device that stopped answering
/// took the lines it acknowledged and nothing after them, so it now holds
/// part of the configuration; the record says how much.
fn record_failed_push(record: &mut Deployment, error: &SshError) {
    record.status = DeploymentStatus::Failed;
    if let SshError::ShellInterrupted {
        acknowledged,
        total,
        reason,
        ..
    } = error
    {
        record.lines_pushed = *acknowledged as u64;
        record.error = Some(format!(
            "device stopped answering after {acknowledged} of {total} lines ({reason}); \
             the configuration is partly applied"
        ));
    } else {
        record.error = Some(error.to_string());
    }
}

/// Pull the first `FortiOS` error line out of a shell transcript
/// for terse display in the GUI's deploy-result banner.
fn extract_first_error(transcript: &str) -> String {
    transcript
        .lines()
        .find(|l| l.contains("Command fail") || l.contains("Command parse error"))
        .unwrap_or("Unknown FortiOS error")
        .trim()
        .to_owned()
}

/// Restore from a saved backup. Reads the backup .conf and
/// pushes it via `shell_interact` — same path as a deploy but
/// the source is an old config, not a fresh render. A new
/// Deployment record with status=RolledBack is created so the
/// rollback shows up in history.
pub async fn rollback(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::DaemonState>>,
    secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
    host_id: uuid::Uuid,
    backup_path: &str,
) -> Result<Deployment> {
    let host_str = host_id.simple().to_string();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let backup_text =
        std::fs::read_to_string(backup_path).with_context(|| format!("read {backup_path}"))?;
    // Backups taken before the read was checked can hold an error message
    // instead. Pushing that restores nothing and would be recorded as a
    // rollback all the same.
    if !is_full_config(&backup_text) {
        return Err(anyhow!(
            "{backup_path} is not a FortiOS configuration; nothing was restored"
        ));
    }

    let mut record = Deployment {
        id: id.clone(),
        host_id: host_str.clone(),
        customer_slug: "rollback".into(),
        site_id: "rollback".into(),
        template_id: "rollback".into(),
        started_at: chrono::Utc::now(),
        finished_at: None,
        status: DeploymentStatus::Running,
        backup_path: Some(backup_path.to_owned()),
        rendered_config: backup_text.clone(),
        lines_pushed: 0,
        error: None,
    };
    save_deployment(&record)?;

    let (_host, session) = match open_session(state, secrets, host_id).await {
        Ok(p) => p,
        Err(e) => {
            record.status = DeploymentStatus::Failed;
            record.error = Some(format!("ssh connect failed: {e:#}"));
            record.finished_at = Some(chrono::Utc::now());
            save_deployment(&record)?;
            return Err(e);
        }
    };
    let lines: Vec<String> = backup_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect();
    let inputs: Vec<ShellInput<'_>> = lines.iter().map(|l| ShellInput::Command(l)).collect();
    let result = session.shell_interact(&inputs, 180).await;
    let _ = session.disconnect().await;
    record.finished_at = Some(chrono::Utc::now());
    match result {
        Ok(_) => {
            record.status = DeploymentStatus::RolledBack;
            record.lines_pushed = lines.len() as u64;
        }
        Err(e) => record_failed_push(&mut record, &e),
    }
    save_deployment(&record)?;
    Ok(record)
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
                octets[0],
                octets[1],
                octets[2],
                last + 1
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
            let cidr = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("cidr_dhcp_start requires a string"))?;
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
            let cidr = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("cidr_dhcp_end requires a string"))?;
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
            let cidr = value
                .as_str()
                .ok_or_else(|| tera::Error::msg("cidr_netmask requires a string"))?;
            let parts: Vec<&str> = cidr.split('/').collect();
            let prefix: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
            let mask = if prefix == 0 {
                0u32
            } else {
                (!0u32) << (32 - prefix)
            };
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
mod backup_tests {
    use super::is_full_config;

    const CONFIG: &str = "#config-version=FGT60F-7.2.8-FW-build1639-240313:opmode=0:vdom=0\n\
                          #conf_file_ver=1\n\
                          config system global\n    \
                              set hostname \"branch\"\n\
                          end\n\
                          config system interface\n    \
                              edit \"wan1\"\n        \
                                  set mode dhcp\n    \
                              next\n\
                          end\n";

    #[test]
    fn a_configuration_is_one() {
        assert!(is_full_config(CONFIG));
        // Line endings and trailing blank lines are the device's business.
        assert!(is_full_config(&CONFIG.replace('\n', "\r\n")));
        assert!(is_full_config(&format!("{CONFIG}\n\n")));
    }

    #[test]
    fn an_error_or_nothing_is_not_a_configuration() {
        assert!(!is_full_config(""));
        assert!(!is_full_config("\n"));
        assert!(!is_full_config("Command fail. Return code -61\n"));
        assert!(!is_full_config("Unknown action 0\nend\n"));
    }

    #[test]
    fn output_cut_off_inside_a_block_is_not_a_configuration() {
        let cut = &CONFIG[..CONFIG.find("set mode").unwrap()];
        assert!(!is_full_config(cut));
    }

    #[test]
    fn rejects_path_traversal_in_template_and_deployment_ids() {
        assert!(super::template_body("../etc/passwd").is_err());
        assert!(super::template_body("../../secrets").is_err());
        assert!(super::list_deployments("../escape", 10).is_err());
        assert!(super::load_deployment("../escape", "dep1").is_err());
        assert!(super::load_deployment("validhost", "../escape").is_err());
    }

    #[test]
    fn built_in_templates_refuse_missing_or_placeholder_secrets_and_render_explicit_ones() {
        use crate::customer::{Customer, Site, Vlan};

        let customer = Customer {
            slug: "acme".into(),
            display_name: "Acme Corp".into(),
            ..Customer::default()
        };
        let site = Site {
            id: "oslo".into(),
            display_name: "Oslo".into(),
            wan_type: "dhcp".into(),
            lan_base: "10.10.0.0/24".into(),
            vlans: vec![Vlan {
                id: 10,
                name: "Corp".into(),
                subnet: "10.10.10.0/24".into(),
                purpose: "internal".into(),
            }],
            ..Site::default()
        };

        let empty = serde_json::Map::new();
        for tmpl in ["fortigate.branch_office", "fortigate.hq", "unifi.wifi_basic"] {
            assert!(
                super::render_with_customer(&customer, &site, tmpl, &empty).is_err(),
                "{tmpl} must refuse rendering without explicit secrets"
            );
        }

        // Placeholder / weak secrets must also be refused.
        for bad in ["admin", "CHANGE-ME", "CHANGE-ME-LONG-PASSPHRASE", "short", "bad\"quote123"] {
            let mut ex = serde_json::Map::new();
            ex.insert("vpn_psk".into(), serde_json::Value::String(bad.into()));
            ex.insert(
                "vpn_admin_password".into(),
                serde_json::Value::String("ValidAdminPass!2026".into()),
            );
            assert!(
                super::render_with_customer(&customer, &site, "fortigate.branch_office", &ex)
                    .is_err(),
                "expected {bad:?} to be rejected"
            );
        }

        // Explicit strong secrets render cleanly.
        let mut branch_extras = serde_json::Map::new();
        branch_extras.insert(
            "vpn_psk".into(),
            serde_json::Value::String("R9x#kL29!mPq81$vN4zW".into()),
        );
        branch_extras.insert(
            "vpn_admin_password".into(),
            serde_json::Value::String("T7y@bQ44!zXc92#pL8mK".into()),
        );
        let rendered = super::render_with_customer(
            &customer,
            &site,
            "fortigate.branch_office",
            &branch_extras,
        )
        .unwrap();
        assert!(rendered.output.contains("R9x#kL29!mPq81$vN4zW"));
        assert!(!rendered.output.contains("CHANGE-ME"));

        let mut hq_extras = serde_json::Map::new();
        hq_extras.insert(
            "radius_secret".into(),
            serde_json::Value::String("F4c!R8d1uS#S3cr3t99".into()),
        );
        hq_extras.insert(
            "vpn_psk".into(),
            serde_json::Value::String("H9q#VpnPsk!2026Strong".into()),
        );
        let hq = super::render_with_customer(&customer, &site, "fortigate.hq", &hq_extras).unwrap();
        assert!(hq.output.contains("F4c!R8d1uS#S3cr3t99"));
        assert!(!hq.output.contains("CHANGE-ME"));

        let mut wifi_extras = serde_json::Map::new();
        wifi_extras.insert(
            "wifi_password".into(),
            serde_json::Value::String("Wpa3StrongPass!2026".into()),
        );
        let wifi =
            super::render_with_customer(&customer, &site, "unifi.wifi_basic", &wifi_extras)
                .unwrap();
        assert!(wifi.output.contains("Wpa3StrongPass!2026"));
        assert!(!wifi.output.contains("CHANGE-ME"));
    }

    #[test]
    fn linear_space_lcs_diffs_10k_line_configs_accurately() {
        use std::fmt::Write as _;
        let mut dev = String::from("config firewall address\n");
        let mut tmpl = String::from("config firewall address\n");
        // Differ on the very first, middle, and very last entries so outer
        // prefix/suffix trimming alone cannot bypass the inner LCS solver.
        writeln!(dev, "    edit \"first-old\"").unwrap();
        writeln!(tmpl, "    edit \"first-new\"").unwrap();
        for i in 1..9_999 {
            if i == 5_000 {
                writeln!(dev, "    set subnet 10.0.0.0 255.255.255.0").unwrap();
                writeln!(tmpl, "    set subnet 10.99.0.0 255.255.255.0").unwrap();
            } else {
                writeln!(dev, "    edit \"addr-{i}\"").unwrap();
                writeln!(tmpl, "    edit \"addr-{i}\"").unwrap();
            }
        }
        writeln!(dev, "    edit \"last-old\"\nend").unwrap();
        writeln!(tmpl, "    edit \"last-new\"\nend").unwrap();

        let diffs = super::diff_sections(&tmpl, &dev);
        assert_eq!(diffs.len(), 1);
        assert!(matches!(diffs[0].status, super::SectionStatus::Modified));
        assert!(diffs[0].unified_diff.contains("-    edit \"first-old\""));
        assert!(diffs[0].unified_diff.contains("+    edit \"first-new\""));
        assert!(diffs[0].unified_diff.contains("-    set subnet 10.0.0.0 255.255.255.0"));
        assert!(diffs[0].unified_diff.contains("+    set subnet 10.99.0.0 255.255.255.0"));
        assert!(diffs[0].unified_diff.contains("-    edit \"last-old\""));
        assert!(diffs[0].unified_diff.contains("+    edit \"last-new\""));
    }
}
