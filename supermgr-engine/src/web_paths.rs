//! Web path enumeration — finds common forgotten exposures.
//!
//! For every HTTP/HTTPS port we enumerate a curated list of
//! high-value paths. Hits are only flagged when both the status
//! AND the body content look right — `200 OK` on `/.env` from a
//! React SPA that returns the same `index.html` for every path
//! is a false positive that we explicitly avoid.
//!
//! # Why curated, not exhaustive
//!
//! Tools like dirsearch ship 80k path lists. Useful for full
//! pentests but enormously noisy for an MSP fleet scan that
//! needs to finish in seconds. We focus on the ~30 paths that
//! actually show up in incidents:
//!   - `.git/HEAD`         → full source code disclosure
//!   - `.env`              → DB creds, API keys, secrets
//!   - `.svn/entries`      → ditto for old SVN repos
//!   - `wp-admin/`         → WordPress admin login
//!   - `server-status`     → Apache mod_status, leaks IPs
//!   - `phpinfo.php`       → PHP config, paths, env
//!   - `backup.{zip,sql}`  → unencrypted backups
//!   - `swagger.json`      → API surface enumeration
//!   - `api/v1/`           → exposed APIs that often need auth
//!   - `console`           → admin consoles
//!
//! # SPA false-positive guard
//!
//! Single-page apps return `200 OK` + `index.html` for any path
//! the router doesn't know. Without a content check we'd flag
//! every path on every SPA. So each path entry has a
//! `content_signature` substring that must appear in the body
//! for the finding to fire.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbe {
    pub path: String,
    pub status: u16,
    pub size: usize,
    pub content_type: Option<String>,
    pub matched: bool,
}

/// What kind of response we expect a real hit to produce.
/// Used to reject false positives from catch-all redirects
/// (e.g. Synology DSM port-80 stub that returns the same
/// HTML for every path).
#[derive(Clone, Copy, PartialEq)]
enum ExpectedKind {
    /// Any 200/403 with non-empty body is acceptable, subject
    /// to signature checks below. Used for path probes where
    /// the response is HTML (admin consoles, error pages, etc).
    Any,
    /// Response MUST be a non-text content type — `text/html`,
    /// `text/plain`, `application/xml` reject. Used for binary
    /// resources like heapdumps, zip/tar archives, SQL dumps
    /// where any text-shaped response is a catch-all redirect,
    /// not the real resource.
    Binary,
}

/// Curated list of paths to check, with the body-substring
/// signature used to confirm the hit isn't an SPA fall-through.
struct PathRule {
    path: &'static str,
    /// Body must contain ANY of these substrings (case-insensitive)
    /// for the finding to fire. Empty list = match any 200/403.
    signatures: &'static [&'static str],
    /// What Content-Type shape we expect from a real hit.
    /// Defaults to `Any`. Set `Binary` for endpoints where a
    /// text/html response is by definition a false positive.
    expected_kind: ExpectedKind,
    severity: Severity,
    cvss: f32,
    finding_id: &'static str,
    title: &'static str,
    detail: &'static str,
    recommendation: &'static str,
    /// If true, a 403 still counts (means file exists but blocked).
    /// Useful for `.htaccess` style entries.
    flag_on_403: bool,
}

const PATH_RULES: &[PathRule] = &[
    // -------- Git exposure (highest impact: full source disclosure) --------
    PathRule {
        path: "/.git/HEAD",
        signatures: &["ref: refs/", "ref:refs/"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.git-exposed",
        title: "Exposed .git directory",
        detail: "The `.git/` directory is reachable over HTTP. Attackers can recover the full source-history including secrets, internal URLs, and removed-but-never-rebased credentials.",
        recommendation: "Block `/.git/` at the web server (e.g. `Deny from all` in Apache, `location ~ /\\.git { deny all; }` in nginx). Remove `.git/` from web roots entirely.",
        flag_on_403: false,
    },
    PathRule {
        path: "/.git/config",
        signatures: &["[core]", "[remote", "repositoryformatversion"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.git-config",
        title: "Exposed .git/config",
        detail: "Git config file readable via HTTP — leaks remote URLs, credentials embedded in remote URLs, branch names.",
        recommendation: "Block `/.git/` at the web server.",
        flag_on_403: false,
    },
    // -------- SVN --------
    PathRule {
        path: "/.svn/entries",
        signatures: &["dir\n", "12\n"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.5,
        finding_id: "web.svn-exposed",
        title: "Exposed .svn directory",
        detail: "SVN metadata exposed — like `.git`, leaks source history.",
        recommendation: "Block `/.svn/` at the web server. Migrate to git if still on SVN.",
        flag_on_403: false,
    },
    // -------- Env / config files --------
    PathRule {
        path: "/.env",
        signatures: &["DB_", "APP_KEY", "SECRET", "API_KEY", "AWS_", "DATABASE_URL"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.env-exposed",
        title: "Exposed .env file",
        detail: "`.env` file readable over HTTP — leaks database credentials, API keys, encryption keys. Used by Laravel, Rails, Node.js, Symfony, Django, and many other frameworks.",
        recommendation: "Move `.env` outside the web root. Block hidden files at the web server: `location ~ /\\. { deny all; }` (nginx) or `<FilesMatch \"^\\.\">Require all denied</FilesMatch>` (Apache).",
        flag_on_403: false,
    },
    PathRule {
        path: "/.env.local",
        signatures: &["DB_", "APP_KEY", "SECRET", "API_KEY"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.env-local-exposed",
        title: "Exposed .env.local file",
        detail: "Local override env file readable over HTTP.",
        recommendation: "Move outside web root or block hidden files.",
        flag_on_403: false,
    },
    PathRule {
        path: "/config.php.bak",
        signatures: &["<?php", "DB_", "$config"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.config-bak",
        title: "Exposed config.php.bak",
        detail: "Backup of PHP config file readable as plaintext (no PHP execution).",
        recommendation: "Remove backup files from web root. Configure web server to deny `.bak`/`.old`/`.swp`.",
        flag_on_403: false,
    },
    // -------- Mac quirks --------
    PathRule {
        path: "/.DS_Store",
        signatures: &["Bud1"], // .DS_Store magic header
        expected_kind: ExpectedKind::Any,
        severity: Severity::Medium,
        cvss: 4.0,
        finding_id: "web.ds-store",
        title: "Exposed .DS_Store file",
        detail: "macOS Finder metadata exposed — discloses directory contents (filenames). Used by attackers to enumerate hidden paths.",
        recommendation: "Block `.DS_Store` at the web server. Add to `.gitignore` to prevent future leaks.",
        flag_on_403: false,
    },
    // -------- PHP debug --------
    PathRule {
        path: "/phpinfo.php",
        signatures: &["phpinfo()", "PHP Version"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.5,
        finding_id: "web.phpinfo",
        title: "Exposed phpinfo.php",
        detail: "phpinfo() output discloses full PHP environment: paths, modules, env vars, server hostname, internal IPs, request headers.",
        recommendation: "Remove phpinfo.php immediately. Disable in production php.ini: `disable_functions = phpinfo`.",
        flag_on_403: false,
    },
    PathRule {
        path: "/info.php",
        signatures: &["phpinfo()", "PHP Version"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.5,
        finding_id: "web.info-php",
        title: "Exposed info.php (phpinfo)",
        detail: "phpinfo() output discloses full PHP environment.",
        recommendation: "Remove. Disable phpinfo() in production.",
        flag_on_403: false,
    },
    // -------- Apache --------
    PathRule {
        path: "/server-status",
        signatures: &["Apache Server Status", "Server Version"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.5,
        finding_id: "web.apache-status",
        title: "Apache mod_status exposed",
        detail: "`/server-status` reveals current connections, request URLs, client IPs, and server internals.",
        recommendation: "Restrict mod_status: `<Location /server-status>Require ip 127.0.0.1</Location>`.",
        flag_on_403: false,
    },
    PathRule {
        path: "/server-info",
        signatures: &["Apache Server Information", "Server Version"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.0,
        finding_id: "web.apache-info",
        title: "Apache mod_info exposed",
        detail: "`/server-info` reveals full Apache configuration.",
        recommendation: "Restrict mod_info to localhost or disable.",
        flag_on_403: false,
    },
    // -------- WordPress --------
    PathRule {
        path: "/wp-login.php",
        signatures: &["WordPress", "wp-login", "User_login"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Low,
        cvss: 3.0,
        finding_id: "web.wp-login",
        title: "WordPress login page exposed",
        detail: "Direct exposure of WordPress login page — informational. Recommend rate-limiting + 2FA.",
        recommendation: "Enable rate-limiting (e.g. WP Limit Login Attempts), enforce 2FA, restrict by IP if administrator-only.",
        flag_on_403: false,
    },
    PathRule {
        path: "/wp-config.php.bak",
        signatures: &["DB_NAME", "DB_PASSWORD", "AUTH_KEY"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.wp-config-bak",
        title: "Exposed wp-config.php.bak",
        detail: "Backup of WordPress config — leaks database credentials and auth keys.",
        recommendation: "Remove backup. Block `.bak` extensions at the web server.",
        flag_on_403: false,
    },
    // -------- Swagger / API docs --------
    PathRule {
        path: "/swagger.json",
        signatures: &["\"swagger\":", "\"openapi\":", "\"paths\":"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Medium,
        cvss: 5.0,
        finding_id: "web.swagger-exposed",
        title: "Swagger/OpenAPI spec exposed",
        detail: "Full API surface enumeration via Swagger spec. Useful for attackers to find unauthenticated endpoints.",
        recommendation: "Restrict Swagger UI to internal networks or auth-required. Don't expose API spec publicly unless intended.",
        flag_on_403: false,
    },
    PathRule {
        path: "/api-docs",
        signatures: &["\"swagger\":", "\"openapi\":"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Medium,
        cvss: 5.0,
        finding_id: "web.api-docs",
        title: "API docs exposed",
        detail: "OpenAPI/Swagger documentation publicly reachable.",
        recommendation: "Restrict to authenticated/internal access.",
        flag_on_403: false,
    },
    PathRule {
        path: "/v2/api-docs",
        signatures: &["\"swagger\":", "\"openapi\":"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Medium,
        cvss: 5.0,
        finding_id: "web.api-docs-v2",
        title: "Spring API docs exposed",
        detail: "Springdoc/SpringFox OpenAPI documentation publicly reachable.",
        recommendation: "Restrict to internal access.",
        flag_on_403: false,
    },
    // -------- Backup files --------
    PathRule {
        path: "/backup.zip",
        signatures: &[], // Any 200 with binary content is suspicious here
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 8.0,
        finding_id: "web.backup-zip",
        title: "backup.zip reachable",
        detail: "A backup archive at a guessable URL is one of the top causes of mass data leaks. Often contains DB dumps + source.",
        recommendation: "Move backups outside the web root. Never store backups under `/`.",
        flag_on_403: false,
    },
    PathRule {
        path: "/backup.tar.gz",
        signatures: &[],
        expected_kind: ExpectedKind::Binary,
        severity: Severity::High,
        cvss: 8.0,
        finding_id: "web.backup-targz",
        title: "backup.tar.gz reachable",
        detail: "Backup archive at guessable URL.",
        recommendation: "Move outside web root.",
        flag_on_403: false,
    },
    PathRule {
        path: "/db.sql",
        signatures: &["INSERT INTO", "CREATE TABLE", "-- MySQL dump", "SQL DUMP"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.sql-dump",
        title: "SQL dump exposed",
        detail: "Database dump file readable over HTTP — full data leak.",
        recommendation: "Remove immediately. Audit access logs.",
        flag_on_403: false,
    },
    PathRule {
        path: "/database.sql",
        signatures: &["INSERT INTO", "CREATE TABLE"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.5,
        finding_id: "web.database-sql",
        title: "database.sql exposed",
        detail: "SQL dump file readable.",
        recommendation: "Remove immediately.",
        flag_on_403: false,
    },
    // -------- Admin consoles --------
    PathRule {
        path: "/manager/html",
        signatures: &["Tomcat Web Application Manager", "Manager Login"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 7.5,
        finding_id: "web.tomcat-manager",
        title: "Tomcat manager exposed",
        detail: "Tomcat manager is a known mass-exploit target — default-creds + WAR upload = RCE.",
        recommendation: "Restrict `/manager/` to localhost or VPN. Change default tomcat/admin credentials. Disable if not needed.",
        flag_on_403: false,
    },
    PathRule {
        path: "/jmx-console",
        signatures: &["JBoss", "JMX Console"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.jboss-jmx",
        title: "JBoss JMX console exposed",
        detail: "JBoss JMX console without auth = full server takeover.",
        recommendation: "Disable JMX console or require auth. Upgrade JBoss.",
        flag_on_403: false,
    },
    PathRule {
        path: "/actuator/env",
        signatures: &["activeProfiles", "propertySources"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.spring-actuator-env",
        title: "Spring Boot actuator /env exposed",
        detail: "Spring actuator `/env` endpoint discloses all environment variables including database creds, API keys, JWT secrets.",
        recommendation: "Disable management endpoints in production: `management.endpoints.enabled-by-default=false`. Or restrict to internal networks.",
        flag_on_403: false,
    },
    PathRule {
        path: "/actuator/heapdump",
        signatures: &[], // binary; just status check
        expected_kind: ExpectedKind::Binary,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.spring-actuator-heapdump",
        title: "Spring Boot actuator /heapdump exposed",
        detail: "Heap dump exposes credentials, session tokens, request bodies — gold mine for attackers.",
        recommendation: "Disable in production.",
        flag_on_403: false,
    },
    // -------- Robots / informational (NOT findings, just data) --------
    // (skip — robots.txt is fine to expose)
    // -------- Debug / staging --------
    PathRule {
        path: "/test.php",
        signatures: &["<?php", "test"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Low,
        cvss: 3.0,
        finding_id: "web.test-php",
        title: "test.php reachable",
        detail: "Generic test PHP file in web root — often contains debug data.",
        recommendation: "Remove.",
        flag_on_403: false,
    },
    PathRule {
        path: "/.htpasswd",
        signatures: &[":$", ":apr1$", ":$2y$", ":$1$"],
        expected_kind: ExpectedKind::Any,
        severity: Severity::Critical,
        cvss: 9.0,
        finding_id: "web.htpasswd",
        title: ".htpasswd file exposed",
        detail: "Apache `.htpasswd` readable — leaks usernames + hashed passwords for offline cracking.",
        recommendation: "Block `.htpasswd` at the web server immediately. Rotate all listed credentials.",
        flag_on_403: false,
    },
    PathRule {
        path: "/.htaccess",
        signatures: &["RewriteEngine", "AuthType", "Order ", "Require "],
        expected_kind: ExpectedKind::Any,
        severity: Severity::High,
        cvss: 6.0,
        finding_id: "web.htaccess",
        title: ".htaccess file exposed",
        detail: "`.htaccess` readable — leaks rewrite rules, auth setup, internal URL structure.",
        recommendation: "Block `.htaccess` at the web server.",
        flag_on_403: false,
    },
];

/// Run all path checks against (host:port). Returns the
/// per-path probe results + any findings produced. Concurrency
/// is bounded with a per-host semaphore (8 in flight) so we
/// don't hammer a single web server.
pub async fn enumerate(host: &str, port: u16, tls: bool) -> (Vec<PathProbe>, Vec<Finding>) {
    let scheme = if tls { "https" } else { "http" };
    let base = format!("{scheme}://{host}:{port}");
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let sema = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut futs = Vec::with_capacity(PATH_RULES.len());
    for rule in PATH_RULES {
        let url = format!("{base}{}", rule.path);
        let client = client.clone();
        let sema = sema.clone();
        futs.push(tokio::spawn(async move {
            let _permit = sema.acquire_owned().await.ok()?;
            check_one(&client, &url, rule).await
        }));
    }
    let mut probes: Vec<PathProbe> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    for f in futs {
        if let Ok(Some((probe, maybe_finding))) = f.await {
            probes.push(probe);
            if let Some(mut finding) = maybe_finding {
                finding.host_ip = host.to_owned();
                finding.port = Some(port);
                finding.service = Some(if tls { "https".into() } else { "http".into() });
                findings.push(finding);
            }
        }
    }
    (probes, findings)
}

async fn check_one(
    client: &reqwest::Client,
    url: &str,
    rule: &PathRule,
) -> Option<(PathProbe, Option<Finding>)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Read up to ~32KB body to keep memory bounded.
    let bytes = resp.bytes().await.ok()?;
    let size = bytes.len();
    let body_text = String::from_utf8_lossy(&bytes[..bytes.len().min(32 * 1024)]).to_string();

    let mut matched = false;
    let mut should_flag = false;

    if status == 200 {
        // Content-Type guard for Binary-expected rules. Catch-all
        // redirects (Synology DSM port-80 stub, SPAs that return
        // index.html for any path, error-page-on-200 misconfigs)
        // all serve HTML. A real heapdump / zip / tar.gz never
        // comes back as text/*; if it does, this is a false
        // positive and we drop the rule on the floor.
        let content_type_lc = content_type
            .as_deref()
            .unwrap_or("")
            .to_lowercase();
        let is_text_response = content_type_lc.starts_with("text/")
            || content_type_lc.starts_with("application/xml")
            || content_type_lc.starts_with("application/xhtml")
            || content_type_lc.starts_with("application/json");
        let kind_rejects = rule.expected_kind == ExpectedKind::Binary && is_text_response;

        if kind_rejects {
            // Don't flag, don't even mark `matched` — this is
            // clearly the catch-all path, not the actual resource.
        } else if rule.signatures.is_empty() {
            // No signature required — flag any 200 OK with
            // non-trivial size, after we've passed the Content-Type
            // shape check above.
            // Also skip the "obviously index.html" heuristic for
            // belt-and-braces on legacy rules that haven't been
            // promoted to ExpectedKind::Binary yet.
            let lc = body_text.to_lowercase();
            let is_spa_fallback = lc.contains("<!doctype html") && lc.contains("<title>");
            if !is_spa_fallback && size > 0 {
                matched = true;
                should_flag = true;
            }
        } else {
            let lc = body_text.to_lowercase();
            for sig in rule.signatures {
                if lc.contains(&sig.to_lowercase()) {
                    matched = true;
                    should_flag = true;
                    break;
                }
            }
        }
    } else if status == 403 && rule.flag_on_403 {
        // 403 means file exists but is blocked — still informational.
        matched = true;
        should_flag = false;
    }

    let probe = PathProbe {
        path: rule.path.to_owned(),
        status,
        size,
        content_type,
        matched,
    };

    let finding = if should_flag {
        Some(Finding {
            id: rule.finding_id.to_owned(),
            host_ip: String::new(), // filled in by caller
            port: None,
            service: None,
            severity: rule.severity,
            title: rule.title.to_owned(),
            detail: format!("{} URL: `{}` returned {} ({} bytes).", rule.detail, url, status, size),
            recommendation: rule.recommendation.to_owned(),
            cve: None,
            cvss: Some(rule.cvss),
        })
    } else {
        None
    };

    Some((probe, finding))
}
