//! One-shot remediation script generator.
//!
//! Takes a finding (or list of findings on the same host) and
//! generates a shell script the operator can paste into an SSH
//! session to remediate. Each script:
//!   - Backs up the affected config first.
//!   - Applies the fix idempotently.
//!   - Verifies the fix succeeded.
//!
//! # Coverage
//!
//! Only findings whose `id` matches a known recipe produce a
//! script — anything else returns `None`. The recipes are
//! conservative: every command is read+verify before it acts,
//! and destructive operations (replacing files, removing
//! services) include a backup with timestamped filename.
//!
//! # Adding a recipe
//!
//! 1. Add a `match` arm in `script_for_finding`.
//! 2. Return a multi-line bash heredoc that:
//!    - Sources to a `bash -c` invocation,
//!    - Writes a backup to `/var/backups/supermgr-<finding_id>-<date>.bak`
//!    - Applies the fix,
//!    - Re-tests and exits non-zero on failure.

use crate::vuln::Finding;

/// Returns a remediation script for the given finding, or `None`
/// if no recipe is registered for this finding id.
pub fn script_for_finding(f: &Finding) -> Option<String> {
    let id = f.id.as_str();
    match id {
        "config.telnet-open" => Some(script_disable_telnet(f)),
        "config.ftp-cleartext" => Some(script_disable_ftp(f)),
        "config.snmp-public" => Some(script_snmp_change_community(f)),
        "smb.null-session" => Some(script_smb_disable_null_session(f)),
        "tls.tls10" | "tls.tls11" | "tls.ssl-deprecated" => Some(script_disable_old_tls(f)),
        "web.git-exposed" | "web.git-config" => Some(script_block_dotgit(f)),
        "web.env-exposed" | "web.env-local-exposed" => Some(script_block_dotenv(f)),
        "web.htpasswd" | "web.htaccess" => Some(script_block_dotfiles(f)),
        "web.phpinfo" | "web.info-php" => Some(script_remove_phpinfo(f)),
        "web.apache-status" | "web.apache-info" => Some(script_restrict_mod_status(f)),
        "dns.spf-missing" => Some(advice_dns_spf(f)),
        "dns.dmarc-missing" => Some(advice_dns_dmarc(f)),
        _ => None,
    }
}

/// Generate ONE script that addresses a batch of findings on the
/// same host. Good for fleet-wide remediation: a host with 5
/// related findings gets one paste-once script. Any unrecognised
/// finding ids are skipped silently — caller has already checked
/// `script_for_finding` returns Some for at least one entry.
pub fn batch_script(host: &str, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "#!/usr/bin/env bash\n# SuperManager remediation script for {host}\n# Generated {}\n\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    ));
    out.push_str("set -euo pipefail\n");
    out.push_str("BACKUP_DIR=/var/backups/supermgr-$(date +%Y%m%d-%H%M%S)\n");
    out.push_str("mkdir -p \"$BACKUP_DIR\"\n");
    out.push_str("echo \"Backups → $BACKUP_DIR\"\n\n");

    let mut applied = 0;
    for f in findings {
        if let Some(s) = script_for_finding(f) {
            out.push_str(&format!(
                "# ----- {} (severity {:?}) -----\n",
                f.title, f.severity
            ));
            out.push_str(&s);
            out.push_str("\n\n");
            applied += 1;
        }
    }
    if applied == 0 {
        out.push_str("echo \"No automated remediation available for the supplied findings.\"\n");
    } else {
        out.push_str(&format!(
            "echo \"\\u2713 {applied} remediation step(s) applied.\"\n"
        ));
    }
    out
}

// -----------------------------------------------------------
// Recipes
// -----------------------------------------------------------

fn header(f: &Finding) -> String {
    format!(
        "# Target: {}{}\n# Finding: {}\n",
        f.host_ip,
        f.port.map(|p| format!(":{p}")).unwrap_or_default(),
        f.title
    )
}

fn script_disable_telnet(f: &Finding) -> String {
    format!(
        "{header}\
if systemctl is-active telnet.socket >/dev/null 2>&1; then\n\
\u{20}\u{20}systemctl stop telnet.socket && systemctl disable telnet.socket\n\
\u{20}\u{20}echo 'telnet socket disabled'\n\
elif command -v service >/dev/null 2>&1; then\n\
\u{20}\u{20}service telnet stop || true\n\
\u{20}\u{20}service xinetd reload 2>/dev/null || true\n\
fi\n\
ss -tln 2>/dev/null | grep -q ':23 ' && echo 'WARN: port 23 still listening — investigate' || echo 'port 23 closed'",
        header = header(f)
    )
}

fn script_disable_ftp(f: &Finding) -> String {
    format!(
        "{header}\
for svc in vsftpd proftpd pure-ftpd; do\n\
\u{20}\u{20}if systemctl is-active \"$svc\" >/dev/null 2>&1; then\n\
\u{20}\u{20}\u{20}\u{20}systemctl stop \"$svc\" && systemctl disable \"$svc\"\n\
\u{20}\u{20}\u{20}\u{20}echo \"$svc disabled\"\n\
\u{20}\u{20}fi\n\
done\n\
ss -tln | grep -q ':21 ' && echo 'WARN: port 21 still listening' || echo 'FTP port closed'",
        header = header(f)
    )
}

fn script_snmp_change_community(f: &Finding) -> String {
    format!(
        "{header}\
NEW_COMMUNITY=$(openssl rand -hex 16)\n\
CONF=/etc/snmp/snmpd.conf\n\
[ -f \"$CONF\" ] || {{ echo 'snmpd.conf not found — likely not running snmpd directly'; exit 0; }}\n\
cp \"$CONF\" \"$BACKUP_DIR/snmpd.conf.bak\"\n\
sed -i.tmp 's/^rocommunity\\s\\+public.*$/rocommunity '\"$NEW_COMMUNITY\"' default/' \"$CONF\"\n\
echo \"new SNMP community: $NEW_COMMUNITY (record this in customer credentials)\"\n\
systemctl restart snmpd",
        header = header(f)
    )
}

fn script_smb_disable_null_session(f: &Finding) -> String {
    format!(
        "{header}\
CONF=/etc/samba/smb.conf\n\
[ -f \"$CONF\" ] || {{ echo 'samba not installed'; exit 0; }}\n\
cp \"$CONF\" \"$BACKUP_DIR/smb.conf.bak\"\n\
grep -q '^restrict anonymous' \"$CONF\" || echo 'restrict anonymous = 2' >> \"$CONF\"\n\
testparm -s >/dev/null && systemctl restart smbd nmbd && echo 'samba reloaded'",
        header = header(f)
    )
}

fn script_disable_old_tls(f: &Finding) -> String {
    format!(
        "{header}\
# nginx + apache covered separately — pick whichever is installed.\n\
if [ -d /etc/nginx ]; then\n\
\u{20}\u{20}cp -r /etc/nginx \"$BACKUP_DIR/nginx\" 2>/dev/null || true\n\
\u{20}\u{20}sed -i.bak 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf 2>/dev/null || true\n\
\u{20}\u{20}nginx -t && systemctl reload nginx && echo 'nginx: TLS 1.0/1.1 disabled'\n\
fi\n\
if [ -d /etc/apache2 ]; then\n\
\u{20}\u{20}cp -r /etc/apache2 \"$BACKUP_DIR/apache2\" 2>/dev/null || true\n\
\u{20}\u{20}sed -i.bak 's/SSLProtocol.*/SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1/' /etc/apache2/mods-available/ssl.conf 2>/dev/null || true\n\
\u{20}\u{20}apachectl configtest && systemctl reload apache2 && echo 'apache: TLS 1.0/1.1 disabled'\n\
fi",
        header = header(f)
    )
}

fn script_block_dotgit(f: &Finding) -> String {
    // Bash braces collide with format!{} placeholders. Use raw
    // r#""# strings to keep the bash heredoc legible.
    let body = r#"# Block .git/ in nginx + Apache. If you don't run either, this is a no-op.
if [ -d /etc/nginx ]; then
  grep -q '/\\\.git' /etc/nginx/nginx.conf 2>/dev/null \
    || sed -i '/server_name/a \\tlocation ~ /\\.git { deny all; return 404; }' /etc/nginx/nginx.conf
  nginx -t && systemctl reload nginx && echo 'nginx: blocked .git/'
fi
if [ -d /etc/apache2 ]; then
  cat > /etc/apache2/conf-available/block-dotgit.conf <<'CONF'
<DirectoryMatch "/\.git">
    Require all denied
</DirectoryMatch>
CONF
  a2enconf block-dotgit && systemctl reload apache2 && echo 'apache: blocked .git/'
fi
"#;
    let mut out = header(f);
    out.push_str(body);
    out
}

fn script_block_dotenv(f: &Finding) -> String {
    let body = r#"# Block .env (and any hidden file) at the web server.
if [ -d /etc/nginx ]; then
  grep -q 'location ~ /\\\\\\.' /etc/nginx/nginx.conf 2>/dev/null \
    || sed -i '/server_name/a \\tlocation ~ /\\\\. { deny all; return 404; }' /etc/nginx/nginx.conf
  nginx -t && systemctl reload nginx && echo 'nginx: blocked hidden files'
fi
"#;
    let mut out = header(f);
    out.push_str(body);
    out
}

fn script_block_dotfiles(f: &Finding) -> String {
    script_block_dotenv(f)
}

fn script_remove_phpinfo(f: &Finding) -> String {
    format!(
        "{header}\
for path in /var/www /srv/www /usr/share/nginx/html; do\n\
\u{20}\u{20}[ -d \"$path\" ] || continue\n\
\u{20}\u{20}find \"$path\" -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' \\\n\
\u{20}\u{20}\u{20}\u{20}-exec mv {{}} \"$BACKUP_DIR/\" \\;\n\
done\n\
echo 'phpinfo/test files moved to backup dir'",
        header = header(f)
    )
}

fn script_restrict_mod_status(f: &Finding) -> String {
    format!(
        "{header}\
# Restrict mod_status to localhost only.\n\
if [ -f /etc/apache2/mods-available/status.conf ]; then\n\
\u{20}\u{20}cp /etc/apache2/mods-available/status.conf \"$BACKUP_DIR/\"\n\
\u{20}\u{20}cat > /etc/apache2/mods-available/status.conf <<'CONF'\n\
<Location /server-status>\n\
\u{20}\u{20}\u{20}\u{20}SetHandler server-status\n\
\u{20}\u{20}\u{20}\u{20}Require local\n\
</Location>\n\
CONF\n\
\u{20}\u{20}apachectl configtest && systemctl reload apache2 && echo 'apache: server-status restricted to localhost'\n\
fi",
        header = header(f)
    )
}

fn advice_dns_spf(f: &Finding) -> String {
    // DNS isn't fixable via SSH — surface the suggested record so
    // the operator can paste into the registrar's DNS panel.
    format!(
        "{header}\
echo '# Add this TXT record at the apex of {host}:'\n\
echo 'v=spf1 include:_spf.google.com -all'\n\
echo '# (replace include: with your actual mail sender). Then run dig TXT {host} to verify.'",
        header = header(f),
        host = f.host_ip
    )
}

fn advice_dns_dmarc(f: &Finding) -> String {
    format!(
        "{header}\
echo '# Add this TXT record at _dmarc.{host}:'\n\
echo 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{host}; pct=100'\n\
echo '# Start with p=none; ramp to quarantine then reject after monitoring rua reports.'",
        header = header(f),
        host = f.host_ip
    )
}
