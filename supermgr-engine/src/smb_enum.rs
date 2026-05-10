//! SMB enumeration via shell-out to `smbclient` + `nmblookup`.
//!
//! Tries:
//!   1. `smbclient -L //host -N -t 3` — null-session share listing
//!   2. `nmblookup -A host` — NetBIOS name + workgroup + roles
//!
//! Both are read-only network probes. Findings are produced when:
//!   - Null session succeeds (any share visible without auth)
//!   - Specific high-value shares are exposed (`ADMIN$`, `C$`, `IPC$`)
//!   - SMBv1 negotiation succeeds (separate probe in future iteration)
//!
//! We intentionally do NOT shell out to `nmap --script smb-vuln-*`
//! — that's slow + heavy. The lightweight checks here cover the
//! 80%-case, and authenticated SMB enumeration is out of scope
//! for v1 (would need credentials managed via the engagement).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbInfo {
    /// Shares visible via null-session, if any.
    pub shares: Vec<SmbShare>,
    pub netbios_name: Option<String>,
    pub workgroup: Option<String>,
    pub server_role: Option<String>,
    pub null_session: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbShare {
    pub name: String,
    pub kind: String,    // "Disk", "IPC", "Printer", etc.
    pub comment: String,
}

/// Run SMB enumeration against `host`. Times out per-tool at
/// 6s — combined budget under 12s. Returns None if `smbclient`
/// isn't available on the system.
pub async fn enumerate(host: &str) -> Option<(SmbInfo, Vec<Finding>)> {
    let shares = smbclient_list(host).await;
    let (netbios_name, workgroup, server_role) = nmblookup(host).await;

    let null_session = shares.is_some() && shares.as_ref().is_some_and(|s| !s.is_empty());

    let info = SmbInfo {
        shares: shares.unwrap_or_default(),
        netbios_name,
        workgroup,
        server_role,
        null_session,
    };

    let mut findings: Vec<Finding> = Vec::new();
    if info.null_session {
        findings.push(Finding {
            id: "smb.null-session".into(),
            host_ip: host.to_owned(),
            port: Some(445),
            service: Some("smb".into()),
            severity: Severity::High,
            title: "SMB null-session enumeration succeeded".into(),
            detail: format!(
                "Anonymous SMB session listed {} share(s) without credentials. \
                 Attackers use this for fingerprinting + finding open shares.",
                info.shares.len()
            ),
            recommendation: "Disable null sessions: set `RestrictNullSessAccess=1` and `NullSessionShares=` (empty) in HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA. On Samba: `restrict anonymous = 2` in smb.conf.".into(),
            cve: None,
            cvss: Some(7.0),
        });
    }
    for share in &info.shares {
        let upper = share.name.to_uppercase();
        if matches!(upper.as_str(), "ADMIN$" | "C$" | "D$" | "E$") {
            findings.push(Finding {
                id: format!("smb.admin-share-{}", upper.to_lowercase().replace('$', "")),
                host_ip: host.to_owned(),
                port: Some(445),
                service: Some("smb".into()),
                severity: Severity::Critical,
                title: format!("Administrative SMB share visible: {}", share.name),
                detail: "Hidden administrative shares (`C$`, `ADMIN$`, etc.) reachable from the network are a primary lateral-movement vector for ransomware.".into(),
                recommendation: "Block SMB at the network edge. Disable admin shares unless required for backup tooling. Restrict to MGMT VLAN only.".into(),
                cve: None,
                cvss: Some(8.5),
            });
        }
    }

    Some((info, findings))
}

/// Run `smbclient -L //host -N -t 3` and parse the share list.
/// Returns `Some(vec)` if smbclient ran (even with empty list);
/// `None` if smbclient isn't available.
async fn smbclient_list(host: &str) -> Option<Vec<SmbShare>> {
    let target = format!("//{host}");
    let res = tokio::time::timeout(
        Duration::from_secs(6),
        tokio::process::Command::new("smbclient")
            .args(["-L", &target, "-N", "-t", "3", "-g"])
            .output(),
    )
    .await
    .ok()?
    .ok()?;

    let stdout = String::from_utf8_lossy(&res.stdout);
    let stderr = String::from_utf8_lossy(&res.stderr);

    // -g (grepable) format on success outputs lines:
    //   Disk|sharename|comment
    //   IPC|IPC$|IPC Service
    //   Printer|HP|HP LaserJet
    let mut shares: Vec<SmbShare> = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 2 {
            let kind = parts[0].trim();
            if matches!(kind, "Disk" | "IPC" | "Printer") {
                shares.push(SmbShare {
                    name: parts[1].trim().to_owned(),
                    kind: kind.to_owned(),
                    comment: parts.get(2).map(|s| s.trim().to_owned()).unwrap_or_default(),
                });
            }
        }
    }

    // Auth-required failure → null session not allowed; not a finding,
    // but smbclient IS present.
    if shares.is_empty() && stderr.contains("NT_STATUS_ACCESS_DENIED") {
        return Some(Vec::new());
    }
    if shares.is_empty() && stderr.contains("NT_STATUS_LOGON_FAILURE") {
        return Some(Vec::new());
    }
    // Unrecognised stderr — assume tool not present.
    if shares.is_empty() && !res.status.success() && !stderr.is_empty() {
        return None;
    }
    Some(shares)
}

/// Parse `nmblookup -A host` output for NetBIOS name + workgroup.
async fn nmblookup(host: &str) -> (Option<String>, Option<String>, Option<String>) {
    let res = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("nmblookup")
            .args(["-A", host])
            .output(),
    )
    .await;
    let Ok(Ok(out)) = res else {
        return (None, None, None);
    };
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut netbios_name: Option<String> = None;
    let mut workgroup: Option<String> = None;
    let mut server_role: Option<String> = None;
    for line in stdout.lines() {
        // Lines look like:
        //   HOSTNAME       <00> -         B <ACTIVE>
        //   WORKGROUP      <00> - <GROUP> B <ACTIVE>
        //   HOSTNAME       <20> -         B <ACTIVE>     (file server)
        let trim = line.trim();
        if !trim.contains('<') || !trim.contains('>') {
            continue;
        }
        let name_part: String = trim
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if trim.contains("<00>") && trim.contains("<GROUP>") {
            workgroup = Some(name_part);
        } else if trim.contains("<00>") && netbios_name.is_none() {
            netbios_name = Some(name_part);
        } else if trim.contains("<20>") {
            server_role = Some("file server".into());
        } else if trim.contains("<1B>") {
            server_role = Some("domain master browser".into());
        }
    }
    (netbios_name, workgroup, server_role)
}
