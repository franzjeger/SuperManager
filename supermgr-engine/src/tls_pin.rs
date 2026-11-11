//! First-use TLS certificate fingerprint pinning (`TOFU`) for self-signed
//! network appliances.
//!
//! When an operator explicitly disables strict CA chain verification
//! (`api_verify_tls = false` on an SSH host or `verify_tls = false` on a
//! standalone `UniFi` controller), we still refuse to accept silent
//! certificate swaps after the first connection. Before sending any bearer
//! token, API key, or password over HTTPS, we probe the endpoint's leaf X.509
//! certificate and verify/enroll its SHA-256 DER fingerprint in
//! [`KnownHostsStore`] under `tls:<normalized_host>:<port>`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use supermgr_core::ssh::known_hosts::{HostKeyCheck, KnownHostsStore};

const TLS_PIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Normalize an endpoint hostname or IP literal for [`KnownHostsStore`] lookup.
#[must_use]
pub fn normalize_tls_pin_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// Verify an existing `tls:<host>:<port>` pin against `cert_der` or enroll it
/// on first sight. Rejects mismatches with an actionable message pointing to
/// `ssh_forget_host_key`.
pub fn verify_or_enroll_der(
    known_hosts: &KnownHostsStore,
    host: &str,
    port: u16,
    cert_der: &[u8],
) -> Result<String> {
    let normalized = normalize_tls_pin_host(host);
    if normalized.is_empty() {
        return Err(anyhow!("empty TLS host"));
    }
    if cert_der.is_empty() {
        return Err(anyhow!("empty TLS certificate DER for {normalized}:{port}"));
    }

    let fp = KnownHostsStore::fingerprint(cert_der);
    let pin_host = format!("tls:{normalized}");
    match known_hosts
        .check_and_enroll(&pin_host, port, &fp)
        .context("persist TLS certificate pin")?
    {
        HostKeyCheck::Match => Ok(fp),
        HostKeyCheck::NewHost => {
            tracing::info!(
                host = %normalized,
                port = port,
                fingerprint = %fp,
                "TOFU: enrolled self-signed TLS certificate fingerprint"
            );
            Ok(fp)
        }
        HostKeyCheck::Mismatch { stored, current } => {
            tracing::error!(
                host = %normalized,
                port = port,
                stored = %stored,
                current = %current,
                "TLS certificate fingerprint MISMATCH — refusing connection"
            );
            Err(anyhow!(
                "TLS certificate fingerprint mismatch for {normalized}:{port} — \
                 stored={stored}, server-presented={current}; refusing to send credentials. \
                 If the certificate was rotated intentionally, call `ssh_forget_host_key` \
                 with hostname=\"{pin_host}\" and port={port}."
            ))
        }
    }
}

/// Probe `host:port` over TLS without sending application credentials, read the
/// peer leaf certificate, and verify/enroll its SHA-256 DER fingerprint in
/// `known_hosts`.
pub async fn verify_or_enroll_endpoint(
    known_hosts: &KnownHostsStore,
    host: &str,
    port: u16,
) -> Result<String> {
    let normalized = normalize_tls_pin_host(host);
    if normalized.is_empty() {
        return Err(anyhow!("empty TLS host"));
    }

    let tcp = if let Ok(ip) = normalized.parse::<IpAddr>() {
        tokio::time::timeout(
            TLS_PIN_TIMEOUT,
            tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await
        .map_err(|_| anyhow!("TLS preflight TCP connect to {normalized}:{port} timed out"))?
        .with_context(|| format!("TLS preflight TCP connect to {normalized}:{port}"))?
    } else {
        tokio::time::timeout(
            TLS_PIN_TIMEOUT,
            tokio::net::TcpStream::connect((normalized.as_str(), port)),
        )
        .await
        .map_err(|_| anyhow!("TLS preflight TCP connect to {normalized}:{port} timed out"))?
        .with_context(|| format!("TLS preflight TCP connect to {normalized}:{port}"))?
    };

    let native = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .context("build TLS preflight connector")?;
    let connector = tokio_native_tls::TlsConnector::from(native);

    let tls_stream = tokio::time::timeout(TLS_PIN_TIMEOUT, connector.connect(&normalized, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake with {normalized}:{port} timed out"))?
        .with_context(|| format!("TLS handshake with {normalized}:{port}"))?;

    let cert = tls_stream
        .get_ref()
        .peer_certificate()
        .context("read peer TLS certificate")?
        .ok_or_else(|| anyhow!("server {normalized}:{port} presented no TLS certificate"))?;
    let der = cert
        .to_der()
        .context("encode peer TLS certificate as DER")?;

    verify_or_enroll_der(known_hosts, &normalized, port, &der)
}

/// Verify or enroll the TLS certificate of an `https://` URL before sending
/// credentials. Plain `http://` URLs (used only on explicit operator opt-in or
/// loopback tests) have no TLS layer to pin and return `Ok(())`.
pub async fn verify_or_enroll_url(known_hosts: &KnownHostsStore, raw_url: &str) -> Result<()> {
    let parsed =
        url::Url::parse(raw_url).with_context(|| format!("invalid appliance URL: {raw_url}"))?;
    match parsed.scheme() {
        "https" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("appliance URL missing host: {raw_url}"))?;
            let port = parsed.port_or_known_default().unwrap_or(443);
            verify_or_enroll_endpoint(known_hosts, host, port).await?;
            Ok(())
        }
        "http" => Ok(()),
        other => Err(anyhow!("unsupported appliance URL scheme: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolls_first_certificate_and_accepts_matching_reconnections() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();

        let fp1 = verify_or_enroll_der(&store, "FW-01.Example.COM", 443, b"cert-der-v1").unwrap();
        let fp2 = verify_or_enroll_der(&store, "fw-01.example.com", 443, b"cert-der-v1").unwrap();
        assert_eq!(fp1, fp2);

        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "tls:fw-01.example.com:443");
    }

    #[test]
    fn rejects_certificate_swap_until_explicitly_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();

        verify_or_enroll_der(&store, "[fd00::1]", 8443, b"original-cert").unwrap();
        let err = verify_or_enroll_der(&store, "fd00::1", 8443, b"mitm-cert")
            .expect_err("changed self-signed cert must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("mismatch"), "{msg}");
        assert!(msg.contains("tls:fd00::1"), "{msg}");

        assert!(store.forget("tls:fd00::1", 8443).unwrap());
        verify_or_enroll_der(&store, "fd00::1", 8443, b"mitm-cert")
            .expect("forgotten pin should re-enroll on next sight");
    }
}
