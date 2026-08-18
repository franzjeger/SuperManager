//! Process-wide shared `reqwest::Client` instances.
//!
//! Building a `reqwest::Client` allocates a `hyper` connection pool, a TLS
//! context and (when a cookie store is enabled) a cookie jar. Doing that on
//! every request defeats TCP/TLS connection reuse and session resumption —
//! each call pays a fresh handshake. These two statics give the whole process
//! one long-lived pool each, so repeated calls to the same host reuse the
//! underlying socket.
//!
//! Two variants, because the app talks to two very different kinds of
//! endpoint:
//!
//! * [`default_client`] — plain internet endpoints (webhooks, Azure OAuth,
//!   the NVD feed, crt.sh, ifconfig.me, the Claude API). Standard TLS.
//! * [`insecure_client`] — LAN gear (`FortiGate`, `UniFi`, `OPNsense`, Sophos,
//!   self-signed admin panels) that needs `danger_accept_invalid_certs`.
//!
//! Deliberately NOT shared: per-controller `UniFi` clients that carry a
//! `cookie_store` / `cookie_provider` / `default_headers` with a per-controller
//! API key. Sharing those would leak cookies and credentials between
//! controllers, so those keep building their own client.
//!
//! Timeouts are intentionally left to the *request* (via
//! `RequestBuilder::timeout`) rather than baked into the client: different
//! call sites need different budgets (3 s for ifconfig.me, 60 s for a
//! `FortiGate` backup). A client-level timeout would be the minimum for all of
//! them, which is exactly the coupling we don't want. The value set here is
//! only a safety net for the rare call site that sets none.

use std::sync::OnceLock;
use std::time::Duration;

/// A generous default for calls that don't set their own request timeout.
/// This is a safety net, not a policy — most call sites override it.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn build(accept_invalid_certs: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .timeout(DEFAULT_TIMEOUT)
        .build()
        // A `reqwest::Client` can only fail to build if the system has no
        // usable TLS backend at all, in which case nothing in this process
        // could do any HTTPS anyway.
        .expect("build shared reqwest client")
}

/// Shared client for standard (valid-TLS) internet endpoints.
pub fn default_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| build(false))
}

/// Shared client for LAN gear that presents self-signed or otherwise
/// invalid certificates.
pub fn insecure_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| build(true))
}
