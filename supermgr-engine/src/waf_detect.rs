//! WAF / CDN identification from HTTP response signatures.
//!
//! Inspired by Kali's `wafw00f` and `whatweb`. The signal sources
//! are limited — we won't actively send malicious payloads to
//! fingerprint a WAF (that's gray-hat-leaning-black). Instead we
//! look at the response headers + cookies of a benign GET and
//! match against well-known vendor fingerprints. That's enough
//! to identify ~80% of real-world deployments.
//!
//! # Why this matters to an MSP audit
//!
//! 1. **Context for the rest of the audit.** If a target is
//!    behind Cloudflare, port-scan results are less reliable
//!    (the IP we see may be the edge, not the origin), and
//!    findings like "no rate-limit on login" need to factor in
//!    the WAF rules. Surfacing the WAF up-front saves the operator
//!    from chasing false leads.
//! 2. **Asset attribution.** Cloudflare/Akamai/Fastly fronting
//!    tells the customer where to log into to get edge logs +
//!    rule-change history — useful when an incident hits.
//! 3. **Origin-leak risk.** When a CDN is in front but a host
//!    elsewhere in scope serves the same content directly, we
//!    can flag the origin-bypass risk in a future iteration.
//!
//! # Detection sources
//!
//! - **Server header** — sometimes vendor-branded (e.g.
//!   `Server: cloudflare`).
//! - **Vendor-specific headers** — `CF-RAY`, `X-Sucuri-ID`,
//!   `X-CDN`, `X-Cache`, `X-Akamai-Transformed`, `Via:` with
//!   product name, etc.
//! - **Cookies** — `__cfduid`, `incap_ses_*`, `visid_incap_*`,
//!   `awselb`, `AWSALB`.
//!
//! Pure pattern matching on the response we already fetch during
//! HTTP/HTTPS probing — no extra round trip.

use std::collections::HashSet;

/// Information about an identified WAF / CDN / reverse proxy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WafInfo {
    pub vendor: String,
    pub kind: WafKind,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafKind {
    Cdn,
    Waf,
    LoadBalancer,
    ReverseProxy,
}

/// Inspect a response's headers + cookies for vendor signatures.
/// Returns one entry per vendor matched (a request can hit
/// multiple — e.g. AWS ALB in front of CloudFront).
///
/// Inputs:
///   - `headers`: header pairs from the HTTP response. Keys are
///     case-insensitive — the matcher lowercases them.
///   - `cookies`: parsed `Set-Cookie` names (not full values).
pub fn detect(headers: &[(String, String)], cookies: &[String]) -> Vec<WafInfo> {
    let mut hits: Vec<WafInfo> = Vec::new();
    let mut seen_vendors: HashSet<String> = HashSet::new();

    // Normalise headers to lowercase keys for cheap matching.
    let lower: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();
    let cookie_lower: Vec<String> = cookies.iter().map(|c| c.to_lowercase()).collect();

    for rule in SIGNATURES {
        let mut evidence: Vec<String> = Vec::new();

        // Header-key signal — presence alone is enough (the
        // values are usually opaque IDs).
        for hk in rule.header_keys {
            if lower.iter().any(|(k, _)| k == hk) {
                evidence.push(format!("header `{hk}`"));
            }
        }

        // Header-value contains — for headers we already
        // expected (like Server / Via / X-Powered-By).
        for (hk, needle) in rule.header_value_contains {
            if let Some((_, hv)) = lower.iter().find(|(k, _)| k == hk) {
                if hv.contains(*needle) {
                    evidence.push(format!("`{hk}: …{needle}…`"));
                }
            }
        }

        // Cookie-name prefix match.
        for cookie_pfx in rule.cookie_prefixes {
            if cookie_lower.iter().any(|c| c.starts_with(cookie_pfx)) {
                evidence.push(format!("cookie `{cookie_pfx}*`"));
            }
        }

        if !evidence.is_empty() && seen_vendors.insert(rule.vendor.to_owned()) {
            hits.push(WafInfo {
                vendor: rule.vendor.to_owned(),
                kind: rule.kind,
                evidence,
            });
        }
    }

    hits
}

/// One vendor's detection rules. All checks are OR-ed: any
/// matching signal flips the vendor on.
struct Signature {
    vendor: &'static str,
    kind: WafKind,
    header_keys: &'static [&'static str],
    header_value_contains: &'static [(&'static str, &'static str)],
    cookie_prefixes: &'static [&'static str],
}

const SIGNATURES: &[Signature] = &[
    // --- Cloudflare ----------------------------------------------------------
    Signature {
        vendor: "Cloudflare",
        kind: WafKind::Cdn,
        header_keys: &["cf-ray", "cf-cache-status", "cf-request-id"],
        header_value_contains: &[
            ("server", "cloudflare"),
            ("via", "cloudflare"),
        ],
        cookie_prefixes: &["__cfduid", "__cf_bm", "__cflb", "cf_clearance"],
    },
    // --- AWS CloudFront ------------------------------------------------------
    Signature {
        vendor: "AWS CloudFront",
        kind: WafKind::Cdn,
        header_keys: &["x-amz-cf-id", "x-amz-cf-pop"],
        header_value_contains: &[
            ("via", "cloudfront"),
            ("server", "cloudfront"),
        ],
        cookie_prefixes: &[],
    },
    // --- AWS ALB / ELB -------------------------------------------------------
    Signature {
        vendor: "AWS ELB/ALB",
        kind: WafKind::LoadBalancer,
        header_keys: &[],
        header_value_contains: &[
            ("server", "awselb"),
            ("server", "awsalb"),
        ],
        cookie_prefixes: &["awselb", "awsalb", "awsalbcors"],
    },
    // --- AWS WAF -------------------------------------------------------------
    Signature {
        vendor: "AWS WAF",
        kind: WafKind::Waf,
        header_keys: &["x-amzn-waf-action", "x-amzn-requestid"],
        header_value_contains: &[],
        cookie_prefixes: &["aws-waf-token"],
    },
    // --- Akamai --------------------------------------------------------------
    Signature {
        vendor: "Akamai",
        kind: WafKind::Cdn,
        header_keys: &[
            "x-akamai-transformed",
            "akamai-grn",
            "x-akamai-staging",
        ],
        header_value_contains: &[
            ("server", "akamaighost"),
            ("via", "akamai"),
        ],
        cookie_prefixes: &["akamai-ldns-test"],
    },
    // --- Fastly --------------------------------------------------------------
    Signature {
        vendor: "Fastly",
        kind: WafKind::Cdn,
        header_keys: &["fastly-debug-digest", "x-fastly-request-id", "x-served-by"],
        header_value_contains: &[
            ("via", "varnish"),  // not specific to fastly but common
            ("server", "fastly"),
        ],
        cookie_prefixes: &[],
    },
    // --- Sucuri --------------------------------------------------------------
    Signature {
        vendor: "Sucuri",
        kind: WafKind::Waf,
        header_keys: &["x-sucuri-id", "x-sucuri-cache"],
        header_value_contains: &[("server", "sucuri")],
        cookie_prefixes: &[],
    },
    // --- Imperva / Incapsula -------------------------------------------------
    Signature {
        vendor: "Imperva (Incapsula)",
        kind: WafKind::Waf,
        header_keys: &["x-iinfo", "x-cdn"],
        header_value_contains: &[("x-cdn", "incapsula")],
        cookie_prefixes: &["incap_ses_", "visid_incap_", "nlbi_"],
    },
    // --- F5 BIG-IP -----------------------------------------------------------
    Signature {
        vendor: "F5 BIG-IP",
        kind: WafKind::LoadBalancer,
        header_keys: &[],
        header_value_contains: &[("server", "bigip"), ("server", "big-ip")],
        cookie_prefixes: &["bigipserver", "f5_cspm", "ts"],
    },
    // --- Barracuda WAF -------------------------------------------------------
    Signature {
        vendor: "Barracuda WAF",
        kind: WafKind::Waf,
        header_keys: &["x-barracuda-apc-cookie"],
        header_value_contains: &[("server", "barracudangf"), ("server", "barracuda")],
        cookie_prefixes: &["barra_counter_session"],
    },
    // --- Citrix NetScaler / ADC ---------------------------------------------
    Signature {
        vendor: "Citrix NetScaler/ADC",
        kind: WafKind::LoadBalancer,
        header_keys: &["via"],
        header_value_contains: &[("via", "netscaler"), ("server", "netscaler")],
        cookie_prefixes: &["citrix_ns_id", "ns_af"],
    },
    // --- ModSecurity (generic) ----------------------------------------------
    // Hardest to fingerprint passively — ModSec usually only
    // reveals itself on a blocked response. The Server header
    // sometimes leaks the version.
    Signature {
        vendor: "ModSecurity",
        kind: WafKind::Waf,
        header_keys: &[],
        header_value_contains: &[
            ("server", "mod_security"),
            ("server", "modsecurity"),
        ],
        cookie_prefixes: &[],
    },
    // --- nginx + Lua / OpenResty (often used to host WAFs) ------------------
    Signature {
        vendor: "OpenResty",
        kind: WafKind::ReverseProxy,
        header_keys: &[],
        header_value_contains: &[("server", "openresty")],
        cookie_prefixes: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }
    fn c(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn detects_cloudflare_via_cf_ray_header() {
        let hits = detect(&h(&[("CF-RAY", "8123abc-AMS"), ("Server", "cloudflare")]), &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vendor, "Cloudflare");
        assert_eq!(hits[0].kind, WafKind::Cdn);
        assert!(hits[0].evidence.iter().any(|e| e.contains("cf-ray")));
    }

    #[test]
    fn detects_cloudflare_via_cookie() {
        let hits = detect(&[], &c(&["__cf_bm=abc123"]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vendor, "Cloudflare");
    }

    #[test]
    fn detects_cloudfront_via_amz_header() {
        let hits = detect(&h(&[("X-Amz-Cf-Id", "abc"), ("Via", "1.1 abc.cloudfront.net")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "AWS CloudFront"));
    }

    #[test]
    fn detects_aws_elb_via_cookie() {
        let hits = detect(&[], &c(&["AWSALB=xyz", "AWSALBCORS=xyz"]));
        assert!(hits.iter().any(|w| w.vendor == "AWS ELB/ALB"));
    }

    #[test]
    fn detects_incapsula_visid_cookie() {
        let hits = detect(&[], &c(&["visid_incap_12345=abc", "nlbi_12345=xyz"]));
        assert!(hits.iter().any(|w| w.vendor == "Imperva (Incapsula)"));
    }

    #[test]
    fn detects_akamai_via_server_header() {
        let hits = detect(&h(&[("Server", "AkamaiGHost")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "Akamai"));
    }

    #[test]
    fn detects_sucuri_via_x_sucuri_id() {
        let hits = detect(&h(&[("X-Sucuri-ID", "abc")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "Sucuri"));
    }

    #[test]
    fn detects_f5_via_bigipserver_cookie() {
        let hits = detect(&[], &c(&["BIGipServer_pool_x=1234.5678"]));
        assert!(hits.iter().any(|w| w.vendor == "F5 BIG-IP"));
    }

    #[test]
    fn detects_modsecurity_in_server_header() {
        let hits = detect(&h(&[("Server", "Apache/2.4.65 mod_security/2.9")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "ModSecurity"));
    }

    #[test]
    fn no_signatures_clean_server_returns_empty() {
        let hits = detect(&h(&[("Server", "nginx/1.25.0"), ("Content-Type", "text/html")]), &[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn case_insensitive_header_keys() {
        let hits = detect(&h(&[("cf-ray", "8123abc")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "Cloudflare"));
        let hits = detect(&h(&[("CF-RAY", "8123abc")]), &[]);
        assert!(hits.iter().any(|w| w.vendor == "Cloudflare"));
    }

    #[test]
    fn multiple_vendors_simultaneously() {
        // Real example: an ALB fronting a CloudFront-fronted origin.
        let hits = detect(
            &h(&[
                ("X-Amz-Cf-Id", "abc"),
                ("Via", "1.1 cloudfront.net"),
            ]),
            &c(&["AWSALB=xyz"]),
        );
        let vendors: Vec<&str> = hits.iter().map(|w| w.vendor.as_str()).collect();
        assert!(vendors.contains(&"AWS CloudFront"));
        assert!(vendors.contains(&"AWS ELB/ALB"));
    }

    #[test]
    fn no_duplicate_vendor_when_multiple_signals_match() {
        // Cloudflare hits via BOTH header AND cookie — should
        // produce exactly one entry with combined evidence.
        let hits = detect(
            &h(&[("CF-RAY", "abc"), ("Server", "cloudflare")]),
            &c(&["__cf_bm=xyz"]),
        );
        let cf: Vec<&WafInfo> = hits.iter().filter(|w| w.vendor == "Cloudflare").collect();
        assert_eq!(cf.len(), 1, "should not duplicate Cloudflare hit");
    }
}
