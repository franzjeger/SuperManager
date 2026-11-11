//! Network discovery JSON-RPC handlers.
//!
//! Passive scan (cert/SNI sweep), inventory loader, active port-scan
//! fan-out, and the persisted-findings loader for the discovery scope.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_discovery_passive_scan(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let customer_slug = params
            .get("customer_slug")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let engagement_id = params
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        match crate::discovery::passive_scan(
            &self.state,
            customer_slug.as_deref(),
            engagement_id.as_deref(),
        )
        .await
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_discovery_active_scan(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let customer_slug = params
            .get("customer_slug")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let engagement_id = params
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let targets_raw: Vec<String> = match params.get("targets").and_then(|v| v.as_array()) {
            Some(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let Some(s) = item.as_str() else {
                        return Response::err(
                            id,
                            protocol::INVALID_PARAMS,
                            "every entry in 'targets' must be a string".to_owned(),
                        );
                    };
                    if let Err(reason) = crate::discovery::validate_scan_target(s) {
                        return Response::err(id, protocol::INVALID_PARAMS, reason);
                    }
                    out.push(s.trim().to_owned());
                }
                out
            }
            None => Vec::new(),
        };
        if targets_raw.is_empty() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "missing or empty 'targets'".to_owned(),
            );
        }

        let ports: Vec<u16> = match params.get("ports") {
            None => crate::probes::COMMON_PORTS.to_vec(),
            Some(v) => {
                let Some(arr) = v.as_array() else {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        "'ports' must be an array of TCP port numbers (1..=65535)".to_owned(),
                    );
                };
                if arr.is_empty() || arr.len() > crate::discovery::MAX_SCAN_PORTS {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        format!(
                            "'ports' must contain between 1 and {} port numbers",
                            crate::discovery::MAX_SCAN_PORTS
                        ),
                    );
                }
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let Some(p) = item
                        .as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|&p| p > 0)
                    else {
                        return Response::err(
                            id,
                            protocol::INVALID_PARAMS,
                            "invalid port number in 'ports' (expected 1..=65535)".to_owned(),
                        );
                    };
                    out.push(p);
                }
                out
            }
        };

        let requested_cap = match params.get("max_targets") {
            None => 512usize,
            Some(v) => {
                let Some(n) = v.as_u64() else {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        "'max_targets' must be a positive integer".to_owned(),
                    );
                };
                if n == 0 || n > crate::discovery::MAX_SCAN_TARGETS as u64 {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        format!(
                            "'max_targets' must be between 1 and {}",
                            crate::discovery::MAX_SCAN_TARGETS
                        ),
                    );
                }
                n as usize
            }
        };
        let targets = crate::discovery::expand_targets(&targets_raw, requested_cap);
        if targets.is_empty() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                format!("no targets after expansion (CIDR may exceed max_targets={requested_cap})"),
            );
        }

        // Strict-scope enforcement. Any specified engagement MUST load
        // cleanly (failing closed on missing/unreadable/corrupt scope files).
        // When `strict_scope = true`, every IP must match `scope_cidrs` and
        // avoid `exclusions`, and any hostname target must appear in
        // `scope_hosts`.
        if let Some(eid_raw) = engagement_id.as_deref() {
            let eid = eid_raw.trim();
            if eid.is_empty() {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "'engagement_id' must not be empty".to_owned(),
                );
            }
            let engagement = match crate::engagement::load(eid) {
                Ok(e) => e,
                Err(err) => {
                    return Response::err_engine(
                        id,
                        &crate::error::EngineError::InvalidScope {
                            reason: format!("Failed to load engagement '{eid}': {err:#}"),
                        },
                    );
                }
            };
            if engagement.strict_scope {
                let mut violations = crate::engagement::targets_outside_scope(
                    &targets,
                    &engagement.scope_cidrs,
                    &engagement.exclusions,
                );
                if !engagement.scope_cidrs.is_empty() || !engagement.scope_hosts.is_empty() {
                    for t in &targets {
                        if t.parse::<std::net::IpAddr>().is_err()
                            && !engagement
                                .scope_hosts
                                .iter()
                                .any(|allowed| allowed.eq_ignore_ascii_case(t))
                        {
                            violations.push(t.clone());
                        }
                    }
                }
                if !violations.is_empty() {
                    let sample = violations
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    let extra = if violations.len() > 5 {
                        format!(" (+ {} more)", violations.len() - 5)
                    } else {
                        String::new()
                    };
                    return Response::err_engine(
                        id,
                        &crate::error::EngineError::InvalidScope {
                            reason: format!(
                                "Strict scope: {} target(s) outside engagement scope or inside exclusions: {sample}{extra}",
                                violations.len()
                            ),
                        },
                    );
                }
            }
        }

        // Register the scan as a cancellable operation. The guard
        // unregisters on drop so we don't have to remember to
        // clean up on error paths.
        let label = format!(
            "Active scan — {} targets, {} ports",
            targets.len(),
            ports.len(),
        );
        let guard = self.operations.start("active_scan", label);
        let cancel = Some(guard.cancel_flag());
        let scan_result = crate::discovery::active_scan(
            &targets,
            &ports,
            customer_slug.as_deref(),
            engagement_id.as_deref(),
            cancel,
        )
        .await;

        match scan_result {
            Ok(mut result) => {
                // Controller-first annotation. Cross-reference
                // every scanned host's MAC against the union of
                // all configured UniFi controllers' device
                // inventories. Matches get `controller_state`
                // populated so the GUI can swap SSH-based
                // actions for controller-API ones. Failures
                // (unreachable controller, login refused, etc.)
                // log + continue — the underlying scan result
                // is still valid and useful even when no
                // controller responded.
                // Snapshot the override store + controller
                // list under a single lock acquisition so we
                // don't hold the state lock during the
                // network round-trips below.
                let (controllers, override_store) = {
                    let st = self.state.lock().await;
                    (
                        st.unifi_controllers.values().cloned().collect::<Vec<_>>(),
                        st.device_type_overrides.clone(),
                    )
                };
                // Apply manual device-type overrides FIRST so
                // the controller cross-reference and the GUI
                // both see the operator's chosen type. We just
                // stash the override string on the host; the
                // GUI's row renderer treats it as authoritative.
                for host in &mut result.hosts {
                    if let Some(ref mac) = host.mac {
                        if let Some(t) = override_store.get(mac).await {
                            host.device_type_override = Some(t);
                        }
                    }
                }
                if !controllers.is_empty() {
                    let macs: Vec<String> =
                        result.hosts.iter().filter_map(|h| h.mac.clone()).collect();
                    if !macs.is_empty() {
                        let by_mac = crate::unifi_controllers::cross_reference(
                            &self.secrets,
                            &controllers,
                            &macs,
                        )
                        .await;
                        for host in &mut result.hosts {
                            if let Some(ref mac) = host.mac {
                                if let Some(state) = by_mac.get(&mac.to_ascii_lowercase()) {
                                    host.controller_state = Some(state.clone());
                                }
                            }
                        }
                    }
                }
                match serde_json::to_value(&result) {
                    Ok(v) => Response::ok(id, v),
                    Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
                }
            }
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// List every device-type override the operator has set,
    /// returned as a flat map MAC → device-type string.
    pub(crate) async fn handle_device_type_overrides_list(&self, id: u64) -> Response {
        let store = {
            let st = self.state.lock().await;
            st.device_type_overrides.clone()
        };
        let map = store.snapshot().await;
        match serde_json::to_value(&map) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Set (or clear, when `device_type` is null/empty) a
    /// manual device-type override. Params:
    ///   - `mac` (or `key`) — the MAC the override applies to
    ///   - `scope` — `"mac"` (default) for exact-MAC match,
    ///     `"oui"` to apply to every device with the same
    ///     three-octet OUI prefix
    ///   - `device_type` — type string (or empty to clear)
    pub(crate) async fn handle_device_type_override_set(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let key = match params
            .get("mac")
            .or_else(|| params.get("key"))
            .and_then(|v| v.as_str())
        {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing mac".to_owned()),
        };
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some("oui") => crate::device_type_overrides::OverrideScope::Oui,
            _ => crate::device_type_overrides::OverrideScope::Mac,
        };
        let device_type = params.get("device_type").and_then(|v| v.as_str());
        let store = {
            let st = self.state.lock().await;
            st.device_type_overrides.clone()
        };
        let dt = device_type.filter(|s| !s.is_empty());
        match store.set(&key, scope, dt).await {
            Ok(()) => Response::ok(
                id,
                serde_json::json!({ "ok": true, "scope": scope.as_str() }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_discovery_findings(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("customer_slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing customer_slug".to_owned(),
                )
            }
        };
        match crate::discovery::load_findings(&slug) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// DNS zone-transfer (AXFR) probe — Kali-style recon. Tries
    /// to pull the full zone from each of the domain's authoritative
    /// nameservers. Returns one finding per leaking NS.
    pub(crate) async fn handle_discovery_dns_axfr(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let domain = match params.get("domain").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing or empty `domain` parameter".to_owned(),
                );
            }
        };
        let findings = crate::dns_axfr::check(&domain).await;
        match serde_json::to_value(&findings) {
            Ok(v) => Response::ok(id, serde_json::json!({"findings": v})),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Analyse a packet capture for cleartext-protocol exposure.
    /// Parses the .pcap, classifies events per (`src_ip`, protocol),
    /// emits findings, and writes redacted evidence files to the
    /// engagement's `captures/` directory. The full unredacted
    /// .pcap stays on disk for the operator's Wireshark review.
    pub(crate) async fn handle_discovery_analyse_pcap(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let pcap_path = match params.get("pcap_path").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing or empty `pcap_path`".to_owned(),
                );
            }
        };
        let engagement_id = params
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let evidence_dir = if let Some(eid) = engagement_id.as_deref() {
            if let Err(e) = crate::customer::validate_slug(eid) {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!("invalid engagement_id: {e}"),
                );
            }
            crate::traffic_sniff::engagement_evidence_dir(eid)
        } else {
            let mut p = crate::secrets::default_data_dir();
            p.push("captures");
            p
        };

        let pcap = std::path::Path::new(&pcap_path);
        match crate::traffic_sniff::analyse_pcap(pcap, &evidence_dir).await {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_discovery_inventory(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("customer_slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing customer_slug".to_owned(),
                )
            }
        };
        match crate::discovery::load_inventory(&slug) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
