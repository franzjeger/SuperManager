//! Process-local, bounded, single-use approvals. Restart or expiry requires review again.
use super::RenderRequest;
use crate::customer::Customer;
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use supermgr_core::{host::Host, DeviceType};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(600);
const MAX_PLANS: usize = 32;
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

pub(crate) enum PlanOperation {
    DeployTemplate,
    RestoreBackup { source_deployment_id: String },
}

pub(crate) struct Plan {
    pub operation: PlanOperation,
    pub host: Host,
    pub customer: Customer,
    pub request: RenderRequest,
    pub rendered: String,
    pub live_digest: Vec<u8>,
    created: Instant,
}
impl Plan {
    pub fn new(
        host: Host,
        customer: Customer,
        request: RenderRequest,
        rendered: String,
        live: &str,
    ) -> Result<Self> {
        if !crate::ssh::shell::supported_commands(&rendered.lines().collect::<Vec<_>>()) {
            bail!("Configuration contains unsupported multiline quoted commands or control characters");
        }
        if rendered.len() > MAX_CONFIG_BYTES {
            bail!("configuration exceeds preview size limit");
        }
        Ok(Self {
            operation: PlanOperation::DeployTemplate,
            host,
            customer,
            request,
            rendered,
            live_digest: digest(live),
            created: Instant::now(),
        })
    }
    pub fn validate_current(&self, host: &Host, customer: &Customer) -> Result<()> {
        if serde_json::to_value(host)? != serde_json::to_value(&self.host)?
            || serde_json::to_value(customer)? != serde_json::to_value(&self.customer)?
        {
            bail!("Target or customer changed since preview; review a new preview");
        }
        Ok(())
    }
    pub fn validate_live(&self, live: &str) -> Result<()> {
        if digest(live) != self.live_digest {
            bail!("Device configuration changed since preview; review a new preview");
        }
        Ok(())
    }
}
fn digest(text: &str) -> Vec<u8> {
    Sha256::digest(text.as_bytes()).to_vec()
}

#[derive(Default)]
struct Entries {
    pending: HashMap<Uuid, Plan>,
    active: HashSet<(String, u16)>,
}
#[derive(Default)]
pub(crate) struct PlanRegistry {
    entries: Mutex<Entries>,
}
impl PlanRegistry {
    pub fn insert(&self, plan: Plan) -> Result<Uuid> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("deployment registry unavailable"))?;
        entries.pending.retain(|_, p| p.created.elapsed() < TTL);
        if entries.pending.len() >= MAX_PLANS {
            bail!("Too many pending previews; close previews and wait for expiry");
        }
        let id = Uuid::new_v4();
        entries.pending.insert(id, plan);
        Ok(id)
    }
    /// Consumes before any I/O. Retry cannot push the configuration twice.
    pub fn take(self: &Arc<Self>, id: Uuid) -> Result<(Plan, TargetLease)> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("deployment registry unavailable"))?;
        let plan = entries.pending.remove(&id).ok_or_else(|| anyhow!(
            "Preview unavailable (expired, restarted, or already used). Check deployment history before creating another preview."))?;
        if plan.created.elapsed() >= TTL {
            bail!("Preview expired; review a new preview");
        }
        let endpoint = (plan.host.hostname.clone(), plan.host.port);
        if !entries.active.insert(endpoint.clone()) {
            bail!(
                "A deployment to this host is already in progress; review again after it finishes"
            );
        }
        let lease = TargetLease {
            registry: Arc::clone(self),
            endpoint,
        };
        Ok((plan, lease))
    }
}
pub(crate) struct TargetLease {
    registry: Arc<PlanRegistry>,
    endpoint: (String, u16),
}
impl Drop for TargetLease {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.registry.entries.lock() {
            entries.active.remove(&self.endpoint);
        }
    }
}

/// Resolve structural membership without last-write-wins address aliases.
/// Legacy IP links are accepted only when globally unique. Conflicting customer
/// links fail closed even when `group` claims one of the customers.
pub(crate) fn validate_target<'a>(
    hosts: &[Host],
    customers: &'a [Customer],
    host_id: Uuid,
    request: &RenderRequest,
) -> Result<&'a Customer> {
    let host = hosts
        .iter()
        .find(|h| h.id == host_id)
        .ok_or_else(|| anyhow!("host not found"))?;
    if host.device_type != DeviceType::Fortigate {
        bail!("Deployment requires a FortiGate target");
    }
    let selected: Vec<_> = customers
        .iter()
        .filter(|c| c.slug == request.customer_slug)
        .collect();
    if selected.len() != 1 {
        bail!("Customer missing or ambiguous");
    }
    let customer = selected[0];
    let sites: Vec<_> = customer
        .sites
        .iter()
        .filter(|s| s.id == request.site_id)
        .collect();
    if sites.len() != 1 {
        bail!("Site missing or ambiguous");
    }
    if !host.customer.is_empty() && host.customer != customer.slug {
        bail!("Target customer tag does not match selected customer");
    }
    if customers.iter().any(|c| c.slug == host.group) && host.group != customer.slug {
        bail!("Target belongs to a different customer");
    }
    let links_host =
        |token: &str| Uuid::parse_str(token).ok() == Some(host.id) || token == host.hostname;
    if customers.iter().any(|c| {
        c.slug != customer.slug
            && c.sites
                .iter()
                .any(|s| s.host_ids.iter().any(|t| links_host(t)))
    }) {
        bail!("Target has conflicting customer links; use explicit host IDs and repair membership");
    }
    let attached = sites[0].host_ids.iter().any(|token| {
        Uuid::parse_str(token).ok() == Some(host.id)
            || (token == &host.hostname
                && hosts.iter().filter(|h| h.hostname == host.hostname).count() == 1)
    });
    if !attached {
        bail!("Target is not unambiguously attached to the selected site; link its host record ID");
    }
    Ok(customer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Host, Customer, RenderRequest) {
        let host: Host = serde_json::from_value(json!({"id": Uuid::new_v4(), "label":"FW", "hostname":"10.0.0.1", "username":"admin", "auth_method":"password", "device_type":"fortigate", "group":"acme"})).unwrap();
        let customer: Customer = serde_json::from_value(json!({"slug":"acme", "display_name":"Acme", "sites":[{"id":"hq", "display_name":"HQ", "host_ids":[host.id.to_string()]}]})).unwrap();
        let request = RenderRequest {
            template_id: "branch_office".into(),
            customer_slug: "acme".into(),
            site_id: "hq".into(),
            extras: Default::default(),
        };
        (host, customer, request)
    }
    fn plan() -> Plan {
        let (h, c, r) = fixture();
        Plan::new(
            h,
            c,
            r,
            "config system global\nset hostname reviewed\nend\n".into(),
            "original live config",
        )
        .unwrap()
    }
    #[test]
    fn scope_rejects_other_site_customer_and_vendor() {
        let (mut h, c, mut r) = fixture();
        assert!(
            validate_target(std::slice::from_ref(&h), std::slice::from_ref(&c), h.id, &r).is_ok()
        );
        r.site_id = "branch".into();
        assert!(
            validate_target(std::slice::from_ref(&h), std::slice::from_ref(&c), h.id, &r).is_err()
        );
        r.site_id = "hq".into();
        r.customer_slug = "other".into();
        assert!(
            validate_target(std::slice::from_ref(&h), std::slice::from_ref(&c), h.id, &r).is_err()
        );
        r.customer_slug = "acme".into();
        h.device_type = DeviceType::Linux;
        assert!(validate_target(std::slice::from_ref(&h), &[c], h.id, &r).is_err());
    }
    #[test]
    fn shared_ip_rejected_but_explicit_ids_work() {
        let (h, mut c, r) = fixture();
        let mut other = h.clone();
        other.id = Uuid::new_v4();
        other.group = "beta".into();
        let hosts = vec![h.clone(), other];
        c.sites[0].host_ids = vec![h.hostname.clone()];
        assert!(validate_target(&hosts, std::slice::from_ref(&c), h.id, &r).is_err());
        c.sites[0].host_ids = vec![h.id.simple().to_string()];
        assert!(validate_target(&hosts, &[c], h.id, &r).is_ok());
    }
    #[test]
    fn unique_legacy_ip_works_but_conflicting_claims_and_duplicate_sites_fail() {
        let (h, mut c, r) = fixture();
        c.sites[0].host_ids = vec![h.hostname.clone()];
        assert!(
            validate_target(std::slice::from_ref(&h), std::slice::from_ref(&c), h.id, &r).is_ok()
        );
        let mut other = c.clone();
        other.slug = "beta".into();
        assert!(validate_target(std::slice::from_ref(&h), &[c.clone(), other], h.id, &r).is_err());
        c.sites.push(c.sites[0].clone());
        assert!(validate_target(std::slice::from_ref(&h), &[c], h.id, &r).is_err());
    }
    #[test]
    fn changed_host_credentials_customer_or_live_config_invalidates_plan() {
        let p = plan();
        assert!(p.validate_current(&p.host, &p.customer).is_ok());
        let mut host = p.host.clone();
        host.hostname = "wrong-host".into();
        assert!(p.validate_current(&host, &p.customer).is_err());
        host = p.host.clone();
        host.auth_key_id = Some(Uuid::new_v4());
        assert!(p.validate_current(&host, &p.customer).is_err());
        let mut customer = p.customer.clone();
        customer.sites[0].lan_base = "other-config".into();
        assert!(p.validate_current(&p.host, &customer).is_err());
        assert!(p.validate_live("original live config").is_ok());
        assert!(p.validate_live("changed live config").is_err());
    }
    #[test]
    fn approval_retains_exact_output_and_is_single_use() {
        let registry = Arc::new(PlanRegistry::default());
        let p = plan();
        let approved = p.rendered.clone();
        let id = registry.insert(p).unwrap();
        let (taken, lease) = registry.take(id).unwrap();
        assert_eq!(taken.rendered, approved);
        assert!(registry.take(id).is_err());
        drop(lease);
        assert!(registry.take(id).is_err());
        assert!(Arc::new(PlanRegistry::default()).take(id).is_err());
    }
    #[test]
    fn expiry_capacity_and_large_config_fail_closed() {
        let registry = Arc::new(PlanRegistry::default());
        let mut expired = plan();
        expired.created = Instant::now() - TTL;
        let id = registry.insert(expired).unwrap();
        assert!(registry.take(id).is_err());
        for _ in 0..MAX_PLANS {
            registry.insert(plan()).unwrap();
        }
        assert!(registry.insert(plan()).is_err());
        let (h, c, r) = fixture();
        assert!(Plan::new(h, c, r, "x".repeat(MAX_CONFIG_BYTES + 1), "live").is_err());
    }
    #[test]
    fn concurrent_requests_only_one_can_consume_and_lease_releases_on_drop() {
        let registry = Arc::new(PlanRegistry::default());
        let p = plan();
        let host = p.host.clone();
        let id = registry.insert(p).unwrap();
        let winners: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| usize::from(registry.take(id).is_ok())))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(winners, 1);
        let mut p1 = plan();
        p1.host = host.clone();
        let mut p2 = plan();
        p2.host = host.clone();
        p2.host.id = Uuid::new_v4();
        let id1 = registry.insert(p1).unwrap();
        let id2 = registry.insert(p2).unwrap();
        let (_, lease) = registry.take(id1).unwrap();
        assert!(registry.take(id2).is_err());
        drop(lease);
        let mut p3 = plan();
        p3.host = host;
        let id3 = registry.insert(p3).unwrap();
        assert!(registry.take(id3).is_ok());
    }
}
