//! What a deploy may push: exactly the configuration a preview showed, to
//! the host it was previewed against.
//!
//! A preview renders the template, diffs it with the unit's running
//! configuration, and leaves a plan: the rendered bytes, the request they
//! were rendered from, and the host they are for. The user reads the diff
//! and deploys the plan, not a render request, so the deploy pushes those
//! bytes and never renders again: a customer, site, template or extra
//! edited in between cannot change what goes to the unit. A plan is used
//! once and lasts [`TTL`]; plans live in memory, so after a restart, as
//! after expiry, the unit is previewed again.
//!
//! At deploy the target is checked again: the host must still be the site's
//! own FortiGate ([`validate_target`]), reached the same way as at the
//! preview. The unit's running configuration is not compared again: FortiOS
//! shows stored secrets (`ENC …`) freshly encrypted on every read, so two
//! reads of an unchanged unit differ. The backup taken right before the
//! push is what a rollback restores.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use supermgr_core::host::Host;
use supermgr_core::DeviceType;
use uuid::Uuid;

use super::RenderRequest;
use crate::customer::Customer;

/// How long a preview can be deployed.
pub const TTL: Duration = Duration::from_mins(15);
const MAX_PLANS: usize = 32;
/// A FortiGate configuration runs to a few hundred kilobytes.
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

pub struct Plan {
    pub host: Host,
    pub request: RenderRequest,
    pub rendered: String,
    created: Instant,
}

impl Plan {
    pub fn new(host: Host, request: RenderRequest, rendered: String) -> Result<Self> {
        if rendered.len() > MAX_CONFIG_BYTES {
            bail!("the rendered configuration is larger than a preview may hold");
        }
        Ok(Self {
            host,
            request,
            rendered,
            created: Instant::now(),
        })
    }

    /// `host` is reached the way the previewed one was: same address,
    /// account and credentials, and still assigned the same way. Other
    /// edits to the record, a label or a pin, do not matter to a deploy.
    pub fn validate_target_unchanged(&self, host: &Host) -> Result<()> {
        let reached = |h: &Host| {
            (
                h.id,
                h.hostname.clone(),
                h.port,
                h.username.clone(),
                h.device_type,
                h.auth_method,
                h.auth_key_id,
                h.auth_password_ref.clone(),
                h.auth_cert_ref.clone(),
                h.proxy_jump,
                h.group.clone(),
                h.customer.clone(),
            )
        };
        if reached(host) != reached(&self.host) {
            bail!("the host changed since the preview; preview it again");
        }
        Ok(())
    }
}

#[derive(Default)]
struct Entries {
    pending: HashMap<Uuid, Plan>,
    /// Hosts, by address, with a deploy in flight.
    active: HashSet<(String, u16)>,
}

/// The plans waiting to be deployed.
#[derive(Default)]
pub struct PlanRegistry {
    entries: Mutex<Entries>,
}

impl PlanRegistry {
    pub fn insert(&self, plan: Plan) -> Result<Uuid> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("the preview registry is unavailable"))?;
        entries.pending.retain(|_, p| p.created.elapsed() < TTL);
        if entries.pending.len() >= MAX_PLANS {
            bail!("too many previews are waiting; deploy or let them expire first");
        }
        let id = Uuid::new_v4();
        entries.pending.insert(id, plan);
        Ok(id)
    }

    /// Take the plan for a deploy. It is gone from the registry before any
    /// I/O, so a retry cannot push it twice. The lease keeps a second
    /// deploy off the same host until this one ends.
    pub fn take(self: &Arc<Self>, id: Uuid) -> Result<(Plan, TargetLease)> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("the preview registry is unavailable"))?;
        let plan = entries.pending.remove(&id).ok_or_else(|| {
            anyhow!(
                "this preview can no longer be deployed: it expired, was already \
                 deployed, or the app restarted. Preview again."
            )
        })?;
        if plan.created.elapsed() >= TTL {
            bail!("this preview expired; preview again");
        }
        let endpoint = (plan.host.hostname.clone(), plan.host.port);
        if !entries.active.insert(endpoint.clone()) {
            bail!("a deploy to this host is already running; preview again when it ends");
        }
        Ok((
            plan,
            TargetLease {
                registry: Arc::clone(self),
                endpoint,
            },
        ))
    }
}

/// A deploy's hold on its host. Dropping it lets the next one in.
pub struct TargetLease {
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

/// The customer `request` is for, if `host_id` is the one FortiGate its site
/// may be provisioned on: the site links it by record id, or by an address
/// no other host has, and no other customer's site links it. The app's
/// `HostIndex.provisioningHost` applies the same rules.
pub fn validate_target<'a>(
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
        bail!("provisioning deploys to FortiGate units only");
    }
    let [customer] = customers
        .iter()
        .filter(|c| c.slug == request.customer_slug)
        .collect::<Vec<_>>()[..]
    else {
        bail!("customer '{}' not found", request.customer_slug);
    };
    let [site] = customer
        .sites
        .iter()
        .filter(|s| s.id == request.site_id)
        .collect::<Vec<_>>()[..]
    else {
        bail!("site '{}' not found", request.site_id);
    };
    if customers.iter().any(|c| c.slug == host.group) && host.group != customer.slug {
        bail!("{} is assigned to another customer", host.label);
    }
    let unique_address = hosts.iter().filter(|h| h.hostname == host.hostname).count() == 1;
    let links = |token: &str| {
        Uuid::parse_str(token).ok() == Some(host.id) || (unique_address && token == host.hostname)
    };
    let linked_elsewhere = customers.iter().any(|c| {
        c.slug != customer.slug && c.sites.iter().any(|s| s.host_ids.iter().any(|t| links(t)))
    });
    if linked_elsewhere {
        bail!("{} is linked by another customer's site", host.label);
    }
    if !site.host_ids.iter().any(|t| links(t)) {
        bail!(
            "{} is not linked to site '{}'; link it by its record there",
            host.label,
            site.id
        );
    }
    Ok(customer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host(id: Uuid, address: &str, group: &str) -> Host {
        serde_json::from_value(json!({
            "id": id, "label": "FW", "hostname": address, "username": "admin",
            "auth_method": "password", "device_type": "fortigate", "group": group
        }))
        .unwrap()
    }

    fn customer(slug: &str, site: &str, links: &[String]) -> Customer {
        serde_json::from_value(json!({
            "slug": slug, "display_name": slug,
            "sites": [{"id": site, "display_name": site, "host_ids": links}]
        }))
        .unwrap()
    }

    fn request(customer: &str, site: &str) -> RenderRequest {
        RenderRequest {
            template_id: "branch_office".into(),
            customer_slug: customer.into(),
            site_id: site.into(),
            extras: serde_json::Map::new(),
        }
    }

    fn plan() -> Plan {
        Plan::new(
            host(Uuid::new_v4(), "10.0.0.1", "acme"),
            request("acme", "hq"),
            "config system global\n    set hostname reviewed\nend\n".into(),
        )
        .unwrap()
    }

    #[test]
    fn the_sites_own_firewall_is_the_target_and_nothing_else_is() {
        let id = Uuid::new_v4();
        let hosts = [host(id, "10.0.0.1", "acme")];
        let acme = customer("acme", "hq", &[id.to_string()]);
        assert_eq!(
            validate_target(
                &hosts,
                std::slice::from_ref(&acme),
                id,
                &request("acme", "hq")
            )
            .unwrap()
            .slug,
            "acme"
        );
        for req in [request("acme", "branch"), request("beta", "hq")] {
            assert!(validate_target(&hosts, std::slice::from_ref(&acme), id, &req).is_err());
        }
        let mut linux = hosts[0].clone();
        linux.device_type = DeviceType::Linux;
        assert!(validate_target(&[linux], &[acme], id, &request("acme", "hq")).is_err());
    }

    /// An address two hosts share names neither; a record id is exact.
    #[test]
    fn a_shared_address_is_not_a_link_but_a_record_id_is() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let hosts = [host(a, "192.168.1.1", ""), host(b, "192.168.1.1", "")];
        let by_address = customer("acme", "hq", &["192.168.1.1".into()]);
        assert!(validate_target(&hosts, &[by_address], a, &request("acme", "hq")).is_err());
        let by_id = customer("acme", "hq", &[a.simple().to_string()]);
        assert!(validate_target(&hosts, &[by_id], a, &request("acme", "hq")).is_ok());
        // A unique address is a link.
        let hosts = [host(a, "10.0.0.1", "")];
        let by_address = customer("acme", "hq", &["10.0.0.1".into()]);
        assert!(validate_target(&hosts, &[by_address], a, &request("acme", "hq")).is_ok());
    }

    #[test]
    fn a_firewall_another_customer_claims_is_not_a_target() {
        let id = Uuid::new_v4();
        let acme = customer("acme", "hq", &[id.to_string()]);
        let beta = customer("beta", "hq", &[id.to_string()]);
        let hosts = [host(id, "10.0.0.1", "")];
        assert!(validate_target(
            &hosts,
            &[acme.clone(), beta.clone()],
            id,
            &request("acme", "hq")
        )
        .is_err());
        let assigned_to_beta = [host(id, "10.0.0.1", "beta")];
        assert!(validate_target(
            &assigned_to_beta,
            &[acme, customer("beta", "hq", &[])],
            id,
            &request("acme", "hq")
        )
        .is_err());
    }

    #[test]
    fn a_plan_keeps_the_reviewed_bytes_and_is_used_once() {
        let registry = Arc::new(PlanRegistry::default());
        let p = plan();
        let reviewed = p.rendered.clone();
        let id = registry.insert(p).unwrap();
        let (taken, lease) = registry.take(id).unwrap();
        assert_eq!(taken.rendered, reviewed);
        assert!(registry.take(id).is_err());
        drop(lease);
        assert!(registry.take(id).is_err());
        // Plans do not outlive the registry: a restart means a new preview.
        assert!(Arc::new(PlanRegistry::default()).take(id).is_err());
    }

    #[test]
    fn expired_plans_too_many_plans_and_oversized_configurations_fail() {
        let registry = Arc::new(PlanRegistry::default());
        let mut expired = plan();
        expired.created = Instant::now().checked_sub(TTL).unwrap();
        let id = registry.insert(expired).unwrap();
        assert!(registry.take(id).is_err());
        for _ in 0..MAX_PLANS {
            registry.insert(plan()).unwrap();
        }
        assert!(registry.insert(plan()).is_err());
        let too_big = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert!(Plan::new(plan().host, request("acme", "hq"), too_big).is_err());
    }

    /// One deploy per host at a time; the lease ends with the deploy.
    #[test]
    fn a_second_deploy_to_the_same_host_waits_for_the_first() {
        let registry = Arc::new(PlanRegistry::default());
        let first = plan();
        let mut second = plan();
        second.host.hostname = first.host.hostname.clone();
        let (a, b) = (
            registry.insert(first).unwrap(),
            registry.insert(second).unwrap(),
        );
        let (_, lease) = registry.take(a).unwrap();
        assert!(registry.take(b).is_err());
        drop(lease);
        let mut third = plan();
        third.host.hostname = "10.0.0.1".into();
        let c = registry.insert(third).unwrap();
        assert!(registry.take(c).is_ok());
    }

    #[test]
    fn only_one_of_many_concurrent_deploys_takes_a_plan() {
        let registry = Arc::new(PlanRegistry::default());
        let id = registry.insert(plan()).unwrap();
        let winners: usize = std::thread::scope(|scope| {
            (0..16)
                .map(|_| scope.spawn(|| usize::from(registry.take(id).is_ok())))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|t| t.join().unwrap())
                .sum()
        });
        assert_eq!(winners, 1);
    }

    /// The app reads `plan_id` and `expires_in_secs` from the preview.
    #[test]
    fn the_preview_names_its_plan_and_expiry_for_the_app() {
        let preview = super::super::DiffPreviewResult {
            plan_id: Uuid::nil().to_string(),
            expires_in_secs: TTL.as_secs(),
            rendered: String::new(),
            sections: Vec::new(),
            summary: super::super::DiffSummary {
                added: 0,
                modified: 0,
                equal: 0,
                total: 0,
            },
        };
        let json = serde_json::to_value(preview).unwrap();
        assert_eq!(json["plan_id"], Uuid::nil().to_string());
        assert_eq!(json["expires_in_secs"], 900);
    }

    #[test]
    fn a_host_reached_differently_invalidates_the_plan_and_a_label_does_not() {
        let p = plan();
        let mut host = p.host.clone();
        host.label = "renamed".into();
        host.pinned = true;
        assert!(p.validate_target_unchanged(&host).is_ok());
        host.hostname = "10.9.9.9".into();
        assert!(p.validate_target_unchanged(&host).is_err());
        let mut host = p.host.clone();
        host.auth_key_id = Some(Uuid::new_v4());
        assert!(p.validate_target_unchanged(&host).is_err());
    }
}
