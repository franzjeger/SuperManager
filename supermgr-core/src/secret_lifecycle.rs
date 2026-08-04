//! Which secret-store labels an entity owns, and which stored labels no
//! longer have an owner.
//!
//! # Why this module exists
//!
//! Secrets in this codebase are stored out-of-band: a [`Profile`], [`Host`],
//! or [`SshKey`] holds a [`SecretRef`] label, and the bytes live in the
//! keyring / keychain / secrets file under that label.  Deleting the record
//! is therefore two operations, and this codebase has shipped the first
//! without the second **three separate times** — once for VPN profiles, once
//! for SSH keys, once for SSH hosts.  Each was found and fixed in isolation,
//! and each fix left the next one to be discovered by a human reading the
//! code.  A leaked label is not a tidiness problem: the bytes behind it are a
//! private key, a firewall API token, or a customer's VPN password, and the
//! backup archive tars the whole store.
//!
//! So this module makes the ownership map a *single* piece of data that every
//! delete path consults, and adds an audit that finds what the earlier misses
//! already left behind on real installs.
//!
//! # The compile-time half
//!
//! [`SecretOwner::secret_labels`] is implemented by destructuring each type
//! with **every field named** and matching each enum with **no wildcard arm**.
//! That is deliberate and load-bearing:
//!
//! ```text
//! adding a field to `Host`            -> this file stops compiling
//! adding a `ProfileConfig` variant    -> this file stops compiling
//! ```
//!
//! The fix in both cases is one line, but writing it forces the question
//! "is this a secret reference?" to be asked at the moment the field is
//! added rather than after a customer's key outlives its profile.  **Do not
//! silence a build error here with `..` or `_ =>`** — that converts a
//! compile error into the exact bug this module exists to prevent.
//!
//! # The runtime half
//!
//! [`LiveSecrets`] collects the labels every surviving entity points at, and
//! [`LiveSecrets::find_orphans`] reports stored labels that no longer have an
//! owner.  It is deliberately **sound rather than complete**: it would rather
//! miss an orphan than name a live secret, because the only sensible action
//! on the output is deletion.  See [`LiveSecrets::is_orphan`] for the rule.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::host::Host;
use crate::ssh::key::SshKey;
use crate::vpn::profile::{
    AzureVpnConfig, ForticlientSslvpnConfig, FortiGateConfig, GenericConfig, OpenVpnConfig,
    Profile, ProfileConfig, WireGuardConfig, WireGuardPeer,
};

// ---------------------------------------------------------------------------
// Derived labels
// ---------------------------------------------------------------------------

/// Label under which an Azure VPN profile's cached `OAuth2` refresh token
/// is stored.
///
/// Unlike every other secret in the codebase this one is *derived* from the
/// profile UUID rather than pointed at by a [`SecretRef`] field, because it
/// is written lazily at connect time rather than at import time.  It is a
/// long-lived credential to the customer's Entra tenant all the same, so it
/// belongs to the profile's lifetime and is reported by
/// [`SecretOwner::secret_labels`] like any other.
///
/// [`SecretRef`]: crate::vpn::profile::SecretRef
#[must_use]
pub fn azure_refresh_token_label(profile_id: &Uuid) -> String {
    format!("supermgr/azure/{}/refresh_token", profile_id.simple())
}

// ---------------------------------------------------------------------------
// SecretOwner
// ---------------------------------------------------------------------------

/// An entity whose lifetime owns zero or more secret-store labels.
///
/// Deleting the entity must delete every label this returns.  Implementations
/// are exhaustive by construction — see the module docs.
pub trait SecretOwner {
    /// Every secret-store label whose lifetime is bound to this entity.
    ///
    /// May contain duplicates only if the entity genuinely points two fields
    /// at the same label; callers that delete should tolerate a repeat.
    fn secret_labels(&self) -> Vec<String>;
}

impl SecretOwner for Profile {
    fn secret_labels(&self) -> Vec<String> {
        // Named-field destructure, no `..`: a new field on `Profile` must be
        // classified here before this compiles again.
        let Profile {
            id,
            name: _,
            auto_connect: _,
            full_tunnel: _,
            last_connected_at: _,
            kill_switch: _,
            customer: _,
            config,
            updated_at: _,
        } = self;

        let mut labels = config.secret_labels();

        // Derived (not reference-carried) labels are keyed on the profile id.
        if matches!(config, ProfileConfig::AzureVpn(_)) {
            labels.push(azure_refresh_token_label(id));
        }

        labels
    }
}

impl SecretOwner for ProfileConfig {
    fn secret_labels(&self) -> Vec<String> {
        // No wildcard arm: a new backend variant must be classified here.
        match self {
            Self::WireGuard(cfg) => cfg.secret_labels(),
            Self::FortiGate(cfg) => cfg.secret_labels(),
            Self::ForticlientSslvpn(cfg) => cfg.secret_labels(),
            Self::OpenVpn(cfg) => cfg.secret_labels(),
            Self::AzureVpn(cfg) => cfg.secret_labels(),
            Self::Generic(cfg) => cfg.secret_labels(),
        }
    }
}

impl SecretOwner for WireGuardConfig {
    fn secret_labels(&self) -> Vec<String> {
        let WireGuardConfig {
            private_key,
            addresses: _,
            dns: _,
            dns_search: _,
            mtu: _,
            listen_port: _,
            peers,
            interface_name: _,
            split_routes: _,
        } = self;

        // One profile owns one interface key plus a pre-shared key per peer.
        // The per-peer PSKs are the part that historically got missed: code
        // that "handled WireGuard" deleted `private_key` and stopped.
        let mut labels = Vec::with_capacity(1 + peers.len());
        labels.push(private_key.label().to_owned());
        for peer in peers {
            labels.extend(peer.secret_labels());
        }
        labels
    }
}

impl SecretOwner for WireGuardPeer {
    fn secret_labels(&self) -> Vec<String> {
        let WireGuardPeer {
            public_key: _,
            endpoint: _,
            allowed_ips: _,
            preshared_key,
            persistent_keepalive: _,
        } = self;

        preshared_key
            .iter()
            .map(|psk| psk.label().to_owned())
            .collect()
    }
}

impl SecretOwner for FortiGateConfig {
    fn secret_labels(&self) -> Vec<String> {
        let FortiGateConfig {
            host: _,
            username: _,
            password,
            psk,
            dns_servers: _,
            routes: _,
            local_id: _,
        } = self;

        vec![password.label().to_owned(), psk.label().to_owned()]
    }
}

impl SecretOwner for ForticlientSslvpnConfig {
    fn secret_labels(&self) -> Vec<String> {
        let ForticlientSslvpnConfig {
            host: _,
            port: _,
            username: _,
            password,
            // A TOFU certificate fingerprint is public information, not a
            // credential — nothing is stored under it.
            trusted_cert: _,
            dns_servers: _,
            routes: _,
        } = self;

        vec![password.label().to_owned()]
    }
}

impl SecretOwner for OpenVpnConfig {
    fn secret_labels(&self) -> Vec<String> {
        let OpenVpnConfig {
            config_file: _,
            username: _,
            password,
        } = self;

        password.iter().map(|p| p.label().to_owned()).collect()
    }
}

impl SecretOwner for AzureVpnConfig {
    fn secret_labels(&self) -> Vec<String> {
        let AzureVpnConfig {
            gateway_fqdn: _,
            tenant_id: _,
            client_id: _,
            // `server_secret_hex` and `ca_cert_pem` are stored inline in the
            // profile TOML rather than in the secret store, so they are not
            // labels and are removed with the profile file itself.
            server_secret_hex: _,
            ca_cert_pem: _,
            routes: _,
            dns_servers: _,
        } = self;

        // The cached refresh token is keyed on the profile UUID, which this
        // type does not carry; `Profile::secret_labels` adds it.
        Vec::new()
    }
}

impl SecretOwner for GenericConfig {
    fn secret_labels(&self) -> Vec<String> {
        let GenericConfig {
            backend_id: _,
            // An opaque plugin blob. Its values are inline, not labels — a
            // plugin that wants keyring storage needs a typed variant so its
            // secrets take part in this lifetime.
            config: _,
        } = self;

        Vec::new()
    }
}

impl SecretOwner for Host {
    fn secret_labels(&self) -> Vec<String> {
        let Host {
            id: _,
            label: _,
            hostname: _,
            port: _,
            username: _,
            group: _,
            device_type: _,
            auth_method: _,
            // A key id, not a secret label: the key is a separate entity with
            // its own lifetime and may be deployed to other hosts.
            auth_key_id: _,
            auth_password_ref,
            auth_cert_ref,
            vpn_profile_id: _,
            api_port: _,
            // Holds FortiGate, OPNsense, and Sophos credentials depending on
            // `device_type` — all three write into this one field.
            api_token_ref,
            api_verify_tls: _,
            unifi_controller_url: _,
            unifi_api_token_ref,
            rdp_port: _,
            vnc_port: _,
            port_forwards: _,
            proxy_jump: _,
            pinned: _,
            customer: _,
            created_at: _,
            updated_at: _,
        } = self;

        [
            auth_password_ref.as_ref(),
            auth_cert_ref.as_ref(),
            api_token_ref.as_ref(),
            unifi_api_token_ref.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|r| r.label().to_owned())
        .collect()
    }
}

impl SecretOwner for SshKey {
    fn secret_labels(&self) -> Vec<String> {
        let SshKey {
            id: _,
            name: _,
            description: _,
            key_type: _,
            public_key: _,
            private_key_ref,
            fingerprint: _,
            tags: _,
            // Host ids this key was pushed to. Deleting the key does not
            // delete those hosts' secrets.
            deployed_to: _,
            created_at: _,
            updated_at: _,
        } = self;

        vec![private_key_ref.label().to_owned()]
    }
}

// ---------------------------------------------------------------------------
// LiveSecrets
// ---------------------------------------------------------------------------

/// The set of secrets that still have an owner, plus the ids of the owners.
///
/// Build one from everything currently persisted, then ask it which stored
/// labels are orphaned.
#[derive(Debug, Default, Clone)]
pub struct LiveSecrets {
    labels: BTreeSet<String>,
    entity_ids: BTreeSet<Uuid>,
}

impl LiveSecrets {
    /// An empty set — nothing alive, so every stored label is an orphan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a profile and the labels it owns.
    pub fn add_profile(&mut self, profile: &Profile) {
        self.entity_ids.insert(profile.id);
        self.labels.extend(profile.secret_labels());
    }

    /// Record a host and the labels it owns.
    pub fn add_host(&mut self, host: &Host) {
        self.entity_ids.insert(host.id);
        self.labels.extend(host.secret_labels());
    }

    /// Record an SSH key and the labels it owns.
    pub fn add_ssh_key(&mut self, key: &SshKey) {
        self.entity_ids.insert(key.id);
        self.labels.extend(key.secret_labels());
    }

    /// Record a secret-owning entity this crate does not model.
    ///
    /// The engine's standalone `UniFi` controller registry is one: it is a
    /// top-level entity with its own `Uuid` and a credentials label, but it
    /// lives above this crate.  A caller that forgets to register such a type
    /// gets false orphans, so register every `Uuid`-keyed entity that reaches
    /// the same secret store — passing an empty `labels` still protects
    /// anything keyed on that id.
    pub fn add_other(&mut self, id: Uuid, labels: impl IntoIterator<Item = String>) {
        self.entity_ids.insert(id);
        self.labels.extend(labels);
    }

    /// Number of labels currently referenced by a live entity.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether no live entity references any label.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Whether some live entity points at `label`.
    #[must_use]
    pub fn contains(&self, label: &str) -> bool {
        self.labels.contains(label)
    }

    /// Every referenced label, sorted.
    #[must_use]
    pub fn labels(&self) -> &BTreeSet<String> {
        &self.labels
    }

    /// Whether a stored `label` belongs to no surviving entity.
    ///
    /// Two independent conditions must both hold, and the second is what
    /// makes the answer safe to act on:
    ///
    /// 1. No live entity references the label.
    /// 2. The label embeds a UUID, and that UUID is not a live entity's id.
    ///
    /// Every per-entity label this codebase generates carries its owner's
    /// UUID — `supermgr/wg/<id>/privkey`, `supermgr/ssh/host/<id>/password`,
    /// `vpn/<id>/psk`, `supermgr/unifi/<id>/credentials`.  So condition 2
    /// keeps a live entity's secret out of the report even when the field
    /// pointing at it is one this crate does not model, and keeps
    /// namespace-less labels (a future global setting, a hand-written entry)
    /// out entirely.  The cost is that a label with no UUID is never
    /// reported: this is a leak detector, not an inventory.
    #[must_use]
    pub fn is_orphan(&self, label: &str) -> bool {
        if self.labels.contains(label) {
            return false;
        }
        let mut saw_uuid = false;
        for segment in label.split('/') {
            if let Ok(id) = Uuid::parse_str(segment) {
                if self.entity_ids.contains(&id) {
                    return false;
                }
                saw_uuid = true;
            }
        }
        saw_uuid
    }

    /// Every stored label that belongs to no surviving entity, sorted and
    /// deduplicated.
    ///
    /// See [`is_orphan`](Self::is_orphan) for what qualifies.
    #[must_use]
    pub fn find_orphans<I, S>(&self, stored: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut orphans: BTreeSet<String> = BTreeSet::new();
        for label in stored {
            let label = label.as_ref();
            if self.is_orphan(label) {
                orphans.insert(label.to_owned());
            }
        }
        orphans.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::IpAddr;

    use chrono::Utc;
    use proptest::prelude::*;

    use super::*;
    use crate::host::AuthMethod;
    use crate::ssh::key::SshKeyType;
    use crate::vpn::profile::SecretRef;

    // -----------------------------------------------------------------
    // Builders
    // -----------------------------------------------------------------

    /// An entity together with every label its import path wrote into the
    /// secret store.
    ///
    /// `wrote` is recorded at build time from literal label strings, never
    /// from [`SecretOwner::secret_labels`].  That independence is the whole
    /// point: if `secret_labels` under-reports — exactly the mistake that
    /// left `WireGuard` peer PSKs behind — the label survives the delete and
    /// the invariant tests below see an orphan.  Deriving the store contents
    /// and the delete from the same function would let the omission cancel
    /// itself out on both sides and the tests would pass over the bug.
    #[derive(Debug)]
    struct Imported<T> {
        entity: T,
        wrote: Vec<String>,
    }

    fn base_profile(id: Uuid, config: ProfileConfig) -> Profile {
        Profile {
            id,
            name: format!("profile-{}", id.simple()),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: String::new(),
            config,
            updated_at: Utc::now(),
        }
    }

    fn wg_profile(id: Uuid, peer_count: usize) -> Imported<Profile> {
        let mut wrote = Vec::new();

        let private_key = format!("supermgr/wg/{}/privkey", id.simple());
        wrote.push(private_key.clone());

        let mut peers = Vec::with_capacity(peer_count);
        for n in 0..peer_count {
            let psk = format!("supermgr/wg/{}/psk/{n}", id.simple());
            wrote.push(psk.clone());
            peers.push(WireGuardPeer {
                public_key: format!("pub{n}"),
                endpoint: Some("vpn.example.com:51820".into()),
                allowed_ips: Vec::new(),
                preshared_key: Some(SecretRef::new(psk)),
                persistent_keepalive: None,
            });
        }

        Imported {
            entity: base_profile(
                id,
                ProfileConfig::WireGuard(WireGuardConfig {
                    private_key: SecretRef::new(private_key),
                    addresses: Vec::new(),
                    dns: Vec::new(),
                    dns_search: Vec::new(),
                    mtu: None,
                    listen_port: None,
                    peers,
                    interface_name: None,
                    split_routes: Vec::new(),
                }),
            ),
            wrote,
        }
    }

    fn fortigate_profile(id: Uuid) -> Imported<Profile> {
        let password = format!("supermgr/fg/{}/password", id.simple());
        let psk = format!("supermgr/fg/{}/psk", id.simple());
        Imported {
            entity: base_profile(
                id,
                ProfileConfig::FortiGate(FortiGateConfig {
                    host: "fg.example.com".into(),
                    username: "user".into(),
                    password: SecretRef::new(&password),
                    psk: SecretRef::new(&psk),
                    dns_servers: Vec::new(),
                    routes: Vec::new(),
                    local_id: String::new(),
                }),
            ),
            wrote: vec![password, psk],
        }
    }

    fn sslvpn_profile(id: Uuid) -> Imported<Profile> {
        let password = format!("supermgr/fg/{}/password", id.simple());
        Imported {
            entity: base_profile(
                id,
                ProfileConfig::ForticlientSslvpn(ForticlientSslvpnConfig {
                    host: "fg.example.com".into(),
                    port: 10443,
                    username: "user".into(),
                    password: SecretRef::new(&password),
                    trusted_cert: None,
                    dns_servers: Vec::new(),
                    routes: Vec::new(),
                }),
            ),
            wrote: vec![password],
        }
    }

    fn openvpn_profile(id: Uuid, with_password: bool) -> Imported<Profile> {
        let password = with_password.then(|| format!("supermgr/ovpn/{}/password", id.simple()));
        Imported {
            entity: base_profile(
                id,
                ProfileConfig::OpenVpn(OpenVpnConfig {
                    config_file: "/etc/supermgrd/ovpn/x.ovpn".into(),
                    username: Some("user".into()),
                    password: password.as_deref().map(SecretRef::new),
                }),
            ),
            wrote: password.into_iter().collect(),
        }
    }

    fn azure_profile(id: Uuid) -> Imported<Profile> {
        Imported {
            entity: base_profile(
                id,
                ProfileConfig::AzureVpn(AzureVpnConfig {
                    gateway_fqdn: "azuregateway-x.vpn.azure.com".into(),
                    tenant_id: "tenant".into(),
                    client_id: "client".into(),
                    server_secret_hex: "ab".repeat(256),
                    ca_cert_pem: "-----BEGIN CERTIFICATE-----".into(),
                    routes: Vec::new(),
                    dns_servers: Vec::<IpAddr>::new(),
                }),
            ),
            // Written at connect time by `vpn::azure`, not at import — no
            // `SecretRef` field points at it. Spelled out literally here so
            // this is an independent statement of the label format rather
            // than a second call to the function under test.
            wrote: vec![format!("supermgr/azure/{}/refresh_token", id.simple())],
        }
    }

    fn generic_profile(id: Uuid) -> Imported<Profile> {
        Imported {
            entity: base_profile(id, ProfileConfig::Generic(GenericConfig::default())),
            wrote: Vec::new(),
        }
    }

    /// `refs` is a bit set over the host's four secret fields, so the
    /// generator can reach every combination including "none at all".
    fn host(id: Uuid, refs: u8) -> Imported<Host> {
        let mut wrote = Vec::new();
        let mut label = |bit: u8, suffix: &str| {
            (refs & bit != 0).then(|| {
                wrote.push(suffix.to_owned());
                SecretRef::new(suffix)
            })
        };

        let auth_password_ref = label(1, &format!("supermgr/ssh/host/{}/password", id.simple()));
        let auth_cert_ref = label(2, &format!("supermgr/ssh/host/{}/certificate", id.simple()));
        let api_token_ref = label(4, &format!("supermgr/fg/{}/api_token", id.simple()));
        let unifi_api_token_ref = label(8, &format!("supermgr/unifi/{}/credentials", id.simple()));

        Imported {
            entity: Host {
                id,
                label: "box".into(),
                hostname: "10.0.0.1".into(),
                port: 22,
                username: "root".into(),
                group: String::new(),
                device_type: crate::ssh::device_type::DeviceType::default(),
                auth_method: AuthMethod::Password,
                auth_key_id: None,
                auth_password_ref,
                auth_cert_ref,
                vpn_profile_id: None,
                api_port: None,
                api_token_ref,
                api_verify_tls: true,
                unifi_controller_url: None,
                unifi_api_token_ref,
                rdp_port: None,
                vnc_port: None,
                port_forwards: Vec::new(),
                proxy_jump: None,
                pinned: false,
                customer: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            wrote,
        }
    }

    fn ssh_key(id: Uuid) -> Imported<SshKey> {
        let private_key_ref = format!("supermgr/ssh/{}/privkey", id.simple());
        Imported {
            entity: SshKey {
                id,
                name: "key".into(),
                description: String::new(),
                key_type: SshKeyType::Ed25519,
                public_key: "ssh-ed25519 AAAA".into(),
                private_key_ref: SecretRef::new(&private_key_ref),
                fingerprint: "SHA256:x".into(),
                tags: Vec::new(),
                deployed_to: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            wrote: vec![private_key_ref],
        }
    }

    // -----------------------------------------------------------------
    // Per-type ownership
    // -----------------------------------------------------------------

    #[test]
    fn wireguard_owns_interface_key_and_every_peer_psk() {
        let id = Uuid::new_v4();
        let labels = wg_profile(id, 3).entity.secret_labels();

        assert_eq!(
            labels.len(),
            4,
            "one interface key + three peer PSKs, got {labels:?}"
        );
        assert!(labels.contains(&format!("supermgr/wg/{}/privkey", id.simple())));
        for n in 0..3 {
            assert!(
                labels.contains(&format!("supermgr/wg/{}/psk/{n}", id.simple())),
                "peer {n} PSK missing from {labels:?}"
            );
        }
    }

    #[test]
    fn fortigate_owns_password_and_psk() {
        let id = Uuid::new_v4();
        let labels = fortigate_profile(id).entity.secret_labels();
        assert_eq!(labels.len(), 2, "{labels:?}");
        assert!(labels.iter().any(|l| l.ends_with("/password")));
        assert!(labels.iter().any(|l| l.ends_with("/psk")));
    }

    #[test]
    fn optional_refs_are_absent_when_unset() {
        let id = Uuid::new_v4();
        assert!(openvpn_profile(id, false).entity.secret_labels().is_empty());
        assert_eq!(openvpn_profile(id, true).entity.secret_labels().len(), 1);
        assert!(host(id, 0).entity.secret_labels().is_empty());
        assert_eq!(host(id, 0b1111).entity.secret_labels().len(), 4);
    }

    #[test]
    fn azure_owns_its_derived_refresh_token() {
        // The refresh token is not carried by any `SecretRef` field, so
        // walking the struct alone would leave a live Entra credential
        // behind. Compared against the literal format, not against
        // `azure_refresh_token_label`, so a change to that function has to
        // be a deliberate one.
        let id = Uuid::new_v4();
        let labels = azure_profile(id).entity.secret_labels();
        assert_eq!(
            labels,
            vec![format!("supermgr/azure/{}/refresh_token", id.simple())]
        );
    }

    #[test]
    fn non_azure_profiles_do_not_claim_a_refresh_token() {
        let id = Uuid::new_v4();
        for imported in [
            wg_profile(id, 1),
            fortigate_profile(id),
            sslvpn_profile(id),
            openvpn_profile(id, true),
            generic_profile(id),
        ] {
            let labels = imported.entity.secret_labels();
            assert!(
                !labels.contains(&azure_refresh_token_label(&id)),
                "{} claimed an Azure refresh token: {labels:?}",
                imported.entity.config.backend_name()
            );
        }
    }

    #[test]
    fn every_profile_backend_is_classified() {
        // Not an assertion about counts — a reminder that a new variant
        // added to `ProfileConfig` has to be added to the generator too,
        // right next to the exhaustive match that already refused to
        // compile.
        let id = Uuid::new_v4();
        let all = [
            wg_profile(id, 1),
            fortigate_profile(id),
            sslvpn_profile(id),
            openvpn_profile(id, true),
            azure_profile(id),
            generic_profile(id),
        ];
        let names: HashSet<&str> = all
            .iter()
            .map(|i| i.entity.config.backend_name())
            .collect();
        assert_eq!(names.len(), all.len(), "duplicate backend in coverage list");
    }

    // -----------------------------------------------------------------
    // The invariant: delete anything, leave nothing behind
    // -----------------------------------------------------------------

    /// A whole install: the persisted records, and the secret store as the
    /// import paths actually filled it.
    ///
    /// `Debug` is what proptest prints for a shrunk counterexample. Only
    /// labels are held here, never secret bytes.
    #[derive(Debug)]
    struct World {
        profiles: Vec<Imported<Profile>>,
        hosts: Vec<Imported<Host>>,
        keys: Vec<Imported<SshKey>>,
    }

    impl World {
        fn live(&self) -> LiveSecrets {
            let mut live = LiveSecrets::new();
            for p in &self.profiles {
                live.add_profile(&p.entity);
            }
            for h in &self.hosts {
                live.add_host(&h.entity);
            }
            for k in &self.keys {
                live.add_ssh_key(&k.entity);
            }
            live
        }

        /// The secret store: every label written when these entities were
        /// imported.
        fn stored(&self) -> Vec<String> {
            let mut all = Vec::new();
            for p in &self.profiles {
                all.extend(p.wrote.iter().cloned());
            }
            for h in &self.hosts {
                all.extend(h.wrote.iter().cloned());
            }
            for k in &self.keys {
                all.extend(k.wrote.iter().cloned());
            }
            all
        }

        /// Delete one entity the way a correct delete path must: drop the
        /// record, then clear every label [`SecretOwner`] says it owned.
        ///
        /// Note which side of the comparison each list comes from — the
        /// store was filled by the builders, the deletion is driven by the
        /// code under test. That is what makes an under-reporting
        /// `secret_labels` visible instead of self-consistent.
        fn delete_nth(&mut self, index: usize, stored: &mut Vec<String>) {
            let profiles = self.profiles.len();
            let hosts = self.hosts.len();
            let owned = if index < profiles {
                self.profiles.remove(index).entity.secret_labels()
            } else if index < profiles + hosts {
                self.hosts.remove(index - profiles).entity.secret_labels()
            } else {
                self.keys
                    .remove(index - profiles - hosts)
                    .entity
                    .secret_labels()
            };
            stored.retain(|l| !owned.contains(l));
        }

        /// Drop the record and nothing else — the bug, reproduced.
        fn delete_nth_record_only(&mut self, index: usize) {
            self.delete_nth(index, &mut Vec::new());
        }

        fn entity_count(&self) -> usize {
            self.profiles.len() + self.hosts.len() + self.keys.len()
        }
    }

    fn arb_world() -> impl Strategy<Value = World> {
        // Each entity gets a fresh UUID at build time, so generated
        // installs never collide.
        let profile = (0usize..6, 0usize..4).prop_map(|(kind, peers)| {
            let id = Uuid::new_v4();
            match kind {
                0 => wg_profile(id, peers),
                1 => fortigate_profile(id),
                2 => sslvpn_profile(id),
                3 => openvpn_profile(id, peers % 2 == 0),
                4 => azure_profile(id),
                _ => generic_profile(id),
            }
        });
        let a_host = (0u8..16).prop_map(|refs| host(Uuid::new_v4(), refs));
        let a_key = Just(()).prop_map(|()| ssh_key(Uuid::new_v4()));

        (
            prop::collection::vec(profile, 0..6),
            prop::collection::vec(a_host, 0..6),
            prop::collection::vec(a_key, 0..4),
        )
            .prop_map(|(profiles, hosts, keys)| World {
                profiles,
                hosts,
                keys,
            })
    }

    proptest! {
        // No regression file. Entities take a fresh `Uuid::new_v4()` at
        // build time, which is the faithful model — production ids are
        // distinct by construction, and shrinking a UUID toward zero would
        // manufacture two entities sharing an id, a state that cannot
        // occur. The cost is that a saved seed would not replay the same
        // ids, so persisting one would leave a file that looks like a
        // reproducer and is not. The shrunk `World` proptest prints on
        // failure carries everything needed to write a unit test for the
        // case by hand.
        #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

        /// Nothing deleted, nothing orphaned. Guards the failure mode that
        /// matters most: an audit that names a live secret is an audit that
        /// gets a customer's key deleted.
        #[test]
        fn intact_install_has_no_orphans(world in arb_world()) {
            let orphans = world.live().find_orphans(world.stored());
            prop_assert!(orphans.is_empty(), "false positives: {orphans:?}");
        }

        /// Delete any single entity, clearing what this module says it
        /// owned, and no unowned secret is left. This is the invariant the
        /// three shipped leaks each violated — and it fails if
        /// `secret_labels` misses a field, because the store was filled
        /// independently of it.
        #[test]
        fn deleting_any_entity_leaves_no_orphan(world in arb_world(), pick in 0usize..64) {
            let mut world = world;
            let count = world.entity_count();
            prop_assume!(count > 0);

            let mut stored = world.stored();
            world.delete_nth(pick % count, &mut stored);

            let orphans = world.live().find_orphans(&stored);
            prop_assert!(orphans.is_empty(), "leaked after delete: {orphans:?}");
        }

        /// Delete every entity one at a time and the store empties out. A
        /// per-entity check can pass while the accumulated result does not.
        #[test]
        fn deleting_everything_empties_the_store(world in arb_world()) {
            let mut world = world;
            let mut stored = world.stored();
            while world.entity_count() > 0 {
                world.delete_nth(0, &mut stored);
            }
            prop_assert!(stored.is_empty(), "left behind: {stored:?}");
            prop_assert!(world.live().is_empty());
        }

        /// Forget the secrets — the mistake this module is about — and the
        /// audit reports exactly the entity's own labels. Without this, the
        /// invariants above would all pass against a `find_orphans` that
        /// returns nothing at all.
        #[test]
        fn a_delete_that_forgets_the_secrets_is_detected(world in arb_world(), pick in 0usize..64) {
            let mut world = world;
            let count = world.entity_count();
            prop_assume!(count > 0);

            let stored = world.stored();
            let before = world.stored().len();
            world.delete_nth_record_only(pick % count);
            let leaked = before - world.stored().len();

            let orphans = world.live().find_orphans(&stored);
            prop_assert_eq!(
                orphans.len(),
                leaked,
                "audit disagreed with the leak it was shown: orphans={:?} stored={:?}",
                orphans,
                stored
            );
        }
    }

    // -----------------------------------------------------------------
    // Soundness of the orphan rule
    // -----------------------------------------------------------------

    #[test]
    fn label_without_a_uuid_is_never_an_orphan() {
        // Anything not keyed on an entity id is outside what this audit can
        // reason about, and guessing would mean recommending the deletion
        // of something it does not understand.
        let live = LiveSecrets::new();
        for label in [
            "supermgr/settings",
            "some/global/token",
            "",
            "supermgr/wg/not-a-uuid/privkey",
        ] {
            assert!(!live.is_orphan(label), "{label} wrongly reported");
        }
    }

    #[test]
    fn label_keyed_on_a_live_entity_is_never_an_orphan() {
        // The safety net for entities this crate does not model: the
        // engine's UniFi controller registry registers its id via
        // `add_other` and its labels are protected even though
        // `LiveSecrets` was never told what they are.
        let controller = Uuid::new_v4();
        let mut live = LiveSecrets::new();
        live.add_other(controller, Vec::new());

        assert!(!live.is_orphan(&format!("unifi/{controller}/creds")));
        assert!(!live.is_orphan(&format!(
            "supermgr/unifi/{}/credentials",
            controller.simple()
        )));
        assert!(live.is_orphan(&format!("unifi/{}/creds", Uuid::new_v4())));
    }

    #[test]
    fn hyphenated_and_simple_uuid_forms_both_match() {
        // The daemon writes `Uuid::simple()`; the engine writes the
        // hyphenated `Display` form. Both must resolve to the same entity
        // or one backend's secrets look orphaned to the other's audit.
        let id = Uuid::new_v4();
        let mut live = LiveSecrets::new();
        live.add_other(id, Vec::new());

        assert!(!live.is_orphan(&format!("vpn/{id}/password")));
        assert!(!live.is_orphan(&format!("supermgr/wg/{}/privkey", id.simple())));
    }

    #[test]
    fn referenced_label_survives_even_with_a_dead_uuid_in_the_path() {
        // A label an entity points at is live by reference, whatever ids
        // the string happens to contain — e.g. a host that kept a label
        // minted under a since-deleted profile's id.
        let host_id = Uuid::new_v4();
        let dead = Uuid::new_v4();
        let label = format!("supermgr/fg/{}/api_token", dead.simple());

        let mut h = host(host_id, 0).entity;
        h.api_token_ref = Some(SecretRef::new(&label));

        let mut live = LiveSecrets::new();
        live.add_host(&h);

        assert!(!live.is_orphan(&label));
    }

    #[test]
    fn find_orphans_sorts_and_deduplicates() {
        let dead = Uuid::new_v4();
        let privkey = format!("supermgr/wg/{}/privkey", dead.simple());
        let password = format!("supermgr/fg/{}/password", dead.simple());

        let orphans = LiveSecrets::new().find_orphans([&password, &privkey, &password]);

        assert_eq!(orphans.len(), 2, "duplicate not collapsed: {orphans:?}");
        assert!(orphans.windows(2).all(|w| w[0] < w[1]), "unsorted: {orphans:?}");
        assert!(orphans.contains(&privkey) && orphans.contains(&password));
    }

    #[test]
    fn audit_finds_the_shipped_leaks() {
        // What a real install looks like today: profiles and hosts deleted
        // by a version whose delete path removed the record and nothing
        // else. Four credentials still sitting in the store — and the
        // backup archive tars the store whole.
        let gone_profile = Uuid::new_v4();
        let gone_host = Uuid::new_v4();
        let live_key = ssh_key(Uuid::new_v4());

        let stored = vec![
            format!("supermgr/wg/{}/privkey", gone_profile.simple()),
            format!("supermgr/wg/{}/psk/0", gone_profile.simple()),
            format!("supermgr/ssh/host/{}/password", gone_host.simple()),
            format!("supermgr/unifi/{}/credentials", gone_host.simple()),
            live_key.entity.private_key_ref.label().to_owned(),
        ];

        let mut live = LiveSecrets::new();
        live.add_ssh_key(&live_key.entity);

        let orphans = live.find_orphans(&stored);
        assert_eq!(orphans.len(), 4, "{orphans:?}");
        assert!(!orphans.contains(&live_key.entity.private_key_ref.label().to_owned()));
    }
}
