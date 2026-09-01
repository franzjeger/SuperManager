//! Customer, site and asset-link types shared by every frontend.
//!
//! A customer slug is the stable cross-feature key. Human names may change;
//! links from sites to managed hosts must therefore use host record IDs rather
//! than labels or addresses whenever possible.

use serde::{Deserialize, Serialize};

/// One managed customer or tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Customer {
    /// Stable URL-safe identifier.
    pub slug: String,
    /// Human-readable customer name.
    pub display_name: String,
    /// Primary contact name.
    #[serde(default)]
    pub contact_name: String,
    /// Primary contact email address.
    #[serde(default)]
    pub contact_email: String,
    /// Free-form operational notes.
    #[serde(default)]
    pub notes: String,
    /// Provisioning template suggested for new sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_template: Option<String>,
    /// Domains allowed on management networks in generated policy.
    #[serde(default)]
    pub mgmt_allowlist_domains: Vec<String>,
    /// Public domain used for DNS and report checks.
    #[serde(default)]
    pub primary_domain: String,
    /// Physical or logical sites belonging to this customer.
    #[serde(default)]
    pub sites: Vec<Site>,
}

/// One location belonging to a [`Customer`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    /// Stable identifier within its customer.
    pub id: String,
    /// Human-readable site name.
    pub display_name: String,
    /// Postal address or location note.
    #[serde(default)]
    pub address: String,
    /// Managed host record IDs attached to this site.
    ///
    /// Readers tolerate legacy hostname/IP tokens, but every new writer must
    /// persist a real host ID.
    #[serde(default)]
    pub host_ids: Vec<String>,
    /// WAN type such as `fiber`, `dhcp`, `pppoe` or `static`.
    #[serde(default)]
    pub wan_type: String,
    /// Static public WAN address when applicable.
    #[serde(default)]
    pub wan_static_ip: String,
    /// Native/default LAN subnet in CIDR notation.
    #[serde(default)]
    pub lan_base: String,
    /// VLANs rendered for this site.
    #[serde(default)]
    pub vlans: Vec<Vlan>,
}

/// One VLAN in a site's provisioning model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vlan {
    /// IEEE 802.1Q VLAN identifier.
    pub id: u16,
    /// Human-readable VLAN name.
    pub name: String,
    /// VLAN subnet in CIDR notation.
    pub subnet: String,
    /// Operational purpose such as `management`, `guest`, `iot` or `voice`.
    #[serde(default)]
    pub purpose: String,
}

/// Convert a display name to a stable slug candidate.
#[must_use]
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_dash = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("customer");
    }
    out
}

/// Validate a customer or site identifier before it becomes a filename/key.
pub fn validate_id(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("identifier must not be empty".into());
    }
    if value.len() > 96 {
        return Err("identifier is too long".into());
    }
    if value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(
            "identifier must contain lowercase ASCII letters, digits and internal hyphens only"
                .into(),
        );
    }
    Ok(())
}

impl Customer {
    /// Validate stable keys and uniqueness constraints.
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.slug)?;
        if self.display_name.trim().is_empty() {
            return Err("customer display name must not be empty".into());
        }
        let mut site_ids = std::collections::HashSet::new();
        for site in &self.sites {
            validate_id(&site.id)?;
            if site.display_name.trim().is_empty() {
                return Err(format!("site '{}' has no display name", site.id));
            }
            if !site_ids.insert(site.id.as_str()) {
                return Err(format!("duplicate site id '{}'", site.id));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_is_stable_and_filesystem_safe() {
        assert_eq!(slugify("Acme International AS"), "acme-international-as");
        assert_eq!(slugify("  Ærlig / Kunde  "), "rlig-kunde");
        assert!(validate_id(&slugify("A customer")).is_ok());
    }

    #[test]
    fn customer_rejects_duplicate_sites() {
        let customer = Customer {
            slug: "acme".into(),
            display_name: "Acme".into(),
            sites: vec![
                Site {
                    id: "hq".into(),
                    display_name: "HQ".into(),
                    ..Site::default()
                },
                Site {
                    id: "hq".into(),
                    display_name: "HQ 2".into(),
                    ..Site::default()
                },
            ],
            ..Customer::default()
        };
        assert!(customer.validate().is_err());
    }
}
