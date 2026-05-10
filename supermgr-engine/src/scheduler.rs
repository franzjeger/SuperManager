//! In-daemon recurring scan scheduler.
//!
//! For every engagement with a `Schedule { cadence, next_scan_at }`
//! the scheduler polls (every 60s) and fires an `active_scan`
//! when `next_scan_at <= now`. After each run it advances
//! `next_scan_at` and persists.
//!
//! # Why in-daemon (not launchd)
//!
//! - No separate plist to install/uninstall per customer.
//! - Survives daemon restarts since `next_scan_at` is on disk.
//! - Customer-side state stays in `engagements/` — single source
//!   of truth.
//!
//! Drawback: scans only fire when the daemon is running. The Mac
//! app spawns the daemon automatically, so this is fine for an
//! always-on workstation; a future improvement is a launchd
//! `LaunchAgent` that wakes the daemon if it's idle.

use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use crate::engagement::{self, Cadence, Engagement};

/// Spawn the scheduler loop as a tokio task. Returns immediately;
/// the task lives for the daemon's lifetime.
pub fn spawn() {
    tokio::spawn(async move {
        // Brief startup delay so the daemon's RPC server is up.
        tokio::time::sleep(Duration::from_secs(15)).await;
        loop {
            if let Err(e) = tick().await {
                warn!("scheduler tick failed: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

async fn tick() -> anyhow::Result<()> {
    // Weekly CVE feed refresh — cheap when fresh, single HTTP
    // call when stale. Fire-and-forget: a feed-fetch failure
    // shouldn't block engagement scheduling.
    maybe_refresh_cve_feed().await;

    let engagements = engagement::list_all()?;
    let now = Utc::now();
    for mut e in engagements {
        let Some(schedule) = e.schedule.clone() else {
            continue;
        };
        if schedule.next_scan_at > now {
            continue;
        }
        // Don't fire if the engagement has expired.
        if e.expires_at < now {
            info!("scheduler: skip expired engagement {}", e.id);
            continue;
        }
        if e.scope_cidrs.is_empty() {
            continue;
        }

        info!(
            "scheduler: firing {} (cadence={})",
            e.title,
            schedule.cadence.label()
        );
        let customer = if e.customer_slug.is_empty() {
            None
        } else {
            Some(e.customer_slug.as_str())
        };
        let targets: Vec<String> = e.scope_cidrs.clone();
        let engagement_id = e.id.clone();

        // Run the scan. We deliberately do NOT cap targets via
        // expand_targets's max_targets here — assume the customer
        // configured a sane scope. (UI's manual button uses 256.)
        let res = crate::discovery::active_scan(
            &targets,
            crate::probes::COMMON_PORTS,
            customer,
            Some(&engagement_id),
        )
        .await;
        match res {
            Ok(_) => info!("scheduler: completed {}", engagement_id),
            Err(err) => warn!("scheduler: {} failed: {err:#}", engagement_id),
        }

        // Advance schedule and persist.
        let new_next = schedule.cadence.advance(now);
        e.schedule = Some(engagement::Schedule {
            cadence: schedule.cadence,
            next_scan_at: new_next,
            last_scan_at: Some(now),
        });
        if let Err(err) = engagement::save(&e) {
            warn!("scheduler: persist {} failed: {err:#}", e.id);
        }
    }
    Ok(())
}

/// Refresh the NVD CVE feed if it's been more than a week since
/// the last successful fetch. Errors are logged + swallowed.
async fn maybe_refresh_cve_feed() {
    let cache = crate::cve_feed::load();
    let now = Utc::now();
    let needs_refresh = match cache.last_fetched_at {
        None => true,
        Some(t) => (now - t) > chrono::Duration::weeks(1),
    };
    if !needs_refresh {
        return;
    }
    match crate::cve_feed::refresh().await {
        Ok(added) => info!("scheduler: cve_feed refreshed (+{added})"),
        Err(e) => warn!("scheduler: cve_feed refresh failed: {e:#}"),
    }
}

/// Set or clear an engagement's schedule. Returns the updated
/// engagement after save.
pub fn set_schedule(
    engagement_id: &str,
    cadence: Option<Cadence>,
) -> anyhow::Result<Engagement> {
    let mut e = engagement::load(engagement_id)?;
    e.schedule = cadence.map(|c| engagement::Schedule {
        cadence: c,
        // First run kicks off in 60 seconds — gives the user a
        // chance to verify the scan works without sitting around.
        next_scan_at: Utc::now() + chrono::Duration::seconds(60),
        last_scan_at: None,
    });
    engagement::save(&e)?;
    Ok(e)
}
