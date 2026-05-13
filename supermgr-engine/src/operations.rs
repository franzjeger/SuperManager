//! Operation registry — track long-running work so it can be
//! cancelled from the UI.
//!
//! # Why this exists
//!
//! Active scans, compliance runs, SMB enumeration, CVE refresh —
//! all can take minutes. Before this module the user had no way
//! to interrupt: clicking "Stop" was wired to nothing, and the
//! scan ran to completion regardless. This was the most-reported
//! UX gap.
//!
//! # Design
//!
//! Each long-running RPC handler asks the registry for an
//! [`OperationGuard`]. The guard holds:
//!   - A unique opaque id (returned to the UI so it can call
//!     `operation_cancel({id})` later)
//!   - An `Arc<AtomicBool>` cancel flag the worker polls between
//!     batches / hosts / port chunks
//!   - A `Drop` impl that unregisters the operation on completion
//!
//! Cancellation is cooperative — the worker chooses when to check
//! the flag. We don't `abort()` tokio tasks, because aborting
//! while a probe is mid-write to disk or mid-RPC-reply leaves the
//! findings store in an inconsistent state. Polling at batch
//! boundaries is enough granularity for the UI.
//!
//! # What about tokio-util CancellationToken?
//!
//! Considered, but added a dependency just for one bool. The
//! `AtomicBool` approach has the same semantics for our use case
//! (we never need to *await* on a cancel — checking between
//! batches is enough).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A live operation handle — serialised to the UI so the user
/// can see what's running and cancel it.
#[derive(Debug, Clone, Serialize)]
pub struct OperationInfo {
    pub id: String,
    /// Stable machine-readable kind: `"active_scan"`,
    /// `"compliance_run"`, `"smb_enum"`, …
    pub kind: String,
    /// Human-readable label for the status bar:
    /// `"Active scan — 192.0.2.0/24 (124 hosts)"`.
    pub label: String,
    pub started_at: DateTime<Utc>,
    /// True after `operation_cancel` has been called but before
    /// the worker has noticed. UI uses this to show "Cancelling…"
    /// vs "Running".
    pub cancel_requested: bool,
}

struct Entry {
    info: OperationInfo,
    cancel: Arc<AtomicBool>,
}

/// Process-wide operation registry. Stored as
/// `Arc<OperationRegistry>` on `EngineServer`.
#[derive(Default)]
pub struct OperationRegistry {
    inner: Mutex<HashMap<String, Entry>>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new operation and hand back a guard. The guard
    /// auto-unregisters on drop, so handlers never have to
    /// remember to clean up.
    pub fn start(self: &Arc<Self>, kind: impl Into<String>, label: impl Into<String>) -> OperationGuard {
        let id = Uuid::new_v4().simple().to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        let info = OperationInfo {
            id: id.clone(),
            kind: kind.into(),
            label: label.into(),
            started_at: Utc::now(),
            cancel_requested: false,
        };
        let mut g = self.inner.lock().expect("operations lock poisoned");
        g.insert(
            id.clone(),
            Entry {
                info,
                cancel: Arc::clone(&cancel),
            },
        );
        OperationGuard {
            id,
            registry: Arc::clone(self),
            cancel,
        }
    }

    /// Snapshot of every running operation, in start-order.
    pub fn list(&self) -> Vec<OperationInfo> {
        let g = self.inner.lock().expect("operations lock poisoned");
        let mut out: Vec<OperationInfo> = g
            .values()
            .map(|e| {
                let mut info = e.info.clone();
                info.cancel_requested = e.cancel.load(Ordering::Acquire);
                info
            })
            .collect();
        out.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        out
    }

    /// Request cancellation of operation `id`. Returns `true` if
    /// the id was known. Cancellation is cooperative — workers
    /// only honour the flag at safe checkpoints.
    pub fn cancel(&self, id: &str) -> bool {
        let g = self.inner.lock().expect("operations lock poisoned");
        match g.get(id) {
            Some(e) => {
                e.cancel.store(true, Ordering::Release);
                true
            }
            None => false,
        }
    }

    fn unregister(&self, id: &str) {
        let mut g = self.inner.lock().expect("operations lock poisoned");
        g.remove(id);
    }
}

/// RAII handle returned by [`OperationRegistry::start`].
///
/// Workers clone the inner cancel flag and check it at batch
/// boundaries via [`OperationGuard::is_cancelled`] or
/// [`OperationGuard::cancel_flag`]. The operation is removed
/// from the registry the moment this guard drops, regardless of
/// success / error / panic.
pub struct OperationGuard {
    id: String,
    registry: Arc<OperationRegistry>,
    cancel: Arc<AtomicBool>,
}

impl OperationGuard {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    /// Hand out a clone of the cancel flag to a worker task.
    /// Workers should `load(Ordering::Acquire)` between batches.
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.registry.unregister(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_then_drop_removes_entry() {
        let reg = Arc::new(OperationRegistry::new());
        {
            let _g = reg.start("active_scan", "Scanning 192.168.0.0/24");
            assert_eq!(reg.list().len(), 1);
        }
        assert!(reg.list().is_empty(), "guard drop should unregister");
    }

    #[test]
    fn cancel_flips_flag() {
        let reg = Arc::new(OperationRegistry::new());
        let g = reg.start("active_scan", "test");
        let id = g.id().to_owned();
        assert!(!g.is_cancelled());
        assert!(reg.cancel(&id));
        assert!(g.is_cancelled());
    }

    #[test]
    fn cancel_unknown_id_returns_false() {
        let reg = Arc::new(OperationRegistry::new());
        assert!(!reg.cancel("nonexistent"));
    }

    #[test]
    fn list_shows_cancel_requested_after_cancel() {
        let reg = Arc::new(OperationRegistry::new());
        let g = reg.start("active_scan", "test");
        let id = g.id().to_owned();
        assert!(!reg.list()[0].cancel_requested);
        reg.cancel(&id);
        assert!(reg.list()[0].cancel_requested);
    }

    #[test]
    fn list_sorted_by_started_at() {
        let reg = Arc::new(OperationRegistry::new());
        let g1 = reg.start("a", "first");
        // Sleep just enough to guarantee Utc::now() differs.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let g2 = reg.start("b", "second");
        let list = reg.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, g1.id());
        assert_eq!(list[1].id, g2.id());
    }

    #[test]
    fn concurrent_register_unregister_is_safe() {
        let reg = Arc::new(OperationRegistry::new());
        let handles: Vec<_> = (0..32)
            .map(|i| {
                let r = Arc::clone(&reg);
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let g = r.start("k", format!("{i}"));
                        let _ = g.is_cancelled();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(reg.list().is_empty());
    }
}
