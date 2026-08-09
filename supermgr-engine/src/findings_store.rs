//! Re-export of the findings store, which now lives in `supermgr-core`.
//!
//! # Why it moved
//!
//! Nothing in it was macOS-specific — the only mention of `~/Library` was in a
//! doc comment, and the path itself already came from
//! `supermgr_core::paths::default_data_dir()`, which is per-platform. It lived
//! here because the engine is where the scanner lives, not because it needed
//! anything the engine has.
//!
//! That mattered: the Linux daemon has to be able to record and serve findings
//! for the GTK GUI to grow a Security page, and the Windows daemon will want the
//! same. Sixteen modules in this crate reference this path, so it stays as a
//! re-export rather than a rename spread across all of them.
//!
//! # What changed in the move
//!
//! `load_store` and `save_store` return [`supermgr_core::error::FindingsError`]
//! instead of `EngineError`. The three variants are the same three
//! (`FindingsIo` → `Io`, `FindingsParse` → `Parse`, `InvalidScope` unchanged);
//! nothing outside the module called either function, so no caller sees the
//! difference.
//!
//! Slug validation now calls `supermgr_core::findings::validate_slug` directly
//! rather than `crate::customer::validate_slug`. `customer.rs` could not come
//! along — it pulls in provisioning and engine state — so the seventeen-line
//! validator moved on its own and `customer::validate_slug` delegates to it.
//! One definition of what a legal slug is, which is the point: it is a
//! path-traversal guard, and two copies would be two chances to disagree.

pub use supermgr_core::findings_store::*;
