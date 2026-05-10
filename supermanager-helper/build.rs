// Inject a build timestamp the helper exposes via `helper_version`.
//
// The GUI uses this to detect a stale deployed helper: if the
// timestamp the deployed helper reports is older than the bundled
// helper's, hot-swap via `deploy_self`. Avoids the "unknown method"
// surprise after every Cargo iteration.
//
// `cargo:rerun-if-changed=build.rs` keeps the timestamp fresh on
// every rebuild — without it the env var would be cached forever
// and we'd think every build was the same vintage.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=HELPER_BUILD_TIMESTAMP={ts}");
    // Force re-run on every build so the env var doesn't get
    // cached. Touching `build.rs` itself is the laziest trick.
    println!("cargo:rerun-if-changed=build.rs");
    // And a sentinel that ALWAYS bumps so cargo doesn't reuse the
    // env from the previous build. This is a hack; if cargo ever
    // gets a "really, run me every time" hook, replace it.
    println!("cargo:rerun-if-env-changed=HELPER_BUILD_TIMESTAMP");
}
