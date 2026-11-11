// Inject a build timestamp the helper exposes via `helper_version`.
//
// The GUI uses this to detect a stale deployed helper: a helper whose
// build differs from the one bundled in the app is reinstalled. Avoids
// the "unknown method" surprise after every Cargo iteration.
//
// `cargo:rerun-if-changed=build.rs` keeps the timestamp fresh on
// every rebuild — without it the env var would be cached forever
// and we'd think every build was the same vintage.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    println!("cargo:rustc-env=HELPER_BUILD_TIMESTAMP={ts}");
    // Re-run whenever the helper's own source changes, which is what
    // makes the timestamp mean something.
    //
    // The previous pair of directives did NOT do this, despite saying
    // so. `rerun-if-changed=build.rs` fires only when build.rs itself
    // is edited, and `rerun-if-env-changed=HELPER_BUILD_TIMESTAMP`
    // watches a variable that is this script's *output*, not an input
    // — nothing sets it externally, so it never changed and never
    // triggered. The result was a timestamp frozen at whatever the
    // first build in a given `target/` produced, ageing silently: an
    // Xcode-built app was embedding a helper stamped ten days earlier
    // than its actual contents.
    //
    // That matters because the GUI compares this value to decide
    // whether deploying the bundled helper is an upgrade. A frozen
    // timestamp makes a genuinely newer helper look identical to the
    // deployed one, and the deploy gets skipped.
    //
    // Watching `src` is also better semantics than the wall clock it
    // replaces: the value now changes when the *code* changes, so two
    // builds of identical source agree — which is the correct answer
    // to "should I redeploy", not a spurious difference.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
}
