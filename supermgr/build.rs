//! Embed the git commit the GUI was built from.
//!
//! Linux installs build from a checkout of `main` rather than from tagged
//! release artifacts, so the crate version alone cannot answer "is there a
//! newer version?" — the commit can. The Settings → Updates page compares
//! this value against the tip of `origin/main` on GitHub.
//!
//! Builds outside a git checkout (a source tarball) get `unknown`, and the
//! updates page says it cannot tell instead of guessing.

use std::process::Command;

fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SUPERMGR_GIT_COMMIT={commit}");

    // Rebuild when HEAD moves — .git/HEAD changes on branch switches, the
    // per-branch ref file changes on commits/pulls. Missing paths are fine:
    // cargo treats a nonexistent rerun-if-changed path as always-dirty only
    // if it appears later, and the tarball build has no .git at all.
    let git_dir = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned());
    if let Some(dir) = git_dir {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        if let Ok(head) = std::fs::read_to_string(format!("{dir}/HEAD")) {
            if let Some(reference) = head.trim().strip_prefix("ref: ") {
                println!("cargo:rerun-if-changed={dir}/{reference}");
            }
        }
    }
}
