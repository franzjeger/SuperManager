# SuperManager Release & Rollback Runbook

This document defines the standard **beta-first staged release workflow** and the **emergency retraction / rollback procedure** across macOS, Windows, and Linux.

---

## 1. Pipeline Architecture & Privilege Separation

`.github/workflows/release.yml` enforces strict separation between untrusted third-party build code (`build.rs`, Cargo proc-macros, SwiftPM plugins) and release signing material:

1. **`ci`** — Runs the full cross-platform test, formatting (`cargo fmt`), lint (`clippy` / `shellcheck`), and supply-chain (`cargo-deny`) matrix on the target commit before any release build starts.
2. **`build-macos`** — Runs with `contents: read`, `persist-credentials: false`, and **zero signing secrets**. Builds all Rust binaries (`--locked`), compiles the SHA-256-pinned VPN & Tailscale runtime (`scripts/build-vpn-runtime.sh`), builds `SuperManagerMac.app` unsigned (`CODE_SIGNING_ALLOWED=NO`), and uploads `macos-unsigned-app` (`retention-days: 1`).
3. **`sign-macos`** (`needs: [build-macos]`, `environment: release`) — Runs on a clean macOS runner that **never executes `cargo`, `build.rs`, `xcodebuild`, or untrusted build binaries**. Imports Developer ID certificates into an ephemeral keychain, signs nested Mach-O helpers/daemons and the `.app` inside-out with hardened runtime + entitlements, notarises and staples `.app` / `.pkg` / `.dmg`, signs the update archive with official SHA-256-pinned Sparkle `sign_update`, and generates `appcast-beta.xml` (plus `appcast.xml` for stable promotions).
4. **`build-windows`** (`needs: [ci]`) — Compiles Windows crates with `--locked`, stages SHA-256-pinned vendor dependencies, builds and tests the WiX v5 `.msi` + Burn `.exe` bundle, and emits `.sha256` sidecars.
5. **`publish`** (`needs: [sign-macos, build-windows]`, `environment: release`) — Verifies every cross-platform artifact and XML feed (`xmllint`), stages a draft GitHub Release, publishes it atomically, and commits updated appcast XML feed(s) to `main`.

---

## 2. Beta-First Release Flow

Every functional release ships to the **beta channel** first and soaks before reaching the general fleet.

### Step 1 — Cut a Beta Pre-Release (`vX.Y.Z-beta.1`)

1. Ensure `main` is green in CI and `Cargo.lock` matches all manifests (`cargo metadata --locked --format-version 1 >/dev/null`).
2. Tag and push a SemVer pre-release tag (`-beta.N` or `-rc.N`):
   ```bash
   git checkout main && git pull --ff-only
   git tag -a v1.9.0-beta.1 -m "Release v1.9.0-beta.1"
   git push origin v1.9.0-beta.1
   ```
3. Approve the `release` GitHub Environment gate when `sign-macos` / `publish` request review.
4. **Effect of pre-release tag:**
   - GitHub Release is published with `prerelease: true` (so Windows/Linux `releases/latest` queries ignore it and stable users remain on the previous stable release).
   - `appcast-beta.xml` on `main` is updated immediately for macOS beta-channel subscribers.
   - `appcast.xml` is **not** modified.

### Step 2 — Beta Soak & Verification

Allow at least **24–48 hours** of soak testing on beta installs before promoting to stable. Verify:

- Privileged helper / Windows Service upgrade succeeds cleanly from the prior stable version.
- WireGuard, OpenVPN / Azure Entra ID P2S, FortiGate IKEv2, and Tailscale tunnels connect and tear down DNS cleanly.
- Crash reports (`PLCrashReporter` / Windows Event Log) show no regressions.

If fixes are needed, land them on `main` and cut `v1.9.0-beta.2` (or `v1.9.0-rc.1`).

### Step 3 — Promote to Stable (`vX.Y.Z`) with 24-Hour Phased Rollout

1. Tag and push the clean stable SemVer tag:
   ```bash
   git checkout main && git pull --ff-only
   git tag -a v1.9.0 -m "Release v1.9.0"
   git push origin v1.9.0
   ```
   *(Alternatively, trigger **Actions → Release → Run workflow** on an existing tag with `channel = beta` first to stage, then re-run with `channel = stable` to promote.)*
2. Approve the `release` environment deployment gate.
3. **Effect of stable promotion:**
   - `appcast.xml` on `main` is updated with:
     ```xml
     <sparkle:phasedRolloutInterval>86400</sparkle:phasedRolloutInterval>
     ```
     Sparkle rolls the update out gradually across automatic background checks over **24 hours (86,400 seconds)** rather than updating 100% of the macOS fleet simultaneously. (Users who explicitly click **Check for Updates…** still receive it immediately.)
   - `appcast-beta.xml` on `main` is also updated **without** a phased rollout delay so beta testers immediately converge onto the final stable build.
   - The GitHub Release is published as the new `latest` stable release (`prerelease: false`).

---

## 3. Emergency Release Retraction & Rollback Procedure

If a severe regression or security defect is discovered during the beta soak or the 24-hour phased rollout window, execute the steps below **in order** to halt distribution within minutes.

### Phase A — Halt Further Auto-Updates Immediately (< 5 minutes)

1. **Demote or draft the GitHub Release** (stops Windows `supermgr-win` and Linux `install.sh` / `update-linux.sh`, which query `releases/latest`):
   ```bash
   # Mark as pre-release so /releases/latest immediately falls back to the previous stable tag:
   gh release edit v1.9.0 --prerelease=true --latest=false
   ```
   If the build contains a security vulnerability or broken installer that nobody should download manually either, convert the release to a draft or delete its installer assets:
   ```bash
   # Convert release to draft (hides all download URLs from unauthenticated clients):
   gh release edit v1.9.0 --draft=true

   # Or yank specific compromised/broken assets:
   gh release delete-asset v1.9.0 SuperManager-1.9.0.zip --yes
   gh release delete-asset v1.9.0 SuperManager-Setup-1.9.0.exe --yes
   gh release delete-asset v1.9.0 SuperManager-Setup.exe --yes
   ```

2. **Revert `appcast.xml` / `appcast-beta.xml` on `main`** (stops Sparkle on macOS from offering `v1.9.0` to any client that has not yet downloaded it):
   ```bash
   git checkout main && git pull --ff-only
   # Find the `chore(release): publish v1.9.0 ... appcast` commit at HEAD:
   git log -n 3 --oneline -- appcast.xml appcast-beta.xml

   # Revert the appcast commit cleanly and push to main:
   git revert --no-edit <APPCAST_COMMIT_SHA>
   xmllint --noout appcast.xml appcast-beta.xml
   git push origin main
   ```

> **Important:** Reverting `appcast.xml` prevents *new* clients from upgrading to the retracted build, but Sparkle **will not downgrade** Macs that already installed `1.9.0` back to `1.8.26` because `1.8.26 < 1.9.0` (`CFBundleVersion`). To remediate already-updated machines, proceed to Phase B.

### Phase B — Remediate Clients Already on the Retracted Version (Forward Hotfix)

Never delete and recreate an existing `vX.Y.Z` tag with different binaries. Always ship a strictly higher version (`vX.Y.(Z+1)`):

1. Prepare either:
   - A targeted fix on `main` (or a `release/1.9` hotfix branch), **or**
   - A clean `git revert` of the offending commit(s) so the codebase matches the last known-good state.
2. Tag the next patch version (`v1.9.1`), ensuring `SUPERMANAGER_VERSION` / `CFBundleVersion` / `CFBundleShortVersionString` strictly increments (`1.9.1 > 1.9.0`):
   ```bash
   # Smoke-test via beta channel first if time permits:
   git tag -a v1.9.1-beta.1 -m "Hotfix candidate v1.9.1-beta.1"
   git push origin v1.9.1-beta.1

   # Once verified, publish stable hotfix:
   git tag -a v1.9.1 -m "Hotfix release v1.9.1"
   git push origin v1.9.1
   ```
3. Once `publish` completes for `v1.9.1`:
   - Every client still on `1.8.x` upgrades directly to `1.9.1` (skipping the retracted `1.9.0`).
   - Every client that already installed `1.9.0` sees `1.9.1 > 1.9.0` (`CFBundleVersion` / `SUPERMGR_VERSION`) and upgrades cleanly off the faulty build.
4. Add a post-incident note on the retracted `v1.9.0` GitHub Release pointing operators to `v1.9.1`.
