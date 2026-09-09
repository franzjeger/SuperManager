# SuperManager audit remediation — first batch

Date: 2026-09-09. Implemented on the existing `feat/tailscale-device-mgmt` working branch, based on `b53f04f`, preserving its pre-existing uncommitted work. The audit describes a different commit of main; findings were checked against this branch before editing. The original audit remains unchanged.

## Implemented

| Audit finding | Changes in this batch | Remaining qualification |
|---|---|---|
| SM-03: Windows RPC path traversal | Every host_id/key_id argument in Windows dispatch now passes a shared UUID validator before path construction, secret lookup or downstream calls. Simple/hyphenated UUID spelling is preserved for existing filenames and credential labels. Negative tests cover absolute/relative/UNC/device paths, alternate streams, malformed values and non-filename UUID encodings. | Windows-target service compilation passed; installed Windows service exploitation/ACL tests were not run. SM-02 caller authorization remains open. |
| SM-07: lost credential updates | Engine FileSecretStore locks the complete read/modify/replace operation using a stable OS file lock. Separate instances and processes serialize. Blocking work runs through spawn_blocking. Temporary files are random, create-new and private before writing, with flush/sync/atomic replacement. Corrupt/read-error data is not silently treated as an empty map. | This fixes the engine implementation. The separate Linux daemon secret store still requires equivalent work/consolidation. This does not encrypt plaintext storage or fix incomplete backups. std::fs::File::lock requires Rust 1.89+; verification used the installed 1.95 toolchain. |
| SM-10: SSH trust failures | Engine construction now returns an error for corrupt/unreadable trust storage instead of using /tmp/supermgr-empty. Both engine and Linux SSH callbacks use atomic check-and-enroll and abort when enrollment persistence fails. Competing first-use fingerprints cannot overwrite the winner within the shared store. Record/forget publish cache changes only after successful persistence; private atomic files replace predictable temporary paths. | TOFU remains the first-use policy, and host:port is still the identity. Independently opened trust-store caches across multiple daemon processes are not reconciled by this batch. Canonical customer/device trust identity remains future work. |

Only one line was added to the already-modified macOS daemon main function to propagate the new startup error. Existing Keychain/helper/Tailscale/UI changes were retained. No helper/service installation, VPN changes, customer-device commands or updater execution was performed.

## Validation

- `cargo test --locked -p supermgr-core -p supermgr-engine -p supermgrd-mac -p supermgrd-win`: **436 passed** (198 core, 229 engine, 7 engine RPC integration, 2 portable Windows argument tests). One ignored test is a subprocess helper explicitly executed by its parent regression test, not a skipped acceptance test.
- Engine regression: 32 concurrent independent store instances retain all 32 acknowledged entries.
- Engine regression: four independent writer processes retain all 40 entries.
- Concurrent delete/store regression prevents stale snapshots from restoring removed entries.
- Corruption, private file modes and legacy predictable-temp symlink regressions pass using disposable fake data.
- Trust regression: 16 competing first-use fingerprints yield one enrollment and 15 mismatches, with the winning pin on disk. Failed enrollment/forget and corrupt startup tests pass.
- `cargo check --locked --target x86_64-pc-windows-msvc -p supermgrd-win`: **passed**, checking the actual Windows service modules. This is not native execution or an installed ACL test.
- `cargo clippy --locked --all-targets -p supermgr-core -p supermgr-engine -p supermgrd-mac -p supermgrd-win -- -D warnings -A clippy::pedantic -A clippy::style -A clippy::complexity`: **passed**.
- `git diff --check`: passed. Pre-existing diff verified still applicable in reverse with `git apply --reverse --check` (check only; nothing reverted).

Tests ran against this feature branch, so counts differ from the main-branch audit. No Linux-native service or live SSH handshake test was performed here. Whole-workspace formatting drift identified in the audit was not mass-reformatted.

## Next production blockers

1. Constrain/authenticate the macOS root helper and authorize Windows callers; ID validation does not close those boundaries.
2. Remove ambiguous cross-customer/IP and cross-site target resolution, then bind deployment to immutable reviewed bytes and a validated device identity.
3. Enforce vendor TLS verification and harden deployment timeout/acknowledgment/rollback semantics.
4. Apply transactional secret persistence to the separate Linux store; finish vault, backup and cross-process trust policies.
5. Continue coverage-safe reconciliation, VPN lifecycle ownership and independently signed updates in the audit's dependency order.

This is an initial remediation batch, not production clearance or closure of the complete audit.

## Second batch — provisioning scope and reviewed deployment plans

Implemented on the existing `feat/tailscale-device-mgmt` working tree, preserving the first batch and pre-existing work. This narrows SM-04/SM-05 for the shared engine's template deployment RPC and macOS provisioning UI; it does **not** close wrong-target risks throughout the product.

### Changes

- **Customer/site/host resolution:** macOS no longer resolves overlapping IP addresses by whichever host was inserted last. Conflicting customer claims do not produce a deployment target. UUID references accept compact/hyphenated spellings; duplicate record IDs fail lookup. Fleet customer membership no longer adds a host to another customer's card merely because that customer has a conflicting IP link.
- **No other-site fallback:** the macOS provisioning action requires exactly one unambiguously linked FortiGate in the selected site. It cannot silently select the first of several firewalls or a firewall in another site. Legacy IP links still work when unique and uncontested. Ambiguous data requires explicit record-ID links; this batch does not add a full migration or an HA target-selection workflow.
- **Backend scope checks:** preview and deployment both validate structural membership, unique customer/site selection, FortiGate device type, and conflicting customer/group tags. Preview also checks the template vendor. Customer enumeration for this path fails on unreadable records rather than ignoring them. Customer loading validates slugs before constructing paths.
- **Immutable approval:** preview retains the rendered configuration, host record, customer record, render metadata and SHA-256 of the live configuration in an engine-owned plan. It returns `plan_id`; deployment accepts that ID, consumes the plan, and uses its retained configuration without re-rendering. Changing template files after preview therefore cannot change the approved commands.
- **Expiry, replay and concurrency:** plans expire after ten minutes; an engine restart invalidates them. There are at most 32 pending plans and rendered configuration is limited to 2 MiB per plan. A plan can be consumed once. A process-local lease prevents overlapping plan deployments to the same literal hostname/port, including different host records pointing at that endpoint. Leases release on task/guard drop. DNS aliases, separate engine processes and non-plan mutation paths are not covered by this lease.
- **Validation before push:** changed host/customer records or changed live configuration abort. The SSH connection uses the captured host record, and the same connection reads current configuration, takes the backup and sends the commands. The host ID is not re-resolved into a new endpoint between backup and push.
- **Backups and read failures:** configuration reads have a 60-second timeout and reject failed exit status, stderr, empty/non-config output and common FortiOS error markers. Backups use unique create-new private files, sync before publication and avoid overwriting another backup made in the same second. Manual pre-deploy backups use the same writer.
- **UI scope and stale results:** the preview sheet captures its target/customer/site/template/extras at opening. Deployment submits only the plan ID. The sheet displays customer/site context, offers the complete configuration alongside the section diff, consumes approval locally and prevents dismissal while the request is active. Late render responses cannot repopulate a different customer's/site's form; template/extra changes invalidate rendered output. Compliance auto-start now requires a successful deployment result.

### Protocol compatibility

`provisioning_diff_preview` keeps the existing input and adds a required `plan_id` to its response. `provisioning_deploy` now takes `{ "plan_id": "<UUID>" }`. Legacy `{host_id, render_request}` deployment calls are rejected with `INVALID_PARAMS`. Upgrade the macOS client and engine together. The new client also fails to decode an old engine's preview rather than falling back to unreviewed deployment.

A lost response does not authorize another push: the same plan cannot execute twice. A missing/used plan error tells the operator to inspect deployment history before creating a new preview. There is not yet a durable plan-to-operation recovery API; an engine crash during a push can still leave a running/uncertain deployment record.

### Validation

- `cargo test --locked -p supermgr-core -p supermgr-engine -p supermgrd-mac -p supermgrd-win`: **446 passed** (198 core, 238 engine, 8 RPC integration, 2 portable Windows argument tests). The existing ignored subprocess helper is exercised by its parent regression test.
- Nine additional Rust unit tests cover wrong customer/site/vendor, shared IPs, unique legacy links, conflicting links, duplicate sites, changed host/credential references/customer/live state, retained configuration, one-use approval, restart invalidation, expiry/capacity/size limits, concurrent consumption, endpoint leases, rejected config reads and private/non-colliding backups. One additional socket-level RPC test rejects legacy and unknown approvals.
- `bash scripts/test-host-index.sh`: **12 XCTest tests passed**. The script copies the actual resolver, models and tests into a disposable Swift package; it does not substitute mock model definitions or launch the desktop app/helper/daemon.
- macOS **`xcodebuild build-for-testing` passed** for the app and test bundle in an isolated source copy. Signing and Rust bundling/build scripts were omitted in that temporary project; this verifies Swift compilation/linking, not a signed installer or runtime UI interaction. Rust code was tested separately above.
- Clippy passed with the same scope and lint policy as the first batch: all targets for core, engine, macOS daemon and Windows daemon, `-D warnings -A clippy::pedantic -A clippy::style -A clippy::complexity`.
- New Rust plan module is rustfmt-formatted. Existing workspace formatting drift was not mass-reformatted.
- `git diff --check` and reverse-application **check only** of the pre-second-batch diff passed, confirming earlier changes were retained.

Logs: `/tmp/supermanager-second-tests-final.log`, `/tmp/supermanager-second-swift-tests-final.log`, `/tmp/supermanager-second-clippy-final.log`, `/tmp/supermanager-second-xcode-final.log`.

### Explicit remaining limits / next work

1. **SM-06 remains open:** the SSH interactive-shell implementation can still misclassify timeout/EOF/write failure as success and does not provide reliable per-command acknowledgment. Fix this and prove partial-deployment behavior before relying on deployment status. Retaining reviewed commands does not prove the device applied them.
2. Automatic confirmed rollback, post-deploy verification, durable crash reconciliation and backup restore safety remain open. The existing rollback RPC and other SSH/API/AI mutation paths do not use preview plans or the new endpoint lease.
3. These checks bind a host record/endpoint, not a cryptographically verified customer/site/device serial. Shared private address spaces, DNS aliases, VPN route changes, bastions and TOFU trust still require a canonical identity/network-context design. External administrators can change the device after the final read; this is not an atomic FortiOS transaction.
4. Customer/host persistence is not one cross-process transaction. Snapshot checks catch observed changes; they do not serialize all editors. Credentials are retrieved through the captured references at connection time, not frozen as secret values in the plan.
5. Rendered configurations and customer data can contain secrets. Plans stay in process memory (expired entries are pruned on later insertions/consumption), and historical deployment records still need the broader encryption/redaction/retention work. This batch hardens new backup files, not all historical artifacts.
6. Linux GTK provisioning and Windows provisioning were not migrated to this workflow. No live FortiGate, installed privileged helper, native Windows service or Linux desktop was exercised.

This batch makes the reviewed-plan path substantially safer, but is not production clearance. Privileged-helper authorization, vendor TLS, shell execution correctness and signed updates remain higher priority than visual polish.

## Third batch — bounded SSH command acknowledgment and honest outcomes

**Git status at completion of this batch:** work was local and uncommitted. See the fourth batch below for publication.

### Changes

- Replaced the engine's permissive interactive send loop with a transport-injected FortiOS shell driver. Initial prompt, each write and each response are required. EOF, channel rejection, unsuccessful exit, failed writes and deadlines produce errors and stop further commands.
- Shell setup, writes and response waits share one total deadline. Closing the channel is bounded, and the provisioning/restore disconnect after execution has a two-second bound. The driver checks deadlines even when a peer continuously supplies immediately-ready events.
- Prompt matching checks the complete final line and the learned device hostname/context. An explicitly issued `set hostname` permits the corresponding new hostname. Embedded `#`, echoed comments and `New API key:` text are not acknowledgments. Common FortiOS command errors stop the batch immediately, including when split across packets.
- Configuration deployment and backup-command restore both use this driver. Their progress counts now represent acknowledged input lines. Errors identify the interrupted line and explicitly say that it may have applied. Failure messages do not copy command text, passwords or raw device output.
- API-token creation passes a password separately. It is sent only in response to a password request from the final command, at most once. If the device never requests a password, it is never sent as an ordinary command. Configuration operations reject password prompts.
- Shell input rejects embedded control characters, and response/transcript accumulation is bounded (256 KiB per response, 4 MiB total). Unsupported prompt behavior fails closed rather than silently progressing.
- Added `acknowledgment_checked` to deployment records, defaulting to false when loading older records. Existing wire status names and `lines_pushed` remain compatible; older estimated progress is not relabeled as measured acknowledgment.
- macOS results/history now distinguish acknowledged commands from legacy reported success. Restore confirmation no longer claims that replaying a backup completely replaces the current configuration. Successful command acknowledgment explicitly still requires device-state verification. A rollback connection failure now finalizes its history record as failed instead of leaving it running.

### Validation

- Full selected Rust suite: **461 passed** (198 core, 253 engine, 8 RPC integration, 2 portable Windows argument tests). The existing subprocess-helper test is intentionally ignored by the normal runner and invoked by its parent test.
- Twelve new shell-driver tests exercise fragmented prompts, hostname changes, initial EOF/rejection/timeout, failures after partial progress, blocked/failed writes, fragmented device errors, echo/prompt confusion, unexpected/repeated password prompts, password omission, output/control-character bounds and zero-deadline handling.
- Three new deployment-result tests check legacy record decoding, partial failure with acknowledged progress, and success/failure mapping for restore commands.
- **14 isolated Swift XCTest tests passed**, including two new outcome/legacy-history tests using the actual production models. Run with `bash scripts/test-host-index.sh`; this does not launch the application or daemon.
- macOS app and test bundle **build-for-testing passed** in the same isolated unsigned project used for the second batch, with Rust packaging scripts omitted. This is compilation/link verification, not runtime UI or installer validation.
- Clippy passed for all targets of the selected Rust packages with the preceding batches' lint policy.
- `git diff --check` passed. The original pre-remediation user diff still passes reverse-application check (check only), confirming those changes were preserved. Earlier provisioning changes were intentionally extended, so the complete pre-third-batch diff is not independently reverse-applicable; the earlier regression tests continue to pass.

Logs: `/tmp/supermanager-third-tests-final.log`, `/tmp/supermanager-third-shell-tests.log`, `/tmp/supermanager-third-swift-tests.log`, `/tmp/supermanager-third-clippy.log`, `/tmp/supermanager-third-xcode.log`.

### What this does not establish

SM-06 is **partially remediated**, not closed in full. Tests use an injected transport to exercise the production driver; no live FortiGate/firmware matrix or local SSH-server integration was run. Prompt acknowledgment cannot prove device state, defeat a lying device, or make command replay transactional. Unrecognized firmware/prompt formats may now abort and require explicit support.

Independent readback, confirmed timed rollback, safe backup-source/target binding, durable progress during crashes, cancellation cleanup and reconciliation of interrupted operations remain open. The existing rollback RPC still needs the same reviewed-plan/scope protections as deployment. Linux's separate SSH implementation is unchanged. Privileged helper/service authorization and the other P0 security issues remain production blockers.

## Fourth batch — reviewed, target-bound backup replay

### Publication

Batches 1–3 were committed as `d1f2109` and pushed to `origin/fix/audit-remediation-20260909`. This fourth batch is prepared on the same remediation branch. `main` and the existing feature branch are not overwritten. A separate worktree excludes the user's pre-remediation local edits; those remain in the original workspace. The audit report/raw evidence remain local and are not part of these code-fix commits.

### Changes

- Disabled direct `provisioning_rollback {host_id, backup_path}` execution. It now returns `INVALID_PARAMS` and requires a reviewed restore plan.
- Added `provisioning_restore_preview {host_id, deployment_id, customer_slug, site_id}`. It loads a registered deployment, checks its record ID and host/customer/site, validates current membership, and requires the host to match the target snapshot captured with the backup.
- New deployment records retain a host snapshot, the pre-operation backup's SHA-256 and, for restores, the source deployment ID. Backup contents must match the stored digest. This detects changed/corrupted backups; it is not a signature against an attacker able to rewrite both the backup and its private metadata.
- Restore sources must be regular files in the selected host's backup directory. Reads are size-bounded; Unix opens use `O_NOFOLLOW | O_NONBLOCK`, rejecting final symlinks and avoiding FIFO hangs. Metadata is checked before reading contents. Added direct `libc` dependency for these platform flags; Cargo.lock adds only the existing libc dependency edge, without a version upgrade.
- Restore preview captures the verified backup text in the same bounded, expiring, single-use plan registry as deployment. Editing the source file after preview cannot change the commands deployed. Execution rechecks host/customer/live state, shares the endpoint lease, takes a fresh backup on the same connection, and uses the acknowledged shell driver. Successful command replay records `rolled_back` plus source provenance; it does not claim verified restoration.
- Deployment history files now use private temporary files, sync and atomic replacement. Newly created/replaced records are mode 0600 on Unix. History loading filters records whose host ID contradicts the requested directory.
- macOS Restore opens the shared diff/full-command preview instead of executing from a file path. Legacy backups without target/digest metadata are disabled with an explanation. Any host-record change since backup also blocks automated restore; no unsafe override or automatic rebinding is introduced.
- The prompt-per-line driver cannot handle multiline quoted certificate/key values. It now preflights all command lines and rejects these unsupported forms before the first command is sent; preview plans also reject them. Remaining disconnect waits in provisioning are bounded.

### Validation

- Selected full Rust suite: **468 passed** (198 core, 259 engine, 9 RPC integration, 2 portable Windows argument tests), plus the subprocess helper exercised by its parent test.
- New tests cover wrong host/customer/site, changed endpoint, missing legacy metadata, other-host backup directories, changed contents, symlinks/FIFOs/non-regular files, bounded reads, private atomic record replacement, immutable restore approval after file edits, and rejection of direct rollback/path-traversal RPC inputs.
- Multiline quoted commands are rejected before any write. Existing scope, replay, acknowledgment, secret-store and host-trust tests continue to pass.
- **14 isolated Swift tests passed**; macOS app/test-bundle compilation passed in an isolated unsigned project. Rust bundling scripts were omitted for that Swift compilation; this does not validate an installer or live device interaction.
- Clippy uses the same selected packages/all-targets/lint policy as preceding batches. `git diff --check` passes. The original pre-remediation user diff still reverse-applies in check-only mode.

Logs: `/tmp/supermanager-fourth-tests-final.log`, `/tmp/supermanager-fourth-swift-tests.log`, `/tmp/supermanager-fourth-clippy.log`, `/tmp/supermanager-fourth-xcode.log`. Publication-worktree verification is logged separately under `/tmp/supermanager-publish-fourth-*`.

### Remaining limits

This is reviewed backup **command replay**, not a complete replacement transaction. New settings may remain, and readback verification, confirmed timed rollback, crash/cancellation reconciliation and firmware-specific multiline handling still need implementation and live-device tests. Older backups require manual inspection/recovery because their historical target cannot be established safely. Host records are not cryptographic device/customer identities. Administrative helper/service authorization and other audit P0 issues remain open.

## Batch 5 — macOS helper admission and privileged executable inputs

### Changes

- The helper obtains the connecting process's kernel audit token and validates its dynamic code identity before reading requests and again before each dispatch. It admits only `com.sybr.supermanager`, Apple-anchored and signed by team `LY6LJ395B8`, with hardened runtime, valid dynamic signing state and no debug/injection entitlements. Root UID and `dev-rpc` provide no bypass. Socket group permissions remain a coarse admission filter. Connections are capped at 64 with bounded frame reads and response writes.
- `deploy_self` is always rejected, including development builds. Replacing the helper requires the signed installation path. Existing GUI auto-redeployment attempts will receive an error; they do not install this remediation into an already-running older helper.
- Tailscale daemon and CLI are copied into private staging files in a protected root-owned directory. Both staged copies must pass Security.framework signature verification with their respective pinned SuperManager identifiers before the existing service is stopped. Root execution uses fixed installed paths under `/Library/PrivilegedHelperTools`; user-selected live files and Homebrew CLI fallback are removed. The bundle script re-signs on every build instead of trusting a version stamp.
- VPN executables are resolved only under `/Library/PrivilegedHelperTools/SuperManagerVPN`. Ancestors and the bounded runtime tree must be root-owned, non-writable by group/others, and contain no symlinks or special files. Background strongSwan/WireGuard probes follow the same restriction. This does not authenticate transitive libraries or scripts outside that tree; a managed installer must supply a self-contained runtime with protected dependencies.
- Privileged WireGuard input rejects hooks, unsupported directives and shell metacharacters. OpenVPN accepts an explicit directive allowlist, inline certificates/keys and no executable plugins, config includes, external credential paths or caller-selected output files. Accepted OpenVPN text is copied into a root-private snapshot before execution. Profile IDs are validated as UUIDs. IKEv2 fields reject control characters, validate address/route grammar and quote credential identities. Packet capture uses the absolute system tcpdump path.
- Sensitive OpenVPN logs and config snapshots use private atomic writes in protected directories. Explicit disconnect removes its snapshot. Private snapshots can remain after failures/crashes; no crash janitor is claimed.

### Compatibility and rollout — required reading

**This is fail-closed hardening, not a production VPN runtime release.** Homebrew-based WireGuard/OpenVPN/strongSwan installations no longer satisfy privileged execution requirements. No managed runtime package is provided in this batch. Do not fix errors by recursively chowning Homebrew, copying binaries with unresolved Homebrew library dependencies, or weakening the checks. A separately built and tested protected runtime is required before these VPN workflows can be released again.

Unsigned/ad-hoc/debug GUI builds cannot use the root helper. Release signing and a real signed GUI/helper integration test are prerequisites for rollout. A compromised already-authorized GUI session is still powerful; this change is not per-operation user consent or customer authorization. Existing helper installation/update trust and the Linux/Windows service boundaries remain separate audit work.

WireGuard DNS/Table/SaveConfig and hook directives are currently rejected. OpenVPN quoted/continued directives, non-inline key material, unsupported options and OpenVPN3/Azure are unavailable through this helper. Root-private log files are not directly readable by the GUI's old file-opening flow; helper status diagnostics remain available. These restrictions need explicit product/UI treatment before shipping, not a claim of feature parity.

Existing Tailscale service installations require reinstallation with signed artifacts to move to the new paths. Both signatures are checked before stopping the old service, but publishing two binaries plus a plist is not a multi-file transaction; launch failure rollback, legacy artifact cleanup, downgrade protection and upstream artifact provenance remain open. Pinning the SuperManager signer does not establish independent upstream Tailscale provenance.

### Validation

- Selected full Rust suite: **551 passed, 1 ignored** (83 helper, 198 core, 259 engine, 9 RPC integration, 2 portable Windows argument tests). Linux/Windows native UI and live service behavior are not validated by this macOS run.
- Helper tests: **83 passed** with `dev-rpc`, including unsigned/unrelated signer rejection, rejection before reading a frame, disabled self-deployment, immutable bounded staging, symlink/non-regular-file rejection, UUID validation and malicious VPN directive rejection.
- Native macOS Security.framework requirement parsing and negative signature checks are exercised. A positive Developer-ID-signed GUI-to-installed-root-helper scenario was **not run**. No service was installed or started and no live VPN/network state was changed for validation.
- Helper Clippy runs with `--all-targets --features dev-rpc -- -D warnings -A clippy::pedantic -A clippy::style -A clippy::complexity`; this retains the existing selected lint policy rather than claiming strict pedantic cleanliness.
- New Rust modules are rustfmt-formatted; shell syntax and patch whitespace are checked. Full-workspace formatting remains outside this focused change because pre-existing files do not uniformly conform.
- Logs: `/tmp/supermanager-fifth-tests-final.log`, `/tmp/supermanager-fifth-helper-dev-tests.log`, `/tmp/supermanager-fifth-helper-clippy.log`.
