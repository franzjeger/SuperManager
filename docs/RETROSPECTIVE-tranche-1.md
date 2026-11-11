# Tranche 1 Retrospective

Captures the lessons that emerged from Tranche 1 execution (PR #81)
and the 1.12a gate (PR #83), so they survive into future tranches
without re-learning.

This document is not a changelog. The PR descriptions are the
changelog. This document is the meta-pattern across them.

## The headline lesson

**Any refactor that changes a function's return shape — its
signature, its tuple arity, the keys on its wire response — is a
silent deletion of whatever the caller stops receiving. The
dropped half deserves the same reader-trace as the added half.**

A green build proves the new path compiles. It does not prove that
nothing on the dropped path was being read. The compiler can't see
through JSON-RPC, can't see across the Swift / Rust boundary,
can't see what was being decoded by name on the wire.

So: every time we change a return shape — including renaming
fields, dropping fields, swapping `(A, B)` for `C` — we trace
**both halves**:

- Who reads the added shape? (Existing readers: do they decode
  the new field name correctly? Will old persisted rows still
  load?)
- Who read the dropped shape? (Existing decoders by name. Other
  callers of the function. Other branches of a wire schema.)

If either half has a hidden consumer, the "green-building
refactor" is a regression.

## The four instances that taught us this

Tranche 1 + 1.12a surfaced this same class of bug four times in
quick succession. Each one was almost shipped before someone (or
the discipline) caught it.

### K2 — false-orphan deletion of `tailscaleResumeWatchdog`

**Setup.** Phase-1 audit identified `tailscaleResumeWatchdog` as
a Swift wrapper with "no callers" — slated for deletion in
Tranche 1, step K2.

**What was almost wrong.** The "no callers" claim was based on a
single grep for the symbol name. A deeper search found **five
live call sites** in `AppState+Tailscale.swift` — all on the
exit-node-setup error path, releasing the watchdog after a
failed connect. Safety-critical.

**The save.** "Treat every 'no callers' claim as a hypothesis to
disprove, not a fact." K2 was cancelled before any code shipped.

**The class.** A symbol with apparent zero consumers might have
consumers under different spellings (snake_case wire name vs
camelCase Swift, substring matches, indirect dispatch).

### 1.9 — engagement context dropped on sheet relocation

**Setup.** Tranche 1 step 1.9 relocated `TrafficCaptureSheet`
from the Security section to the Recon section, replacing the
Security-side trigger with a cross-link that called
`appState.selectedSection = .recon`.

**What was almost wrong.** The sheet writes scoped data — pcap
captures filed against an engagement ID. The relocation passed
the section selection but **not the `engagement.id`**. ReconView
fell back to "first active engagement," which would file pcaps
against the wrong engagement entirely. Exact wrong-scope bug C1
was originally about, reintroduced by C1's own fix.

**The save.** Pre-merge investigation caught it. Fixed by
adding `pendingReconEngagementId: String?` to AppState, consumed
by ReconView before `syncEngagementSelection`. Commit `5785657`
(1.9b).

**The class.** Relocating a sheet that writes scoped data is
never just a relocation. The scope itself is a hidden consumer
of the trigger site — drop the trigger context, drop the scope.

### 1.14 — broken `[String: String]` decoder that no one called

**Setup.** Tranche 1 step 1.14 added a new Settings → Network tab
listing device-type overrides. The wrapper `loadDeviceTypeOverrides()`
already existed in `AppState+UnifiControllers.swift`.

**What was almost wrong.** The wrapper had been silently broken
for an unknown amount of time: it decoded `[String: String]`,
but the engine had been returning the structured shape
`{by_mac: {...}, by_oui: {...}}` the whole time. No caller had
ever invoked the wrapper, so the bug never fired. The companion
`setDeviceTypeOverride` SETTER was live (called from the scan
sheet's host-row menu) but the GETTER had a stub-quality decoder
nobody had pressure-tested.

**The save.** Investigation under Gate-2 review caught the
decoder mismatch. The "(manual)" indicator the operator sees is
driven by a different path (per-host `ActiveHost.deviceTypeOverride`
annotation from the engine), so the broken decoder was a true
Schrödinger bug — present but unobserved. Fixed during 1.14 with
a typed `DeviceTypeOverrides` Swift model mirroring the engine
shape.

**The class.** A wrapper with zero callers is not a "leaf to
delete" — it might be a latent contract that the SETTER's behavior
implicitly depends on, or a future GETTER's only deserializer.
Either build it with the right shape now (if you're adding the
caller) or delete it as obviously unreachable (if it's truly
dead) — never leave a broken decoder alive on the assumption
that "no caller, no problem."

### 1.12a — dropped `findings` half of `run_baseline`'s return shape

**Setup.** 1.12a refactored `ssh_compliance::run_baseline` from
returning `(Vec<LinuxCheckResult>, Vec<Finding>)` to a single
`ComplianceRun`. The handler `handle_compliance_run_linux` over
the wire changed from `{checks, findings}` to a flat
`ComplianceRun`.

**What was almost wrong (the hypothesis).** "The `Finding` half
was never pushed to `findings_store` — drop it." That rationale
described what the function STARTED, not what its callers
RECEIVED. A return-shape change is a deletion of whatever the
caller stops receiving; the caller-side question was never
asked.

**The save.** Caught on review before the PR was opened.
Required grepping:

- `SuperManagerMac/` for `"findings"` as a JSON key in any
  compliance-related decode (zero hits — the three `let findings:`
  Codable properties in `SecurityModels.swift` belong to
  `EngagementEvent`, `ActiveScanResult`, `DnsHealthReport`, none
  of which touch a `ComplianceRun` shape)
- `SuperManagerMac/` for any caller of `compliance_run_linux`
  at all (zero — the RPC exists in the engine but has no Swift
  client today)
- The engine for any other caller of `run_baseline` (zero — only
  call site was the handler being rewritten)

All three came up clean, so the deletion was sound. The commit
body was upgraded from "was never pushed to findings_store" (a
reader-claim) to "verified zero readers of the dropped findings
vec" (the proof).

**The class.** This case generalized the previous three. The
hidden consumer in K2 was a symbol-table caller; in 1.9, a scope
field; in 1.14, a future decoder. In 1.12a, it was a wire key
that — happily — also turned out to have no consumer. The
underlying discipline is the same: **anything you remove needs
the same enumeration as anything you add.**

## The discipline going forward

When changing a function's return shape:

1. **Enumerate the added half's readers.** What new fields will
   they decode? What `#[serde(default)]` does back-compat need?
   What loaders / migrations / scheduled paths exist?
2. **Enumerate the dropped half's readers — by name.** Grep the
   wire-key name on the consumer side, not just the producer.
   Grep the field name on every cross-process boundary
   (Swift / Rust / SQLite / disk schema). Grep the function name
   for callers consuming the deleted tuple element.
3. **Document the trace in the PR.** Not as a checklist that
   reads "I checked" — as a paragraph quoting the grep terms
   and the hit counts. Future reviewers (and future-you) need to
   verify the trace, not trust it.
4. **If anything reads the dropped half:** it's a 1.9-class
   regression hiding in a green-building refactor. Either preserve
   the consumer with explicit deprecation, or migrate the
   consumer in the same commit.

When the impulse is to write "no callers, safe to delete" —
stop. That's a hypothesis to disprove, not a fact to assert.

## What this list is NOT

It's not an exhaustive bug catalog. Tranche 1 + 1.12a had other
defects (stale Xcode project file regenerated by xcodegen, the
Phase-1 doc's internal Q1–Q5 severity contradiction, C3 overreach
in Phase-1 root-causing) — those weren't of the same class. The
four instances above share a specific shape: a hidden consumer
of something a refactor was silently removing.

That shape recurred fast enough across one tranche that it's
worth naming. The future tranches will see it again. When they
do, this document should make the catch feel routine instead of
heroic.
