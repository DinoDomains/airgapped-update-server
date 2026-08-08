# OpenUpdater — Air-Gapped Update System PLAN

Status: design plan, not yet fully implemented. Wired single-server system
is already built and verified (see PROGRESS.txt / MANUAL.txt). This document
supersedes prior air-gap notes for the three-module design below.

---

## 1. Goal

A secure, sandboxed, USB-mediated update pipeline that:

- keeps the isolated network (DevNet) fully air-gapped, ever,
- lets updates flow in only through a verified, sandboxed, physical-media
  conduit,
- lets DevNet report its own inventory back out through the same conduit
  without exposing DevNet internals,
- gives admins a working frontend to approve, reject, or pause updates
  per package, per ring, before anything reaches endpoints.

**Operating model:** this is a scheduled maintenance-window system, not
near-real-time. Each update cycle is bounded by the physical USB
round-trip time (collect → carry → process → test → carry → verify →
deploy). Treat this as an explicit constraint when setting expectations
with stakeholders — a patch released upstream today does not reach
DevNet endpoints same-day. Current scale target: comfortably supports
DevNet deployments under ~100 nodes; revisit the model (parallel drives,
more frequent cycles) if that grows significantly.

---

## 2. System Topology — Three Modules

### 2.1 Update Server (online)
- The only module with internet access.
- Downloads vendor updates, verifies them (hash + signature), and where
  applicable runs behavior-based testing (sandboxed dynamic analysis)
  before a package is eligible for release.
- Reads DevNet inventory (arrives via USB), computes what DevNet actually
  needs, builds a signed update bundle.
- Hosts the admin frontend (see Section 6) for reject/approve/pause control.

### 2.2 DevNet (fully air-gapped, wired)
- No internet connection, ever.
- One DevNet server + wired endpoint agents on PCs/end devices.
- Endpoint agents report installed package/version inventory to the
  DevNet server.
- DevNet server has one **sandbox unit** attached to it (not a separate
  physical machine) that mediates all USB activity — see Section 3.
- Approved, verified updates are pushed from DevNet server to endpoint
  agents over the existing wired (and optionally wireless) network.

### 2.3 Endpoint Agents
- Existing design (Rust, mTLS, poll-pull-verify-install-rollback-report).
- No changes required for this plan — they only ever talk to the DevNet
  server, never to the sandbox unit or the USB directly.

---

## 3. The USB Round Trip

The USB is the *only* connection between DevNet and the Update Server.
It carries data in both directions, on different legs of a round trip:

```
[DevNet endpoint agents] --wired--> [DevNet server]
        |
        v  (writes inventory)
   [Sandbox Unit: EXPORT VM]
        |
        v  (USB OUT)
     >>> USB drive #1 (OUTBOUND, inventory only) >>>
        |
        v
   [Update Server] -- reads inventory, downloads, verifies, tests --
        |
        v  (writes signed update bundle)
     <<< USB drive #2 (INBOUND, updates only) <<<
        |
        v
   [Sandbox Unit: INGEST VM] -- re-verify hash/sig, re-test behavior --
        |
        v  (only verdict + verified artifact + logs cross this line)
   [DevNet server core] -- approval / rings / audit --
        |
        v
   [DevNet endpoint agents]
```

**Key design decision:** the sandbox unit is a subsystem on the DevNet
server itself (VM-based or equivalent), not a separate physical box. The
isolation has to be enforced in software/hypervisor config rather than
by an air gap between machines. See Section 4.

**Two physical USB drives, not one.** One drive is permanently the
OUTBOUND (inventory-only) drive, the other is permanently the INBOUND
(update-only) drive. Never swap roles. This avoids cross-contamination
between the two very different trust directions this device serves,
and limits the blast radius of a compromised or malicious drive.

- If operational constraints force a single physical drive, enforce it
  with separate partitions (OUTBOUND / INBOUND) and have each VM refuse
  to parse anything outside its assigned partition.

**Drive lifecycle / attestation (required, not optional).** The USB is
the entire supply chain here — a stale, confused, or misrouted drive
(e.g. the OUTBOUND drive plugged into the INGEST reader, or last week's
drive reinserted) must be detected and rejected, not silently accepted
or left to wedge the pipeline:
- Each physical drive gets a fixed `drive_id`, provisioned once and
  never reused across roles.
- Every bundle written to a drive is tagged with `drive_id` +
  `direction` (`outbound` / `inbound`) + `session.id`.
- The receiving VM checks `drive_id` + `direction` + `session.id`
  against what it expects **before** touching anything else — same
  fail-closed priority as the signature check. Mismatch = reject and
  alert, not a silent no-op.

---

## 4. Sandbox Unit Isolation Design (DevNet side)

### 4.1 Layering, on one physical host
```
Layer 0: Bare-metal hypervisor (Type-1: KVM/Xen/bhyve-class)
   - Runs as little else as possible.
   - Owns USB controller passthrough directly to VMs — the host OS
     itself never touches the raw USB device or its driver stack.

Layer 1: Sandbox VMs (ephemeral, snapshot-based)
   - EXPORT VM  — builds and signs the outbound inventory bundle,
                  writes it to the OUTBOUND USB. No access to raw
                  DevNet server internals — only a whitelisted,
                  minimal schema (pkg name, version, installed
                  binary hash). Reverted to golden snapshot after
                  every export.
   - INGEST VM  — mounts the INBOUND USB **read-only**, verifies
                  manifest.sig before parsing anything else, hash-
                  checks every artifact, re-runs behavior testing
                  locally (nested VM or equivalent). No network
                  access except the one narrow handoff channel to
                  Layer 2. Reverted to golden snapshot after every
                  run, pass or fail, no exceptions.

Layer 2: DevNet core services (separate VM/process boundary)
   - Approval service, admin state, RBAC, audit log, ring management.
   - Holds signing/verification keys.
   - Never touches USB content or raw untrusted artifacts directly.
   - Independently re-verifies signature + hashes on anything the
     INGEST VM hands over — never trusts the sandbox verdict blindly.
```

### 4.2 Why two VMs, not one shared sandbox
The export and ingest legs have different risk profiles: export is a
*data-exfiltration/sanitization* boundary, ingest is a *malicious-code*
boundary. Sharing one sandbox context between them means a compromise
picked up during ingest could persist and quietly corrupt the next
export (falsified inventory, exfiltration attempt). Two independently
ephemeral VMs prevent that.

### 4.3 Sandbox → core handoff channel
This is the new "diode" and deserves the same rigor as the original
Zone A → Zone B conduit:
- One direction only: INGEST VM → core VM.
- Implementation options: a strictly one-directional virtio channel,
  or the INGEST VM writes to a small, size-capped virtual disk that the
  core VM mounts read-only and never writes back to.
- Core VM re-validates everything it receives; it does not trust the
  sandbox's PASS verdict as sufficient on its own.

### 4.4 Additional hardening
- Cap the INGEST VM's CPU/memory/disk so a malicious payload can't
  starve the core services running alongside it on the same hardware.
- Enforce a minimum dwell time on behavior tests (some malware delays
  execution or detects sandboxes and stays dormant) — don't just run
  once and check immediately.
- Snapshot revert is unconditional: pass, fail, or timeout, the VM is
  discarded and rebuilt from a golden image every single run.

---

## 5. Data & Trust Contracts

### 5.1 Outbound bundle (DevNet → Update Server), via OUTBOUND USB
```
/outbound/
  drive_id.txt          # fixed physical drive identifier
  direction.txt          # "outbound" — checked by every reader
  inventory.json      # devnet server + each endpoint agent:
                       #   pkg name, version, installed binary hash
  inventory.sig        # signed by DevNet's export key
  session.id            # monotonically increasing, prevents replay
```

### 5.2 Inbound bundle (Update Server → DevNet), via INBOUND USB
```
/inbound/
  drive_id.txt           # fixed physical drive identifier
  direction.txt           # "inbound" — checked by every reader
  catalog.json         # what's in this bundle, versions, metadata
  artifacts/            # actual update packages
  manifest.json         # inventory of the bundle
  manifest.sig           # signed by Update Server's release key
  session.id             # matches / advances the outbound session id
```

### 5.3 Rules enforced on both ends
- `drive_id` + `direction` checked **first**, before signature parsing —
  reject and alert on any mismatch (wrong drive, wrong slot, stale
  drive). See "Drive lifecycle / attestation" in Section 3.
- Signature verified **before** anything else is parsed. Fail closed.
- Every artifact hash-checked against the manifest — no exceptions for
  "small" or "trusted-looking" files.
- `session.id` must be strictly increasing / unique — reject replays of
  previously-used bundles (old inventory or a since-revoked update set).
- DevNet's core VM independently re-verifies signatures/hashes even
  though the sandbox VM already did — never a single point of trust.

### 5.4 Revocation
- Update Server can mark a previously-shipped package/version as
  revoked. Revocation entries travel in the next `catalog.json` /
  `manifest.json` and DevNet's approval service must check pending and
  already-staged (not yet endpoint-deployed) updates against it before
  promoting anything further.
- **Revocation must also reach already-deployed endpoints, not just
  staged/pending ones.** When a revocation entry arrives, the DevNet
  approval service checks it against the last known endpoint inventory
  (Section 6.1 drift data). Any match must surface as an actionable
  alert to the admin — **it must not auto-trigger a revert.** Deciding
  whether to revert a specific endpoint (and to what version) is an
  admin decision, made through the frontend, not an automatic pipeline
  action. Automatic revert is explicitly out of scope for now; revisit
  only if a strong case for it emerges later.
  **This requires new agent-side work, not just a new trigger.** The
  existing agent rollback path only fires on a self-detected failed
  install (mid-transaction). Reverting an already-successfully-applied
  update on admin command is a different code path: a new
  admin-initiated server→agent command type ("revert package X to
  prior version"), a new agent handler for it, and a revert mechanism
  that works from a healthy, already-applied state rather than a
  failed-mid-install state. Scope this as its own agent feature, not a
  wiring exercise.
  **Not every update is cleanly revertible.** Linux packages generally
  support `dnf downgrade` / reinstall of a prior version. Windows KBs
  do not: some are uninstallable (`wusa /uninstall`, DISM), but some
  are permanent, superseded by a later cumulative update, or otherwise
  non-removable. The admin-facing revert action must be able to report
  "not revertible" as a real outcome — not silently fail or imply a
  revert happened when it didn't. See Section 7 for the fallback
  decision needed here.

### 5.5 Key Management Lifecycle
Key compromise breaks the entire pipeline's trust model, so this is a
first-class design concern, not an implementation detail:
- **Keys in play:** DevNet export key (signs outbound inventory),
  Update Server release key (signs inbound bundles), and any per-VM or
  per-drive keys used for `drive_id` attestation.
- **Storage:** prefer HSM or hardware-backed secure storage (e.g. TPM,
  Secure Enclave-class device) on both the Update Server and DevNet
  core VM. Software-only key storage is a fallback, not the target —
  document explicitly if used, with compensating controls.
- **Access:** signing keys are only ever used by the core VM / Update
  Server release process — never exposed to the EXPORT or INGEST
  sandbox VMs.
- **Rotation:** define a rotation cadence (e.g. annual, or on personnel
  change) and a rotation procedure that accounts for the physical
  round-trip — a rotated key must be trusted by both ends before it's
  used, which itself may require a dedicated USB trip carrying the new
  public key/cert.
- **Compromise response:** define the recovery procedure in advance —
  which keys get revoked, how the replacement is distributed given the
  air gap, and what happens to bundles already in flight when a
  compromise is discovered. This is harder to improvise here than in a
  normal online system, so it should not be left undocumented.

---

## 6. Update Server Admin Frontend

Needed so a human can control what actually gets bundled for DevNet —
this is the primary release gate and needs to be a first-class UI, not
an afterthought.

### 6.1 Core screens
- **Package queue** — every package pending review, with source, hash
  status (pass/fail), behavior-test verdict (clean / suspicious /
  failed / not-applicable), and a diff of what changed since the last
  approved version.
- **Reject / Approve / Pause controls**, per package, per version:
  - Approve → eligible for the next outbound bundle.
  - Reject → permanently blocked for that version, logged with reason.
  - Pause → held out of the next bundle without rejecting outright
    (e.g. "wait for more testing," "waiting on vendor patch").
- **Ring assignment** — dev / staging / prod, same model as the
  existing wired system; a package can be approved for dev without
  being promoted to prod.
- **Behavior test report viewer** — syscalls, network attempts, file
  writes, persistence attempts, flagged anomalies, per package.
- **Drift / tamper alerts (required)** — a separate alert stream, not
  folded into the update queue, that fires when an endpoint-reported
  package version/hash doesn't match DevNet's expected state. This is
  the only tamper signal available inside the air-gapped network and
  must be a first-class alert, not an optional future feature.
- **Bundle builder** — shows exactly what will go into the next
  outbound USB bundle before it's built; requires explicit
  confirmation before signing.
- **Revocation panel** — mark a previously approved package/version as
  revoked, with reason, propagated into the next manifest. When a
  revoked package matches an already-deployed endpoint, this panel
  surfaces it as an actionable item — the admin explicitly chooses
  whether to issue a revert command per endpoint; nothing reverts
  automatically. Reports "not revertible" plainly when the agent can't
  revert a given update (e.g. non-uninstallable KB).
- **Audit log** — immutable record of every approve/reject/pause/
  revoke action, who did it, and when.

### 6.2 Requirements
- RBAC: not every operator should be able to approve for `prod`.
- Every state-changing action requires a reason string, stored in the
  audit log (matches the existing audit-log pattern from the wired
  system).
- The frontend must reflect DevNet's actual reported inventory (from
  the last inbound sync) so admins aren't approving updates for
  packages DevNet doesn't even have.
- **"Tested" labeling must be honest.** A package that only received
  hash/signature verification plus an allowlist fallback (e.g. firmware
  or kernel modules that can't be dynamically analyzed pre-install)
  must never show the same "tested" badge as one that went through full
  behavior testing. Use distinct, explicit statuses (e.g. "behavior
  tested," "hash-verified only — dynamic analysis not applicable,"
  "manual review required") so admins never mistake verification scope.
- Drift/tamper alerts (Section 6.1) must be visibly distinct from the
  ordinary update queue — an admin should never have to infer "this row
  means something might be compromised" from context.

---

## 7. Open Decisions To Resolve Before/During Build

1. Confirm hypervisor choice for the DevNet sandbox unit (Type-1
   preferred: KVM, Xen, or bhyve-class).
2. Confirm two physical drives (OUTBOUND/INBOUND, preferred) vs. one
   partitioned drive, and finalize the `drive_id` provisioning process.
3. Define, per package type, whether behavior testing applies (e.g.
   firmware/kernel modules may not be dynamically testable pre-install)
   and what the fallback control is when it doesn't — this feeds
   directly into the frontend's "tested" labeling (Section 6.2).
4. Decide the exact mechanism for the sandbox → core handoff channel
   (virtio channel vs. read-only shared virtual disk).
5. Decide minimum dwell time for behavior/sandbox testing.
6. Decide HSM vs. software-backed key storage for each key (Section
   5.5), and finalize the rotation cadence.
7. Decide the fallback for endpoints where a revert genuinely isn't
   possible (e.g. a superseded or permanent Windows KB) — options
   include: leave as-is with a persistent flagged risk on that
   endpoint, force a compensating update forward instead of reverting,
   or require manual/out-of-band remediation. This needs a defined
   admin-facing outcome, not a silent dead end.

Resolved as hard requirements (no longer open): drift/tamper alerting
(Section 6.1), drive lifecycle/attestation (Section 3), revocation
reaching already-deployed endpoints (Section 5.4).

---

## 8. Next Steps (build order)

1. Set up key management first: provision export/release keys (Section
   5.5), decide HSM vs. software storage, document the rotation and
   compromise-response procedure before any signed bundle is built.
2. Freeze the data schemas in Section 5 (including `drive_id` /
   `direction` / `session.id`) as `docs/bundle-schema.md`.
3. Provision physical USB drives with fixed `drive_id`s; build the
   drive-attestation check as a precondition on both VMs.
4. Stand up the sandbox unit: hypervisor + EXPORT VM + INGEST VM +
   core VM boundary, USB passthrough to sandbox VMs only.
5. Build the outbound path: DevNet inventory collection → EXPORT VM →
   signed bundle → OUTBOUND USB.
6. Build the inbound path: Update Server reads OUTBOUND USB → computes
   needed updates → downloads/verifies/tests → signs bundle → INBOUND
   USB.
7. Build INGEST VM verification + re-test logic, and the sandbox→core
   handoff channel.
8. Build drift/tamper detection: compare endpoint-reported inventory
   against expected state, surface as a distinct alert (Section 6.1).
9. Build the Update Server admin frontend (Section 6) — package queue
   with honest "tested" labeling, approve/reject/pause, ring
   assignment, bundle builder, revocation panel, drift alerts, audit
   log.
10. Wire DevNet core approval/ring logic to consume verified bundles
    from the INGEST VM handoff and push to endpoint agents (reuse
    existing wired-system agent protocol).
11. Build new agent-side revert capability: an admin-initiated
    server→agent command to revert an already-applied package to its
    prior version, and the handler for it (distinct from the existing
    failed-install rollback path). Wire revocation matches against
    deployed endpoints to a **flagged admin alert**, not an automatic
    revert — the admin decides per endpoint whether to issue the revert
    command. Build the "not revertible" reporting path for cases the
    agent can't handle (Section 7 fallback decision).
12. End-to-end test: stage a deliberately bad/malicious package, confirm
    it's caught at both Update Server and DevNet sandbox stages, and
    never reaches an endpoint agent.
13. Rollback drill: confirm endpoint agent rollback actually fires on a
    bad install, confirm an admin-initiated revert command actually
    works on a healthy already-applied update, and confirm the
    "not revertible" case is reported accurately rather than silently
    failing.
14. Drive-confusion drill: deliberately plug the wrong drive into the
    wrong reader and confirm the system rejects it loudly rather than
    silently wedging.

---

## 9. Implementation Modules

Breakdown for assigning work in parallel. Each module lists its scope,
what it depends on, what it exposes to other modules, and which build
steps (Section 8) it owns. Modules are grouped by which physical
component they run on.

### M1 — Bundle Schema & Shared Contracts (shared library/crate)
- **Scope:** `drive_id` / `direction` / `session.id` format, outbound
  inventory schema, inbound catalog/manifest schema, signature and
  hash-check helper functions used by every other module.
- **Depends on:** nothing — build first.
- **Exposes:** a shared crate/library consumed by M2, M3, M4, M5.
- **Owns build steps:** 2.
- **Why first:** every other module reads or writes these formats;
  changing the schema after modules are built means rework everywhere.

### M2 — Key Management & PKI
- **Scope:** export key (DevNet), release key (Update Server), storage
  decision (HSM vs. software-backed), rotation procedure, compromise
  response procedure, key provisioning tooling.
- **Depends on:** M1 (for what gets signed).
- **Exposes:** signing/verification functions used by M3 and M6; keys
  themselves never exposed to sandbox VMs (M4).
- **Owns build steps:** 1.
- **Why early:** nothing can be signed or trusted until this exists;
  retrofitting key management after bundles are already flowing is
  expensive and risky.

### M3 — Update Server Core (online host)
- **Scope:** vendor catalog sync, download, hash/signature verify,
  behavior-test orchestration (dynamic analysis harness) for inbound
  vendor packages, bundle signing, OUTBOUND USB reader, INBOUND USB
  writer, drive-attestation check on read.
- **Depends on:** M1, M2.
- **Exposes:** the inbound bundle (consumed physically by M4/M5 via
  USB); package/behavior-test state consumed by M7 (admin frontend).
- **Owns build steps:** 3 (drive provisioning ties in here), 6.

### M4 — DevNet Sandbox Unit (hypervisor + EXPORT/INGEST VMs)
- **Scope:** Type-1 hypervisor setup, USB controller passthrough to
  VMs only, EXPORT VM (build+sign outbound inventory), INGEST VM
  (verify inbound bundle, re-run behavior test, drive-attestation
  check), golden-snapshot revert logic, sandbox→core handoff channel.
- **Depends on:** M1, M2 (verification only — signing keys stay out of
  this module entirely).
- **Exposes:** the one-directional handoff channel consumed by M5.
- **Owns build steps:** 4, 5 (EXPORT side), 7.
- **Isolation note:** this is the highest-risk module from a security
  standpoint (Section 4) — treat VM escape as the design threat to
  defend against throughout, not just at the boundary.

### M5 — DevNet Core Server
- **Scope:** approval service, ring logic (dev/staging/prod), RBAC,
  audit log, drift/tamper detection (compare endpoint-reported
  inventory vs. expected state), revocation matching against deployed
  endpoints, independent re-verification of anything from M4's handoff
  channel, mTLS server for endpoint agents (extends existing wired
  system).
- **Depends on:** M1, M4 (handoff channel), M2 (verification).
- **Exposes:** approved-update feed to M6 (endpoint agents); drift
  alerts and revocation-match alerts to M7 (admin frontend, DevNet
  side if applicable) or M3's frontend if admin UI is centralized on
  the Update Server.
- **Owns build steps:** 8, 10 (server-side half).

### M6 — Endpoint Agent (extends existing wired agent)
- **Scope:** existing poll/pull/verify/install/auto-rollback/report
  loop (already built) plus new work: admin-initiated revert command
  handler (revert an already-applied update to prior version from a
  healthy state), "not revertible" outcome reporting for cases like
  non-uninstallable Windows KBs.
- **Depends on:** M5 (command source), M1 (message formats).
- **Exposes:** inventory reports (consumed by M5 drift detection),
  install/revert outcome reports.
- **Owns build steps:** 10 (agent-side half), 11.

### M7 — Update Server Admin Frontend
- **Scope:** package queue with honest tested/hash-only/manual-review
  labeling, approve/reject/pause controls, ring assignment UI, behavior
  test report viewer, drift/tamper alert stream (visibly distinct from
  the update queue), bundle builder with explicit confirmation,
  revocation panel with admin-gated per-endpoint revert action and
  "not revertible" reporting, immutable audit log view.
- **Depends on:** M3 (package/test state), M5 (drift + revocation-match
  alerts, via whatever channel connects Update Server admin UI to
  DevNet state — likely the same USB round trip, since DevNet has no
  network path to expose this directly).
- **Owns build steps:** 9.

### M8 — Integration & Validation (cross-module)
- **Scope:** end-to-end malicious-package test, rollback drill,
  drive-confusion drill — these only make sense once M1–M7 are wired
  together.
- **Depends on:** all of the above.
- **Owns build steps:** 12, 13, 14.

### Suggested build order across modules
```
M1 (schema) → M2 (keys) → M3 & M4 in parallel (Update Server / Sandbox
Unit) → M5 (DevNet core, needs M4's handoff) → M6 (agent revert
capability, needs M5) → M7 (frontend, needs M3 + M5 state) → M8
(integration + drills)
```
M3 and M4 can genuinely be built in parallel by separate people/teams
since they only share M1/M2 as contracts. M6's new revert capability
can also start early against a mocked M5 command interface if agent
and server work need to happen concurrently.
