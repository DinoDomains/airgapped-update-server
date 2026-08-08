# Bundle Schema — Air-Gap Transfer Contracts (M1)

Status: FROZEN. Supersedes the earlier single-manifest `UsbManifest` in
`crates/transport` (legacy; kept for the wired path only). This file is the
authority for every bundle written to or read from the OUTBOUND and INBOUND
USB drives. See PLAN.md §5. Any change here is a cross-module breaking change
(M2–M7 depend on these shapes).

The USB is the *only* connection between the Update Server and DevNet. It
carries data in both directions but on two physically separate drives with
locked roles. Every bundle on a drive is tagged with `drive_id` + `direction`
+ `session.id`, and those three are checked **before** signature parsing.

---

## 0. Envelope files (every drive, every bundle)

Each drive root carries the attestation envelope that MUST be verified first:

| file | content | notes |
|---|---|---|
| `drive_id.txt` | fixed physical drive identifier, e.g. `USB-OUTBOUND-0001` | provisioned once, never reused across roles |
| `direction.txt` | `outbound` or `inbound` | matches the drive's locked role |
| `session.id` | monotonically increasing `u64` (decimal) | anti-replay; must be strictly greater than the last seen session |

Order of checks on ANY reader:
1. `drive_id.txt` present and equals the expected drive id.
2. `direction.txt` matches the reader's role (INGEST VM expects `inbound`,
   EXPORT VM writes `outbound`, Update Server reads `outbound`).
3. `session.id` strictly greater than the highest previously consumed session
   for this drive (persisted locally on the reader).
4. ONLY THEN parse/signature-verify the payload.
Mismatch on 1–3 = reject and alert (loud), never a silent no-op.

---

## 1. Outbound bundle (DevNet → Update Server), OUTBOUND drive

Directory layout on the drive (OUTBOUND partition/root):

```
drive_id.txt
direction.txt            # "outbound"
session.id
inventory.json
inventory.sig
```

### `inventory.json`
Signed by the DevNet **export key** (§ M2). One record per reporting machine
(DevNet server + each endpoint agent). Minimal, whitelisted schema — NO other
DevNet internals are exposed across the boundary.

```jsonc
{
  "schema_version": 1,
  "devnet_id": "devnet-1",
  "collected_at": "2026-08-08T19:30:00Z",
  "devices": [
    {
      "device_id": "endpoint-07",
      "hostname": "ws-07",
      "family": "windows",            // rhel | debian | windows | other
      "arch": "x86_64",
      "packages": [
        {
          "name": "kb5039227",
          "version": "20348.2527",
          "installed_sha256": "…"     // hash of installed binary/state
        }
      ]
    }
  ]
}
```

`inventory.json` must be serialized canonically (sorted keys, stable field
order) so the signature over the exact bytes is reproducible.

### `inventory.sig`
Ed25519 detached signature over the exact bytes of `inventory.json`, base64.
Signed by the DevNet export key.

---

## 2. Inbound bundle (Update Server → DevNet), INBOUND drive

Directory layout on the drive (INBOUND partition/root):

```
drive_id.txt
direction.txt            # "inbound"
session.id
catalog.json
manifest.json
manifest.sig
artifacts/               # the actual update packages (rpm/deb/msu/cab/bundle)
  <artifact-sha256>.rpm
  ...
```

### `catalog.json`
What is in THIS bundle: versions, metadata, and any revocation entries.
Signed (via `manifest.sig` over `manifest.json`, which references the catalog).

```jsonc
{
  "schema_version": 1,
  "session": 42,
  "releases": [
    {
      "update_id": "rocky-coreutils-9.1-7.el8",
      "package": "coreutils",
      "family": "rhel",
      "version": "9.1-7.el8",
      "ring": "prod",                 // dev | staging | prod
      "artifact": "artifacts/ab12….rpm",
      "sha256": "ab12…",
      "behavior_verdict": "behavior-tested",   // behavior-tested | hash-verified-only | manual-review-required
      "tested_at": "2026-08-08T18:00:00Z"
    }
  ],
  "revocations": [
    {
      "package": "coreutils",
      "version": "9.1-6.el8",
      "reason": "CVE-2026-… regression",
      "revoked_at": "2026-08-08T18:05:00Z"
    }
  ]
}
```

### `manifest.json`
Inventory of the whole bundle. Contains SHA-256 for every artifact file and
references the catalog. This is what gets signed.

```jsonc
{
  "schema_version": 1,
  "session": 42,
  "catalog_sha256": "…",
  "artifacts": [
    {
      "path": "artifacts/ab12….rpm",
      "sha256": "ab12…",
      "size": 123456
    }
  ]
}
```

### `manifest.sig`
Ed25519 detached signature over the exact bytes of `manifest.json`, base64.
Signed by the Update Server **release key** (§ M2).

### Artifacts
Every file under `artifacts/` MUST be hash-checked against `manifest.json`
before use. No exceptions for small files. `catalog.json` entries reference
artifact paths whose sha256 must match the manifest and the file on disk.

---

## 3. Signature & verification rules (both ends)

- `drive_id` + `direction` + `session.id` checked FIRST (see §0). Reject +
  alert on mismatch.
- Signature verified BEFORE parsing the payload. Fail closed.
- Every artifact hash-checked against the manifest. No exceptions.
- `session.id` strictly increasing / unique — replay of a previously-consumed
  bundle is rejected.
- DevNet core VM (M5) independently re-verifies signatures/hashes on anything
  handed over by the INGEST VM (M4) — it never trusts the sandbox verdict as
  sufficient on its own.

---

## 4. Canonical serialization (signing prerequisite)

Signatures cover exact bytes. To make them reproducible across processes:

- Objects serialize with keys in declared order (serde `struct` field order is
  stable; do not use `HashMap` for signed payloads — use `Vec` or `BTreeMap`).
- No pretty-printing for signed bytes; use compact JSON with a single
  canonical writer.
- Hash inputs are the raw file bytes, never a re-encoded representation.

---

## 5. Versioning

`schema_version` starts at 1. A schema change that alters any signed byte
layout MUST bump this. Readers MUST reject `schema_version` they do not know.
