# Key Management — Rotation & Compromise Response (M2)

Companion to `crates/keys` (software-backed implementation) and PLAN.md §5.5.
This file documents the operational procedure. Key material never lives in
git; `keys/` in the repo holds only these notes and public keys.

## Keys in play

| key | role | signs | held by | used by |
|---|---|---|---|---|
| DevNet export key | `export` | outbound `inventory.json` | DevNet core VM | DevNet EXPORT flow |
| Update Server release key | `release` | inbound `manifest.json` | Update Server | Update Server release flow |
| per-drive keys | drive attestation | drive envelope | both ends | drive lifecycle |

Hard rule (both ends): signing keys are only ever used by the core VM /
Update Server release process. The EXPORT and INGEST sandbox VMs never see
them. See PLAN.md §5.5.

## Storage

- Target: HSM / TPM / Secure-Enclave-class storage on the Update Server and
  the DevNet core VM.
- Fallback (implemented now): software-backed files under the key manager
  dir, mode 0600, never committed to git. Compensating controls:
  - private key files are 0600 and owned by the service account;
  - the key dir is on the encrypted boot volume only;
  - backup of the key dir is itself encrypted and offline;
  - documented migration to HSM is a planned hardening step.

### Server key directory (`AIRGAP_KEY_DIR`)

The Update Server keeps its private key material **outside** the store
directory. The store is the web-facing path; anything that can walk the store
tree must not be able to walk into a signing key.

Resolution order:

1. `$AIRGAP_KEY_DIR`, if set;
2. otherwise a **sibling** of the store dir — `<store>-keys`. A sibling, not
   a child, so a traversal rooted at the store cannot reach it.

```sh
AIRGAP_STORE_DIR=/var/lib/airgap-server/data
# -> keys land in /var/lib/airgap-server/data-keys
```

What lives where:

| path | mode | contents |
|---|---|---|
| `<key-dir>/ca-key.pem` | 0600 | CA private key |
| `<key-dir>/server-key.pem` | 0600 | mTLS server private key |
| `<key-dir>/keys/*-signing-key` | 0600 | DevNet / release signing private keys |
| `<key-dir>/certs/*-key.pem` | 0600 | per-agent mTLS private keys |
| `<key-dir>/ca.pem`, `server.pem` | 0644 | public certificates |
| `<store>/ca/ca.pem`, `server.pem` | 0644 | public mirror, for agent provisioning |
| `<store>/keys/*-verifying-key.pub` | 0644 | public signing keys |

Public material is mirrored into the store so the dashboard and provisioning
flow can read it without access to the key directory. It is not secret.

Every private key the server writes — CA, server, signing, and per-agent mTLS
— lives under the key directory. On first startup after upgrading, the server
relocates any that are still under the store:

- `<store>/ca/{ca,server}-key.pem` → `<key-dir>/`
- `<store>/keys/*-signing-key` → `<key-dir>/keys/`
- `<store>/certs/*-key.pem` → `<key-dir>/certs/`

If the destination already holds *different* key material, neither copy is
touched and the server logs a warning — resolve that by hand rather than
letting it be overwritten.

`data/` is gitignored; confirm with `git ls-files data/` (expect no output)
before you ever place a key there.

## Provisioning (first use)

1. On DevNet core VM: `airgap-keys provision export` -> writes
   `export-signing-key`, `export-verifying-key.pub`, `export-key-meta.json`.
2. On Update Server: `airgap-keys provision release` -> `release-*` files.
3. Distribute the PUBLIC keys across the air gap on the next USB trips:
   - Update Server imports DevNet's `export` public key
     (`airgap-keys import export <b64>`).
   - DevNet core VM imports Update Server's `release` public key.
4. Nothing is trusted until BOTH ends hold the other's public key and can
   verify a first real (or test) bundle.

## Rotation

Cadence: annual, or immediately on personnel change / suspected exposure.
Procedure (accounts for the physical round-trip):

1. Generate the new keypair on the owning side
   (`airgap-keys provision <role>` with `--overwrite` on the NEW key name).
   Keep the old public key trusted.
2. Carry the new PUBLIC key to the other end on a dedicated USB trip
   (label it clearly, use a fresh `session.id`).
3. The other end imports it and starts accepting signatures from BOTH the
   old and the new key during a grace window.
4. After the grace window, the old public key is untrusted
   (`airgap-keys untrust <role> <old>`) and old-signed bundles are rejected.
5. Record the rotation in the immutable audit log on both ends.

Because bundles are re-verified by the core VM independent of the sandbox,
rotating the verifying key is safe even while old bundles are still in
flight during the grace window.

## Compromise response

Do NOT improvise this. Sequence:

1. **Isolate**: suspend the compromised end's release/export process. Stop
   producing new bundles. A compromised bundle already on a USB is suspect.
2. **Assess scope**: was the private key material actually exposed, or only
   a host? If the key was exposed, it is burned.
3. **Revoke**: burn the compromised key — stop trusting it on the verifying
   end immediately (not after a grace window).
4. **Reissue**: provision a fresh key (see Rotation) and distribute the new
   public key over a dedicated, physically supervised USB trip.
5. **Back-out in flight**: any bundle signed by the compromised key is
   treated as untrusted. If it already reached an endpoint, treat it via the
   same admin-gated path as a revocation (§5.4): flag + alert, admin decides
   per endpoint whether to revert.
6. **Post-mortem + audit**: record the timeline in the audit log; confirm
   which bundles were affected and their disposition.

## Tooling

A thin CLI (`airgap-keys`, from `crates/keys/src/main.rs` if built) exposes:
`provision <export|release>`, `sign <role> <file>`, `verify <role> <file>
<sig>`, `import <role> <pubkey-b64>`, `export-pub <role>`, `metadata <role>`,
`untrust <role> <pubkey-b64>` (future: HSM-backed storage).

For now the library API in `airgap_keys` is used by the processor/collector;
the CLI is added when M3/M5 consume it.
