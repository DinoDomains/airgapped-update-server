# Air-Gapped Update Platform (WSUS-like)

Secure update distribution for a fully air-gapped DevOps network.
Delivers OS packages, container images, and app artifacts to <100
nodes without any internet path out of the internal network.

## Topology

    Zone A (internet ingest)  ->  CONDUIT (one-way)  ->  Zone B (air-gapped)
    - fetch upstream            - USB sneakernet       - validate + approve
    - build transfer bundles    - data diode           - internal mirrors/registry
    - sign bundles                                    - rings + audit + RBAC

Invariant: Zone B has no route to Zone A or the internet. The
transfer bundle is the only interface between zones, so the conduit
implementation is interchangeable.

## Layout

    docs/                 Architecture, bundle schema, threat model
    zone-a/ingest/        Bundle builder (Zone A, internet side)
    conduit/              One-way transfer (usb/ and data-diode/ backends)
    zone-b/core-server/   Validator + approval service (WSUS analog)
    zone-b/repositories/  Internal mirrors: aptly, zot, MinIO
    zone-b/db/            Metadata/status DB (Postgres)
    agent/                Client-side update agent (systemd unit)
    keys/                 Key management notes (no secrets committed)

## Transfer bundle (the contract between zones)

    bundle-<ts>/
      catalog.json      metadata: packages, images, versions, CVEs, deps
      artifacts/        deb/ | dnf/ | apk/ | oci/ | app/
      manifest.json     SHA-256 of every file (content-addressed)
      manifest.sig      detached signature over manifest

## Stack

    aptly (apt mirror) + zot (OCI registry) + MinIO (generic artifacts)
    + Postgres (metadata) + small Go/shell agent + GPG signing

## Next steps

1. Spec the bundle schema (docs/bundle-schema.md)
2. PoC: Zone A builder -> USB -> verify/ingest on a VM
3. Agent + rings (dev -> staging -> prod)

See RESUME.txt for the originating OpenCode session.
