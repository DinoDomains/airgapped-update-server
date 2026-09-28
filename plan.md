# OpenUpdater — Full Project Plan & Technical Explanation

Written for a helper AI / engineer who is new to this project. Read this
top-to-bottom before changing anything. Everything in this file describes
the CURRENT working state (beta + dashboard update, commit `ddc03b1`).

---

## 1. What this project is

**OpenUpdater** is a WSUS-style update-management system for air-gapped /
isolated Linux machines, written in Rust.

- A **server** is the ONLY machine allowed on the internet.
- **Agents** (VMs/machines on an isolated network with no default route)
  may ONLY talk to the server, over **mutual TLS (mTLS)**.
- The server fetches upstream package metadata (apt + dnf), shows operators
  which software is installed on every device vs. the latest version, and
  lets them **approve updates per device** (currently recorded; actual
  installation is the next milestone).
- Nothing happens without a human approving it.

### Current milestone status
- M0 (skeleton): COMPLETE. Enroll → register → inventory → poll over mTLS.
- Dashboard (partially pulled forward): COMPLETE. Web UI on :8080 lists
  devices, per-device installed vs latest versions, update approvals.
- M1 (real package mirroring + ring channels + agent install): NOT STARTED.
- Later milestones (source policy, bundles, sandbox test host, kernel
  handling, Windows agent, Postgres): NOT STARTED.

---

## 2. Architecture

```
                INTERNET
                   |
            (only machine online)
        +---------------------+
        |   srv  (Rocky 8.10)  |
        |   172.16.5.20        |
        |                      |
        |  airgap-server       |
        |   - internal CA      |         HOST-ONLY NETWORK 172.16.5.0/24
        |   - mTLS API :8443   |<----------------------------+
        |   - dashboard :8080  |                             |
        +---------------------+                             |
            |                                               |
            +------------------+------------------+         |
                               |                  |         |
                    +----------------------+  +----------------------+
                    | agent-rocky         |  | agent-ubu            |
                    | 172.16.5.21         |  | 172.16.5.22          |
                    | Rocky 8.10 yum/dnf  |  | Ubuntu 24.04 apt/dpkg |
                    +----------------------+  +----------------------+
```

Key invariants:
- Agents have **no default route** → cannot reach the internet.
- Agents trust ONLY the server cert; server accepts ONLY agents presenting a
  cert it issued (CN == agent_id enforced per-route).
- All software versions come to agents from the server (not yet wired).

---

## 3. Repository layout

```
openupdater/
├── Cargo.toml              # workspace: proto, server, agent (+shared deps)
├── Cargo.lock
├── MANUAL.txt              # run/test instructions (user-facing)
├── lab/                    # VMware VMs (NOT in git)
│   ├── srv/srv.vmx
│   ├── agent-rocky/agent-rocky.vmx
│   └── agent-ubu/agent-ubu.vmx
└── crates/
    ├── proto/   airgap-proto  # shared wire types (the API contract)
    ├── server/  airgap-server # CA, mTLS API, JSON store, dashboard, catalog
    └── agent/   airgap-agent  # inventory, enrollment, registration, poll
```

Git repo: `https://github.com/DinoDomains/openupdater` (public).
History:
- `0ffffe0` beta 0.1.0 (M0 skeleton) — DO NOT delete, rollback point.
- `ddc03b1` update: dashboard + catalog + approvals (current HEAD).

---

## 4. The proto crate (crates/proto/src/lib.rs)

Pure data types shared by server and agent, serde Serialize/Deserialize,
`API_VERSION = 1`. Types: `DistroFamily` (Rhel/Debian/Windows/Other),
`OsInventory` (hostname, os fields, family, arch, kernel, bootloader,
packages, repos), `Package`, `Enroll*`, `Register*`, `Inventory*`,
`Poll*`/`UpdateItem`, `Report*`/`ReportStatus`.

---

## 5. The server crate (crates/server)

Built as a **lib + bin** (`lib.rs` + `main.rs`) so the future admin CLI can
reuse the modules. Modules:

### ca.rs — internal Certificate Authority
- First run: generates self-signed root CA + server cert into
  `<store>/ca/` (ca.pem, ca-key.pem 0600, server.pem, server-key.pem,
  serial). 
- Later runs: **rebuilds the signing issuer from the persisted key** so
  restarting does not invalidate existing agent certs.
- `issue_client(agent_id)`: client cert CN=agent_id, EKU ClientAuth, signed
  by our CA, saved under `<store>/certs/`.
- `tls_server_config()`: rustls config — server cert + WebPkiClientVerifier
  requiring client certs from our CA, but `allow_unauthenticated` so /enroll
  works before a cert exists. Real auth is enforced per-route.

### tls.rs — custom mTLS accept loop
- `TcpListener` accept → `TlsAcceptor` handshake → extract peer cert CN via
  x509-parser → build `ClientIdentity { cn, authenticated, peer }` →
  inject into request extensions → hand to the axum router (hyper http1
  `serve_connection`). The dashboard gets device IPs from `identity.peer`.

### store.rs — JSON state
- Files in `<store>/`: agents.json, reports.json, catalog.json (legacy,
  unused for now), tokens.json, updates.json.
- `AgentRecord { agent_id, hostname, inventory, last_seen, status, ip }`.
- `UpdateRequest { id, agent_id, package, from_version, to_version, ring,
  ts, status }` — "approved-pending" approvals.
- Seed token from `AIRGAP_ENROLL_TOKEN` (default `airgap-bootstrap`), stored
  as a `sha256:` digest; the raw value is never written to disk.

### api.rs — mTLS endpoints (:8443)
- `POST /enroll` (token) → issues cert, returns cert+key+CA.
- `POST /register`, `POST /inventory` (require CN == agent_id).
- `POST /updates` → returns `catalog.updates` (currently empty).
- `POST /report`, `GET /health`.

### catalog.rs — upstream "latest versions"
- Fetches and parses upstream repository METADATA (no packages yet):
  - **apt**: `archive.ubuntu.com` (noble, noble-updates) and
    `security.ubuntu.com` (noble-security) × components main/universe ×
    amd64 → `dists/<suite>/<comp>/binary-amd64/Packages.gz` (flate2 gzip +
    paragraph parse).
  - **dnf**: `mirror.rackspace.com` Rocky 8 BaseOS + AppStream →
    `repodata/repomd.xml` → find `primary.xml.gz` → parse with quick-xml
    (name/ver/rel/arch).
- Merges into `catalog.json` keyed by **`family/name`** (e.g.
  `debian/bash-completion` vs `rhel/bash-completion`) so the two distro
  families don't collide. `version_gt()` is epoch-aware, best-effort.
- `build_client()` pins every upstream host to **IPv4** via
  `ClientBuilder::resolve()` — dl.rockylinux.org advertises AAAA records
  and the server has no IPv6 route, so reqwest would stall without this.
- `sync()` guarded by a Mutex so refresh can't run twice concurrently.

### http.rs — dashboard + JSON API (:8080, plain HTTP)
- `GET /` → single-file HTML dashboard (embedded const string). No build
  step, no external assets. Dark theme, vanilla JS.
- `GET /api/devices` → device list (id, hostname, OS, family, arch, kernel,
  bootloader, ip, last_seen, status, package count).
- `GET /api/devices/:id/packages` → installed vs latest per package,
  `update_available` computed by comparing strings within the SAME family.
  **IMPORTANT**: axum 0.7 in this tree resolved to matchit 0.7.3 which
  uses `:id` path syntax, NOT `{id}`. Do not "fix" it to `{id}`.
- `POST /api/refresh` → runs catalog sync (blocks up to ~90s).
- `POST /api/update` → body `{agent_id, package}`; validates package is
  installed and a newer upstream version exists; writes an UpdateRequest
  with ring="dev", status="approved-pending".
- `GET /api/updates` → pending approvals.
- Dashboard UI flow: page loads devices → click a device → fetches
  packages table → "Approve & update" uses `confirm()` then POSTs.

### lib.rs / main.rs
- `run()` builds both routers, starts both listeners concurrently via
  `tokio::try_join!`. Env: `AIRGAP_LISTEN` (8443), `AIRGAP_HTTP_LISTEN`
  (8080), `AIRGAP_STORE_DIR` (default `data`), `AIRGAP_ENROLL_TOKEN`.

### Server dependencies (crates/server/Cargo.toml)
axum 0.7 (json, macros, http2), hyper 1, hyper-util, tower, rustls 0.23 +
tokio-rustls 0.26 (**provider pinned to ring**), rcgen 0.13 (x509-parser),
rustls-pemfile, x509-parser, reqwest 0.12 (rustls-tls), serde/serde_json,
thiserror, tracing, flate2, sha2+hex, tokio-util, quick-xml 0.36.

---

## 6. The agent crate (crates/agent)

Static musl binary, runs on each isolated machine, state in
`/var/lib/airgap-agent`.

### inventory.rs
- OS from `/etc/os-release`; family string-detect; `arch()` reads
  `/proc/sys/kernel/arch` with `uname -m` fallback (Rocky lacks the file);
  bootloader via grub2/systemd-boot path checks; packages via
  `rpm -qa --qf ...` or `dpkg-query -W ...`; repos via `dnf repolist` /
  `apt-cache policy`.

### client.rs
- `load_or_enroll(server, state_dir)`:
  1. read `ca.pem` (provisioned out-of-band), 
  2. reuse `client.pem`/`client-key.pem` if present,
  3. else POST /enroll with `AIRGAP_ENROLL_TOKEN`, save cert/key (0600) +
     agent-id,
  4. build reqwest client with CA pinned + client identity (this makes it
     mutual TLS).
- Methods: register, inventory, poll, report (report unused for now).

### main.rs
- env `AIRGAP_SERVER` (default https://172.16.5.20:8443),
  `AIRGAP_STATE_DIR` (default /var/lib/airgap-agent). Run = collect
  inventory → load_or_enroll → register → inventory → poll → log.

---

## 7. Lab environment & deployment

VMware Workstation on host "Raptor". VMs in `lab/` (paths referenced with
the current folder name **openupdater** — they were renamed twice; check
`vmrun list` output for the true paths).

| VM | OS | IP (host-only) | Login |
|---|---|---|---|
| srv | Rocky 8.10 | 172.16.5.20 | ssh root@172.16.5.20 (key ~/.ssh/airgap_lab); console user admin/1234 |
| agent-rocky | Rocky 8.10 | 172.16.5.21 | ssh root@172.16.5.21 (key) |
| agent-ubu | Ubuntu 24.04 | 172.16.5.22 | ssh ubuntu@172.16.5.22 (key); console ubuntu/ubu-cloud |

Networks: vmnet8 NAT (172.16.237.0/24, only srv has a NIC there,
.133) and vmnet1 host-only (172.16.5.0/24). Agents have NO default route.

Server run on srv:
```
AIRGAP_STORE_DIR=/var/lib/airgap-server \
AIRGAP_LISTEN=0.0.0.0:8443 \
AIRGAP_HTTP_LISTEN=0.0.0.0:8080 \
nohup setsid /usr/local/bin/airgap-server >> /var/lib/airgap-server/server.log 2>&1 &
```
- firewalld: 8443/tcp + 8080/tcp allowed, plus a rich rule for 172.16.5.0/24.
- SELinux Permissive (lab only).
- Agent run (one-shot):
```
AIRGAP_STATE_DIR=/var/lib/airgap-agent AIRGAP_SERVER=https://172.16.5.20:8443 \
/usr/local/bin/airgap-agent
```

Build (on host, static musl):
```
cargo build --release --target x86_64-unknown-linux-musl
```
Deploy: `scp target/x86_64-unknown-linux-musl/release/airgap-server
root@172.16.5.20:/usr/local/bin/` (kill old process first — running
processes hold the binary), same for agent to the two agent VMs.

---

## 8. How it works end-to-end (current state)

1. Server boots → creates CA + server cert.
2. Operator copies `ca.pem` to each agent's state dir (trust bootstrap).
3. Agent runs once with token → POST /enroll → gets client cert/key.
4. Agent POSTs /register + /inventory → server stores device record.
5. Operator clicks "Refresh package catalog" in the dashboard → server
   downloads Ubuntu + Rocky metadata → catalog.json (family/name → latest).
6. Dashboard shows each device's installed vs latest, flags updates.
7. Operator clicks "Approve & update" → confirm → UpdateRequest saved
   (ring dev, approved-pending). **No install happens yet.**

---

## 9. Known quirks, bugs, constraints

- **Never run the server without AIRGAP_STORE_DIR** — it creates a fresh CA
  in ./data and invalidates every agent cert (BadSignature).
- rustls must stay pinned to `ring` everywhere; mixing aws-lc-rs causes
  "Could not automatically determine the process-level CryptoProvider".
- axum route params here are `:id` (matchit 0.7.3), not `{id}`.
- dl.rockylinux.org stalls without IPv4 resolution pinning (that is why
  `build_client()` exists; also why dnf repos point at rackspace now).
- `version_gt` is best-effort; distro version strings (epochs, ~, build
  numbers) can misorder a few packages. Example known false-positive:
  `gcc-14-base` shows an older "14-20240412-0ubuntu1" as newer than
  "14.2.0-4ubuntu2...".
- Version comparison compares strings only within the same distro family;
  cross-family comparison was fixed by the family/name catalog key.
- Catalog JSON holds ~81k entries; syncing takes ~60-90s.
- `pkill -f` can kill your own shell (pattern matches the command string);
  use `pkill -x`.
- No python3 on srv; inspect JSON with grep/sed/awk.
- The "pending_updates" (Catalog.updates) used by `/updates` is a legacy
  empty structure; real approvals live in updates.json.

---

## 10. Roadmap / next milestones

- **M1 (next)**: real package mirroring + ring channels + agent install.
  - Server: sync actual packages (dnf reposync; apt pool download on
    approval), serve repos at :8080 under /mirror and /channels/<ring>/,
    regenerate metadata (createrepo_c for dnf; generate Packages/Release
    for apt), connect /updates to real approvals, extend agent to apply
    approved updates (dnf update / apt upgrade) and POST /report.
  - Admin CLI (ctl crate planned) — currently the server is lib+bin so a
    ctl binary can reuse catalog/store modules.
- **M2**: source policy engine (allowlist/blacklist, default-deny).
- **M3**: update bundles + git-managed metadata.
- **M4**: VM sandbox test host (boot/health/smoke gate before release).
- **M5**: kernel + bootloader updates (alternate boot entry).
- **M6**: full dashboard (approval UI across rings, history).
- **M7**: Windows agent. Postgres later.

---

## 11. Open design questions (for the next AI to help with)

1. Agent install flow: how should the agent discover approved updates and
   pull them? (Poll /updates → get ring channel package list → dnf/apt
   against the server-hosted repo → report result.)
2. Repo trust: apt/dnf channels generated on the server need signatures.
   Options: sign with a dedicated repo key, or trusted=yes for the lab.
   What is the least-complex path that still verifies integrity?
3. Ring model: per-package approval per ring (dev→staging→prod) vs
   whole-repo snapshots.
4. Rolling back: agents should keep the last-known-good package set
   (dnf history / apt snapshots) — how to expose that in the dashboard.
5. Should the dashboard also serve the mirror (so one port) or stay split
   :8443 (mTLS API) / :8080 (HTTP dashboard + repos)?
