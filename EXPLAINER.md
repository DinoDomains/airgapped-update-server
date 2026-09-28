# AIRGAP UPDATE PLATFORM — FULL EXPLAINER (for a novice builder)

This file explains, from zero, what we are building, every tool we use,
how the code is organized, and exactly what happens when you run it.
Read this top to bottom once, then keep it open as a reference.

---

## 1. WHAT ARE WE BUILDING?

Imagine the Windows Update model, but for a company's own Linux servers
that must stay **off the internet** for security:

- One central **server** is the only machine allowed online.
- The other machines (**agents**) are isolated on their own network and
  may ONLY talk to that server.
- The server downloads package updates from the internet, an operator
  **approves** them, and agents pull and install only approved updates.
- The server has to serve as a **mirror** (a local copy of the package
  repositories) because the agents can't reach any outside repository.

That is "air-gapped update distribution": updates travel in, are gated by
humans, and flow out through a verified channel. No agent ever touches the
internet, and nothing gets installed unless a human approved it.

Everything is written in **Rust**.

---

## 2. BIG PICTURE (ASCII DIAGRAM)

```
                INTERNET
                   |
            (only machine online)
        +---------------------+
        |   srv (Rocky 8.10)  |
        |   172.16.5.20       |
        |                     |
        |   airgap-server     |
        |   - CA authority    |            HOST-ONLY NETWORK 172.16.5.0/24
        |   - mTLS API :8443  |<-------------------------------+
        |   - repo :8080  (M1)|                                |
        +---------------------+                                |
            |                                                 |
            +------------------+------------------+           |
                               |                  |           |
                    +------------------+  +------------------+
                    | agent-rocky     |  | agent-ubu        |
                    | 172.16.5.21     |  | 172.16.5.22      |
                    | Rocky 8.10      |  | Ubuntu 24.04     |
                    | yum/dnf         |  | apt/dpkg         |
                    +------------------+  +------------------+
```

Rules that matter:
- Agents have **no default route** → they physically cannot reach the
  internet. Ping an outside IP from an agent and it fails.
- Agents trust ONLY the server's TLS certificate, and the server only
  accepts agents that present a certificate it issued (mutual TLS).
- All packages come from `http://172.16.5.20:8080/...` (server-hosted repo).

---

## 3. KEY CONCEPTS (plain-English)

### Certificates, CA, TLS, mTLS
- **TLS** = the encryption layer of HTTPS. It stops eavesdropping.
- **Certificate** = a digital ID card. It contains a name, who issued it,
  and a cryptographic key. "Signed by a CA" = a trustworthy authority
  vouches for the card.
- **CA (Certificate Authority)** = the trusted authority. Here *we* are the
  CA. We generate a self-signed root certificate (`ca.pem`) plus its secret
  key. Everything signed by this root is trusted by anyone who holds the
  root cert.
- **Server cert** = the server's ID card, signed by our CA, listing the
  server's names/IPs (SANs). Agents verify it against `ca.pem`.
- **Client cert** = an agent's ID card, signed by our CA, with the
  **CN (Common Name)** set to the agent's ID (e.g. `agent-agent-rocky`).
- **mTLS (mutual TLS)** = BOTH sides present certificates. The server
  proves itself to the agent AND the agent proves itself to the server.
  This is how an isolated network knows who it's talking to.

### Enrollment token
A one-time shared secret (`airgap-bootstrap` by default). An agent that has
no certificate yet uses this token once, on `/enroll`, to prove it's allowed
in. The server then issues it a client cert. After that, the token is not
needed — the cert is the identity.

### Ring (dev / staging / prod)
The approval pipeline. Updates go into `dev` first, then (after testing)
get approved into `staging`, then `prod`. Agents are assigned to a ring and
only ever see/install what is approved for their ring. (M1 work.)

### Mirror / repository / channel
- A **repository (repo)** is just a folder of packages + a metadata index.
  - yum/dnf repos have `repodata/repomd.xml` + `.rpm` files.
  - apt repos have `dists/.../Packages` + a `pool/` of `.deb` files.
- A **mirror** is a byte-for-byte copy of an upstream repo, stored locally.
- A **channel** is our *filtered* repo — only approved packages, one per
  ring. Agents point at `channels/<ring>/...`.

### Serialization / JSON
When the agent and server talk, they send text (JSON). JSON is how the data
is written on the wire and how the server stores its state files. Serde is
the Rust library that converts Rust data structures to/from JSON
automatically.

---

## 4. TECHNOLOGY STACK (what each piece is for)

| Piece | What it is | Why we use it |
|---|---|---|
| Rust (stable 1.97.1) | systems programming language | memory-safe, fast, single static binary |
| Cargo workspace | one project, several crates | shared build + deps across `proto/server/agent/ctl` |
| tokio | async runtime | concurrent network handling without threads per connection |
| axum 0.7 | web framework (HTTP layer) | routes like `/enroll`, request bodies, JSON |
| hyper 1 + hyper-util + tower | lower-level HTTP + service plumbing | needed because we terminate TLS ourselves |
| rustls 0.23 + tokio-rustls | TLS in pure Rust | mTLS without OpenSSL; provider pinned to `ring` |
| rcgen | generate certificates/CA | we are our own CA, issue server + agent certs |
| x509-parser | read certificate fields | extract the CN from an agent's cert |
| reqwest | HTTP client (agent side) | agent talks to server, syncs upstream later |
| serde/serde_json | data (de)serialization | JSON wire + storage format |
| flate2 | gzip | read/write `Packages.gz` for apt (M1) |
| sha2 + hex | hashing | verify downloaded files aren't corrupted (M1) |
| thiserror | error types | clean, typed errors |
| tracing | logging | see what the server/agent are doing |
| rcgen's `x509-parser` feature | parse certs for CN | identity enforcement per connection |

---

## 5. THE CODE MAP

```
airgap-update-platform/
├── Cargo.toml               # workspace: lists crates + shared dependency versions
├── crates/
│   ├── proto/               # airgap-proto: types both sides share (the "contract")
│   │   └── src/lib.rs
│   ├── server/              # airgap-server: the central authority + API
│   │   └── src/{main,ca,store,tls,api}.rs
│   ├── agent/               # airgap-agent: runs on each isolated machine
│   │   └── src/{main,inventory,client}.rs
│   └── ctl/                 # airgap-ctl: admin CLI (sync/approve/publish) [M1]
├── lab/LAB.md               # how the VMs are built/run
├── PLAN.txt                 # the design doc (authority on decisions)
├── STACK.txt                # stack summary for the client
└── PROGRESS.txt             # what has been done so far
```

The rule: **proto** defines the message shapes. **server** and **agent**
both depend on **proto**, so they always agree on what a "register" request
looks like. This is the API contract.

---

## 6. THE PROTO CRATE (`crates/proto/src/lib.rs`)

Just data types + `API_VERSION = 1`. Every type derives
`Serialize, Deserialize` (serde) so it can travel as JSON:

- `DistroFamily` — Rhel / Debian / Windows / Other (default Other).
- `OsInventory` — hostname, OS name/version, family, arch, kernel,
  bootloader, installed `packages` list, `repos` list.
- `Package` — name, version, arch, source.
- `EnrollRequest/Response` — token + hostname in; agent_id + cert/key + CA out.
- `RegisterRequest/Response` — agent_id + full inventory; "accepted" out.
- `InventoryRequest/Response` — refresh inventory.
- `PollRequest/PollResponse` — ask "what updates do I have?"
- `UpdateItem` — id, kind, title, version, ring.
- `ReportRequest/Response` + `ReportStatus` — report install outcome.

---

## 7. THE SERVER (`crates/server/src/`)

Server runs on `srv`, listens on `0.0.0.0:8443` for mTLS API traffic.

### `ca.rs` — the Certificate Authority
- On first run: generates a self-signed root CA + server cert, saves them
  to `<store>/ca/` (ca.pem, ca-key.pem, server.pem, server-key.pem) and a
  `serial` counter file. The CA key is chmod 0600.
- On later runs: **rebuilds the signing issuer from the saved key** so it
  can keep issuing certs signed by the same CA (otherwise every restart
  would create a new CA and all agents would be rejected).
- `issue_client(agent_id)` — issues an agent cert with CN = agent_id,
  EKU = ClientAuth, signed by our CA. Saves a copy under `<store>/certs/`.
- `tls_server_config()` — builds the rustls config that:
  - presents the server cert,
  - asks every client for a cert and verifies it against our CA root,
  - but *allows unauthenticated* connections (the `/enroll` call happens
    before an agent has a cert). Enforcement happens per-route in `api.rs`.

### `tls.rs` — terminate mTLS, hand requests to axum
Custom accept loop:
1. `TcpListener` accepts a raw TCP connection.
2. `TlsAcceptor` performs the TLS handshake (server cert + client verify).
3. It reads the client's certificate, extracts the **CN** with
   `x509-parser`, and creates a `ClientIdentity { cn, authenticated }`.
4. That identity is injected into the HTTP request extensions before the
   request is passed to the axum router. So every handler can see who is
   talking (the `identity` argument in handlers like `register`).

### `store.rs` — the state (JSON files on disk)
`Store` keeps everything in memory behind a read-write lock and persists
as pretty-printed JSON in `<store>/`:
- `agents.json` — map of agent_id → AgentRecord (hostname, inventory,
  last_seen, status).
- `reports.json` — list of install reports.
- `catalog.json` — the current update list.
- `tokens.json` — enrollment tokens, stored as `sha256:<hex>` digests. Raw
  tokens are never persisted. Seeded from `AIRGAP_ENROLL_TOKEN` (default
  `airgap-bootstrap`) on first boot; existing plaintext entries are re-hashed
  automatically on load. See `docs/SECURITY.md`.

Key methods: `check_token`, `register_agent`, `update_inventory`,
`record_report`, `pending_updates`.

### `api.rs` — the HTTP routes
Handlers (each checks identity where required):
- `POST /enroll` — verifies the token, issues a client cert, registers the
  agent, returns cert + key + CA. No client cert needed.
- `POST /register` — agent sends inventory with its first report.
  `require_auth` checks it has a valid cert, and **CN must equal
  agent_id** (403 otherwise). Prevents one agent impersonating another.
- `POST /inventory` — refresh inventory, updates last_seen/status.
- `POST /updates` — poll: returns `pending_updates()`.
- `POST /report` — record an install report.
- `GET /health` — plain "ok".

### `main.rs` — wiring it together
Reads `AIRGAP_LISTEN` (default `0.0.0.0:8443`) and `AIRGAP_STORE_DIR`
(default `data`), loads CA + Store, builds the axum router, builds the
TLS config, and hands it to `tls::serve`.

---

## 8. THE AGENT (`crates/agent/src/`)

Runs on each isolated machine. Static binary at `/usr/local/bin/airgap-agent`.

### `inventory.rs` — "what is this machine made of?"
- OS info: reads `/etc/os-release`.
- Family detection: string-matches the OS name (rocky/centos → Rhel,
  ubuntu/debian → Debian, ...).
- `arch()`: reads `/proc/sys/kernel/arch`; Rocky doesn't have that file, so
  it falls back to running `uname -m`.
- `bootloader()`: checks for grub2/systemd-boot paths (M5 will use this).
- `collect_packages()`: runs `rpm -qa --qf ...` on Rhel or
  `dpkg-query -W ...` on Debian and parses name/version/arch.
- `collect_repos()`: runs `dnf repolist` / `apt-cache policy`.

### `client.rs` — talking to the server, securely
`load_or_enroll(server, state_dir)`:
1. Reads `ca.pem` from the state dir (provisioned out-of-band).
2. If `client.pem` + `client-key.pem` already exist → reuse them.
3. Else → read `AIRGAP_ENROLL_TOKEN`, POST `/enroll`, save the returned
   cert/key (key chmod 0600) and `agent-id`.
4. Builds a reqwest client with the CA pinned AND the client identity.
   This is what makes the connection **mutual** TLS.
Then: `register()`, `inventory()`, `poll()` (and `report()`, not yet used).

### `main.rs` — the agent's "main"
1. Read `AIRGAP_SERVER` (default `https://172.16.5.20:8443`) and
   `AIRGAP_STATE_DIR` (default `/var/lib/airgap-agent`).
2. `inventory::collect()`.
3. `client::load_or_enroll(...)`.
4. Register, then send inventory, then poll for updates, log the count.

So every run = "say who I am, list my packages, ask what's new."

---

## 9. END-TO-END FLOW (the happy path, M0)

1. **Bootstrap CA**: first time the server starts, it creates the CA and
   server cert in `/var/lib/airgap-server/ca/`.
2. **Provision trust**: the operator copies `ca.pem` to each agent's state
   dir so agents trust the server and can reach `/enroll`.
3. **Enroll**: agent runs, posts its token to `/enroll`. Server validates
   token, issues `agent-agent-ubu.pem`, saves it, returns cert+key+CA.
   Agent saves them (key 0600) + `agent-id` file.
4. **Register**: agent posts `agent_id` + full inventory. Server checks the
   client cert CN matches `agent_id`, stores the record in `agents.json`.
5. **Inventory**: same again, refreshes last_seen + status "online".
6. **Poll**: agent asks `/updates`, gets an empty list today.
7. Verify from the server: `grep` in `/var/lib/airgap-server/agents.json`
   shows both agents with their inventories.

---

## 10. THE LAB ENVIRONMENT

Hosted in **VMware Workstation** on this laptop, with 3 VMs:

| VM | OS | IP (host-only) | Role |
|---|---|---|---|
| srv | Rocky Linux 8.10 | 172.16.5.20 | server |
| agent-rocky | Rocky Linux 8.10 | 172.16.5.21 | RHEL-family agent |
| agent-ubu | Ubuntu 24.04.4 LTS | 172.16.5.22 | Debian-family agent |

Networks:
- `vmnet8` = NAT (172.16.237.0/24) → only the server has a NIC here
  (172.16.237.133) so only it reaches the internet.
- `vmnet1` = host-only (172.16.5.0/24) → all three machines, agents have
  NO default route here.

Access from the laptop:
- `ssh -i ~/.ssh/airgap_lab root@172.16.5.20` (server)
- `ssh -i ~/.ssh/airgap_lab root@172.16.5.21` (agent-rocky)
- `ssh -i ~/.ssh/airgap_lab ubuntu@172.16.5.22` (agent-ubu, sudo NOPASSWD)

Deployed paths:
- Server binary: `/usr/local/bin/airgap-server`, started with
  `AIRGAP_STORE_DIR=/var/lib/airgap-server AIRGAP_LISTEN=0.0.0.0:8443`.
- Agent binaries: `/usr/local/bin/airgap-agent`, state in
  `/var/lib/airgap-agent/` (ca.pem, client.pem, client-key.pem, agent-id).
- Firewall (srv): port 8443/tcp allowed + a rich rule accepting the
  172.16.5.0/24 subnet. SELinux set to Permissive (revisit for hardening).

---

## 11. HOW TO BUILD AND TEST (locally, on the laptop)

```
# Build everything (static musl release):
cargo build --release --target x86_64-unknown-linux-musl

# Run the server locally:
AIRGAP_STORE_DIR=/tmp/airgap-test/server-data \
AIRGAP_LISTEN=127.0.0.1:8443 \
./target/x86_64-unknown-linux-musl/release/airgap-server

# On the agent VM (one-shot test):
AIRGAP_STATE_DIR=/var/lib/airgap-agent \
AIRGAP_SERVER=https://172.16.5.20:8443 \
/usr/local/bin/airgap-agent
```

Redeploy = `scp` the fresh static binary to `/usr/local/bin/` on each VM
(sudo on ubu), then re-run the agent.

---

## 12. WHAT M1 ADDS (mirrors + approval rings) — in progress

New server role: an HTTP repo server on port **8080** that serves:

1. **Mirror** (upstream copies under `<store>/mirror/`):
   - yum/dnf: `dnf reposync` pulls Rocky BaseOS/AppStream `.rpm`s +
     metadata. Uses IPv4 mirrors (`dl.rockylinux.org`) because
     `mirror.rockylinux.org` is IPv6-only and fails here.
   - apt: our own Rust sync engine fetches `dists/noble/Packages.gz`,
     parses it, and (later) downloads the `.deb`s we actually approve.
     No `debmirror` needed (Rocky has no such tool).
2. **Channels** (filtered repos under `<store>/channels/<ring>/`):
   - `createrepo_c` regenerates dnf `repodata` from approved rpms.
   - We generate apt `Packages`/`Release` for approved debs (flate2/sha2).
3. **ctl** (`crates/ctl`) — admin CLI sharing server code:
   `sync-dnf`, `sync-apt`, `catalog`, `approve --ring ...`, `channel`,
   `publish`.

Agents change:
- agent-rocky: dnf repo file points at
  `http://172.16.5.20:8080/channels/<ring>/dnf/...`.
- agent-ubu: `sources.list.d` entry with
  `deb http://172.16.5.20:8080/channels/<ring>/apt noble main`.
- After install, agents `dnf update` / `apt upgrade`, refresh inventory,
  and POST a `/report` with before/after versions.

This is the milestone that turns "skeleton" into "actually delivers
approved software to isolated machines."

---

## 13. GLOSSARY

- **CA** Certificate Authority — the thing that signs/trusts certs.
- **CN** Common Name — the human-readable name in a cert (used as agent id).
- **EKU** Extended Key Usage — restricts a cert (ServerAuth vs ClientAuth).
- **SAN** Subject Alternative Name — extra names/IPs a server cert is valid for.
- **mTLS** Mutual TLS — both sides authenticate with certs.
- **JSON** JavaScript Object Notation — plain-text data format.
- **Serde** Rust library for serialization (struct → JSON and back).
- **REPO/Reposync/createrepo_c** — package repo tools for the yum/dnf world.
- **pool/ + Packages** — apt's layout: actual `.deb`s in `pool/`, index in `Packages`.
- **Ring** — approval stage (dev → staging → prod).
- **Mirror** — local byte-copy of an upstream repo.
- **Channel** — our filtered, approved-only repo per ring.
- **os-release** — `/etc/os-release`: standard file describing the OS.
- **static musl build** — a binary with no system-library dependencies,
  runs on any Linux distro of the same CPU arch.

---

## 14. KNOWN QUIRKS / GOTCHAS (learned the hard way)

1. **Always set AIRGAP_STORE_DIR.** Without it the server creates a fresh
   CA in `./data`, so every existing agent's cert becomes invalid
   (`BadSignature`). Cleaned-up accidents: `/home/dino/data`.
2. **rustls provider panic.** rustls and tokio-rustls default to the
   `aws-lc-rs` crypto backend while reqwest pulls `ring` → "Could not
   automatically determine the process-level CryptoProvider". Fix: pin
   everything to `ring` in the workspace `Cargo.toml`.
3. **mirror.rockylinux.org is IPv6-only/unreliable** under NAT. Use IPv4
   mirrors (`dl.rockylinux.org`).
4. **Rocky lacks `/proc/sys/kernel/arch`** → `uname -m` fallback in
   `inventory.rs`.
5. **`pkill -f "pattern"` can kill your own shell** if the pattern appears
   in the command string. Use `pkill -x` for exact process names.
6. **SELinux** left Permissive for the lab; must be properly handled for a
   production hardening pass.
7. **SSH first-contact** on fresh VMs needs
   `-o StrictHostKeyChecking=accept-new` (keys regenerate on clone).
8. **No python3 on srv** — inspect JSON with grep/sed/awk (or the ctl tool).
