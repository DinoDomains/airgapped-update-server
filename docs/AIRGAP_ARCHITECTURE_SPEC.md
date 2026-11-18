# OpenUpdater — Secure Air-Gapped Update Platform Specification

## 1. Overview & Architecture
OpenUpdater is an air-gapped update and patch distribution platform that delivers native operating system packages (RPM/DNF and DEB/APT) to isolated networks without direct internet egress.

```
+-----------------------------------------------------------------------------+
|                               ZONE A: INTERNET PC                           |
|  - Ingests upstream packages (Rocky Linux & Ubuntu repositories)            |
|  - Restricts catalog view to strictly requested USB inventory               |
|  - Sandboxed package download & signature verification                     |
|  - "Encrypt Inbound Bundle" & "Dispatch to Sandbox USB"                     |
+-----------------------------------------------------------------------------+
                                      │
                     PHYSICAL USB MEDIA CONDUIT (TWO-DRIVE)
                      [Directional Attestation & Autolock]
                                      │
+-----------------------------------------------------------------------------+
|                               ZONE B: AIR-GAPPED NETWORK                    |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  |                 AIR-GAP CORE SERVER (172.16.5.20)                     |  |
|  |  - Web Dashboard on Port 8080 (Argon2id Auth + Read-Only Terminal)   |  |
|  |  - mTLS Endpoint on Port 8443 (Internal CA & Agent Certs)             |  |
|  |  - Ingests Inbound USB via Bubblewrap Sandbox (`bwrap`)               |  |
|  |  - Rolling Token Autolock ("Card Autolock" against Replay)            |  |
|  +-----------------------------------------------------------------------+  |
|                       ▲                             ▲                       |
|         mTLS Heartbeat│               mTLS Heartbeat│                       |
|                       ▼                             ▼                       |
|     +--------------------+              +--------------------+              |
|     |  agent-rocky       |              |  agent-ubu         |              |
|     |  (Rocky 8.10)      |              |  (Ubuntu 24.04)    |              |
|     |  - Disk storage    |              |  - Disk storage    |              |
|     |  - IPs & mac       |              |  - IPs & mac       |              |
|     |  - Last OS update  |              |  - Last OS update  |              |
|     |  - Package list    |              |  - Package list    |              |
|     +--------------------+              +--------------------+              |
+-----------------------------------------------------------------------------+
```

---

## 2. Implemented Defense-in-Depth Security

### A. Sandbox & Mount Security (`crates/sandbox`)
- **Bubblewrap (`bwrap`) Isolation:**
  - `unshare_all: true`: Ephemeral user, mount, IPC, PID, and network namespaces.
  - `--unshare-net`: The sandbox container has zero access to network sockets.
  - `no_new_privs: true`: Process cannot gain elevated privileges or execute setuid binaries.
  - `cap_drop = ["all"]`: Strips all Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, etc.).
- **Mount Flags:**
  - Physical media mounted with `noexec, nosuid, nodev, ro` on ingest to guarantee no binary can be executed from the media.
- **Host USB Hardening (USBGuard):**
  - Host configuration rejects all USB classes except Mass Storage Class (`08h`), preventing BadUSB / Rubber Ducky HID injection attacks.

### B. Rolling Token Ratchet ("Card Autolock") (`crates/contracts`)
- Every USB transfer contains a cryptographically random 256-bit token (`cycle_token.txt`) in addition to monotonic `session.id`.
- **Burn-on-Ingest:** As soon as a bundle is verified, the token is recorded in `consumed_tokens.json`.
- **Replay Protection:** If the same USB drive is plugged back in or an old bundle is replayed, verification fails with:
  > `CYCLE REPLAY DETECTED: rolling token ... has already been consumed (card autolock active)`

### C. Agent Telemetry (`crates/proto` & `crates/agent`)
Endpoints collect and report:
- **Device Identifiers:** Hostname, Agent ID, Architecture, Distro Family.
- **Network Interfaces:** Name, MAC address, and non-loopback IP addresses.
- **Disk Storage:** Mount points, filesystems, total bytes, available bytes, used bytes, and percentage gauges.
- **Update History:** Timestamp of last OS update modification derived from `/var/lib/dpkg/status` or `/var/lib/rpm/rpmdb.sqlite`.
- **Full Inventory:** Installed package names and version numbers.

### D. Web Dashboard & Read-Only Live Terminal (`crates/server`)
- **Strong Authentication:** Argon2id password hashing + SHA-256 session digests.
- **Endpoint Inspection Grid:** Displays device cards with online status, IP badges, storage usage bars, last update dates, and searchable package lists.
- **Non-Interactive Live Terminal:**
  - Located at the bottom of the dashboard.
  - Non-interactive, read-only stream preventing command injection vulnerabilities.
  - Tails live background system events: agent polls, inventory scans, sandbox isolation checks, and autolock burns.
