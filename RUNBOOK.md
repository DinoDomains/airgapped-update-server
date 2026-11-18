# OpenUpdater — Complete Step-by-Step Operator Runbook

This guide explains **what file to run, on which machine, and in what exact order**, covering the full operational lifecycle from initial server boot to USB transfer and patch installation.

---

## 1. Quick-Reference: What to Run Where & When

| Step | Machine / Role | IP / Location | Command / File to Run | Why / What it Does |
| :---: | :--- | :--- | :--- | :--- |
| **0** | **Build Host** | Local Workstation | `cargo build --release` | Compiles `airgap-server` and `airgap-agent` binaries. |
| **1** | **Air-Gap Server** | `172.16.5.20` (`srv`) | `./target/release/airgap-server` | Starts CA, mTLS listener (:8443), and Web Dashboard (:8080). |
| **2** | **Endpoint Agents** | `172.16.5.21` (Rocky)<br>`172.16.5.22` (Ubuntu) | `./target/release/airgap-agent` | Enrolls over mTLS, reports disk storage, IPs, and package inventory. |
| **3** | **Air-Gap Operator** | Admin Browser | Open `http://172.16.5.20:8080/devnet` | Inspects devices, storage gauges, and clicks **"Send to USB"**. |
| **4** | **USB Conduit** | Physical USB Drive | Transport: Air-Gap $\rightarrow$ Internet PC | Carries signed inventory + anti-tamper canary (`integrity.canary`). |
| **5** | **Internet Ingest PC** | Online Machine | Ingests outbound bundle & runs package sync | Fetches upstream `.deb`/`.rpm` packages & seals inbound bundle. |
| **6** | **USB Conduit** | Physical USB Drive | Transport: Internet PC $\rightarrow$ Air-Gap | Carries packages + burns rolling token (`cycle_token.txt`). |
| **7** | **Air-Gap Server** | `172.16.5.20` (`srv`) | Clicks **"Verify Inbound"** & **"Push Updates"** | Validates signatures, checks autolock, and distributes patches. |

---

## 2. Step-by-Step Execution Guide

### STEP 0: Compile the Binaries (On Build Host)
From the project root:
```bash
cd /home/dino/Documents/projects/openupdater

# Build optimized release binaries
cargo build --release

# Binaries produced:
#  - target/release/airgap-server   (Core server daemon)
#  - target/release/airgap-agent    (Client endpoint agent)
#  - target/release/airgap-keys     (Key provisioning tool)
```

---

### STEP 1: Start the Air-Gap Core Server (Run First)
* **Location:** Air-Gapped Core Server (`172.16.5.20` / `srv.vmx`)
* **Must be started before agents** so the enrollment CA and mTLS socket are listening.

```bash
# Connect to the server VM
ssh -i ~/.ssh/airgap_lab root@172.16.5.20

# Run the server daemon
AIRGAP_STORE_DIR=/var/lib/airgap-server \
AIRGAP_LISTEN=0.0.0.0:8443 \
AIRGAP_HTTP_LISTEN=0.0.0.0:8080 \
AIRGAP_ENROLL_TOKEN=airgap-bootstrap \
AIRGAP_ADMIN_PASSWORD=admin \
./airgap-server
```
* **Listening ports:**
  - `0.0.0.0:8443`: mTLS port for agent enrollment, inventory, and updates.
  - `0.0.0.0:8080`: Web Dashboard (`/devnet`).

---

### STEP 2: Start the Client Agents (Run Second)
* **Location:** Isolated Client VMs (`agent-rocky` & `agent-ubu`)
* The agents run on isolated subnets with no default route.

#### On Rocky Linux Agent (`172.16.5.21`):
```bash
ssh -i ~/.ssh/airgap_lab root@172.16.5.21

# Run the agent (points to Server's mTLS port 8443)
AIRGAP_SERVER=https://172.16.5.20:8443 \
AIRGAP_STATE_DIR=/var/lib/airgap-agent \
AIRGAP_ENROLL_TOKEN=airgap-bootstrap \
./airgap-agent
```

#### On Ubuntu Agent (`172.16.5.22`):
```bash
ssh -i ~/.ssh/airgap_lab ubuntu@172.16.5.22

# Run the agent
AIRGAP_SERVER=https://172.16.5.20:8443 \
AIRGAP_STATE_DIR=/var/lib/airgap-agent \
AIRGAP_ENROLL_TOKEN=airgap-bootstrap \
./airgap-agent
```
* **What happens automatically:**
  1. The agent contacts `https://172.16.5.20:8443/enroll` with the bootstrap token.
  2. The server CA issues a dedicated client certificate.
  3. The agent scans storage (`df`), IP interfaces (`ip addr`), and installed packages (`rpm`/`dpkg`).
  4. The agent reports this telemetry to the server and begins a background poll heartbeat.

---

### STEP 3: Monitor via the Air-Gap Web Dashboard
* **Location:** Open browser to **`http://172.16.5.20:8080/devnet`**
* **Sign in:** Username `admin` / Password `admin` (or configured password).
* **What you will see:**
  - **Endpoints Grid**: Shows `agent-rocky` and `agent-ubu` cards.
  - **Storage Usage Bars**: Live partition gauge (e.g., `83% used (84.4 GB free / 501.8 GB total)`).
  - **Network Badges**: Non-loopback IP addresses (`172.16.5.21`, `172.16.5.22`).
  - **Installed Packages**: Searchable list of all software versions.
  - **Read-Only Live Terminal** (Bottom of page): Streams background agent queries, heartbeat events, and USB actions.

---

### STEP 4: Export Inventory to USB (Outbound Transfer)
1. Plug the designated **Outbound USB drive** (labeled `USB-OUTBOUND-0001`) into the Air-Gap Server.
2. In the dashboard under **"USB Inventory Transfer"**, select the USB mount point (e.g. `/mnt/usb`).
3. Click **"📤 Compile & Send to USB"**.
4. **Security actions taken by the server:**
   - Writes `inventory.json` containing the requested software.
   - Advances monotonic `session.id`.
   - Generates a fresh 256-bit rolling token (`cycle_token.txt`).
   - Signs and writes the **`IntegrityCanary`** (`integrity.canary` + signature).

---

### STEP 5: Internet PC Processing (Inbound Sync)
1. Unplug the USB from the Air-Gap Server and plug it into the **Internet Ingest PC**.
2. Mount the USB in the bubblewrap sandbox (`crates/sandbox`).
3. The Internet Server reads `inventory.json` and restricts its upstream repository sync to **only** the packages needed by the air-gapped endpoints.
4. Packages are downloaded from official upstream mirrors, GPG-verified, and placed in `artifacts/`.
5. The Inbound catalog is sealed with the Release signing key.

---

### STEP 6: Ingest & Apply Updates on Air-Gap Core Server
1. Bring the USB back to the Air-Gap Server.
2. On the dashboard (`http://172.16.5.20:8080/devnet`), click **"Verify Inbound"**.
3. **Automatic Security Enforcement:**
   - **Anti-Tamper Canary Check**: If any unauthorized machine or rogue process wrote to the USB, `IntegrityCanary::verify` fails $\rightarrow$ **`zeroize_and_shred_envelope`** triggers $\rightarrow$ key envelope is shredded with random noise/zeros.
   - **Card Autolock Check**: `DriveAttestation::verify_rolling_token` checks that the rolling token has not been seen before.
   - **Burn Token**: The rolling token is written to `consumed_tokens.json` (permanently locking out replay attacks).
4. Click **"Push Updates"**: The server approves packages into the deployment ring, and agents download and install them on their next poll loop.

---

## 3. Summary of Systemd Service Deployment (Production)

For automated 24/7 background operation:

### Server Service (`/etc/systemd/system/airgap-server.service`):
```ini
[Unit]
Description=Air-Gap Core Update Server
After=network.target

[Service]
Type=simple
User=root
Environment=AIRGAP_STORE_DIR=/var/lib/airgap-server
Environment=AIRGAP_LISTEN=0.0.0.0:8443
Environment=AIRGAP_HTTP_LISTEN=0.0.0.0:8080
ExecStart=/usr/local/bin/airgap-server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Agent Service (`/etc/systemd/system/airgap-agent.service`):
```ini
[Unit]
Description=Air-Gap Endpoint Update Agent
After=network.target

[Service]
Type=simple
User=root
Environment=AIRGAP_SERVER=https://172.16.5.20:8443
Environment=AIRGAP_STATE_DIR=/var/lib/airgap-agent
Environment=AIRGAP_ENROLL_TOKEN=airgap-bootstrap
ExecStart=/usr/local/bin/airgap-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
