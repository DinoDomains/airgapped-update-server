use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::sync::RwLock;

use crate::store::{Credential, DiscoveryHost, Store};

/// Ports probed during a discovery sweep. Windows services (SMB, WinRM, RDP)
/// are enough to guess the family even though a Windows agent is not built yet.
pub const PROBE_PORTS: &[u16] = &[22, 445, 5985, 3389, 443, 80];

/// The server-facing agent binary that gets pushed to devices. Generated as a
/// shell script on the server (trusted content), so the SSH command line never
/// carries the enrollment token or the agent binary itself.
const START_SCRIPT: &str = r#"#!/bin/sh
set -e
if [ "$(id -u)" = "0" ]; then RUN="sh -c"; else RUN="sudo -n sh -c"; fi
$RUN 'install -m 0755 /tmp/airgap-agent /usr/local/bin/airgap-agent'
$RUN 'mkdir -p /var/lib/airgap-agent'
$RUN 'install -m 0644 /tmp/ca.pem /var/lib/airgap-agent/ca.pem'
# Restart the agent so the freshly pushed binary takes effect; a re-provision
# always means we want the current on-disk binary running.
$RUN 'pkill -x airgap-agent >/dev/null 2>&1 || true'
sleep 1
$RUN 'AIRGAP_STATE_DIR=/var/lib/airgap-agent AIRGAP_SERVER=__SERVER__ AIRGAP_ENROLL_TOKEN=__TOKEN__ nohup /usr/local/bin/airgap-agent >> /var/log/airgap-agent.log 2>&1 &'
echo 'agent started'
"#;

/// State of the most recent (or in-flight) discovery sweep, shared with the
/// dashboard so a scan runs in the background instead of blocking the request.
#[derive(Default)]
pub struct ProvisionState {
    pub scan: RwLock<Option<ScanJob>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanJob {
    pub network: String,
    pub started: String,
    pub running: bool,
    pub hosts: Vec<DiscoveryHost>,
    pub error: String,
}

pub struct ProvisionOutcome {
    pub ok: bool,
    pub agent_id: String,
    pub hostname: String,
    pub detail: String,
}

pub fn parse_cidr(cidr: &str) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let (ip, bits) = cidr
        .split_once('/')
        .ok_or_else(|| "expected CIDR like 172.16.5.0/24".to_string())?;
    let base: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| "invalid IPv4 address in CIDR".to_string())?;
    let bits: u8 = bits.parse().map_err(|_| "invalid prefix length".to_string())?;
    if bits > 32 {
        return Err("prefix length must be 0..=32".to_string());
    }
    let base_u32 = u32::from(base);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    let network = base_u32 & mask;
    let host_count: i64 = if bits >= 31 {
        (1u32 << (32 - bits)) as i64
    } else {
        ((1u32 << (32 - bits)) - 2) as i64
    };
    if host_count > 2048 {
        return Err(format!(
            "network is too large for a sweep ({} hosts); use a /21 or smaller range",
            host_count
        ));
    }
    let start: u32 = if bits >= 31 { 0 } else { 1 };
    let mut out = Vec::with_capacity(host_count as usize);
    for i in 0..host_count {
        out.push(std::net::Ipv4Addr::from(network + start + i as u32));
    }
    Ok(out)
}

fn guess_family(ports: &[u16]) -> String {
    if ports.contains(&445) || ports.contains(&5985) || ports.contains(&3389) {
        "windows".to_string()
    } else if ports.contains(&22) {
        "linux".to_string()
    } else {
        "unknown".to_string()
    }
}

async fn probe(ip: &std::net::Ipv4Addr, port: u16) -> bool {
    let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(*ip), port);
    matches!(
        tokio::time::timeout(Duration::from_millis(700), tokio::net::TcpStream::connect(addr))
            .await,
        Ok(Ok(_))
    )
}

/// Sweeps a CIDR range and returns live hosts with their open probe ports.
pub async fn scan_network(cidr: &str) -> Result<Vec<DiscoveryHost>, String> {
    let addrs = parse_cidr(cidr)?;
    let sem = Arc::new(Semaphore::new(64));
    let mut handles = Vec::new();
    for addr in addrs {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let handle = tokio::spawn(async move {
            let mut ports = Vec::new();
            for &p in PROBE_PORTS {
                if probe(&addr, p).await {
                    ports.push(p);
                }
            }
            drop(permit);
            (addr, ports)
        });
        handles.push(handle);
    }
    let mut hosts = Vec::new();
    for handle in handles {
        if let Ok((addr, ports)) = handle.await {
            if !ports.is_empty() {
                let family = guess_family(&ports);
                hosts.push(DiscoveryHost {
                    ip: addr.to_string(),
                    ports,
                    family,
                    hostname: String::new(),
                    last_scanned: now_iso(),
                    provisioned: false,
                    agent_id: None,
                    error: String::new(),
                });
            }
        }
    }
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(hosts)
}

/// Carries forward the provisioned flag/agent binding for hosts that are still
/// present, so a re-scan does not forget what was already provisioned.
pub fn merge_discovery(old: &[DiscoveryHost], fresh: Vec<DiscoveryHost>) -> Vec<DiscoveryHost> {
    let mut out = Vec::new();
    for mut host in fresh {
        if let Some(prev) = old.iter().find(|o| o.ip == host.ip) {
            host.provisioned = prev.provisioned;
            host.agent_id = prev.agent_id.clone();
            host.hostname = if host.hostname.is_empty() {
                prev.hostname.clone()
            } else {
                host.hostname
            };
        }
        out.push(host);
    }
    out
}

fn ssh_base(cmd: &mut tokio::process::Command, cred: &Credential, ip: &str) {
    cmd.arg("-e")
        .env("SSHPASS", &cred.password)
        .arg("ssh")
        .arg("-p")
        .arg(cred.port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg(format!("{}@{}", cred.username, ip));
}

async fn ssh_cmd(
    cred: &Credential,
    ip: &str,
    remote_cmd: &str,
    timeout_secs: u64,
) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new("sshpass");
    ssh_base(&mut cmd, cred, ip);
    cmd.arg(remote_cmd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        cmd.output(),
    )
    .await
    .map_err(|_| "ssh command timed out".to_string())?
    .map_err(|e| format!("sshpass/ssh failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "ssh exit {}: {} {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Pushes a file to the remote host by streaming it over the ssh channel
/// (`cat > path`), which avoids depending on the sftp subsystem / scp quirks.
async fn ssh_put(
    cred: &Credential,
    ip: &str,
    remote_path: &str,
    data: &[u8],
    timeout_secs: u64,
) -> Result<(), String> {
    let mut cmd = tokio::process::Command::new("sshpass");
    ssh_base(&mut cmd, cred, ip);
    cmd.arg(format!("cat > {remote_path}"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn sshpass: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("failed to open ssh stdin")?;
    let write = async move {
        let _ = stdin.write_all(data).await;
        let _ = stdin.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(timeout_secs), write)
        .await
        .map_err(|_| "upload timed out".to_string())?;
    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| "upload wait timed out".to_string())?
        .map_err(|e| format!("ssh upload: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "upload exit {}: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Pushes the agent binary + CA + a launcher script to `ip` over SSH (password
/// auth via sshpass -e), then starts the agent so it enrolls and registers.
pub async fn provision_host(
    store: &Store,
    store_dir: &Path,
    server_url: &str,
    ip: &str,
    credential: &Credential,
) -> Result<ProvisionOutcome, String> {
    ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| "invalid target IP".to_string())?;
    if !credential
        .username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        return Err("username contains unsafe characters".to_string());
    }
    if !server_url.starts_with("https://") {
        return Err("server URL must be https".to_string());
    }
    let binary = tokio::fs::read(store_dir.join("provision/airgap-agent"))
        .await
        .map_err(|e| format!("agent binary not uploaded yet: {e}"))?;
    if binary.len() < 100_000 {
        return Err("agent binary looks too small to be valid".to_string());
    }
    let ca_pem = store
        .read_ca_pem()
        .await
        .ok_or_else(|| "server CA not found (provisioned at first boot)".to_string())?;
    let token = store.enrollment_token().await?;
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("enrollment token contains characters unsafe for remote push".to_string());
    }

    // 1. reach the host and capture its hostname.
    let out = ssh_cmd(credential, ip, "hostname", 20).await?;
    let hostname = out.lines().next().unwrap_or("unknown").trim().to_string();
    if hostname.is_empty() {
        return Err("could not determine remote hostname".to_string());
    }
    let agent_id = format!("agent-{}", hostname.to_lowercase());

    // 2. upload agent binary + CA + launcher.
    ssh_put(credential, ip, "/tmp/airgap-agent", &binary, 90).await?;
    ssh_put(credential, ip, "/tmp/ca.pem", ca_pem.as_bytes(), 30).await?;
    let script = START_SCRIPT
        .replace("__SERVER__", server_url)
        .replace("__TOKEN__", &token);
    ssh_put(credential, ip, "/tmp/start-agent.sh", script.as_bytes(), 30).await?;

    // 3. run the launcher (uses sudo -n if not already root).
    ssh_cmd(credential, ip, "sh /tmp/start-agent.sh", 60).await?;

    // 4. wait for the agent to enroll + register.
    let mut registered = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if store.get_agent(&agent_id).await.is_some() {
            registered = true;
            break;
        }
    }

    Ok(ProvisionOutcome {
        ok: registered,
        agent_id,
        hostname,
        detail: if registered {
            "agent enrolled and registered".to_string()
        } else {
            "agent pushed but not yet registered (check device log)".to_string()
        },
    })
}

fn now_iso() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
