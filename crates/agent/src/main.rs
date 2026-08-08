use std::path::PathBuf;
use std::time::Duration;

use airgap_proto::{
    DistroFamily, InventoryRequest, PollRequest, RegisterRequest, ReportRequest, ReportStatus,
    UpdateItem,
};

mod client;
mod inventory;

const DEFAULT_SERVER: &str = "https://172.16.5.20:8443";
#[cfg(unix)]
const DEFAULT_STATE_DIR: &str = "/var/lib/airgap-agent";
#[cfg(windows)]
const DEFAULT_STATE_DIR: &str = "C:\\ProgramData\\airgap-agent";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_agent=info".into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main())
}

/// Package names come from the server's catalog (trusted) but are validated
/// anyway before being interpolated into a shell command, to be safe.
/// Windows KB format: KB1234567 or similar.
fn is_safe_package(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c))
}

/// Downloads the artifacts for a batch of approved updates and installs them
/// in a single package-manager transaction so cross-package dependencies
/// (e.g. coreutils -> coreutils-common) resolve offline. Returns one
/// (update_id, code, detail) triple per update.
async fn apply_updates_batch(
    client: &client::Client,
    agent_id: &str,
    state_dir: &PathBuf,
    updates: &[UpdateItem],
) -> Vec<(String, String, String)> {
    let inv = inventory::collect().await;
    let family = inv.family;
    let mut results: Vec<(String, String, String)> = Vec::new();
    let mut staged: Vec<(String, String, PathBuf)> = Vec::new(); // (id, pkg, path)

    for update in updates {
        if update.kind != "package" {
            results.push((
                update.id.clone(),
                "skipped".to_string(),
                format!("unsupported kind {}", update.kind),
            ));
            continue;
        }
        let pkg = &update.title;
        if !is_safe_package(pkg) {
            results.push((update.id.clone(), "failed".to_string(), "invalid package name".to_string()));
            continue;
        }
        let fam = match family {
            DistroFamily::Debian => "debian",
            DistroFamily::Rhel => "rhel",
            DistroFamily::Windows => "windows",
            other => {
                results.push((
                    update.id.clone(),
                    "failed".to_string(),
                    format!("no package installer for {other:?}"),
                ));
                continue;
            }
        };
        let artifact = match client.artifact(agent_id, &update.id, fam).await {
            Ok(a) => a,
            Err(e) => {
                results.push((update.id.clone(), "failed".to_string(), format!("artifact fetch failed: {e}")));
                continue;
            }
        };
        let filename = if artifact
            .filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
            && !artifact.filename.is_empty()
            && artifact.filename.len() <= 200
        {
            artifact.filename.clone()
        } else {
            let ext = if family == DistroFamily::Debian {
                "deb"
            } else if family == DistroFamily::Windows {
                "msu"
            } else {
                "rpm"
            };
            format!("update-{}.{}", update.id, ext)
        };
        let path = state_dir.join(filename);
        if let Err(e) = std::fs::write(&path, &artifact.bytes) {
            results.push((update.id.clone(), "failed".to_string(), format!("write artifact: {e}")));
            continue;
        }
        staged.push((update.id.clone(), pkg.clone(), path));
    }

    if staged.is_empty() {
        return results;
    }

    // Windows wusa accepts one MSU per invocation - run them one at a time.
    if family == DistroFamily::Windows {
        for (id, pkg, path) in staged {
            let output = std::process::Command::new("wusa.exe")
                .args([path.to_str().unwrap_or_default(), "/quiet", "/norestart"])
                .output();
            let new_inv = inventory::collect().await;
            let new_version = new_inv
                .packages
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(&pkg))
                .map(|p| p.version.clone())
                .unwrap_or_default();
            let (code, detail) = match output {
                Ok(out) if out.status.success() => ("ok".to_string(), format!("installed {new_version}")),
                Ok(out) => {
                    let tail: String = String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .rev()
                        .take(8)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join(" | ");
                    ("failed".to_string(), tail)
                }
                Err(e) => ("failed".to_string(), format!("spawn failed: {e}")),
            };
            results.push((id, code, detail));
        }
        return results;
    }

    // Linux: one transaction with every staged file so cross-package deps
    // (and package groups) resolve from local artifacts with repos disabled.
    let (cmd, mut args) = match family {
        DistroFamily::Debian => ("dpkg", vec!["-i".to_string()]),
        _ => (
            "dnf",
            vec![
                "-y".to_string(),
                "install".to_string(),
                "--disablerepo=*".to_string(),
                "--setopt=*_skip_if_unavailable=1".to_string(),
                "--nogpgcheck".to_string(),
            ],
        ),
    };
    for (_id, _pkg, path) in &staged {
        args.push(path.to_str().unwrap_or_default().to_string());
    }
    let names: Vec<&str> = staged.iter().map(|s| s.1.as_str()).collect();
    tracing::info!("applying {} update(s) via {cmd}: {}", staged.len(), names.join(", "));
    let output = std::process::Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output();

    let (ok_all, err_tail) = match output {
        Ok(out) if out.status.success() => (true, String::new()),
        Ok(out) => {
            let tail: String = String::from_utf8_lossy(&out.stderr)
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ");
            (false, tail)
        }
        Err(e) => (false, format!("spawn failed: {e}")),
    };

    let new_inv = inventory::collect().await;
    for (id, pkg, _path) in &staged {
        let new_version = new_inv
            .packages
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(&pkg))
            .map(|p| p.version.clone())
            .unwrap_or_default();
        if ok_all && !new_version.is_empty() {
            results.push((id.to_string(), "ok".to_string(), format!("installed {new_version}")));
        } else if ok_all {
            results.push((id.to_string(), "ok".to_string(), "install reported success".to_string()));
        } else {
            results.push((id.to_string(), "failed".to_string(), err_tail.clone()));
        }
    }
    results
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("AIRGAP_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let state_dir = PathBuf::from(
        std::env::var("AIRGAP_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string()),
    );
    let poll_interval = std::env::var("AIRGAP_POLL_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);

    let mut inv = inventory::collect().await;
    tracing::info!("collected inventory: {} {}", inv.os_name, inv.os_version);

    let client = client::Client::load_or_enroll(&server, &state_dir).await?;
    let agent_id = client.agent_id().to_string();

    let reg = RegisterRequest {
        agent_id: agent_id.clone(),
        inventory: inv.clone(),
    };
    client.register(&reg).await?;
    tracing::info!("registered as {agent_id}");

    client
        .inventory(&InventoryRequest {
            agent_id: agent_id.clone(),
            inventory: inv.clone(),
        })
        .await?;

    loop {
        let poll = client
            .poll(&PollRequest {
                agent_id: agent_id.clone(),
            })
            .await?;
        tracing::info!("server offered {} update(s)", poll.updates.len());

        if poll.scan_requested {
            tracing::info!("server requested a scan - re-collecting inventory");
            inv = inventory::collect().await;
            client
                .inventory(&InventoryRequest {
                    agent_id: agent_id.clone(),
                    inventory: inv.clone(),
                })
                .await?;
            tracing::info!("scan complete - inventory re-reported");
        }

        if !poll.updates.is_empty() {
            let results =
                apply_updates_batch(&client, &agent_id, &state_dir, &poll.updates).await;
            for (update_id, code, detail) in results {
                tracing::info!("update {update_id} -> {code}");
                client
                    .report(&ReportRequest {
                        agent_id: agent_id.clone(),
                        update_id,
                        status: ReportStatus { code, detail },
                    })
                    .await?;
            }
            let fresh = inventory::collect().await;
            client
                .inventory(&InventoryRequest {
                    agent_id: agent_id.clone(),
                    inventory: fresh,
                })
                .await?;
        }

        if poll_interval == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
    }

    Ok(())
}
