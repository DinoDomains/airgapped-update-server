use std::path::PathBuf;
use std::time::Duration;

use airgap_proto::{
    DistroFamily, InventoryRequest, PollRequest, RegisterRequest, ReportRequest, ReportStatus,
    UpdateItem,
};

mod client;
mod inventory;

const DEFAULT_SERVER: &str = "https://172.16.5.20:8443";
const DEFAULT_STATE_DIR: &str = "/var/lib/airgap-agent";

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
fn is_safe_package(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c))
}

/// Applies a single approved update. For "package" updates the agent fetches
/// the artifact (.rpm/.deb) from the server over mTLS, writes it to the
/// state directory, then installs it from the local file so no direct
/// internet access is needed:
///   - RHEL:  dnf -y install --disablerepo=* <file.rpm>   (offline, resolves
///            dependencies against the installed RPM database)
///   - Debian: dpkg -i <file.deb>                          (offline; a missing
///            dependency surfaces as a failed report with the dpkg output)
/// Returns (status code, detail): "ok" when the install succeeded, "failed"
/// otherwise. Detail carries the resulting installed version or the tail of
/// the package manager output.
async fn apply_update(
    client: &client::Client,
    agent_id: &str,
    state_dir: &PathBuf,
    update: &UpdateItem,
) -> (String, String) {
    if update.kind != "package" {
        return ("skipped".to_string(), format!("unsupported kind {}", update.kind));
    }
    let pkg = &update.title;
    if !is_safe_package(pkg) {
        return ("failed".to_string(), "invalid package name".to_string());
    }
    let inv = inventory::collect().await;
    let family = match inv.family {
        DistroFamily::Debian => "debian",
        DistroFamily::Rhel => "rhel",
        other => {
            return (
                "failed".to_string(),
                format!("no package installer for {other:?}"),
            )
        }
    };

    let artifact = match client.artifact(agent_id, &update.id, family).await {
        Ok(a) => a,
        Err(e) => {
            return ("failed".to_string(), format!("artifact fetch failed: {e}"))
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
        format!("update-{}.{}", update.id, if family == "debian" { "deb" } else { "rpm" })
    };
    let path = state_dir.join(filename);
    if let Err(e) = std::fs::write(&path, &artifact.bytes) {
        return ("failed".to_string(), format!("write artifact: {e}"));
    }

    let (cmd, args) = match inv.family {
        DistroFamily::Debian => ("dpkg", vec!["-i", path.to_str().unwrap_or_default()]),
        _ => (
            "dnf",
            vec![
                "-y",
                "install",
                "--disablerepo=*",
                path.to_str().unwrap_or_default(),
            ],
        ),
    };
    tracing::info!("applying {pkg} via {cmd} from {}", path.display());
    let output = std::process::Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output();

    let new_inv = inventory::collect().await;
    let new_version = new_inv
        .packages
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(pkg))
        .map(|p| p.version.clone())
        .unwrap_or_default();

    match output {
        Ok(out) if out.status.success() => {
            let detail = if new_version.is_empty() {
                format!("{} reported success", cmd)
            } else {
                format!("installed {}", new_version)
            };
            ("ok".to_string(), detail)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: String = err.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
            ("failed".to_string(), tail)
        }
        Err(e) => ("failed".to_string(), e.to_string()),
    }
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

        for update in &poll.updates {
            let (code, detail) = apply_update(&client, &agent_id, &state_dir, update).await;
            tracing::info!("update {} -> {}", update.title, code);
            client
                .report(&ReportRequest {
                    agent_id: agent_id.clone(),
                    update_id: update.id.clone(),
                    status: ReportStatus {
                        code: code.clone(),
                        detail,
                    },
                })
                .await?;
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
