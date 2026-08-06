use std::path::PathBuf;

use airgap_proto::{InventoryRequest, PollRequest, RegisterRequest};

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

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("AIRGAP_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());
    let state_dir = PathBuf::from(
        std::env::var("AIRGAP_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string()),
    );

    let inv = inventory::collect().await;
    tracing::info!("collected inventory: {} {}", inv.os_name, inv.os_version);

    let client = client::Client::load_or_enroll(&server, &state_dir).await?;
    let agent_id = client.agent_id().to_string();

    let reg = RegisterRequest {
        agent_id: agent_id.clone(),
        inventory: inv.clone(),
    };
    client.register(&reg).await?;
    tracing::info!("registered as {agent_id}");

    let inv_req = InventoryRequest {
        agent_id: agent_id.clone(),
        inventory: inv,
    };
    client.inventory(&inv_req).await?;

    let poll = client.poll(&PollRequest {
        agent_id: agent_id.clone(),
    }).await?;
    tracing::info!("server offered {} update(s)", poll.updates.len());

    Ok(())
}
