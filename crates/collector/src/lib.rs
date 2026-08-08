use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use airgap_proto::{DistroFamily, OsInventory, UpdateItem};
use airgap_sandbox::BwrapSandbox;
use airgap_transport::{MtlConfig, UsbTransport};
use chrono::Utc;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{info, warn, error};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "airgap-collector")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0:8444")]
    pub listen: String,

    #[arg(long)]
    pub data_dir: PathBuf,

    #[arg(long)]
    pub wired_mode: bool,

    #[arg(long)]
    pub server_url: Option<String>,

    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    #[arg(long)]
    pub client_cert: Option<PathBuf>,

    #[arg(long)]
    pub client_key: Option<PathBuf>,

    #[arg(long)]
    pub usb_mount: Option<PathBuf>,

    #[arg(long, default_value = "60")]
    pub scan_interval: u64,

    #[arg(long, default_value = "30")]
    pub poll_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub ip: IpAddr,
    pub hostname: String,
    pub family: DistroFamily,
    pub last_seen: String,
    pub inventory: Option<OsInventory>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub update_id: String,
    pub endpoint_id: String,
    pub package: String,
    pub version: String,
    pub artifact_sha256: String,
    pub artifact_path: PathBuf,
    pub status: String,
}

pub struct CollectorState {
    pub endpoints: Arc<RwLock<HashMap<String, Endpoint>>>,
    pub pending: Arc<RwLock<HashMap<String, PendingUpdate>>>,
    pub data_dir: PathBuf,
    pub sandbox: BwrapSandbox,
    pub wired_transport: Option<Arc<airgap_transport::WiredTransport>>,
    pub usb_transport: Option<UsbTransport>,
    pub scan_interval: Duration,
    pub poll_interval: Duration,
}

impl CollectorState {
    pub fn new(cli: &Cli) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&cli.data_dir)?;

        let sandbox = BwrapSandbox::minimal()
            .with_rw_bind(&cli.data_dir, "/data");

        let wired_transport = if cli.wired_mode {
            let config = MtlConfig {
                server_url: cli.server_url.clone().unwrap_or_default(),
                ca_cert: cli.ca_cert.clone().unwrap_or_default(),
                client_cert: cli.client_cert.clone().unwrap_or_default(),
                client_key: cli.client_key.clone().unwrap_or_default(),
            };
            Some(Arc::new(airgap_transport::WiredTransport::new(config)?))
        } else {
            None
        };

        let usb_transport = cli.usb_mount.as_ref().map(|m| UsbTransport::new(m.clone())).transpose()?;

        Ok(Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
            data_dir: cli.data_dir.clone(),
            sandbox,
            wired_transport,
            usb_transport,
            scan_interval: Duration::from_secs(cli.scan_interval),
            poll_interval: Duration::from_secs(cli.poll_interval),
        })
    }

    pub async fn scan_network(&self) -> Result<Vec<Endpoint>, Box<dyn std::error::Error>> {
        // Network scan - discover endpoints via ARP/NDP, then try to connect
        // For now, return existing endpoints
        let endpoints = self.endpoints.read().await;
        Ok(endpoints.values().cloned().collect())
    }

    pub async fn register_endpoint(&self, endpoint: Endpoint) {
        self.endpoints.write().await.insert(endpoint.id.clone(), endpoint);
    }

    pub async fn update_inventory(&self, endpoint_id: &str, inventory: OsInventory) {
        let mut endpoints = self.endpoints.write().await;
        if let Some(ep) = endpoints.get_mut(endpoint_id) {
            ep.inventory = Some(inventory);
            ep.last_seen = Utc::now().to_rfc3339();
            ep.status = "online".to_string();
        }
    }

    pub async fn queue_update(&self, update: PendingUpdate) {
        self.pending.write().await.insert(update.update_id.clone(), update);
    }

    pub async fn get_pending_for_endpoint(&self, endpoint_id: &str) -> Vec<PendingUpdate> {
        self.pending.read().await
            .values()
            .filter(|u| u.endpoint_id == endpoint_id && u.status == "pending")
            .cloned()
            .collect()
    }
}

#[derive(Deserialize)]
struct InventoryPost {
    device_id: String,
    inventory: OsInventory,
}

#[derive(Deserialize)]
struct PollPost {
    device_id: String,
}

#[derive(Serialize)]
struct PollResp {
    updates: Vec<UpdateItem>,
    scan_requested: bool,
}

#[derive(Deserialize)]
struct ReportPost {
    device_id: String,
    update_id: String,
    status: airgap_proto::ReportStatus,
}

async fn inventory(
    State(state): State<Arc<CollectorState>>,
    Json(req): Json<InventoryPost>,
) -> impl IntoResponse {
    state.update_inventory(&req.device_id, req.inventory).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

async fn poll(
    State(state): State<Arc<CollectorState>>,
    Json(req): Json<PollPost>,
) -> impl IntoResponse {
    let pending = state.get_pending_for_endpoint(&req.device_id).await;
    let updates: Vec<UpdateItem> = pending.into_iter().map(|u| UpdateItem {
        id: u.update_id,
        kind: "package".to_string(),
        title: u.package,
        version: u.version,
        ring: "prod".to_string(),
    }).collect();

    (StatusCode::OK, Json(PollResp { updates, scan_requested: false }))
}

async fn report(
    State(state): State<Arc<CollectorState>>,
    Json(req): Json<ReportPost>,
) -> impl IntoResponse {
    let mut pending = state.pending.write().await;
    if let Some(u) = pending.get_mut(&req.update_id) {
        u.status = if req.status.code == "ok" { "done" } else { "failed" }.to_string();
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

async fn health(State(state): State<Arc<CollectorState>>) -> impl IntoResponse {
    let endpoints = state.endpoints.read().await.len();
    let pending = state.pending.read().await.len();
    (StatusCode::OK, Json(serde_json::json!({
        "status": "ok",
        "endpoints": endpoints,
        "pending_updates": pending,
    })))
}

pub async fn run_collector(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(CollectorState::new(&cli)?);

    // Background task: periodic network scan
    let state_scan = state.clone();
    let scan_interval = cli.scan_interval;
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(scan_interval));
        loop {
            interval.tick().await;
            if let Err(e) = state_scan.scan_network().await {
                error!("network scan failed: {}", e);
            }
        }
    });

    // Background task: sync with upstream (wired) or USB
    let state_sync = state.clone();
    let wired = cli.wired_mode;
    let state_wired = state_sync.wired_transport.clone();
    let state_usb = state_sync.usb_transport.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            
            // Sync inventory to upstream
            let endpoints = state_sync.endpoints.read().await;
            for ep in endpoints.values() {
                if let Some(inv) = &ep.inventory {
                    if wired {
                        if let Some(transport) = &state_wired {
                            if let Err(e) = transport.send_inventory(&ep.id, inv.clone()).await {
                                warn!("failed to send inventory to upstream: {}", e);
                            }
                        }
                    } else {
                        // USB mode - write to manifest
                        if let Some(transport) = &state_usb {
                            if let Err(e) = transport.write_inventory(&ep.id, inv.clone()) {
                                warn!("failed to write inventory to USB: {}", e);
                            }
                        }
                    }
                }
            }
        }
    });

    // HTTP server for endpoint agents
    let app = Router::new()
        .route("/inventory", post(inventory))
        .route("/poll", post(poll))
        .route("/report", post(report))
        .route("/health", get(health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    info!("Collector listening on {}", cli.listen);
    axum::serve(listener, app).await?;

    Ok(())
}