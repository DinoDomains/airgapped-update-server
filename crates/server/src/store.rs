use std::collections::HashMap;
use std::path::{Path, PathBuf};

use airgap_proto::{OsInventory, ReportStatus, UpdateItem};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentRecord {
    pub agent_id: String,
    pub hostname: String,
    pub inventory: Option<OsInventory>,
    pub last_seen: Option<String>,
    pub status: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRecord {
    pub agent_id: String,
    pub update_id: String,
    pub status: ReportStatus,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    pub id: String,
    pub agent_id: String,
    pub package: String,
    pub from_version: String,
    pub to_version: String,
    pub ring: String,
    pub ts: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Catalog {
    pub updates: Vec<UpdateItem>,
}

#[derive(Debug, Default)]
struct State {
    agents: HashMap<String, AgentRecord>,
    reports: Vec<ReportRecord>,
    catalog: Catalog,
    tokens: HashMap<String, String>,
    updates: Vec<UpdateRequest>,
}

pub struct Store {
    dir: PathBuf,
    state: RwLock<State>,
}

impl Store {
    pub async fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        let store = Store {
            dir: dir.to_path_buf(),
            state: RwLock::new(State::default()),
        };
        store.state.write().await.agents =
            store.read_json("agents.json").await.unwrap_or_default();
        store.state.write().await.reports =
            store.read_json("reports.json").await.unwrap_or_default();
        store.state.write().await.catalog =
            store.read_json("catalog.json").await.unwrap_or_default();
        store.state.write().await.tokens =
            store.read_json("tokens.json").await.unwrap_or_default();
        store.state.write().await.updates =
            store.read_json("updates.json").await.unwrap_or_default();
        {
            let mut state = store.state.write().await;
            if state.tokens.is_empty() {
                let default = std::env::var("AIRGAP_ENROLL_TOKEN")
                    .unwrap_or_else(|_| "airgap-bootstrap".to_string());
                state.tokens.insert(default, "default".to_string());
            }
            let tokens = state.tokens.clone();
            drop(state);
            store.write_json("tokens.json", &tokens).await;
        }
        Ok(store)
    }

    async fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        file: &str,
    ) -> Option<T> {
        let data = tokio::fs::read(self.dir.join(file)).await.ok()?;
        serde_json::from_slice(&data).ok()
    }

    async fn write_json<T: Serialize>(&self, file: &str, value: &T) {
        if let Ok(data) = serde_json::to_vec_pretty(value) {
            let path = self.dir.join(file);
            let tmp = self.dir.join(format!("{file}.tmp"));
            if tokio::fs::write(&tmp, data).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, &path).await;
            }
        }
    }

    pub async fn check_token(&self, token: &str) -> bool {
        self.state.read().await.tokens.contains_key(token)
    }

    pub async fn list_agents(&self) -> Vec<AgentRecord> {
        let mut agents: Vec<AgentRecord> = self.state.read().await.agents.values().cloned().collect();
        agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        agents
    }

    pub async fn get_agent(&self, agent_id: &str) -> Option<AgentRecord> {
        self.state.read().await.agents.get(agent_id).cloned()
    }

    pub async fn register_agent(&self, record: AgentRecord) {
        self.state.write().await.agents.insert(record.agent_id.clone(), record);
        self.write_json("agents.json", &self.snapshot_agents().await).await;
    }

    async fn snapshot_agents(&self) -> HashMap<String, AgentRecord> {
        self.state.read().await.agents.clone()
    }

    pub async fn update_inventory(
        &self,
        agent_id: &str,
        inventory: OsInventory,
        ip: Option<String>,
    ) -> bool {
        let mut state = self.state.write().await;
        let Some(agent) = state.agents.get_mut(agent_id) else {
            return false;
        };
        agent.inventory = Some(inventory);
        agent.last_seen = Some(now_iso());
        agent.status = "online".to_string();
        if ip.is_some() {
            agent.ip = ip;
        }
        let snap = state.agents.clone();
        drop(state);
        self.write_json("agents.json", &snap).await;
        true
    }

    pub async fn record_report(&self, report: ReportRecord) {
        let mut state = self.state.write().await;
        state.reports.push(report);
        let snap = state.reports.clone();
        drop(state);
        self.write_json("reports.json", &snap).await;
    }

    pub async fn pending_updates(&self) -> Vec<UpdateItem> {
        self.state.read().await.catalog.updates.clone()
    }

    pub async fn record_update_request(&self, req: UpdateRequest) {
        let mut state = self.state.write().await;
        state.updates.push(req);
        let snap = state.updates.clone();
        drop(state);
        self.write_json("updates.json", &snap).await;
    }

    pub async fn update_requests(&self) -> Vec<UpdateRequest> {
        self.state.read().await.updates.clone()
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}
