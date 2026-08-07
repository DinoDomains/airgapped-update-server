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
    #[serde(default)]
    pub scan_requested: Option<String>,
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
    #[serde(default)]
    pub approved_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedRecord {
    pub agent_id: String,
    pub revoked_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub action: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub default_deny: bool,
    #[serde(default)]
    pub entries: HashMap<String, PolicyEntry>,
}

/// A whitelisted upstream source that the catalog may sync from.
/// `kind` is "apt", "dnf" or "none" (the latter stores a source without
/// syncing, e.g. a future Windows/WSUS mirror). `suite` is used by apt only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub family: String,
    pub kind: String,
    pub base_url: String,
    #[serde(default)]
    pub suite: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_sources() -> Vec<Source> {
    vec![
        Source {
            name: "ubuntu-noble".to_string(),
            family: "debian".to_string(),
            kind: "apt".to_string(),
            base_url: "http://archive.ubuntu.com/ubuntu".to_string(),
            suite: "noble".to_string(),
            enabled: true,
        },
        Source {
            name: "ubuntu-noble-updates".to_string(),
            family: "debian".to_string(),
            kind: "apt".to_string(),
            base_url: "http://archive.ubuntu.com/ubuntu".to_string(),
            suite: "noble-updates".to_string(),
            enabled: true,
        },
        Source {
            name: "ubuntu-noble-security".to_string(),
            family: "debian".to_string(),
            kind: "apt".to_string(),
            base_url: "http://security.ubuntu.com/ubuntu".to_string(),
            suite: "noble-security".to_string(),
            enabled: true,
        },
        Source {
            name: "rocky8-baseos".to_string(),
            family: "rhel".to_string(),
            kind: "dnf".to_string(),
            base_url: "http://mirror.rackspace.com/rocky/8/BaseOS/x86_64/os".to_string(),
            suite: String::new(),
            enabled: true,
        },
        Source {
            name: "rocky8-appstream".to_string(),
            family: "rhel".to_string(),
            kind: "dnf".to_string(),
            base_url: "http://mirror.rackspace.com/rocky/8/AppStream/x86_64/os".to_string(),
            suite: String::new(),
            enabled: true,
        },
    ]
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
    revoked: HashMap<String, RevokedRecord>,
    policy: Policy,
    sources: Vec<Source>,
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
        store.state.write().await.revoked =
            store.read_json("revoked.json").await.unwrap_or_default();
        store.state.write().await.policy =
            store.read_json("policy.json").await.unwrap_or_default();
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
        {
            let mut state = store.state.write().await;
            if state.sources.is_empty() {
                state.sources = default_sources();
            }
            let sources = state.sources.clone();
            drop(state);
            store.write_json("sources.json", &sources).await;
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

    pub async fn promote_update(&self, id: &str) -> Result<UpdateRequest, String> {
        let mut state = self.state.write().await;
        let req = state
            .updates
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or_else(|| "update request not found".to_string())?;
        let next = match req.ring.as_str() {
            "dev" => "staging",
            "staging" => "prod",
            "prod" => return Err("already in prod".to_string()),
            _ => "staging",
        };
        req.ring = next.to_string();
        let snap = state.updates.clone();
        drop(state);
        self.write_json("updates.json", &snap).await;
        Ok(snap.into_iter().find(|u| u.id == id).unwrap())
    }

    pub async fn revoke_agent(&self, agent_id: &str, reason: &str) -> bool {
        let mut state = self.state.write().await;
        let record = RevokedRecord {
            agent_id: agent_id.to_string(),
            revoked_at: now_iso(),
            reason: reason.to_string(),
        };
        let inserted = state.revoked.insert(agent_id.to_string(), record).is_none();
        let snap = state.revoked.clone();
        drop(state);
        self.write_json("revoked.json", &snap).await;
        inserted
    }

    pub async fn is_revoked(&self, agent_id: &str) -> bool {
        self.state.read().await.revoked.contains_key(agent_id)
    }

    pub async fn list_revoked(&self) -> Vec<RevokedRecord> {
        let mut v: Vec<RevokedRecord> = self.state.read().await.revoked.values().cloned().collect();
        v.sort_by(|a, b| b.revoked_at.cmp(&a.revoked_at));
        v
    }

    pub async fn policy_snapshot(&self) -> Policy {
        self.state.read().await.policy.clone()
    }

    pub async fn policy_allows(&self, name: &str) -> bool {
        let p = &self.state.read().await.policy;
        match p.entries.get(&name.to_lowercase()) {
            Some(e) => e.action == "allow",
            None => !p.default_deny,
        }
    }

    pub async fn set_policy_default_deny(&self, default_deny: bool) {
        let mut state = self.state.write().await;
        state.policy.default_deny = default_deny;
        let snap = state.policy.clone();
        drop(state);
        self.write_json("policy.json", &snap).await;
    }

    pub async fn upsert_policy_entry(&self, name: &str, action: &str, note: &str) {
        let mut state = self.state.write().await;
        state.policy.entries.insert(
            name.to_lowercase(),
            PolicyEntry {
                action: action.to_string(),
                note: note.to_string(),
            },
        );
        let snap = state.policy.clone();
        drop(state);
        self.write_json("policy.json", &snap).await;
    }

    pub async fn delete_policy_entry(&self, name: &str) -> bool {
        let mut state = self.state.write().await;
        let removed = state.policy.entries.remove(&name.to_lowercase()).is_some();
        let snap = state.policy.clone();
        drop(state);
        if removed {
            self.write_json("policy.json", &snap).await;
        }
        removed
    }

    /// Marks an agent for a fresh scan. The agent picks this up on its next
    /// poll and re-reports inventory, which clears the flag.
    pub async fn request_scan(&self, agent_id: &str) -> bool {
        let mut state = self.state.write().await;
        let Some(agent) = state.agents.get_mut(agent_id) else {
            return false;
        };
        agent.scan_requested = Some(now_iso());
        let snap = state.agents.clone();
        drop(state);
        self.write_json("agents.json", &snap).await;
        true
    }

    pub async fn scan_pending(&self, agent_id: &str) -> bool {
        self.state
            .read()
            .await
            .agents
            .get(agent_id)
            .and_then(|a| a.scan_requested.as_ref())
            .is_some()
    }

    pub async fn clear_scan(&self, agent_id: &str) {
        let mut state = self.state.write().await;
        if let Some(agent) = state.agents.get_mut(agent_id) {
            agent.scan_requested = None;
        }
        let snap = state.agents.clone();
        drop(state);
        self.write_json("agents.json", &snap).await;
    }

    pub async fn list_sources(&self) -> Vec<Source> {
        self.state.read().await.sources.clone()
    }

    pub async fn enabled_sources(&self) -> Vec<Source> {
        self.state
            .read()
            .await
            .sources
            .iter()
            .filter(|s| s.enabled)
            .cloned()
            .collect()
    }

    pub async fn upsert_source(&self, source: Source) {
        let mut state = self.state.write().await;
        if let Some(existing) = state.sources.iter_mut().find(|s| s.name == source.name) {
            *existing = source;
        } else {
            state.sources.push(source);
        }
        let snap = state.sources.clone();
        drop(state);
        self.write_json("sources.json", &snap).await;
    }

    pub async fn set_source_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut state = self.state.write().await;
        let Some(source) = state.sources.iter_mut().find(|s| s.name == name) else {
            return false;
        };
        source.enabled = enabled;
        let snap = state.sources.clone();
        drop(state);
        self.write_json("sources.json", &snap).await;
        true
    }

    pub async fn delete_source(&self, name: &str) -> bool {
        let mut state = self.state.write().await;
        let before = state.sources.len();
        state.sources.retain(|s| s.name != name);
        let removed = state.sources.len() != before;
        let snap = state.sources.clone();
        drop(state);
        if removed {
            self.write_json("sources.json", &snap).await;
        }
        removed
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}
