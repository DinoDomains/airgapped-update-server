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
/// `kind` is "apt", "dnf", "wucatalog" (Microsoft Update Catalog, Windows)
/// or "none" (the latter stores a source without syncing). `suite` is used
/// by apt only. `kbs` is an allowlist of KB identifiers used by wucatalog
/// sources - only those updates are synced into the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub family: String,
    pub kind: String,
    pub base_url: String,
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub kbs: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// A stored set of login credentials used to push the agent to a device over
/// SSH. Passwords are never serialized back out to the dashboard/API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub username: String,
    /// The SSH password. Always redacted from API/dashboard responses via
    /// `#[serde(skip_serializing)]`, but persisted on the server disk
    /// (credentials.json) through a dedicated writer so re-provisioning
    /// still works after a restart.
    #[serde(default)]
    #[serde(skip_serializing)]
    pub password: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub note: String,
}

/// Disk-only view of a credential that includes the password. Used so the
/// public `Credential` type can keep `skip_serializing` on the password.
#[derive(Serialize)]
struct CredentialPersist<'a> {
    name: &'a str,
    username: &'a str,
    password: &'a str,
    port: u16,
    domain: &'a str,
    note: &'a str,
}

impl<'a> From<&'a Credential> for CredentialPersist<'a> {
    fn from(c: &'a Credential) -> Self {
        CredentialPersist {
            name: &c.name,
            username: &c.username,
            password: &c.password,
            port: c.port,
            domain: &c.domain,
            note: &c.note,
        }
    }
}

fn default_port() -> u16 {
    22
}

/// A saved network range to sweep during discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    pub cidr: String,
    #[serde(default)]
    pub last_scanned: String,
}

/// A device found during a discovery sweep.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryHost {
    pub ip: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub last_scanned: String,
    #[serde(default)]
    pub provisioned: bool,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub error: String,
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
            kbs: Vec::new(),
            enabled: true,
        },
        Source {
            name: "ubuntu-noble-updates".to_string(),
            family: "debian".to_string(),
            kind: "apt".to_string(),
            base_url: "http://archive.ubuntu.com/ubuntu".to_string(),
            suite: "noble-updates".to_string(),
            kbs: Vec::new(),
            enabled: true,
        },
        Source {
            name: "ubuntu-noble-security".to_string(),
            family: "debian".to_string(),
            kind: "apt".to_string(),
            base_url: "http://security.ubuntu.com/ubuntu".to_string(),
            suite: "noble-security".to_string(),
            kbs: Vec::new(),
            enabled: true,
        },
        Source {
            name: "rocky8-baseos".to_string(),
            family: "rhel".to_string(),
            kind: "dnf".to_string(),
            base_url: "http://mirror.rackspace.com/rocky/8/BaseOS/x86_64/os".to_string(),
            suite: String::new(),
            kbs: Vec::new(),
            enabled: true,
        },
        Source {
            name: "rocky8-appstream".to_string(),
            family: "rhel".to_string(),
            kind: "dnf".to_string(),
            base_url: "http://mirror.rackspace.com/rocky/8/AppStream/x86_64/os".to_string(),
            suite: String::new(),
            kbs: Vec::new(),
            enabled: true,
        },
        Source {
            name: "windows-update-catalog".to_string(),
            family: "windows".to_string(),
            kind: "wucatalog".to_string(),
            base_url: "https://www.catalog.update.microsoft.com".to_string(),
            suite: String::new(),
            kbs: Vec::new(),
            enabled: false,
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
    credentials: Vec<Credential>,
    networks: Vec<Network>,
    discovery: Vec<DiscoveryHost>,
}

pub struct Store {
    dir: PathBuf,
    state: RwLock<State>,
}

impl Store {
    pub async fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        // The store holds enrollment digests, operator records, SSH
        // credentials and audit history. Restrict it to the service account.
        crate::fsguard::ensure_dir(dir, crate::fsguard::DIR_MODE)?;
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
        store.state.write().await.credentials =
            store.read_json("credentials.json").await.unwrap_or_default();
        store.state.write().await.networks =
            store.read_json("networks.json").await.unwrap_or_default();
        store.state.write().await.discovery =
            store.read_json("discovery.json").await.unwrap_or_default();
        store.state.write().await.sources =
            store.read_json("sources.json").await.unwrap_or_default();
        {
            let mut state = store.state.write().await;
            // Migrate any legacy plaintext tokens to hashed form. Existing
            // agents keep working because verification accepts both.
            let (migrated, changed) = crate::secrets::migrate_hashed(&state.tokens);
            state.tokens = migrated;
            let mut changed = changed;

            // `AIRGAP_ENROLL_TOKEN` is authoritative: whatever the operator
            // puts there is accepted. Tokens are stored only as digests, so
            // without this there would be no way to introduce a new token
            // after the initial bootstrap (hand-editing tokens.json used to be
            // possible when it held plaintext, and no longer is).
            if let Ok(env) = std::env::var("AIRGAP_ENROLL_TOKEN") {
                let env = env.trim();
                if !env.is_empty() {
                    let digest = crate::secrets::digest(env);
                    if !state.tokens.contains_key(&digest) {
                        state.tokens.insert(digest, "env".to_string());
                        changed = true;
                        tracing::info!(
                            "registered AIRGAP_ENROLL_TOKEN as an accepted enrollment token"
                        );
                    }
                }
            }

            // Fall back to a bootstrap token only if nothing else is
            // configured, so a fresh install is usable.
            if state.tokens.is_empty() {
                state
                    .tokens
                    .insert(crate::secrets::digest("airgap-bootstrap"), "default".to_string());
                tracing::warn!(
                    "no enrollment token configured; seeded the default bootstrap token. \
                     Set AIRGAP_ENROLL_TOKEN before exposing this server to agents."
                );
            }

            let tokens = state.tokens.clone();
            drop(state);
            if changed {
                tracing::warn!(
                    "enrollment tokens updated: raw tokens are no longer stored on disk"
                );
            }
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

    /// Verifies a presented enrollment token against the stored digests.
    /// Accepts legacy plaintext entries so migration is transparent.
    pub async fn check_token(&self, token: &str) -> bool {
        let tokens = self.state.read().await.tokens.clone();
        crate::secrets::lookup(token, &tokens).is_some()
    }

    /// Adds a new enrollment token, storing only its digest.
    pub async fn add_token(&self, raw: &str, label: &str) {
        let mut state = self.state.write().await;
        state
            .tokens
            .insert(crate::secrets::digest(raw), label.to_string());
        let snap = state.tokens.clone();
        drop(state);
        self.write_json("tokens.json", &snap).await;
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

    pub async fn update_request(&self, id: &str) -> Option<UpdateRequest> {
        self.state
            .read()
            .await
            .updates
            .iter()
            .find(|u| u.id == id)
            .cloned()
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

    /// Approved-pending updates that the named agent should install on its
    /// next poll. Deduplicated per package (newest request wins).
    pub async fn pending_updates_for_agent(&self, agent_id: &str) -> Vec<UpdateItem> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for u in &self.state.read().await.updates {
            if u.agent_id == agent_id
                && u.status == "approved-pending"
                && seen.insert(u.package.clone())
            {
                out.push(UpdateItem {
                    id: u.id.clone(),
                    kind: "package".to_string(),
                    title: u.package.clone(),
                    version: u.to_version.clone(),
                    ring: u.ring.clone(),
                });
            }
        }
        out
    }

    /// Records the outcome of an install: the agent reports back after
    /// running dnf/apt, and the matching request transitions to done/failed.
    pub async fn mark_update_status(&self, id: &str, status: &str) -> bool {
        let mut state = self.state.write().await;
        let Some(req) = state.updates.iter_mut().find(|u| u.id == id) else {
            return false;
        };
        req.status = status.to_string();
        let snap = state.updates.clone();
        drop(state);
        self.write_json("updates.json", &snap).await;
        true
    }

    /// The enrollment token to embed in provisioned agent launch scripts.
    ///
    /// Enrollment tokens are stored only as digests, so the raw value cannot
    /// be recovered from the store. The operator supplies it out-of-band via
    /// `AIRGAP_ENROLL_TOKEN`; this is deliberate, so that read access to the
    /// store does not yield a usable enrollment credential.
    ///
    /// The supplied value is verified against the stored digests before it is
    /// returned. Without that check an operator who set a token the server
    /// does not know about would provision agents that can never enroll, and
    /// would only find out when the first agent failed to come up.
    pub async fn enrollment_token(&self) -> Result<String, String> {
        let raw = std::env::var("AIRGAP_ENROLL_TOKEN").map_err(|_| {
            "AIRGAP_ENROLL_TOKEN is not set in the server environment. Enrollment \
             tokens are stored hashed, so the raw value cannot be recovered from \
             the store; set it to a token the server already accepts before \
             provisioning agents."
                .to_string()
        })?;
        self.validate_enrollment_token(raw.trim()).await
    }

    /// Checks a candidate raw enrollment token against the stored digests.
    ///
    /// Split out from [`Store::enrollment_token`] so the validation rule can
    /// be tested without mutating process-global environment state.
    pub async fn validate_enrollment_token(&self, raw: &str) -> Result<String, String> {
        if raw.is_empty() {
            return Err("AIRGAP_ENROLL_TOKEN is set but empty".to_string());
        }
        if !self.check_token(raw).await {
            return Err(
                "AIRGAP_ENROLL_TOKEN does not match any enrollment token configured on \
                 this server. Provisioning with it would install agents that cannot \
                 enroll. Set AIRGAP_ENROLL_TOKEN to an accepted token, or add the token \
                 to the server first."
                    .to_string(),
            );
        }
        Ok(raw.to_string())
    }

    pub async fn list_credentials(&self) -> Vec<Credential> {
        self.state.read().await.credentials.clone()
    }

    pub async fn get_credential(&self, name: &str) -> Option<Credential> {
        self.state
            .read()
            .await
            .credentials
            .iter()
            .find(|c| c.name == name)
            .cloned()
    }

    pub async fn upsert_credential(&self, credential: Credential) {
        let mut state = self.state.write().await;
        if let Some(existing) = state
            .credentials
            .iter_mut()
            .find(|c| c.name == credential.name)
        {
            *existing = credential;
        } else {
            state.credentials.push(credential);
        }
        let snap = state.credentials.clone();
        drop(state);
        self.write_credentials(&snap).await;
    }

    pub async fn delete_credential(&self, name: &str) -> bool {
        let mut state = self.state.write().await;
        let before = state.credentials.len();
        state.credentials.retain(|c| c.name != name);
        let removed = state.credentials.len() != before;
        let snap = state.credentials.clone();
        drop(state);
        if removed {
            self.write_credentials(&snap).await;
        }
        removed
    }

    /// Persists credentials including passwords. The password is redacted
    /// from every serialization of `Credential` (API responses), so the
    /// on-disk copy uses `CredentialPersist` instead.
    async fn write_credentials(&self, credentials: &[Credential]) {
        let persist: Vec<CredentialPersist> = credentials.iter().map(Into::into).collect();
        if let Ok(data) = serde_json::to_vec_pretty(&persist) {
            let path = self.dir.join("credentials.json");
            let tmp = self.dir.join("credentials.json.tmp");
            if tokio::fs::write(&tmp, data).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, &path).await;
            }
        }
    }

    pub async fn list_networks(&self) -> Vec<Network> {
        self.state.read().await.networks.clone()
    }

    pub async fn upsert_network(&self, network: Network) {
        let mut state = self.state.write().await;
        if let Some(existing) = state.networks.iter_mut().find(|n| n.name == network.name) {
            *existing = network;
        } else {
            state.networks.push(network);
        }
        let snap = state.networks.clone();
        drop(state);
        self.write_json("networks.json", &snap).await;
    }

    pub async fn delete_network(&self, name: &str) -> bool {
        let mut state = self.state.write().await;
        let before = state.networks.len();
        state.networks.retain(|n| n.name != name);
        let removed = state.networks.len() != before;
        let snap = state.networks.clone();
        drop(state);
        if removed {
            self.write_json("networks.json", &snap).await;
        }
        removed
    }

    pub async fn set_network_scanned(&self, name: &str, ts: &str) {
        let mut state = self.state.write().await;
        if let Some(n) = state.networks.iter_mut().find(|n| n.name == name) {
            n.last_scanned = ts.to_string();
        }
        let snap = state.networks.clone();
        drop(state);
        self.write_json("networks.json", &snap).await;
    }

    pub async fn list_discovery(&self) -> Vec<DiscoveryHost> {
        self.state.read().await.discovery.clone()
    }

    pub async fn save_discovery(&self, hosts: Vec<DiscoveryHost>) {
        let mut state = self.state.write().await;
        state.discovery = hosts;
        let snap = state.discovery.clone();
        drop(state);
        self.write_json("discovery.json", &snap).await;
    }

    pub async fn mark_discovery_provisioned(
        &self,
        ip: &str,
        hostname: &str,
        agent_id: &str,
        error: &str,
    ) {
        let mut state = self.state.write().await;
        if let Some(h) = state.discovery.iter_mut().find(|h| h.ip == ip) {
            h.provisioned = error.is_empty();
            h.hostname = hostname.to_string();
            h.agent_id = Some(agent_id.to_string());
            h.error = error.to_string();
        }
        let snap = state.discovery.clone();
        drop(state);
        self.write_json("discovery.json", &snap).await;
    }

    pub async fn read_ca_pem(&self) -> Option<String> {
        tokio::fs::read_to_string(self.dir.join("ca/ca.pem")).await.ok()
    }

    pub async fn agent_binary_present(&self) -> Option<u64> {
        tokio::fs::metadata(self.dir.join("provision/airgap-agent"))
            .await
            .ok()
            .map(|m| m.len())
    }

    pub async fn write_agent_binary(&self, bytes: &[u8]) -> std::io::Result<()> {
        let dir = self.dir.join("provision");
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(dir.join("airgap-agent"), bytes).await
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}
