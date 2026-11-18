use serde::{Deserialize, Serialize};

pub const API_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DistroFamily {
    #[default]
    Rhel,
    Debian,
    Windows,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskStorage {
    pub mount_point: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub used_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsInventory {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub os_pretty: String,
    pub family: DistroFamily,
    pub arch: String,
    pub kernel: String,
    pub bootloader: String,
    pub packages: Vec<Package>,
    pub repos: Vec<String>,
    #[serde(default)]
    pub disks: Vec<DiskStorage>,
    #[serde(default)]
    pub networks: Vec<NetworkInterface>,
    #[serde(default)]
    pub last_updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub cert: String,
    pub cert_key: String,
    pub ca_cert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent_id: String,
    pub inventory: OsInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub accepted: bool,
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryRequest {
    pub agent_id: String,
    pub inventory: OsInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub version: String,
    pub ring: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub updates: Vec<UpdateItem>,
    #[serde(default)]
    pub scan_requested: bool,
    #[serde(default)]
    pub revert_commands: Vec<RevertCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatus {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    pub agent_id: String,
    pub update_id: String,
    pub status: ReportStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub accepted: bool,
}

/// Agent requests the actual package artifact (an .rpm/.deb) for an approved
/// update. The server proxies it from the whitelisted upstream source over
/// the mTLS channel so isolated agents never need direct internet access.
/// `family` is the agent's distro family ("rhel" or "debian").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRequest {
    pub agent_id: String,
    pub update_id: String,
    pub family: String,
}

/// M6 protocol extension: admin-initiated revert command received over mTLS.
/// Extends the existing protocol without a parallel connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertCommand {
    pub agent_id: String,
    pub command_id: String,
    pub package: String,
    pub target_version: String,
}

/// M6 protocol extension: revert outcome reported back to the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevertOutcome {
    Success,
    Failed { reason: String },
    NotRevertible { reason: String },
}

/// The revert report message sent from agent to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertReport {
    pub agent_id: String,
    pub command_id: String,
    pub package: String,
    pub target_version: String,
    pub outcome: RevertOutcome,
    pub executed_at: String,
}
