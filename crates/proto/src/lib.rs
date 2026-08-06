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
