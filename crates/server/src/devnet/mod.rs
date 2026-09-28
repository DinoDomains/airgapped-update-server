//! M5 — DevNet Core Server. PLAN.md §2.2.
//!
//! Extends the existing wired-system server (`crates/server`) with
//! DevNet-specific logic: drift/tamper detection, revocation matching,
//! handoff consumption from M4, and revert command dispatch to M6.
//!
//! This module is the trusted core on the DevNet (air-gapped) side.
//! It holds DevNet's signing key (via M2/KeyManager), consumes verified
//! artifacts from M4's INGEST VM, and dispatches admin-approved revert
//! commands to M6 (endpoint agent).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use airgap_contracts::{
    InboundBundle, InboundCatalog, InstalledPackage, Revocation, sha256_file,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::audit::AuditLog;
use super::store::Store;

/// Ring classification for update promotion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ring {
    #[serde(rename = "dev")]
    Dev,
    #[serde(rename = "staging")]
    Staging,
    #[serde(rename = "prod")]
    Prod,
}

/// Errors returned by `DevNetCoreApi`.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("package not found in state: {0}")]
    PackageNotFound(String),
    #[error("endpoint not found: {0}")]
    EndpointNotFound(String),
    #[error("empty reason")]
    EmptyReason,
    #[error("empty operator")]
    EmptyOperator,
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("artifact not available: {0}")]
    ArtifactNotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature verification failed: {0}")]
    Signature(String),
}

/// A drift/tamper alert — an endpoint's installed package version
/// differs from what DevNet expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftAlert {
    pub endpoint_id: String,
    pub package: String,
    pub expected_version: String,
    pub reported_version: String,
    pub detected_at: String,
}

/// A revocation alert — an endpoint is running a package/version that
/// has been revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationAlert {
    pub endpoint_id: String,
    pub package: String,
    pub revoked_version: String,
    pub reason: String,
    pub matched_at: String,
}

/// Represents a verified inbound bundle consumed from M4's INGEST VM,
/// ready for DevNet core to process. This is the handoff interface
/// from M4 (possibly mocked during standalone testing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVerdict {
    pub passed: bool,
    pub reason: String,
    pub bundle_path: PathBuf,
}

/// One package entry in the release queue, as tracked by M5 after
/// consuming M4's verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageState {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub ring: Ring,
    pub admin_state: AdminState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdminState {
    Pending,
    Approved(Ring),
    Rejected,
}

/// The trait that M7 (admin frontend) and M6 (endpoint agent) consume.
pub trait DevNetCoreApi {
    fn list_drift_alerts(&self) -> Vec<DriftAlert>;
    fn list_revocation_alerts(&self) -> Vec<RevocationAlert>;
    fn issue_revert_command(
        &mut self,
        endpoint_id: &str,
        package: &str,
        target_version: &str,
        operator: &str,
    ) -> Result<(), ApiError>;
    fn ingest_verified_bundle(&mut self, verdict: SandboxVerdict) -> Result<(), ApiError>;
    fn promote_ring(
        &mut self,
        package: &str,
        version: &str,
        ring: Ring,
        operator: &str,
    ) -> Result<(), ApiError>;
}

/// Drift detection: compare endpoint-reported package state against
/// the last approved inbound bundle's expected versions.
pub mod drift_detection;

/// Revocation matching: flag endpoints running revoked package versions.
pub mod revocation_matching;

/// Consumes M4's handoff (INGEST/VM output), re-verifies
/// signatures + hashes independently before promoting anything.
pub mod handoff_consumer;

/// Dispatches admin revert commands to M6 endpoint agents.
pub mod revert_dispatch;

pub mod api;
pub use api::DevNetCore;

mod tests;
