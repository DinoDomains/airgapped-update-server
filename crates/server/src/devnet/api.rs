use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use airgap_contracts::{InboundCatalog, InstalledPackage, Revocation};
use tokio::sync::RwLock;

use crate::audit::AuditLog;
use crate::store::Store;
use crate::devnet::{
    ApiError, DevNetCoreApi, DriftAlert, PackageState, RevocationAlert, Ring, SandboxVerdict,
};
use crate::devnet::{drift_detection, handoff_consumer, revert_dispatch, revocation_matching};

pub use revert_dispatch::{RevertCommand, RevertOutcome};

/// The DevNet Core server — extends the existing wired server with
/// DevNet-specific logic: drift detection, revocation matching, handoff
/// consumption, and revert dispatch.
pub struct DevNetCore {
    /// Reuse the existing wired store for agent records and inventory.
    store: Arc<Store>,
    /// Reuse the existing audit log.
    pub audit: Arc<AuditLog>,
    /// Last approved inbound catalog (from the most recent USB round trip).
    pub last_catalog: Arc<RwLock<Option<InboundCatalog>>>,
    /// Pending drift alerts accumulated from the last scan cycle.
    pub drift_alerts: Arc<RwLock<Vec<DriftAlert>>>,
    /// Pending revocation alerts.
    pub revocation_alerts: Arc<RwLock<Vec<RevocationAlert>>>,
    /// Pending package states awaiting ring promotion.
    pub packages: Arc<RwLock<Vec<PackageState>>>,
    /// Path to the store dir (for persisting alerts).
    pub store_dir: PathBuf,
}

impl DevNetCore {
    pub fn new(store: Arc<Store>, audit: Arc<AuditLog>, store_dir: PathBuf) -> Self {
        Self {
            store,
            audit,
            last_catalog: Arc::new(RwLock::new(None)),
            drift_alerts: Arc::new(RwLock::new(Vec::new())),
            revocation_alerts: Arc::new(RwLock::new(Vec::new())),
            packages: Arc::new(RwLock::new(Vec::new())),
            store_dir,
        }
    }

    /// Run drift detection across all registered agents.
    /// Compares each agent's reported inventory against the last approved
    /// inbound catalog's expected versions.
    pub async fn scan_for_drift(&self) -> Vec<DriftAlert> {
        let catalog = self.last_catalog.read().await.clone();
        let Some(catalog) = catalog else {
            return Vec::new();
        };

        let expected = drift_detection::build_expected_versions(&catalog);
        let mut all_alerts = Vec::new();

        let agents = self.store.list_agents().await;
        for agent in agents {
            if let Some(inv) = &agent.inventory {
                // Map OsInventory packages to InstalledPackage for matching.
                let reported: Vec<InstalledPackage> = inv.packages.iter().map(|p| {
                    InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        installed_sha256: String::new(),
                    }
                }).collect();

                let alerts = drift_detection::detect_drift_from_inventory(
                    &agent.agent_id,
                    &reported,
                    &expected,
                );
                all_alerts.extend(alerts);
            }
        }

        // Store the new alerts (replacing old ones).
        {
            let mut guard = self.drift_alerts.write().await;
            *guard = all_alerts.clone();
        }

        all_alerts
    }

    /// Run revocation matching across all registered agents.
    pub async fn scan_for_revocations(&self) -> Vec<RevocationAlert> {
        let catalog = self.last_catalog.read().await.clone();
        let Some(catalog) = catalog else {
            return Vec::new();
        };

        let mut endpoints: Vec<(String, Vec<InstalledPackage>)> = Vec::new();
        let agents = self.store.list_agents().await;
        for agent in agents {
            if let Some(inv) = &agent.inventory {
                let pkgs: Vec<InstalledPackage> = inv.packages.iter().map(|p| {
                    InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        installed_sha256: String::new(),
                    }
                }).collect();
                endpoints.push((agent.agent_id.clone(), pkgs));
            }
        }

        let alerts = revocation_matching::match_all_endpoints(&endpoints, &catalog.revocations);

        {
            let mut guard = self.revocation_alerts.write().await;
            *guard = alerts.clone();
        }

        alerts
    }
}

impl DevNetCoreApi for DevNetCore {
    fn list_drift_alerts(&self) -> Vec<DriftAlert> {
        // Note: this is a sync method per the trait signature.
        // In practice, callers should use scan_for_drift (async) and
        // read the stored results. This method returns a snapshot.
        futures::executor::block_on(async {
            self.drift_alerts.read().await.clone()
        })
    }

    fn list_revocation_alerts(&self) -> Vec<RevocationAlert> {
        futures::executor::block_on(async {
            self.revocation_alerts.read().await.clone()
        })
    }

    fn issue_revert_command(
        &mut self,
        endpoint_id: &str,
        package: &str,
        target_version: &str,
        operator: &str,
    ) -> Result<(), ApiError> {
        if operator.is_empty() {
            return Err(ApiError::EmptyOperator);
        }

        futures::executor::block_on(async {
            let cmd = revert_dispatch::dispatch_revert(
                &self.store,
                &self.audit,
                endpoint_id,
                package,
                target_version,
                operator,
            ).await?;

            // Persist the revert command for M6 to pick up.
            let cmd_dir = self.store_dir.join("revert-commands");
            std::fs::create_dir_all(&cmd_dir).map_err(ApiError::Io)?;
            let cmd_path = cmd_dir.join(format!("{}.json", cmd.command_id));
            let json = serde_json::to_string_pretty(&cmd)
                .map_err(|e| ApiError::VerificationFailed(e.to_string()))?;
            std::fs::write(cmd_path, json).map_err(ApiError::Io)?;

            Ok(())
        })
    }

    fn ingest_verified_bundle(&mut self, verdict: SandboxVerdict) -> Result<(), ApiError> {
        futures::executor::block_on(async {
            let drive_id = std::fs::read_to_string(verdict.bundle_path.join("drive_id.txt"))
                .map(|s| s.trim().to_string())
                .map_err(|e| {
                    ApiError::VerificationFailed(format!("drive_id.txt unreadable: {e}"))
                })?;
            let bundle = airgap_contracts::InboundBundle::read_and_verify(
                &verdict.bundle_path,
                &drive_id,
                0, // session check delegated to M4
                // The release public key — we need to load it from key management
                &load_release_verifying_key(&self.store_dir)?,
            ).map_err(|e| ApiError::VerificationFailed(e.to_string()))?;

            let catalog = handoff_consumer::process_verified_bundle(
                &verdict,
                &verdict.bundle_path,
                &load_release_verifying_key(&self.store_dir)?,
            )?;

            // Store the catalog as the new "last approved".
            *self.last_catalog.write().await = Some(catalog);

            Ok(())
        })
    }

    fn promote_ring(
        &mut self,
        package: &str,
        version: &str,
        ring: Ring,
        operator: &str,
    ) -> Result<(), ApiError> {
        if operator.is_empty() {
            return Err(ApiError::EmptyOperator);
        }

        self.audit.log(
            operator,
            "promote_ring",
            &format!("{package}:{version}"),
            &format!("{:?}", ring),
        );

        let mut guard = futures::executor::block_on(self.packages.write());
        for pkg in guard.iter_mut() {
            if pkg.name == package && pkg.version == version {
                pkg.ring = ring;
                pkg.admin_state = super::AdminState::Approved(ring);
                return Ok(());
            }
        }
        Err(ApiError::PackageNotFound(package.to_string()))
    }
}

pub fn load_release_verifying_key(store_dir: &PathBuf) -> Result<ed25519_dalek::VerifyingKey, ApiError> {
    let key_path = store_dir.join("release-verifying-key.pub");
    let b64 = std::fs::read_to_string(&key_path)
        .map_err(|_| ApiError::ArtifactNotFound(format!("release public key not found at {}", key_path.display())))?;
    let bytes = base64::decode(b64.trim())
        .map_err(|e| ApiError::VerificationFailed(format!("invalid base64 public key: {e}")))?;
    ed25519_dalek::VerifyingKey::from_bytes(
        &bytes
            .try_into()
            .map_err(|_| ApiError::VerificationFailed("public key not 32 bytes".into()))?,
    )
    .map_err(|e| ApiError::VerificationFailed(e.to_string()))
}
