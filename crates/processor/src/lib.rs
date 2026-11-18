//! M3 — Update Server core (the only online host). PLAN.md §2.1.
//!
//! Cycle (owned build steps 3 + 6):
//!   1. Read the OUTBOUND drive (drive attestation + export-key signature
//!      verify) → DevNet inventory.              (OutboundBundle::read_and_verify)
//!   2. Compute what DevNet actually needs against the vendor catalog.
//!   3. Download each artifact, hash-verify, optionally behavior-test in
//!      the bwrap sandbox.
//!   4. Record the release queue (package + behavior verdict) for M7.
//!   5. Build + sign the INBOUND bundle (catalog + manifest + artifacts)
//!      and write it to the INBOUND drive.       (InboundBundle::write)

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use airgap_contracts::{
    BehaviorVerdict, Direction, DriveAttestation, InboundBundle, InboundCatalog, OutboundBundle,
    OutboundInventory, Release, Revocation, sha256_file,
};
use airgap_keys::{KeyManager, KeyRole};
use chrono::Utc;
use clap::Parser;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("contract error: {0}")]
    Contract(#[from] airgap_contracts::ContractError),
    #[error("key error: {0}")]
    Key(#[from] airgap_keys::KeyError),
    #[error("sandbox error: {0}")]
    Sandbox(#[from] airgap_sandbox::SandboxError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("download error: {0}")]
    Download(String),
    #[error("no OUTBOUND drive found at {0}")]
    NoOutboundDrive(PathBuf),
    #[error("no INBOUND drive configured")]
    NoInboundDrive,
}

#[derive(Parser, Debug)]
#[command(name = "airgap-processor")]
pub struct Cli {
    /// Working data dir (state, downloads, release queue)
    #[arg(long)]
    pub data_dir: PathBuf,

    /// Key manager dir (holds the Update Server release key)
    #[arg(long)]
    pub key_dir: PathBuf,

    /// Mount root that contains the OUTBOUND drive
    #[arg(long)]
    pub outbound_mount: PathBuf,

    /// Expected OUTBOUND drive id (attestation)
    #[arg(long)]
    pub outbound_drive_id: String,

    /// Mount root that contains the INBOUND drive
    #[arg(long)]
    pub inbound_mount: Option<PathBuf>,

    /// Expected INBOUND drive id (attestation)
    #[arg(long, default_value = "")]
    pub inbound_drive_id: String,

    /// Vendor catalog JSON (package -> {family, version, artifact_url, sha256, behavior_applicable})
    #[arg(long)]
    pub catalog: Option<PathBuf>,

    /// Run behavior testing (bwrap + extraction/static analysis) per artifact
    #[arg(long)]
    pub verify_behavior: bool,

    /// Write the release queue even if the catalog is absent (debug/dev)
    #[arg(long)]
    pub dry_run: bool,
}

/// A vendor entry describing an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorEntry {
    pub family: String,
    pub version: String,
    pub artifact_url: String,
    pub sha256: String,
    #[serde(default = "default_true")]
    pub behavior_applicable: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VendorCatalog {
    pub schema_version: u32,
    pub packages: HashMap<String, VendorEntry>,
}

/// One queued release awaiting admin decision (consumed by M7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedRelease {
    pub package: String,
    pub family: String,
    pub version: String,
    pub sha256: String,
    pub artifact_path: PathBuf,
    pub behavior_verdict: BehaviorVerdict,
    pub hash_status: String, // "pass" | "fail"
    pub queued_at: String,
}

pub struct Processor {
    pub data_dir: PathBuf,
    pub outbound_mount: PathBuf,
    pub outbound_drive_id: String,
    pub inbound_mount: Option<PathBuf>,
    pub inbound_drive_id: String,
    pub keys: KeyManager,
    pub sandbox: airgap_sandbox::BwrapSandbox,
    pub verify_behavior: bool,
    /// Last consumed session per drive, persisted so replays are rejected
    /// across runs.
    pub last_session: Arc<RwLock<HashMap<String, u64>>>,
}

impl Processor {
    pub fn new(cli: &Cli) -> Result<Self, ProcessorError> {
        fs::create_dir_all(&cli.data_dir)?;
        fs::create_dir_all(&cli.data_dir.join("downloads"))?;
        fs::create_dir_all(&cli.data_dir.join("artifacts"))?;

        let keys = KeyManager::new(&cli.key_dir)?;
        let sandbox = airgap_sandbox::BwrapSandbox::minimal();

        let last_session = load_last_session(&cli.data_dir)?;

        Ok(Self {
            data_dir: cli.data_dir.clone(),
            outbound_mount: cli.outbound_mount.clone(),
            outbound_drive_id: cli.outbound_drive_id.clone(),
            inbound_mount: cli.inbound_mount.clone(),
            inbound_drive_id: cli.inbound_drive_id.clone(),
            keys,
            sandbox,
            verify_behavior: cli.verify_behavior,
            last_session: Arc::new(RwLock::new(last_session)),
        })
    }

    /// Step 1: read + fully verify the OUTBOUND drive.
    pub async fn read_outbound(&self) -> Result<OutboundBundle, ProcessorError> {
        let last = self
            .last_session
            .read()
            .await
            .get(&self.outbound_drive_id)
            .copied()
            .unwrap_or(0);

        let export_pub = self.keys.load_verifying_key(KeyRole::Export)?;

        let bundle = OutboundBundle::read_and_verify(
            &self.outbound_mount,
            &self.outbound_drive_id,
            last,
            &export_pub,
        )
        .map_err(|e| match e {
            airgap_contracts::ContractError::Missing(_) => {
                ProcessorError::NoOutboundDrive(self.outbound_mount.clone())
            }
            other => ProcessorError::Contract(other),
        })?;

        // Remember this session to reject replays.
        let mut guard = self.last_session.write().await;
        guard.insert(self.outbound_drive_id.clone(), bundle.attestation.session);
        save_last_session(&self.data_dir, &guard)?;

        Ok(bundle)
    }

    /// Step 2: given DevNet inventory + vendor catalog, compute what is
    /// needed. Installed packages that have a catalog entry are candidates;
    /// Windows devices additionally pull catalog entries for their
    /// family/arch that aren't yet installed (cumulative KBs supersede
    /// earlier ones, so a new KB is a valid update target).
    pub fn compute_required(
        &self,
        inventory: &OutboundInventory,
        catalog: &VendorCatalog,
    ) -> Vec<(String, String, VendorEntry)> {
        let mut required: Vec<(String, String, VendorEntry)> = Vec::new();
        for device in &inventory.devices {
            let installed: Vec<String> = device
                .packages
                .iter()
                .map(|p| p.name.to_lowercase())
                .collect();
            for (key, entry) in &catalog.packages {
                let name = key.clone();
                let matches_family = device.distro_family.to_lowercase() == entry.family.to_lowercase();
                if installed.contains(key) {
                    let pkg = device
                        .packages
                        .iter()
                        .find(|p| p.name.to_lowercase() == name)
                        .unwrap();
                    required.push((pkg.name.clone(), device.device_id.clone(), entry.clone()));
                } else if matches_family && entry.family.eq_ignore_ascii_case("windows") {
                    required.push((name, device.device_id.clone(), entry.clone()));
                }
            }
        }
        // De-dup by package name.
        let mut seen = std::collections::HashSet::new();
        required.retain(|(name, _, _)| seen.insert(name.clone()));
        required
    }

    /// Step 3: download an artifact, hash-verify, optionally behavior-test.
    pub async fn fetch_and_verify(
        &self,
        package: &str,
        device_id: &str,
        entry: &VendorEntry,
    ) -> Result<QueuedRelease, ProcessorError> {
        let artifact_path = self
            .data_dir
            .join("downloads")
            .join(format!("{}_{}", device_id, package));

        info!("downloading {} from {}", package, entry.artifact_url);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| ProcessorError::Download(e.to_string()))?;
        let resp = client
            .get(&entry.artifact_url)
            .send()
            .await
            .map_err(|e| ProcessorError::Download(format!("{package}: {e}")))?;
        if !resp.status().is_success() {
            return Err(ProcessorError::Download(format!(
                "{package}: HTTP {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ProcessorError::Download(format!("{package}: {e}")))?;
        fs::write(&artifact_path, &bytes)?;

        let actual = sha256_file(&artifact_path)?;
        let hash_ok = actual == entry.sha256;
        if !hash_ok {
            warn!(
                "hash mismatch for {package}: got {actual}, expected {}",
                entry.sha256
            );
        }

        // Behavior gate (only when hash passed).
        let verdict = if hash_ok && self.verify_behavior && entry.behavior_applicable {
            match airgap_sandbox::extract_and_analyze(
                &self.sandbox,
                &artifact_path,
                Some(&entry.sha256),
            ) {
                Ok(_) => BehaviorVerdict::BehaviorTested,
                Err(airgap_sandbox::SandboxError::VerificationFailed(msg)) => {
                    if msg.contains("suspicious") {
                        BehaviorVerdict::Suspicious
                    } else {
                        BehaviorVerdict::Failed
                    }
                }
                Err(e) => {
                    error!("behavior test error for {package}: {e}");
                    BehaviorVerdict::Failed
                }
            }
        } else if hash_ok {
            // hash-verified only (behavior not applicable or not requested)
            BehaviorVerdict::HashVerifiedOnly
        } else {
            BehaviorVerdict::Failed
        };

        Ok(QueuedRelease {
            package: package.to_string(),
            family: entry.family.clone(),
            version: entry.version.clone(),
            sha256: actual,
            artifact_path,
            behavior_verdict: verdict,
            hash_status: if hash_ok { "pass".into() } else { "fail".into() },
            queued_at: Utc::now().to_rfc3339(),
        })
    }

    /// Write the release queue JSON for M7 (admin frontend).
    pub fn write_release_queue(&self, queue: &[QueuedRelease]) -> Result<(), ProcessorError> {
        let path = self.data_dir.join("release-queue.json");
        fs::write(&path, serde_json::to_vec_pretty(queue)?)?;
        Ok(())
    }

    /// Step 5: build + sign the INBOUND bundle and write it to the INBOUND
    /// drive. `session` is the OUTBOUND session (advances it). Only
    /// `approved` releases go in; revoked versions are excluded.
    pub async fn build_inbound(
        &self,
        session: u64,
        approved: &[QueuedRelease],
        revocations: &[Revocation],
    ) -> Result<InboundBundle, ProcessorError> {
        let inbound_mount = self
            .inbound_mount
            .clone()
            .ok_or(ProcessorError::NoInboundDrive)?;

        // Stage artifacts into a temp dir, then let InboundBundle::write copy.
        let stage = self.data_dir.join("inbound-stage");
        fs::create_dir_all(&stage)?;

        let mut releases = Vec::new();
        for q in approved {
            if q.hash_status != "pass" {
                warn!("skipping {0}: hash {1}", q.package, q.hash_status);
                continue;
            }
            // Copy artifact into stage dir.
            let fname = format!("{}-{}.pkg", q.package, q.version);
            let dest = stage.join(&fname);
            fs::copy(&q.artifact_path, &dest)?;

            releases.push(Release {
                update_id: format!("{}-{}", q.package, q.version),
                package: q.package.clone(),
                distro_family: q.family.clone(),
                version: q.version.clone(),
                ring: "prod".into(),
                artifact: format!("artifacts/{fname}"),
                sha256: q.sha256.clone(),
                behavior_verdict: q.behavior_verdict,
                tested_at: Utc::now(),
            });
        }

        let catalog = InboundCatalog {
            schema_version: airgap_contracts::SCHEMA_VERSION,
            session,
            releases,
            revocations: revocations.to_vec(),
        };

        let attestation = DriveAttestation::new(
            self.inbound_drive_id.clone(),
            Direction::Inbound,
            session,
        );

        let bundle = InboundBundle::build_from(&catalog, &attestation, &stage)?;

        let release_key = self.keys.load_signing_key(KeyRole::Release)?;
        bundle.write(&inbound_mount, &stage, &release_key)?;

        // Advance inbound session.
        let mut guard = self.last_session.write().await;
        guard.insert(self.inbound_drive_id.clone(), session);
        save_last_session(&self.data_dir, &guard)?;

        Ok(bundle)
    }

    /// Full cycle: read OUTBOUND → compute → fetch/verify → queue → build
    /// INBOUND. `approve_all` bypasses the (not-yet-built) M7 frontend gate
    /// so the pipeline can be exercised end to end in the lab.
    pub async fn run(
        &self,
        catalog: &VendorCatalog,
        approve_all: bool,
    ) -> Result<(), ProcessorError> {
        let outbound = self.read_outbound().await?;
        info!(
            "read OUTBOUND session {} from {} ({} devices)",
            outbound.attestation.session,
            outbound.attestation.drive_id,
            outbound.inventory.devices.len()
        );

        let required = self.compute_required(&outbound.inventory, catalog);
        info!("{} packages needed", required.len());

        let mut queue = Vec::new();
        for (package, device_id, entry) in &required {
            match self.fetch_and_verify(package, device_id, entry).await {
                Ok(q) => queue.push(q),
                Err(e) => warn!("failed to process {package}: {e}"),
            }
        }

        self.write_release_queue(&queue)?;

        if approve_all {
            let bundle = self.build_inbound(outbound.attestation.session, &queue, &[]).await?;
            info!(
                "INBOUND bundle session {} written: {} releases",
                bundle.attestation.session,
                bundle.catalog.releases.len()
            );
        } else {
            info!("{} queued; awaiting admin approval (M7)", queue.len());
        }
        Ok(())
    }
}

fn load_last_session(data_dir: &Path) -> Result<HashMap<String, u64>, ProcessorError> {
    let path = data_dir.join("sessions.json");
    match fs::read_to_string(&path) {
        Ok(json) => Ok(serde_json::from_str(&json)?),
        Err(_) => Ok(HashMap::new()),
    }
}

fn save_last_session(
    data_dir: &Path,
    sessions: &HashMap<String, u64>,
) -> Result<(), ProcessorError> {
    let path = data_dir.join("sessions.json");
    fs::write(&path, serde_json::to_vec_pretty(sessions)?)?;
    Ok(())
}

pub async fn run_processor(cli: Cli) -> Result<(), ProcessorError> {
    let processor = Processor::new(&cli)?;

    let catalog = match &cli.catalog {
        Some(path) => {
            let json = fs::read_to_string(path)?;
            serde_json::from_str(&json)?
        }
        None => VendorCatalog::default(),
    };

    if cli.dry_run {
        // Just verify the OUTBOUND drive and report; don't fetch anything.
        let outbound = processor.read_outbound().await?;
        let required = processor.compute_required(&outbound.inventory, &catalog);
        println!(
            "OUTBOUND session {}: {} devices, {} required",
            outbound.attestation.session,
            outbound.inventory.devices.len(),
            required.len()
        );
        return Ok(());
    }

    processor.run(&catalog, true).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use airgap_contracts::{
        DeviceInventory, DriveAttestation, InstalledPackage, OutboundInventory,
    };
    use airgap_keys::KeyRole;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tmp(name: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!("airgap-proc-{}-{}-{}", std::process::id(), name, n))
    }

    #[tokio::test]
    async fn full_outbound_to_inbound_cycle() {
        let root = tmp("cycle");
        let devnet_keys = KeyManager::new(root.join("devnet-keys")).unwrap();
        let upd_keys = KeyManager::new(root.join("upd-keys")).unwrap();
        let (_sk, export_pub) = devnet_keys.provision(KeyRole::Export, "devnet").unwrap();
        let (release_sk, _) = upd_keys.provision(KeyRole::Release, "updatesrv").unwrap();
        // update server imports devnet's export pub key
        upd_keys
            .import_public_key_b64(
                KeyRole::Export,
                &devnet_keys.export_public_key_b64(KeyRole::Export).unwrap(),
                "devnet",
            )
            .unwrap();

        // OUTBOUND drive: devnet writes inventory
        let outbound_drive = root.join("outbound-usb");
        fs::create_dir_all(&outbound_drive).unwrap();
        let mut inv = OutboundInventory::new("devnet-1");
        inv.devices.push(DeviceInventory {
            device_id: "endpoint-07".into(),
            hostname: "ws-07".into(),
            distro_family: "windows".into(),
            arch: "x86_64".into(),
            packages: vec![InstalledPackage {
                name: "kb5039227".into(),
                version: "20348.587".into(),
                installed_sha256: "aaaa".into(),
            }],
        });
        let out = OutboundBundle {
            attestation: DriveAttestation::new("USB-OUT-01", Direction::Outbound, 7),
            inventory: inv,
        };
        out.write(&outbound_drive, &devnet_keys.load_signing_key(KeyRole::Export).unwrap())
            .unwrap();

        // Vendor artifact to "download" (serve over local file via http? we use a
        // real URL; instead stage artifact and record sha256).
        let artifact_bytes = b"fake-msu-bytes";
        let artifact_path = root.join("vendor/kb5039227-x64.msu");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, artifact_bytes).unwrap();
        let artifact_sha = sha256_file(&artifact_path).unwrap();

        // Serve the artifact over a tiny local HTTP server so the download path
        // is exercised for real.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let artifact_bytes = artifact_bytes.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 65536];
            let _n = stream.read(&mut buf).await.unwrap();
            let body = artifact_bytes.clone();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });

        let catalog = VendorCatalog {
            schema_version: 1,
            packages: {
                let mut m = HashMap::new();
                m.insert(
                    "kb5039227".into(),
                    VendorEntry {
                        family: "windows".into(),
                        version: "20348.2527".into(),
                        artifact_url: format!("http://{addr}/kb5039227-x64.msu"),
                        sha256: artifact_sha.clone(),
                        behavior_applicable: false,
                    },
                );
                m
            },
        };

        // Processor (Update Server side)
        let processor = Processor {
            data_dir: root.join("data"),
            outbound_mount: outbound_drive.clone(),
            outbound_drive_id: "USB-OUT-01".into(),
            inbound_mount: Some(root.join("inbound-usb")),
            inbound_drive_id: "USB-IN-02".into(),
            keys: upd_keys,
            sandbox: airgap_sandbox::BwrapSandbox::minimal(),
            verify_behavior: false,
            last_session: Arc::new(RwLock::new(HashMap::new())),
        };
        fs::create_dir_all(processor.data_dir.clone()).unwrap();
        fs::create_dir_all(processor.data_dir.join("downloads")).unwrap();
        fs::create_dir_all(processor.data_dir.join("artifacts")).unwrap();

        let res = processor.run(&catalog, true).await;
        server.await.unwrap();
        if let Err(e) = res {
            panic!("run failed: {e:?}");
        }
        // Release queue written for M7.
        let queue: Vec<QueuedRelease> = serde_json::from_slice(
            &fs::read(processor.data_dir.join("release-queue.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(queue.len(), 1);

        // Verify the INBOUND drive.
        let inbound_drive = root.join("inbound-usb");
        let bundle = InboundBundle::read_and_verify(
            &inbound_drive,
            "USB-IN-02",
            6,
            &release_sk.verifying_key(),
        )
        .unwrap();
        assert_eq!(bundle.catalog.releases.len(), 1);
        assert_eq!(bundle.catalog.releases[0].package, "kb5039227");
        assert_eq!(bundle.catalog.releases[0].version, "20348.2527");
        assert_eq!(bundle.catalog.releases[0].sha256, artifact_sha);

        // Release queue written for M7.
        let queue: Vec<QueuedRelease> = serde_json::from_slice(
            &fs::read(processor.data_dir.join("release-queue.json")).unwrap(),
        )
        .unwrap();
        eprintln!("QUEUE: {queue:?}");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].hash_status, "pass");
        assert_eq!(queue[0].behavior_verdict, BehaviorVerdict::HashVerifiedOnly);

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn replay_of_outbound_session_is_rejected() {
        let root = tmp("replay");
        let devnet_keys = KeyManager::new(root.join("devnet-keys")).unwrap();
        let upd_keys = KeyManager::new(root.join("upd-keys")).unwrap();
        devnet_keys.provision(KeyRole::Export, "devnet").unwrap();
        upd_keys.provision(KeyRole::Release, "updatesrv").unwrap();
        upd_keys
            .import_public_key_b64(
                KeyRole::Export,
                &devnet_keys.export_public_key_b64(KeyRole::Export).unwrap(),
                "devnet",
            )
            .unwrap();

        let outbound_drive = root.join("outbound-usb");
        fs::create_dir_all(&outbound_drive).unwrap();
        let out = OutboundBundle {
            attestation: DriveAttestation::new("USB-OUT-01", Direction::Outbound, 7),
            inventory: OutboundInventory::new("devnet-1"),
        };
        out.write(&outbound_drive, &devnet_keys.load_signing_key(KeyRole::Export).unwrap())
            .unwrap();

        let processor = Processor {
            data_dir: root.join("data"),
            outbound_mount: outbound_drive.clone(),
            outbound_drive_id: "USB-OUT-01".into(),
            inbound_mount: None,
            inbound_drive_id: String::new(),
            keys: upd_keys,
            sandbox: airgap_sandbox::BwrapSandbox::minimal(),
            verify_behavior: false,
            last_session: Arc::new(RwLock::new(HashMap::new())),
        };
        fs::create_dir_all(processor.data_dir.clone()).unwrap();

        // First read succeeds and records session 7.
        processor.read_outbound().await.unwrap();
        // Second read of the SAME session is a replay -> rejected.
        let res = processor.read_outbound().await;
        assert!(matches!(
            res,
            Err(ProcessorError::Contract(airgap_contracts::ContractError::Attestation(_)))
        ));

        let _ = fs::remove_dir_all(&root);
    }
}
