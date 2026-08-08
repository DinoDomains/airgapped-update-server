use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use airgap_transport::{UsbManifest, UsbTransport};
use airgap_sandbox::BwrapSandbox;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::Signer as _;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

#[derive(Parser, Debug)]
#[command(name = "airgap-processor")]
pub struct Cli {
    #[arg(long)]
    pub data_dir: PathBuf,

    #[arg(long)]
    pub usb_mount: PathBuf,

    #[arg(long)]
    pub microsoft_catalog_url: Option<String>,

    #[arg(long)]
    pub verify_behavior: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    pub device_id: String,
    pub package: String,
    pub family: String,
    pub required_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundle {
    pub manifest: UsbManifest,
    pub signature: String,
}

pub struct Processor {
    pub data_dir: PathBuf,
    pub usb_mount: PathBuf,
    pub usb_transport: UsbTransport,
    pub signing_key: SigningKey,
    pub verified_pkgs: Arc<RwLock<Vec<String>>>,
    pub sandbox: BwrapSandbox,
    pub verify_behavior: bool,
}

impl Processor {
    pub fn new(cli: &Cli) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&cli.data_dir)?;
        std::fs::create_dir_all(cli.data_dir.join("artifacts"))?;
        std::fs::create_dir_all(cli.data_dir.join("inventory"))?;

        let signing_key = match std::fs::read_to_string(cli.data_dir.join("signing_key")) {
            Ok(key_b64) => {
                let bytes = base64::decode(&key_b64)?;
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "invalid key length")?;
                SigningKey::from_bytes(&arr)
            }
            Err(_) => {
                let keypair = SigningKey::generate(&mut OsRng);
                let key_bytes = keypair.to_bytes();
                let key_b64 = base64::encode(key_bytes);
                std::fs::write(cli.data_dir.join("signing_key"), key_b64)?;
                keypair
            }
        };

        let sandbox = BwrapSandbox::minimal();

        Ok(Self {
            data_dir: cli.data_dir.clone(),
            usb_mount: cli.usb_mount.clone(),
            usb_transport: UsbTransport::new(cli.usb_mount.clone())?,
            signing_key,
            verified_pkgs: Arc::new(RwLock::new(Vec::new())),
            sandbox,
            verify_behavior: cli.verify_behavior,
        })
    }

    pub async fn ingest_inventory(&self) -> Result<Vec<(String, airgap_proto::OsInventory)>, Box<dyn std::error::Error>> {
        let manifest = self.read_usb_manifest()?;

        let mut inventories = Vec::new();
        if let Some(inv_bundle) = manifest.inventory {
            inventories.push((inv_bundle.device_id, inv_bundle.inventory));
        }

        if !inventories.is_empty() {
            let json = serde_json::to_string_pretty(&inventories)?;
            std::fs::write(
                self.data_dir.join("inventory").join(format!("{}.json", Utc::now().timestamp())),
                json,
            )?;
        }

        Ok(inventories)
    }

    fn read_usb_manifest(&self) -> Result<airgap_transport::UsbManifest, Box<dyn std::error::Error>> {
        let manifest_path = self.usb_mount.join("manifest.json");
        let json = std::fs::read_to_string(manifest_path)?;
        let manifest: airgap_transport::UsbManifest = serde_json::from_str(&json)?;
        Ok(manifest)
    }

    pub async fn compute_required_updates(
        &self,
        inventories: &[(String, airgap_proto::OsInventory)],
        catalog: &HashMap<String, airgap_proto::UpdateItem>,
    ) -> Vec<UpdateRequest> {
        let mut requests = Vec::new();

        for (device_id, inv) in inventories {
            let installed: std::collections::HashSet<String> = inv.packages.iter()
                .map(|p| p.name.to_lowercase())
                .collect();

            for update in catalog.values() {
                let pkg_name = update.title.to_lowercase();
                if installed.contains(&pkg_name) {
                    requests.push(UpdateRequest {
                        device_id: device_id.clone(),
                        package: update.title.clone(),
                        family: update.kind.clone(),
                        required_version: update.version.clone(),
                    });
                }
            }
        }

        requests
    }

    pub async fn download_and_verify(
        &self,
        requests: &[UpdateRequest],
        catalog: &HashMap<String, (String, String)>, // package -> (artifact_url, sha256)
    ) -> Result<Vec<airgap_transport::UpdateBundle>, Box<dyn std::error::Error>> {
        let mut bundles = Vec::new();

        for req in requests {
            info!("Processing update for {}: {}", req.device_id, req.package);

            let (artifact_url, expected_sha) = match catalog.get(&req.package.to_lowercase()) {
                Some(v) => v.clone(),
                None => {
                    warn!("No catalog entry for {}", req.package);
                    continue;
                }
            };

            let client = reqwest::Client::new();
            let resp = client.get(&artifact_url).send().await?;
            if !resp.status().is_success() {
                error!("Failed to download artifact for {}", req.package);
                continue;
            }
            let artifact_bytes = resp.bytes().await?;

            // Verify hash
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(&artifact_bytes);
            let actual_sha = hex::encode(hasher.finalize());

            if actual_sha != expected_sha {
                error!("Hash mismatch for {}: got {}, expected {}", req.package, actual_sha, expected_sha);
                continue;
            }

            let artifact_path = self.data_dir.join("artifacts").join(format!("{}_{}", req.device_id, req.package));
            std::fs::write(&artifact_path, &artifact_bytes)?;

            // Behavior verification in sandbox
            if self.verify_behavior {
                if let Err(e) = airgap_sandbox::extract_and_analyze(&self.sandbox, &artifact_path, Some(&expected_sha)) {
                    error!("Verification failed for {}: {}", req.package, e);
                    continue;
                }
            }

            let bundle = airgap_transport::UpdateBundle {
                update_id: format!("{}-{}-{}", req.device_id, req.package, Utc::now().timestamp()),
                device_id: req.device_id.clone(),
                package: req.package.clone(),
                version: req.required_version.clone(),
                artifact_sha256: actual_sha,
                artifact_path: artifact_path.to_string_lossy().to_string(),
                signature: String::new(),
            };
            bundles.push(bundle);
        }

        // Sign bundles
        for bundle in &mut bundles {
            let manifest_json = serde_json::to_vec(&bundle)?;
            let signature = self.signing_key.sign(&manifest_json);
            bundle.signature = base64::encode(signature.to_bytes());
        }

        if !bundles.is_empty() {
            self.usb_transport.write_updates(bundles.clone())?;
            info!("Wrote {} bundles to USB manifest", bundles.len());
        }

        Ok(bundles)
    }

    pub async fn verify_signature(bundle: &airgap_transport::UpdateBundle, pub_key_bytes: &[u8]) -> bool {
        let arr: [u8; 32] = match pub_key_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let pubkey = match VerifyingKey::from_bytes(&arr) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_bytes = match base64::decode(&bundle.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let manifest_json = match serde_json::to_vec(bundle) {
            Ok(j) => j,
            Err(_) => return false,
        };
        pubkey.verify(&manifest_json, &sig).is_ok()
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let inventories = self.ingest_inventory().await?;
        if inventories.is_empty() {
            info!("No inventory found - waiting...");
            return Ok(());
        }

        let catalog: HashMap<String, airgap_proto::UpdateItem> = HashMap::new();
        let catalog_urls: HashMap<String, (String, String)> = HashMap::new();

        let requests = self.compute_required_updates(&inventories, &catalog).await;
        if requests.is_empty() {
            info!("No updates required");
            return Ok(());
        }

        let bundles = self.download_and_verify(&requests, &catalog_urls).await?;
        if bundles.is_empty() {
            warn!("No bundles produced");
            return Ok(());
        }

        Ok(())
    }
}

pub async fn run_processor(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let processor = Processor::new(&cli)?;
    processor.run().await
}