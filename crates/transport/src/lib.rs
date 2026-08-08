use std::path::PathBuf;
use std::sync::Arc;

use airgap_proto::{OsInventory, PollRequest, PollResponse, ReportRequest, UpdateItem};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] airgap_sandbox::SandboxError),
    #[error("Certificate error: {0}")]
    Cert(String),
    #[error("Not connected")]
    NotConnected,
    #[error("USB device not found: {0}")]
    UsbNotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbManifest {
    pub version: u32,
    pub created_at: String,
    pub source: String,
    pub target: String,
    pub inventory: Option<InventoryBundle>,
    pub updates: Vec<UpdateBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryBundle {
    pub device_id: String,
    pub inventory: OsInventory,
    pub collected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateBundle {
    pub update_id: String,
    pub device_id: String,
    pub package: String,
    pub version: String,
    pub artifact_sha256: String,
    pub artifact_path: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct MtlConfig {
    pub server_url: String,
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

pub struct WiredTransport {
    config: MtlConfig,
    client: Arc<Mutex<Option<Client>>>,
}

impl WiredTransport {
    pub fn new(config: MtlConfig) -> Result<Self, TransportError> {
        Ok(Self {
            config,
            client: Arc::new(Mutex::new(None)),
        })
    }

    async fn get_client(&self) -> Result<Client, TransportError> {
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }

        let ca_pem = tokio::fs::read_to_string(&self.config.ca_cert).await?;
        let ca_cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;

        let cert_pem = tokio::fs::read_to_string(&self.config.client_cert).await?;
        let key_pem = tokio::fs::read_to_string(&self.config.client_key).await?;
        let identity = reqwest::Identity::from_pem(
            format!("{cert_pem}\n{key_pem}").as_bytes(),
        )?;

        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()?;

        *guard = Some(client.clone());
        Ok(client)
    }

    pub async fn send_inventory(&self, device_id: &str, inventory: OsInventory) -> Result<(), TransportError> {
        let client = self.get_client().await?;
        let url = format!("{}/inventory", self.config.server_url.trim_end_matches('/'));
        
        let req = airgap_proto::InventoryRequest {
            agent_id: device_id.to_string(),
            inventory,
        };

        let resp = client.post(&url).json(&req).send().await?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(resp.error_for_status().unwrap_err()));
        }
        Ok(())
    }

    pub async fn poll_updates(&self, device_id: &str) -> Result<Vec<UpdateItem>, TransportError> {
        let client = self.get_client().await?;
        let url = format!("{}/updates", self.config.server_url.trim_end_matches('/'));
        
        let req = PollRequest {
            agent_id: device_id.to_string(),
        };

        let resp: PollResponse = client.post(&url).json(&req).send().await?.json().await?;
        Ok(resp.updates)
    }

    pub async fn report_status(&self, device_id: &str, update_id: &str, code: &str, detail: &str) -> Result<(), TransportError> {
        let client = self.get_client().await?;
        let url = format!("{}/report", self.config.server_url.trim_end_matches('/'));
        
        let req = ReportRequest {
            agent_id: device_id.to_string(),
            update_id: update_id.to_string(),
            status: airgap_proto::ReportStatus {
                code: code.to_string(),
                detail: detail.to_string(),
            },
        };

        let resp = client.post(&url).json(&req).send().await?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(resp.error_for_status().unwrap_err()));
        }
        Ok(())
    }

    pub async fn fetch_artifact(&self, device_id: &str, update_id: &str, family: &str) -> Result<Vec<u8>, TransportError> {
        let client = self.get_client().await?;
        let url = format!("{}/artifact", self.config.server_url.trim_end_matches('/'));
        
        let req = airgap_proto::ArtifactRequest {
            agent_id: device_id.to_string(),
            update_id: update_id.to_string(),
            family: family.to_string(),
        };

        let resp = client.post(&url).json(&req).send().await?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(resp.error_for_status().unwrap_err()));
        }
        Ok(resp.bytes().await?.to_vec())
    }
}

#[derive(Clone)]
pub struct UsbTransport {
    mount_point: PathBuf,
}

impl UsbTransport {
    pub fn new(mount_point: PathBuf) -> Result<Self, TransportError> {
        Ok(Self { mount_point })
    }

    pub fn detect_usb(&self) -> Result<PathBuf, TransportError> {
        let entries = std::fs::read_dir(&self.mount_point)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join("manifest.json").exists() {
                return Ok(path);
            }
        }
        Err(TransportError::UsbNotFound("no valid airgap bundle found".into()))
    }

    pub fn write_inventory(&self, device_id: &str, inventory: airgap_proto::OsInventory) -> Result<(), TransportError> {
        let bundle = UsbManifest {
            version: 1,
            created_at: Utc::now().to_rfc3339(),
            source: device_id.to_string(),
            target: "update-server".to_string(),
            inventory: Some(InventoryBundle {
                device_id: device_id.to_string(),
                inventory,
                collected_at: Utc::now().to_rfc3339(),
            }),
            updates: vec![],
        };

        let usb_path = self.detect_usb()?;
        let manifest_path = usb_path.join("manifest.json");
        let json = serde_json::to_vec_pretty(&bundle)?;
        std::fs::write(manifest_path, json)?;
        Ok(())
    }

    pub fn read_updates(&self) -> Result<Vec<UpdateBundle>, TransportError> {
        let usb_path = self.detect_usb()?;
        let manifest_path = usb_path.join("manifest.json");
        let json = std::fs::read_to_string(manifest_path)?;
        let manifest: UsbManifest = serde_json::from_str(&json)?;
        
        // Verify signatures (simplified - would use actual crypto)
        for update in &manifest.updates {
            // verify_signature(&update)?; // TODO: implement
        }

        Ok(manifest.updates)
    }

    pub fn write_updates(&self, updates: Vec<UpdateBundle>) -> Result<(), TransportError> {
        let usb_path = self.detect_usb()?;
        let manifest_path = usb_path.join("manifest.json");
        
        let mut manifest = if manifest_path.exists() {
            let json = std::fs::read_to_string(&manifest_path)?;
            serde_json::from_str::<UsbManifest>(&json)?
        } else {
            UsbManifest {
                version: 1,
                created_at: Utc::now().to_rfc3339(),
                source: "update-server".to_string(),
                target: "devnet-collector".to_string(),
                inventory: None,
                updates: vec![],
            }
        };

        manifest.updates.extend(updates);
        manifest.created_at = Utc::now().to_rfc3339();

        let json = serde_json::to_vec_pretty(&manifest)?;
        std::fs::write(manifest_path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_manifest_serialization() {
        let manifest = UsbManifest {
            version: 1,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            source: "test".to_string(),
            target: "test".to_string(),
            inventory: None,
            updates: vec![],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: UsbManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
    }
}