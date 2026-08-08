//! M2 — key management & PKI for the air-gap pipeline (PLAN.md §5.5).
//!
//! Two signing keys are in play:
//!   - DevNet **export key**   — signs outbound inventory bundles.
//!   - Update Server **release key** — signs inbound bundles.
//! Plus optional per-drive keys for drive attestation.
//!
//! Storage policy (PLAN.md §5.5): HSM / hardware-backed storage is the
//! target; software-backed storage (files under a state dir) is the
//! documented fallback, never the goal. This crate implements the
//! software-backed path with 0600 file permissions and explicit
//! documentation of the compensating controls.
//!
//! Hard rule: signing keys are only ever used by the core VM / Update Server
//! release process — never exposed to the EXPORT or INGEST sandbox VMs.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("missing key: {0}")]
    Missing(String),
    #[error("key already exists (refusing to overwrite): {0}")]
    AlreadyExists(String),
}

/// The two roles of signing key in the pipeline.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyRole {
    /// DevNet side: signs outbound inventory bundles.
    #[serde(rename = "export")]
    Export,
    /// Update Server side: signs inbound bundles.
    #[serde(rename = "release")]
    Release,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRole::Export => "export",
            KeyRole::Release => "release",
        }
    }
}

/// Metadata recorded alongside a key. Stored separately from key material so
/// it can be inspected without touching the private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub role: KeyRole,
    pub created_at: DateTime<Utc>,
    pub verifying_key_b64: String,
    pub storage: String, // "software" | "hsm" (future)
    pub note: String,
}

pub struct KeyManager {
    dir: PathBuf,
    /// When true, refuse to overwrite an existing key (default).
    no_overwrite: bool,
}

impl KeyManager {
    /// Create a key manager rooted at `dir`. Creates the dir if needed.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, KeyError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            no_overwrite: true,
        })
    }

    /// Allow overwriting existing keys (for tests / deliberate rekey).
    pub fn allow_overwrite(mut self) -> Self {
        self.no_overwrite = false;
        self
    }

    fn private_path(&self, role: KeyRole) -> PathBuf {
        self.dir.join(format!("{}-signing-key", role.as_str()))
    }

    fn public_path(&self, role: KeyRole) -> PathBuf {
        self.dir.join(format!("{}-verifying-key.pub", role.as_str()))
    }

    fn metadata_path(&self, role: KeyRole) -> PathBuf {
        self.dir.join(format!("{}-key-meta.json", role.as_str()))
    }

    /// Generate (or load existing) a signing key for `role`.
    /// Returns the signing key + its verifying key.
    pub fn provision(
        &self,
        role: KeyRole,
        note: impl Into<String>,
    ) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), KeyError> {
        let priv_path = self.private_path(role);
        let pub_path = self.public_path(role);

        if priv_path.exists() {
            if self.no_overwrite {
                // Return existing key.
                let sk = self.load_signing_key(role)?;
                let vk = sk.verifying_key();
                return Ok((sk, vk));
            }
            // fall through to overwrite
        }

        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();

        // Store private key as base64 of raw 32-byte seed, file mode 0600.
        fs::write(&priv_path, base64::encode(sk.to_bytes()))?;
        set_private_permissions(&priv_path)?;

        // Store public key as base64 (avoids depending on key file formats).
        fs::write(&pub_path, base64::encode(vk.to_bytes()))?;

        let meta = KeyMetadata {
            role,
            created_at: Utc::now(),
            verifying_key_b64: base64::encode(vk.to_bytes()),
            storage: "software".into(),
            note: note.into(),
        };
        fs::write(self.metadata_path(role), serde_json::to_vec_pretty(&meta)?)?;

        Ok((sk, vk))
    }

    /// Load the signing key for `role` if it exists.
    pub fn load_signing_key(
        &self,
        role: KeyRole,
    ) -> Result<ed25519_dalek::SigningKey, KeyError> {
        let priv_path = self.private_path(role);
        let b64 = fs::read_to_string(&priv_path)
            .map_err(|_| KeyError::Missing(priv_path.display().to_string()))?;
        let bytes = base64::decode(b64.trim())
            .map_err(|e| KeyError::InvalidKey(format!("bad base64: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyError::InvalidKey("key seed not 32 bytes".into()))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }

    /// Load the verifying (public) key for `role` if it exists.
    pub fn load_verifying_key(
        &self,
        role: KeyRole,
    ) -> Result<ed25519_dalek::VerifyingKey, KeyError> {
        let pub_path = self.public_path(role);
        let b64 = fs::read_to_string(&pub_path)
            .map_err(|_| KeyError::Missing(pub_path.display().to_string()))?;
        let bytes = base64::decode(b64.trim())
            .map_err(|e| KeyError::InvalidKey(format!("bad base64: {e}")))?;
        ed25519_dalek::VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| KeyError::InvalidKey("pub key not 32 bytes".into()))?,
        )
        .map_err(|e| KeyError::InvalidKey(e.to_string()))
    }

    /// Read the stored metadata for a role (no key material).
    pub fn metadata(&self, role: KeyRole) -> Result<KeyMetadata, KeyError> {
        let path = self.metadata_path(role);
        let json = fs::read_to_string(&path)
            .map_err(|_| KeyError::Missing(path.display().to_string()))?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Sign `payload` with `role`'s key; returns base64 detached signature.
    pub fn sign(&self, role: KeyRole, payload: &[u8]) -> Result<String, KeyError> {
        use ed25519_dalek::Signer;
        let sk = self.load_signing_key(role)?;
        let sig = sk.sign(payload);
        Ok(base64::encode(sig.to_bytes()))
    }

    /// Verify a base64 detached signature over `payload` with `role`'s
    /// public key. Fail closed.
    pub fn verify(
        &self,
        role: KeyRole,
        payload: &[u8],
        sig_b64: &str,
    ) -> Result<(), KeyError> {
        use ed25519_dalek::Verifier;
        let vk = self.load_verifying_key(role)?;
        let sig_bytes = base64::decode(sig_b64.trim())
            .map_err(|e| KeyError::InvalidKey(format!("bad base64: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| KeyError::InvalidKey(format!("bad signature: {e}")))?;
        vk.verify(payload, &sig)
            .map_err(|_| KeyError::InvalidKey("signature verification failed".into()))
    }

    /// Export the public key for a role as base64 — this is what gets carried
    /// across the air gap on a dedicated USB trip during key rotation.
    pub fn export_public_key_b64(&self, role: KeyRole) -> Result<String, KeyError> {
        let vk = self.load_verifying_key(role)?;
        Ok(base64::encode(vk.to_bytes()))
    }

    /// Import a public key from base64 (used during rotation, when the other
    /// end must trust a newly rotated key before it's used).
    pub fn import_public_key_b64(
        &self,
        role: KeyRole,
        pub_b64: &str,
        note: impl Into<String>,
    ) -> Result<(), KeyError> {
        let bytes = base64::decode(pub_b64.trim())
            .map_err(|e| KeyError::InvalidKey(format!("bad base64: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyError::InvalidKey("pub key not 32 bytes".into()))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))?;

        let pub_path = self.public_path(role);
        if pub_path.exists() && self.no_overwrite {
            return Err(KeyError::AlreadyExists(
                pub_path.display().to_string(),
            ));
        }
        fs::write(&pub_path, base64::encode(vk.to_bytes()))?;

        let meta = KeyMetadata {
            role,
            created_at: Utc::now(),
            verifying_key_b64: base64::encode(vk.to_bytes()),
            storage: "software".into(),
            note: format!("imported ({})", note.into()),
        };
        fs::write(self.metadata_path(role), serde_json::to_vec_pretty(&meta)?)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), KeyError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "airgap-keys-test-{}-{}",
            std::process::id(),
            n
        ))
    }

    #[test]
    fn provision_and_sign_verify() {
        let dir = tmp_dir();
        let _ = fs::remove_dir_all(&dir);
        let km = KeyManager::new(&dir).unwrap();

        let (_sk, vk) = km.provision(KeyRole::Export, "devnet-1").unwrap();
        let payload = b"inventory bytes";
        let sig = km.sign(KeyRole::Export, payload).unwrap();
        km.verify(KeyRole::Export, payload, &sig).unwrap();

        // Public key stored matches returned vk.
        assert_eq!(km.export_public_key_b64(KeyRole::Export).unwrap(), base64::encode(vk.to_bytes()));

        // Re-provision loads the same key (no overwrite).
        let (sk2, _) = km.provision(KeyRole::Export, "again").unwrap();
        assert_eq!(sk2.to_bytes(), km.load_signing_key(KeyRole::Export).unwrap().to_bytes());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_fails_on_tamper() {
        let dir = tmp_dir();
        let _ = fs::remove_dir_all(&dir);
        let km = KeyManager::new(&dir).unwrap();
        km.provision(KeyRole::Release, "updatesrv").unwrap();

        let sig = km.sign(KeyRole::Release, b"good").unwrap();
        assert!(km.verify(KeyRole::Release, b"bad", &sig).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_public_key() {
        let dir = tmp_dir();
        let _ = fs::remove_dir_all(&dir);

        // Simulate two ends: devnet generates export key, update server imports its pub.
        let devnet = KeyManager::new(dir.join("devnet")).unwrap();
        let (_sk, vk) = devnet.provision(KeyRole::Export, "devnet").unwrap();

        let updatesrv = KeyManager::new(dir.join("updatesrv")).unwrap();
        let pub_b64 = devnet.export_public_key_b64(KeyRole::Export).unwrap();
        updatesrv.import_public_key_b64(KeyRole::Export, &pub_b64, "devnet").unwrap();

        // Updatesrv can now verify devnet-signed bundles.
        let sig = devnet.sign(KeyRole::Export, b"payload").unwrap();
        updatesrv.verify(KeyRole::Export, b"payload", &sig).unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_key_file_is_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tmp_dir();
            let _ = fs::remove_dir_all(&dir);
            let km = KeyManager::new(&dir).unwrap();
            km.provision(KeyRole::Export, "x").unwrap();
            let mode = fs::metadata(dir.join("export-signing-key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
