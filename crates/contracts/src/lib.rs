//! M1 — air-gap transfer bundle contracts.
//!
//! Frozen by `docs/bundle-schema.md`. Every module (M2–M7) that reads or
//! writes the OUTBOUND / INBOUND USB bundles uses the types and helpers
//! here so the wire format never drifts.
//!
//! Trust order on any reader:
//!   1. drive attestation (drive_id + direction + session.id) — §0
//!   2. signature verification — §3
//!   3. payload parsing
//!   4. artifact hash-checking — §3

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Wire format version for every signed payload. Bump on any breaking
/// change; readers reject versions they do not know.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    #[serde(rename = "outbound")]
    Outbound,
    #[serde(rename = "inbound")]
    Inbound,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
        }
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("drive attestation failed: {0}")]
    Attestation(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("unsupported schema version: {0}")]
    UnsupportedVersion(u32),
    #[error("artifact path traversal: {0}")]
    PathTraversal(String),
    #[error("missing file: {0}")]
    Missing(String),
}

/// SHA-256 of raw bytes.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 of a file's raw bytes (used for artifact hash-checking).
pub fn sha256_file(path: &Path) -> Result<String, ContractError> {
    let data = fs::read(path)?;
    Ok(sha256_bytes(&data))
}

// ---------------------------------------------------------------------------
// §0 — drive attestation envelope
// ---------------------------------------------------------------------------

/// The fixed per-drive identity + the monotonic session counter.
///
/// Files on the drive root: `drive_id.txt`, `direction.txt`, `session.id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriveAttestation {
    pub drive_id: String,
    pub direction: Direction,
    pub session: u64,
}

impl DriveAttestation {
    /// Verify the three envelope files exist and match an expected identity
    /// and a strictly-increasing session. Fail closed on any mismatch.
    pub fn read_and_verify(
        drive_root: &Path,
        expected_drive_id: &str,
        expected_direction: Direction,
        last_session: u64,
    ) -> Result<DriveAttestation, ContractError> {
        let drive_id = fs::read_to_string(drive_root.join("drive_id.txt"))
            .map_err(|_| ContractError::Missing("drive_id.txt".into()))?
            .trim()
            .to_string();

        let direction_raw = fs::read_to_string(drive_root.join("direction.txt"))
            .map_err(|_| ContractError::Missing("direction.txt".into()))?
            .trim()
            .to_string();

        let session_raw = fs::read_to_string(drive_root.join("session.id"))
            .map_err(|_| ContractError::Missing("session.id".into()))?;
        let session: u64 = session_raw
            .trim()
            .parse()
            .map_err(|_| ContractError::Attestation(format!("bad session.id: {session_raw}")))?;

        let direction = match direction_raw.as_str() {
            "outbound" => Direction::Outbound,
            "inbound" => Direction::Inbound,
            other => {
                return Err(ContractError::Attestation(format!(
                    "unknown direction: {other}"
                )))
            }
        };

        if drive_id != expected_drive_id {
            return Err(ContractError::Attestation(format!(
                "drive_id mismatch: expected {expected_drive_id}, got {drive_id}"
            )));
        }
        if direction != expected_direction {
            return Err(ContractError::Attestation(format!(
                "direction mismatch: expected {:?}, got {:?}",
                expected_direction, direction
            )));
        }
        if session <= last_session {
            return Err(ContractError::Attestation(format!(
                "session not strictly increasing: got {session}, last was {last_session}"
            )));
        }

        Ok(DriveAttestation {
            drive_id,
            direction,
            session,
        })
    }

    /// Write the three envelope files. Used by the writer side (EXPORT VM
    /// for outbound; Update Server for inbound). Creates the drive root if
    /// needed.
    pub fn write(&self, drive_root: &Path) -> Result<(), ContractError> {
        fs::create_dir_all(drive_root)?;
        fs::write(drive_root.join("drive_id.txt"), &self.drive_id)?;
        fs::write(
            drive_root.join("direction.txt"),
            format!("{}\n", self.direction.as_str()),
        )?;
        fs::write(drive_root.join("session.id"), format!("{}\n", self.session))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// §1 — OUTBOUND bundle (DevNet → Update Server)
// ---------------------------------------------------------------------------

/// One installed package as reported by a machine inside DevNet. This is the
/// minimal whitelisted schema; nothing else about DevNet crosses the boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub installed_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInventory {
    pub device_id: String,
    pub hostname: String,
    #[serde(rename = "family")]
    pub distro_family: String,
    pub arch: String,
    pub packages: Vec<InstalledPackage>,
}

/// The outbound `inventory.json` payload. Serialized canonically; signed by
/// the DevNet export key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundInventory {
    pub schema_version: u32,
    pub devnet_id: String,
    pub collected_at: DateTime<Utc>,
    pub devices: Vec<DeviceInventory>,
}

impl OutboundInventory {
    pub fn new(devnet_id: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            devnet_id: devnet_id.into(),
            collected_at: Utc::now(),
            devices: Vec::new(),
        }
    }

    /// Canonical compact serialization — this exact byte string is what gets
    /// signed and verified, so it must be deterministic.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() {
            return Err(ContractError::Serde(serde_json::Error::io(
                std::io::Error::other("empty serialization"),
            )));
        }
        // Compact form: strip the trailing newline if any (serde_json emits none).
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Ok(bytes)
    }
}

/// Full outbound bundle on the OUTBOUND drive.
///
/// Layout: drive_id.txt, direction.txt, session.id, inventory.json,
/// inventory.sig.
pub struct OutboundBundle {
    pub attestation: DriveAttestation,
    pub inventory: OutboundInventory,
}

impl OutboundBundle {
    /// Write the full outbound bundle to `drive_root`.
    pub fn write(
        &self,
        drive_root: &Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContractError> {
        self.attestation.write(drive_root)?;
        let payload = self.inventory.to_canonical_bytes()?;
        let sig = ed25519_sign(signing_key, &payload);
        fs::write(drive_root.join("inventory.json"), &payload)?;
        fs::write(drive_root.join("inventory.sig"), &sig)?;
        Ok(())
    }

    /// Read + fully verify an outbound bundle (attestation, then signature).
    pub fn read_and_verify(
        drive_root: &Path,
        expected_drive_id: &str,
        last_session: u64,
        export_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<OutboundBundle, ContractError> {
        let attestation = DriveAttestation::read_and_verify(
            drive_root,
            expected_drive_id,
            Direction::Outbound,
            last_session,
        )?;

        let payload = fs::read(drive_root.join("inventory.json"))
            .map_err(|_| ContractError::Missing("inventory.json".into()))?;
        let sig = fs::read_to_string(drive_root.join("inventory.sig"))
            .map_err(|_| ContractError::Missing("inventory.sig".into()))?;

        ed25519_verify(export_public_key, &payload, &sig)?;

        let inventory: OutboundInventory = serde_json::from_slice(&payload)?;
        if inventory.schema_version != SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion(inventory.schema_version));
        }

        Ok(OutboundBundle {
            attestation,
            inventory,
        })
    }
}

// ---------------------------------------------------------------------------
// §2 — INBOUND bundle (Update Server → DevNet)
// ---------------------------------------------------------------------------

/// Behavior-test verdict. Must be labeled honestly in the frontend (PLAN.md
/// §6.2) — "hash-verified only" is never the same as "behavior-tested".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BehaviorVerdict {
    #[serde(rename = "behavior-tested")]
    BehaviorTested,
    #[serde(rename = "hash-verified-only")]
    HashVerifiedOnly,
    #[serde(rename = "manual-review-required")]
    ManualReviewRequired,
    #[serde(rename = "suspicious")]
    Suspicious,
    #[serde(rename = "failed")]
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub update_id: String,
    pub package: String,
    #[serde(rename = "family")]
    pub distro_family: String,
    pub version: String,
    pub ring: String,
    pub artifact: String,
    pub sha256: String,
    pub behavior_verdict: BehaviorVerdict,
    pub tested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    pub package: String,
    pub version: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

/// The inbound `catalog.json` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundCatalog {
    pub schema_version: u32,
    pub session: u64,
    pub releases: Vec<Release>,
    pub revocations: Vec<Revocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// The inbound `manifest.json` payload. Signed by the Update Server release
/// key; references the catalog and hashes every artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundManifest {
    pub schema_version: u32,
    pub session: u64,
    pub catalog_sha256: String,
    pub artifacts: Vec<ArtifactEntry>,
}

impl InboundCatalog {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(bytes)
    }
}

impl InboundManifest {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(bytes)
    }

    /// Build the manifest by hashing every artifact file under `artifacts_dir`
    /// and linking the catalog (by its canonical bytes' sha256).
    pub fn build(
        session: u64,
        catalog: &InboundCatalog,
        artifacts_dir: &Path,
    ) -> Result<InboundManifest, ContractError> {
        let mut artifacts = Vec::new();
        for entry in fs::read_dir(artifacts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let sha256 = sha256_file(&path)?;
            let size = fs::metadata(&path)?.len();
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| ContractError::PathTraversal(path.display().to_string()))?
                .to_string();
            artifacts.push(ArtifactEntry {
                path: format!("artifacts/{file_name}"),
                sha256,
                size,
            });
        }

        Ok(InboundManifest {
            schema_version: SCHEMA_VERSION,
            session,
            catalog_sha256: sha256_bytes(&catalog.to_canonical_bytes()?),
            artifacts,
        })
    }
}

/// Full inbound bundle on the INBOUND drive.
pub struct InboundBundle {
    pub attestation: DriveAttestation,
    pub catalog: InboundCatalog,
    pub manifest: InboundManifest,
}

impl InboundBundle {
    /// Build an InboundBundle in memory from a catalog + attestation +
    /// a staging dir of artifact files (names become the manifest paths).
    /// The manifest is derived by hashing every file in `stage`.
    pub fn build_from(
        catalog: &InboundCatalog,
        attestation: &DriveAttestation,
        stage_dir: &Path,
    ) -> Result<InboundBundle, ContractError> {
        let manifest = InboundManifest::build(catalog.session, catalog, stage_dir)?;
        Ok(InboundBundle {
            attestation: attestation.clone(),
            catalog: catalog.clone(),
            manifest,
        })
    }

    /// Write the full inbound bundle. `artifacts_dir` holds the artifact files
    /// that are copied into `drive_root/artifacts/`.
    pub fn write(
        &self,
        drive_root: &Path,
        artifacts_dir: &Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContractError> {
        self.attestation.write(drive_root)?;

        let catalog_bytes = self.catalog.to_canonical_bytes()?;
        fs::write(drive_root.join("catalog.json"), &catalog_bytes)?;

        let manifest_bytes = self.manifest.to_canonical_bytes()?;
        let sig = ed25519_sign(signing_key, &manifest_bytes);
        fs::write(drive_root.join("manifest.json"), &manifest_bytes)?;
        fs::write(drive_root.join("manifest.sig"), &sig)?;

        let dest = drive_root.join("artifacts");
        fs::create_dir_all(&dest)?;
        for artifact in &self.manifest.artifacts {
            let src = artifacts_dir.join(
                artifact
                    .path
                    .strip_prefix("artifacts/")
                    .unwrap_or(&artifact.path),
            );
            let target = drive_root.join(&artifact.path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src, &target)?;
        }
        Ok(())
    }

    /// Read + fully verify an inbound bundle: attestation, then manifest.sig,
    /// then every artifact hash-checked against the manifest.
    pub fn read_and_verify(
        drive_root: &Path,
        expected_drive_id: &str,
        last_session: u64,
        release_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<InboundBundle, ContractError> {
        let attestation = DriveAttestation::read_and_verify(
            drive_root,
            expected_drive_id,
            Direction::Inbound,
            last_session,
        )?;

        let manifest_bytes = fs::read(drive_root.join("manifest.json"))
            .map_err(|_| ContractError::Missing("manifest.json".into()))?;
        let sig = fs::read_to_string(drive_root.join("manifest.sig"))
            .map_err(|_| ContractError::Missing("manifest.sig".into()))?;
        ed25519_verify(release_public_key, &manifest_bytes, &sig)?;

        let manifest: InboundManifest = serde_json::from_slice(&manifest_bytes)?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion(manifest.schema_version));
        }

        let catalog_bytes = fs::read(drive_root.join("catalog.json"))
            .map_err(|_| ContractError::Missing("catalog.json".into()))?;
        if sha256_bytes(&catalog_bytes) != manifest.catalog_sha256 {
            return Err(ContractError::Signature(
                "catalog.json does not match manifest.catalog_sha256".into(),
            ));
        }
        let catalog: InboundCatalog = serde_json::from_slice(&catalog_bytes)?;
        if catalog.schema_version != SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion(catalog.schema_version));
        }

        // Hash-check every artifact against the manifest. No exceptions.
        for artifact in &manifest.artifacts {
            let rel = artifact.path.trim_start_matches('/');
            if rel.is_empty()
                || artifact.path.starts_with('/')
                || rel.split('/').any(|c| c == ".." || c == ".")
            {
                return Err(ContractError::PathTraversal(artifact.path.clone()));
            }
            let path = drive_root.join(rel);
            let actual = sha256_file(&path)?;
            if actual != artifact.sha256 {
                return Err(ContractError::HashMismatch {
                    expected: artifact.sha256.clone(),
                    got: actual,
                });
            }
        }

        Ok(InboundBundle {
            attestation,
            catalog,
            manifest,
        })
    }
}

// ---------------------------------------------------------------------------
// §3 — ed25519 sign/verify helpers
// ---------------------------------------------------------------------------

/// Sign `payload` with an ed25519 signing key; returns base64 detached
/// signature bytes.
pub fn ed25519_sign(
    key: &ed25519_dalek::SigningKey,
    payload: &[u8],
) -> String {
    use ed25519_dalek::Signer;
    let sig = key.sign(payload);
    base64::encode(sig.to_bytes())
}

/// Verify a base64 ed25519 detached signature over `payload`. Fail closed.
pub fn ed25519_verify(
    key: &ed25519_dalek::VerifyingKey,
    payload: &[u8],
    sig_b64: &str,
) -> Result<(), ContractError> {
    use ed25519_dalek::Verifier;

    let sig_bytes = base64::decode(sig_b64.trim())
        .map_err(|e| ContractError::Signature(format!("bad base64: {e}")))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| ContractError::Signature(format!("bad signature: {e}")))?;
    key.verify(payload, &sig)
        .map_err(|_| ContractError::Signature("ed25519 verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        use rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn outbound_roundtrip() {
        let (sk, vk) = keypair();
        let root = std::env::temp_dir().join(format!("airgap-contracts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let mut inv = OutboundInventory::new("devnet-1");
        inv.devices.push(DeviceInventory {
            device_id: "endpoint-07".into(),
            hostname: "ws-07".into(),
            distro_family: "windows".into(),
            arch: "x86_64".into(),
            packages: vec![InstalledPackage {
                name: "kb5039227".into(),
                version: "20348.2527".into(),
                installed_sha256: "deadbeef".into(),
            }],
        });

        let bundle = OutboundBundle {
            attestation: DriveAttestation {
                drive_id: "USB-OUTBOUND-0001".into(),
                direction: Direction::Outbound,
                session: 41,
            },
            inventory: inv,
        };
        bundle.write(&root, &sk).unwrap();

        let read = OutboundBundle::read_and_verify(&root, "USB-OUTBOUND-0001", 40, &vk).unwrap();
        assert_eq!(read.inventory.devnet_id, "devnet-1");
        assert_eq!(read.inventory.devices[0].packages[0].name, "kb5039227");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn outbound_rejects_wrong_drive_id() {
        let (sk, _vk) = keypair();
        let (_, vk) = keypair();
        let root = std::env::temp_dir().join(format!("airgap-contracts-test2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let bundle = OutboundBundle {
            attestation: DriveAttestation {
                drive_id: "USB-OUTBOUND-0001".into(),
                direction: Direction::Outbound,
                session: 1,
            },
            inventory: OutboundInventory::new("devnet-1"),
        };
        bundle.write(&root, &sk).unwrap();

        let res = OutboundBundle::read_and_verify(&root, "USB-OUTBOUND-0002", 0, &vk);
        assert!(matches!(res, Err(ContractError::Attestation(_))));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn outbound_rejects_replayed_session() {
        let (sk, vk) = keypair();
        let root = std::env::temp_dir().join(format!("airgap-contracts-test3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let bundle = OutboundBundle {
            attestation: DriveAttestation {
                drive_id: "USB-OUTBOUND-0001".into(),
                direction: Direction::Outbound,
                session: 5,
            },
            inventory: OutboundInventory::new("devnet-1"),
        };
        bundle.write(&root, &sk).unwrap();

        // last_session == 5 (same) -> must be rejected
        let res = OutboundBundle::read_and_verify(&root, "USB-OUTBOUND-0001", 5, &vk);
        assert!(matches!(res, Err(ContractError::Attestation(_))));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn inbound_roundtrip_with_artifact() {
        let (sk, vk) = keypair();
        let root = std::env::temp_dir().join(format!("airgap-contracts-test4-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let artifacts_dir = root.join("src-artifacts");
        fs::create_dir_all(&artifacts_dir).unwrap();
        let artifact = vec![0u8, 1, 2, 3, 4];
        fs::write(artifacts_dir.join("ab12.rpm"), &artifact).unwrap();

        let catalog = InboundCatalog {
            schema_version: SCHEMA_VERSION,
            session: 42,
            releases: vec![Release {
                update_id: "rocky-coreutils-9.1".into(),
                package: "coreutils".into(),
                distro_family: "rhel".into(),
                version: "9.1".into(),
                ring: "prod".into(),
                artifact: "artifacts/ab12.rpm".into(),
                sha256: sha256_bytes(&artifact),
                behavior_verdict: BehaviorVerdict::BehaviorTested,
                tested_at: Utc::now(),
            }],
            revocations: vec![],
        };
        let manifest = InboundManifest::build(42, &catalog, &artifacts_dir).unwrap();

        let bundle = InboundBundle {
            attestation: DriveAttestation {
                drive_id: "USB-INBOUND-0002".into(),
                direction: Direction::Inbound,
                session: 42,
            },
            catalog,
            manifest,
        };
        bundle.write(&root, &artifacts_dir, &sk).unwrap();

        let read = InboundBundle::read_and_verify(&root, "USB-INBOUND-0002", 41, &vk).unwrap();
        assert_eq!(read.catalog.releases[0].package, "coreutils");
        assert_eq!(read.catalog.releases[0].sha256, sha256_bytes(&artifact));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn inbound_rejects_tampered_artifact() {
        let (sk, vk) = keypair();
        let root = std::env::temp_dir().join(format!("airgap-contracts-test5-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let artifacts_dir = root.join("src-artifacts");
        fs::create_dir_all(&artifacts_dir).unwrap();
        let artifact = vec![1, 2, 3];
        fs::write(artifacts_dir.join("cafe.deb"), &artifact).unwrap();

        let catalog = InboundCatalog {
            schema_version: SCHEMA_VERSION,
            session: 1,
            releases: vec![Release {
                update_id: "u".into(),
                package: "p".into(),
                distro_family: "debian".into(),
                version: "1".into(),
                ring: "dev".into(),
                artifact: "artifacts/cafe.deb".into(),
                sha256: sha256_bytes(&artifact),
                behavior_verdict: BehaviorVerdict::HashVerifiedOnly,
                tested_at: Utc::now(),
            }],
            revocations: vec![],
        };
        let manifest = InboundManifest::build(1, &catalog, &artifacts_dir).unwrap();
        let bundle = InboundBundle {
            attestation: DriveAttestation {
                drive_id: "USB-INBOUND-0002".into(),
                direction: Direction::Inbound,
                session: 1,
            },
            catalog,
            manifest,
        };
        bundle.write(&root, &artifacts_dir, &sk).unwrap();

        // Tamper with the copied artifact on the drive.
        fs::write(root.join("artifacts/cafe.deb"), vec![9, 9, 9]).unwrap();

        let res = InboundBundle::read_and_verify(&root, "USB-INBOUND-0002", 0, &vk);
        assert!(matches!(res, Err(ContractError::HashMismatch { .. })));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sign_verify_helpers() {
        use ed25519_dalek::Verifier;
        let (sk, vk) = keypair();
        let payload = b"hello world";
        let sig = ed25519_sign(&sk, payload);
        ed25519_verify(&vk, payload, &sig).unwrap();
        assert!(ed25519_verify(&vk, b"tampered", &sig).is_err());
    }
}
