//! Handoff consumer for M5.
//!
//! Consumes M4's INGEST VM handoff output (a verified inbound bundle
//! on a shared directory), and independently re-verifies signatures and
//! artifact hashes. This module MUST NOT trust M4's `SandboxVerdict::Pass`
//! alone — the re-verification is intentional redundancy.

use std::path::Path;

use airgap_contracts::{InboundBundle, InboundCatalog, sha256_file, ContractError};
use ed25519_dalek::{SigningKey, VerifyingKey};

use super::{SandboxVerdict, ApiError};

/// Independently verify an inbound bundle that M4's INGEST VM handed over.
///
/// Re-checks:
///   1. Manifest signature (using the Update Server release key's public half)
///   2. Every artifact hash against the manifest
///
/// Returns the parsed `InboundCatalog` if all checks pass.
pub fn consume_handoff(
    bundle: &InboundBundle,
    drive_root: &Path,
    release_public_key: &VerifyingKey,
) -> Result<InboundCatalog, ApiError> {
    let cat = &bundle.catalog;

    // Re-verify the manifest signature independently. Even though
    // InboundBundle::read_and_verify already checked this, we re-check
    // to be explicit about the security boundary.
    let manifest_bytes = std::fs::read(drive_root.join("manifest.json"))
        .map_err(|_| ApiError::ArtifactNotFound("manifest.json".into()))?;
    let sig = std::fs::read_to_string(drive_root.join("manifest.sig"))
        .map_err(|_| ApiError::ArtifactNotFound("manifest.sig".into()))?;

    airgap_contracts::ed25519_verify(release_public_key, &manifest_bytes, &sig)
        .map_err(|e| ApiError::Signature(e.to_string()))?;

    // Re-hash every artifact against the manifest's declared hashes.
    for artifact_entry in &bundle.manifest.artifacts {
        let rel = artifact_entry.path.trim_start_matches('/');
        let artifact_path = drive_root.join(rel);
        let actual = sha256_file(&artifact_path)
            .map_err(|e| ApiError::ArtifactNotFound(e.to_string()))?;
        if actual != artifact_entry.sha256 {
            return Err(ApiError::VerificationFailed(format!(
                "artifact {} hash mismatch: expected {}, got {}",
                rel, artifact_entry.sha256, actual
            )));
        }
    }

    Ok(cat.clone())
}

/// Process a sandbox verdict — only proceed if `passed` is true AND
/// independent re-verification succeeds.
pub fn process_verified_bundle(
    verdict: &SandboxVerdict,
    drive_root: &Path,
    release_public_key: &VerifyingKey,
) -> Result<InboundCatalog, ApiError> {
    if !verdict.passed {
        return Err(ApiError::VerificationFailed(format!(
            "sandbox verdict failed: {}",
            verdict.reason
        )));
    }

    consume_handoff(
        &InboundBundle::read_and_verify(
            drive_root,
            &bundle_drive_id(drive_root),
            0, // We trust M4's session tracking; this just parses
            release_public_key,
        )
        .map_err(|e| ApiError::VerificationFailed(e.to_string()))?,
        drive_root,
        release_public_key,
    )
}

fn bundle_drive_id(drive_root: &Path) -> String {
    std::fs::read_to_string(drive_root.join("drive_id.txt"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
