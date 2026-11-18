use std::collections::HashMap;
use std::sync::Arc;

use airgap_contracts::{
    ContractError, Direction, DriveAttestation, InboundCatalog, InboundManifest, InstalledPackage,
    IntegrityCanary, Release, Revocation, zeroize_and_shred_envelope,
};
use ed25519_dalek::{Signature, Signer, Verifier};
use chrono::Utc;

use super::*;
use super::drift_detection;
use super::revocation_matching;
use super::revert_dispatch::{RevertOutcome, RevertCommand};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

fn keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Convert an OsInventory-like device inventory to PackageState list.
fn to_package_states(installed: &[InstalledPackage]) -> Vec<PackageState> {
    installed.iter().map(|p| PackageState {
        name: p.name.clone(),
        version: p.version.clone(),
        sha256: p.installed_sha256.clone(),
        ring: Ring::Prod,
        admin_state: AdminState::Approved(Ring::Prod),
    }).collect()
}

#[tokio::test]
async fn drift_detected_on_mismatch() {
    let mut expected = HashMap::new();
    expected.insert("nginx".to_string(), "1.25.0".to_string());
    expected.insert("openssh".to_string(), "8.9p1".to_string());

    let reported = vec![
        PackageState {
            name: "nginx".to_string(),
            version: "1.24.0".to_string(), // DIFFERENT version
            sha256: "abc".into(),
            ring: Ring::Prod,
            admin_state: AdminState::Approved(Ring::Prod),
        },
        PackageState {
            name: "openssh".to_string(),
            version: "8.9p1".to_string(), // matches
            sha256: "def".into(),
            ring: Ring::Prod,
            admin_state: AdminState::Approved(Ring::Prod),
        },
    ];

    let alerts = drift_detection::detect_drift("ep-01", &reported, &expected);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].endpoint_id, "ep-01");
    assert_eq!(alerts[0].package, "nginx");
    assert_eq!(alerts[0].expected_version, "1.25.0");
    assert_eq!(alerts[0].reported_version, "1.24.0");
}

#[test]
fn revocation_creates_alert_not_action() {
    let reported = vec![
        InstalledPackage {
            name: "openssl".to_string(),
            version: "1.1.1w".to_string(),
            installed_sha256: "oldhash".into(),
        },
        InstalledPackage {
            name: "nginx".to_string(),
            version: "1.25.0".to_string(),
            installed_sha256: "somehash".into(),
        },
    ];

    let revocations = vec![
        Revocation {
            package: "openssl".to_string(),
            version: "1.1.1w".to_string(),
            reason: "CVE-2023-XXXX".to_string(),
            revoked_at: Utc::now(),
        },
    ];

    // The agent reports 1.1.1w, and a revocation matches — produce alert.
    let alerts = revocation_matching::match_revocations_for_endpoint(
        "ep-01",
        &reported,
        &revocations,
    );
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].package, "openssl");
    assert_eq!(alerts[0].revoked_version, "1.1.1w");
}

#[tokio::test]
async fn revert_command_requires_operator() {
    let dir = std::env::temp_dir().join("m5_revert_test_1");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let store = Arc::new(Store::load(&dir).await.unwrap());
    let audit = Arc::new(AuditLog::new(&dir));
    let mut core = DevNetCore::new(store, audit, dir.clone());

    // Empty operator → rejected
    let result = core.issue_revert_command("ep-01", "nginx", "1.24.0", "");
    assert!(matches!(result, Err(ApiError::EmptyOperator)));

    // Non-empty operator → accepted
    let result = core.issue_revert_command("ep-01", "nginx", "1.24.0", "admin");
    assert!(result.is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn handoff_reverifies_independently() {
    let dir = std::env::temp_dir().join("m5_handoff_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Create a key pair for signing.
    let (sk, vk) = keypair();

    // Build a minimal inbound bundle on disk.
    let drive_root = dir.join("inbound-drive");
    std::fs::create_dir_all(drive_root.join("artifacts")).unwrap();

    let catalog = InboundCatalog {
        schema_version: 1,
        session: 1,
        releases: vec![Release {
            update_id: "u1".into(),
            package: "nginx".into(),
            distro_family: "debian".into(),
            version: "1.25.0".into(),
            ring: "prod".into(),
            artifact: "artifacts/pkg-1.25.0.deb".into(),
            sha256: "abcd".into(),
            behavior_verdict: airgap_contracts::BehaviorVerdict::HashVerifiedOnly,
            tested_at: Utc::now(),
        }],
        revocations: vec![],
    };

    let manifest = InboundManifest::build(1, &catalog, &drive_root.join("artifacts"))
        .expect("manifest build");

    let attestation = DriveAttestation::new("USB-IN-01", Direction::Inbound, 1);

    // Write attestation files
    std::fs::write(drive_root.join("drive_id.txt"), "USB-IN-01").unwrap();
    std::fs::write(drive_root.join("direction.txt"), "inbound").unwrap();
    std::fs::write(drive_root.join("session.id"), "1").unwrap();

    // Write catalog
    let cat_bytes = serde_json::to_vec(&catalog).unwrap();
    std::fs::write(drive_root.join("catalog.json"), &cat_bytes).unwrap();

    // Write manifest + signature
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let sig = sk.sign(&manifest_bytes);
    std::fs::write(drive_root.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(drive_root.join("manifest.sig"), sig.to_string()).unwrap();

    // Now try to re-verify — this will fail because the artifact hash
    // doesn't match (we didn't write a real artifact), which is correct:
    // the module should reject it.
    let verdict = SandboxVerdict {
        passed: true,
        reason: "all clear".into(),
        bundle_path: drive_root.clone(),
    };

    // We test that the handoff consumer tries to verify and fails on
    // the hash mismatch (since no real artifact exists).
    let result = handoff_consumer::process_verified_bundle(
        &verdict,
        &drive_root,
        &vk,
    );
    // Should fail because the artifact doesn't exist on disk.
    assert!(result.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn drill_unauthorized_write_anti_tamper_zeroization() {
    let (sk, vk) = keypair();
    let dir = std::env::temp_dir().join(format!("devnet-drill-zeroize-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 1. Legitimate export sets up drive with key envelope and signed canary
    std::fs::write(dir.join("drive_id.txt"), "USB-SECURE-001").unwrap();
    std::fs::write(dir.join("key_envelope.bin"), b"AES_MASTER_KEY_SECRET_256_BITS").unwrap();
    std::fs::write(dir.join("manifest.json"), b"{\"releases\":[]}").unwrap();

    let canary = IntegrityCanary::build(&dir, "devnet-server").unwrap();
    canary.write_signed(&dir, &sk).unwrap();

    // Valid drive verifies successfully
    assert!(IntegrityCanary::verify(&dir, &vk).is_ok());

    // 2. Simulated Attack: An unauthorized host writes a rogue script to the USB
    std::fs::write(dir.join("rogue_payload.sh"), b"#!/bin/sh\nrm -rf /").unwrap();

    // 3. Canary detection trips
    let tamper_res = IntegrityCanary::verify(&dir, &vk);
    assert!(tamper_res.is_err());
    assert!(matches!(tamper_res, Err(ContractError::TamperDetected(_))));

    // 4. Trigger cryptographic shredder
    zeroize_and_shred_envelope(&dir).unwrap();

    // 5. Verify the key envelope is purged and lock marker is dropped
    assert!(!dir.join("key_envelope.bin").exists());
    assert!(dir.join("TAMPER_SELF_DESTRUCTED.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn drill_replay_autolock_consumed_token() {
    let dir = std::env::temp_dir().join(format!("devnet-drill-autolock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let consumed_path = dir.join("consumed_tokens.json");
    let token = DriveAttestation::generate_next_token();

    let att = DriveAttestation::new("USB-OUT-01", Direction::Outbound, 1)
        .with_cycle_token(&token);
    att.write(&dir).unwrap();

    // First ingestion: token verified OK
    let verified = DriveAttestation::verify_rolling_token(&dir, &consumed_path).unwrap();
    assert_eq!(verified, Some(token.clone()));

    // Ingestion succeeds -> token is burned
    DriveAttestation::burn_token(&consumed_path, &token).unwrap();

    // Attack drill: Replaying the identical USB bundle must fail closed
    let replay_res = DriveAttestation::verify_rolling_token(&dir, &consumed_path);
    assert!(replay_res.is_err());
    let err_msg = replay_res.unwrap_err().to_string();
    assert!(err_msg.contains("CYCLE REPLAY DETECTED"));
    assert!(err_msg.contains("card autolock active"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn drill_path_traversal_and_badusb_injection() {
    let (sk, vk) = keypair();
    let dir = std::env::temp_dir().join(format!("devnet-drill-traversal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Drive attestation
    let att = DriveAttestation::new("USB-IN-01", Direction::Inbound, 1);
    att.write(&dir).unwrap();

    let catalog = InboundCatalog {
        schema_version: airgap_contracts::SCHEMA_VERSION,
        session: 1,
        releases: vec![],
        revocations: vec![],
    };
    let cat_bytes = catalog.to_canonical_bytes().unwrap();
    let cat_sha256 = airgap_contracts::sha256_bytes(&cat_bytes);
    std::fs::write(dir.join("catalog.json"), &cat_bytes).unwrap();

    // Injected malicious manifest with path traversal
    let manifest = airgap_contracts::InboundManifest {
        schema_version: airgap_contracts::SCHEMA_VERSION,
        session: 1,
        catalog_sha256: cat_sha256,
        artifacts: vec![airgap_contracts::ArtifactEntry {
            path: "artifacts/../../../../etc/shadow".into(),
            sha256: "deadbeef".into(),
            size: 100,
        }],
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let sig = airgap_contracts::ed25519_sign(&sk, &manifest_bytes);
    std::fs::write(dir.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(dir.join("manifest.sig"), sig).unwrap();

    // InboundBundle read_and_verify must fail closed with PathTraversal
    let read_res = airgap_contracts::InboundBundle::read_and_verify(&dir, "USB-IN-01", 0, &vk);
    assert!(read_res.is_err());
    assert!(matches!(read_res, Err(ContractError::PathTraversal(_))));

    let _ = std::fs::remove_dir_all(&dir);
}
