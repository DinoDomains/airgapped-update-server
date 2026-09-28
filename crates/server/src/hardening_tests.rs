//! Tests for the credential-hardening changes: hashed enrollment tokens,
//! persisted hashed sessions, permission enforcement, and key relocation.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::auth::Auth;
use crate::fsguard;
use crate::secrets;
use crate::store::Store;

fn store_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("airgap-hardening-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mode_755() -> std::fs::Permissions {
    std::fs::Permissions::from_mode(0o755)
}

// ── enrollment tokens ───────────────────────────────────────────────────────

#[tokio::test]
async fn store_migrates_legacy_plaintext_tokens() {
    let dir = store_dir("migrate-tokens");
    // Simulate a pre-hardening deployment: plaintext token on disk.
    std::fs::write(
        dir.join("tokens.json"),
        br#"{ "airgap-bootstrap": "default" }"#,
    )
    .unwrap();

    let store = Store::load(&dir).await.unwrap();

    // The legacy token must still authenticate.
    assert!(store.check_token("airgap-bootstrap").await);
    assert!(!store.check_token("wrong-token").await);

    // On disk it must now be a digest, and the raw value gone.
    let raw = std::fs::read_to_string(dir.join("tokens.json")).unwrap();
    assert!(!raw.contains("airgap-bootstrap"), "raw token still on disk: {raw}");
    assert!(raw.contains(secrets::PREFIX), "expected hashed form: {raw}");

    // Still valid after the rewrite.
    assert!(store.check_token("airgap-bootstrap").await);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn store_bootstraps_hashed_default_token() {
    let dir = store_dir("bootstrap-token");
    // Ensure no env token interferes with the default path.
    let store = Store::load(&dir).await.unwrap();
    let raw = std::fs::read_to_string(dir.join("tokens.json")).unwrap();
    assert!(raw.contains(secrets::PREFIX), "default must be hashed: {raw}");
    // The default bootstrap token works.
    assert!(store.check_token("airgap-bootstrap").await);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn added_tokens_are_only_stored_hashed() {
    let dir = store_dir("add-token");
    let store = Store::load(&dir).await.unwrap();
    store.add_token("a-very-secret-token", "second").await;
    assert!(store.check_token("a-very-secret-token").await);
    let raw = std::fs::read_to_string(dir.join("tokens.json")).unwrap();
    assert!(!raw.contains("a-very-secret-token"), "raw added token leaked: {raw}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── provisioning token validation ───────────────────────────────────────────

#[tokio::test]
async fn provisioning_token_must_match_a_configured_token() {
    let dir = store_dir("provision-token");
    let store = Store::load(&dir).await.unwrap();
    store.add_token("configured-token", "primary").await;

    // A token the server accepts is handed back for provisioning.
    let ok = store.validate_enrollment_token("configured-token").await.unwrap();
    assert_eq!(ok, "configured-token");

    // A token the server does not know is rejected, so we never install an
    // agent that cannot enroll.
    let err = store
        .validate_enrollment_token("some-other-token")
        .await
        .unwrap_err();
    assert!(err.contains("does not match"), "unexpected error: {err}");

    // Empty is rejected rather than provisioning an empty token.
    assert!(store.validate_enrollment_token("").await.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn provisioning_token_works_after_legacy_migration() {
    let dir = store_dir("provision-legacy");
    std::fs::write(
        dir.join("tokens.json"),
        br#"{ "legacy-bootstrap": "default" }"#,
    )
    .unwrap();
    let store = Store::load(&dir).await.unwrap();
    // The pre-existing plaintext token must still be provisionable.
    assert_eq!(
        store.validate_enrollment_token("legacy-bootstrap").await.unwrap(),
        "legacy-bootstrap"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── sessions ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_survives_restart_with_hashed_session_file() {
    let dir = store_dir("session-restart");

    let first = Auth::load(&dir).await.unwrap();
    let session = first
        .login("admin", "admin")
        .await
        .expect("default admin should exist");
    let token = session.token.clone();
    assert!(first.session(&token).await.is_some());

    // sessions.json must not contain the raw token.
    let sessions_raw = std::fs::read_to_string(dir.join("sessions.json")).unwrap();
    assert!(!sessions_raw.contains(&token), "raw session token on disk");
    assert!(sessions_raw.contains(secrets::PREFIX), "expected hashed session");

    // A fresh Auth (simulating a restart) accepts the same token.
    let second = Auth::load(&dir).await.unwrap();
    let revived = second.session(&token).await.expect("session must survive restart");
    assert_eq!(revived.operator, "admin");
    assert_eq!(revived.role, "admin");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn logout_invalidates_persisted_session() {
    let dir = store_dir("session-logout");
    let auth = Auth::load(&dir).await.unwrap();
    let session = auth.login("admin", "admin").await.unwrap();
    assert!(auth.session(&session.token).await.is_some());
    auth.logout(&session.token).await;
    assert!(auth.session(&session.token).await.is_none());

    // And it stays invalid after a restart.
    let again = Auth::load(&dir).await.unwrap();
    assert!(again.session(&session.token).await.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn deleting_operator_revokes_their_sessions() {
    let dir = store_dir("session-revoke");
    let auth = Auth::load(&dir).await.unwrap();
    let session = auth.login("admin", "admin").await.unwrap();
    assert!(auth.session(&session.token).await.is_some());
    assert!(auth.delete_operator("admin").await);
    assert!(auth.session(&session.token).await.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn short_operator_passwords_are_rejected() {
    let dir = store_dir("pw-policy");
    let auth = Auth::load(&dir).await.unwrap();
    assert!(auth.create_operator("weak", "short", "viewer").await.is_err());
    assert!(auth
        .create_operator("strong", "a-long-enough-password", "viewer")
        .await
        .is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

// ── permissions ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn store_load_tightens_directory_permissions() {
    let dir = store_dir("store-perms");
    // Simulate a world-readable store left from an earlier run.
    let target = dir.clone();
    std::fs::set_permissions(&target, mode_755()).unwrap();
    assert_eq!(fsguard::mode_of(&target).unwrap() & 0o077, 0o055);

    let _store = Store::load(&dir).await.unwrap();
    let mode = fsguard::mode_of(&dir).unwrap();
    assert_eq!(mode & 0o077, 0, "store dir should be owner-only, got {mode:o}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn write_secret_creates_owner_only_file() {
    let dir = store_dir("write-secret");
    let path = dir.join("sub").join("secret.key");
    fsguard::write_secret(&path, b"top secret").unwrap();
    let mode = fsguard::mode_of(&path).unwrap();
    assert_eq!(mode & 0o077, 0, "secret file should be 0600, got {mode:o}");
    assert_eq!(std::fs::read(&path).unwrap(), b"top secret");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn write_secret_does_not_collide_on_shared_stem() {
    // Regression: the temp file used to be `with_extension("tmp")`, which
    // collapsed `export-signing-key` and `export-signing-key.pem` onto the
    // same path and could clobber one with the other.
    let dir = store_dir("write-secret-collision");
    let bare = dir.join("export-signing-key");
    let dotted = dir.join("export-signing-key.pem");

    fsguard::write_secret(&bare, b"bare-contents").unwrap();
    fsguard::write_secret(&dotted, b"dotted-contents").unwrap();

    assert_eq!(std::fs::read(&bare).unwrap(), b"bare-contents");
    assert_eq!(std::fs::read(&dotted).unwrap(), b"dotted-contents");
    // No stray temp file left behind.
    assert!(!dir.join("export-signing-key.tmp").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn audit_flags_world_readable_store_and_keys() {
    let base = store_dir("audit");
    let store = base.join("data");
    let keys = base.join("data-keys");
    std::fs::create_dir_all(store.join("ca")).unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    // Loose perms + a key left in the store = two findings.
    for p in [&store, &keys, &store.join("ca")] {
        std::fs::set_permissions(p, mode_755()).unwrap();
    }
    std::fs::write(store.join("ca").join("ca-key.pem"), b"-----BEGIN PRIVATE KEY-----").unwrap();

    let findings = fsguard::audit_store_tree(&store, &keys);
    assert!(
        findings.iter().any(|f| f.contains("store dir") && f.contains("0700")),
        "expected store-dir finding, got {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.contains("ca-key.pem")),
        "expected key-in-store finding, got {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn audit_is_quiet_when_hardened() {
    let base = store_dir("audit-clean");
    let store = base.join("data");
    let keys = base.join("data-keys");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    fsguard::harden_tree(&store).unwrap();
    fsguard::harden_tree(&keys).unwrap();
    let findings = fsguard::audit_store_tree(&store, &keys);
    assert!(findings.is_empty(), "expected no findings, got {findings:?}");
    let _ = std::fs::remove_dir_all(&base);
}

// ── key relocation ──────────────────────────────────────────────────────────

#[test]
fn relocate_moves_key_and_restricts_it() {
    let base = store_dir("relocate");
    let store = base.join("data");
    let keys = base.join("data-keys");
    std::fs::create_dir_all(store.join("ca")).unwrap();
    let legacy = store.join("ca").join("ca-key.pem");
    std::fs::write(&legacy, b"private-material").unwrap();

    let dest = fsguard::relocate_key(&legacy, &keys.join("ca-key.pem")).unwrap();
    assert_eq!(dest, keys.join("ca-key.pem"));
    assert!(!legacy.exists(), "legacy key should be gone");
    assert_eq!(std::fs::read(&dest).unwrap(), b"private-material");
    assert_eq!(fsguard::mode_of(&dest).unwrap() & 0o077, 0);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn relocate_keeps_both_on_content_mismatch() {
    let base = store_dir("relocate-conflict");
    let store = base.join("data");
    let keys = base.join("data-keys");
    std::fs::create_dir_all(store.join("ca")).unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    let legacy = store.join("ca").join("ca-key.pem");
    std::fs::write(&legacy, b"old-key").unwrap();
    std::fs::write(keys.join("ca-key.pem"), b"new-key").unwrap();

    // Mismatched contents must not silently clobber either copy.
    let dest = fsguard::relocate_key(&legacy, &keys.join("ca-key.pem")).unwrap();
    assert_eq!(dest, legacy, "should decline to overwrite differing key");
    assert!(legacy.exists());
    assert_eq!(std::fs::read(keys.join("ca-key.pem")).unwrap(), b"new-key");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn audit_flags_agent_private_keys_in_the_store() {
    let base = store_dir("audit-agent-keys");
    let store = base.join("data");
    let keys = base.join("data-keys");
    let certs = store.join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(certs.join("agent-node1-key.pem"), b"private").unwrap();
    std::fs::write(certs.join("agent-node1.pem"), b"public").unwrap();

    let findings = fsguard::audit_store_tree(&store, &keys);
    assert!(
        findings.iter().any(|f| f.contains("agent-node1-key.pem")),
        "agent private key should be flagged, got {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.contains("agent-node1.pem")),
        "agent public cert must not be flagged, got {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn key_dir_defaults_to_sibling_not_child() {
    let store = Path::new("/var/lib/airgap-server");
    let keys = fsguard::sibling_keys_dir(store);
    assert_eq!(keys, Path::new("/var/lib/airgap-server-keys"));
    // Must NOT be inside the store, or a store traversal yields the keys.
    assert!(!keys.starts_with(store));
}

#[test]
fn audit_flags_signing_keys_in_the_store() {
    let base = store_dir("audit-signing");
    let store = base.join("data");
    let keys = base.join("data-keys");
    let legacy = store.join("keys");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    // Private half present alongside its public counterpart.
    std::fs::write(legacy.join("export-signing-key"), b"seed-material").unwrap();
    std::fs::write(legacy.join("export-verifying-key.pub"), b"public").unwrap();
    std::fs::write(legacy.join("export-key-meta.json"), b"{}").unwrap();

    let findings = fsguard::audit_store_tree(&store, &keys);
    assert!(
        findings.iter().any(|f| f.contains("export-signing-key")),
        "private signing key should be flagged, got {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.contains("verifying-key.pub")),
        "public key must not be flagged, got {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}
