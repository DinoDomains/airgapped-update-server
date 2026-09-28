//! Hashed credential material for tokens and sessions.
//!
//! Raw bearer tokens are never persisted. Both enrollment tokens and login
//! session tokens are stored as SHA-256 digests; verification hashes the
//! presented value and compares digests in constant time.
//!
//! SHA-256 (not Argon2) is the right primitive here, unlike for operator
//! passwords: these are high-entropy 256-bit random values, not
//! human-chosen secrets, so there is no dictionary to attack. Argon2 is
//! still used for operator passwords in `auth.rs`.
//!
//! # Migration
//!
//! Deployments that predate this module have plaintext tokens in
//! `tokens.json`. On load, any value that does not parse as a digest is
//! treated as legacy plaintext, hashed in place, and written back. Callers
//! therefore accept either form until migration completes.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Prefix identifying a hashed value, so plaintext and hashed entries can be
/// told apart during migration.
pub const PREFIX: &str = "sha256:";

/// Returns the storage digest for a raw secret.
pub fn digest(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    format!("{PREFIX}{}", hex::encode(h.finalize()))
}

/// True when `stored` is already in hashed form.
pub fn is_hashed(stored: &str) -> bool {
    stored.starts_with(PREFIX) && stored.len() == PREFIX.len() + 64
}

/// Constant-time comparison of a raw secret against a stored entry.
///
/// Accepts both hashed and legacy plaintext so migration is transparent.
pub fn verify(raw: &str, stored: &str) -> bool {
    if is_hashed(stored) {
        constant_time_eq(digest(raw).as_bytes(), stored.as_bytes())
    } else {
        // Legacy plaintext entry: still compare in constant time.
        constant_time_eq(raw.as_bytes(), stored.as_bytes())
    }
}

/// Compares two byte slices without leaking length-independent timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Checks a raw secret against a set of hashed entries, returning the label
/// of the matching entry.
pub fn lookup(raw: &str, entries: &HashMap<String, String>) -> Option<String> {
    let mut found = None;
    for (stored, label) in entries {
        if verify(raw, stored) {
            // Do not early-return: keep scanning so the number of comparisons
            // does not depend on which entry matched.
            if found.is_none() {
                found = Some(label.clone());
            }
        }
    }
    found
}

/// Re-hashes any legacy plaintext values in `entries`, returning the migrated
/// map and whether anything changed.
pub fn migrate_hashed(entries: &HashMap<String, String>) -> (HashMap<String, String>, bool) {
    let mut out = HashMap::with_capacity(entries.len());
    let mut changed = false;
    for (stored, label) in entries {
        if is_hashed(stored) {
            out.insert(stored.clone(), label.clone());
        } else {
            out.insert(digest(stored), label.clone());
            changed = true;
        }
    }
    (out, changed)
}

/// Generates a new random token as 64 hex chars (256 bits of entropy).
pub fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_prefixed() {
        let d = digest("airgap-bootstrap");
        assert!(is_hashed(&d));
        assert!(d.starts_with(PREFIX));
        assert_eq!(d, digest("airgap-bootstrap"));
        assert_ne!(d, digest("airgap-bootstrap2"));
    }

    #[test]
    fn verify_accepts_hashed_and_legacy() {
        let raw = "s3cret-token";
        let hashed = digest(raw);
        assert!(verify(raw, &hashed));
        assert!(!verify("wrong", &hashed));
        // Legacy plaintext still verifies.
        assert!(verify(raw, raw));
        assert!(!verify("wrong", raw));
    }

    #[test]
    fn migration_converts_plaintext_and_is_idempotent() {
        let mut m = HashMap::new();
        m.insert("plain-token".to_string(), "default".to_string());
        m.insert(digest("already-hashed"), "other".to_string());

        let (migrated, changed) = migrate_hashed(&m);
        assert!(changed);
        assert_eq!(migrated.len(), 2);
        for k in migrated.keys() {
            assert!(is_hashed(k), "all keys hashed after migration: {k}");
        }
        // Original plaintext still authenticates.
        assert_eq!(lookup("plain-token", &migrated).as_deref(), Some("default"));
        assert_eq!(lookup("already-hashed", &migrated).as_deref(), Some("other"));

        // Second pass is a no-op.
        let (again, changed2) = migrate_hashed(&migrated);
        assert!(!changed2);
        assert_eq!(again, migrated);
    }

    #[test]
    fn lookup_rejects_wrong_secret() {
        let mut m = HashMap::new();
        m.insert(digest("right"), "default".to_string());
        assert!(lookup("wrong", &m).is_none());
        assert!(lookup("right", &m).is_some());
    }

    #[test]
    fn random_tokens_are_unique_and_hex() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
