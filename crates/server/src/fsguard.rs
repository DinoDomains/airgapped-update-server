//! Filesystem hardening helpers: permission enforcement for the store
//! directory and key material, plus resolution of the out-of-store key
//! directory.
//!
//! Two invariants this module exists to uphold:
//!
//! 1. The store directory and every private key file are readable only by
//!    the owning service account (`0700` dirs, `0600` files).
//! 2. Private key material does not live inside the web-facing store
//!    directory. It lives under a separate key directory so that a
//!    compromise scoped to the store (e.g. a path traversal or a backup
//!    restore of the data volume) does not automatically yield signing
//!    keys.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Mode for directories holding secrets: owner rwx only.
pub const DIR_MODE: u32 = 0o700;
/// Mode for private key files: owner read/write only.
pub const KEY_MODE: u32 = 0o600;
/// Mode for non-secret data files: owner rw, group/other read.
pub const DATA_MODE: u32 = 0o644;

/// Environment variable that overrides the key directory location.
pub const KEY_DIR_ENV: &str = "AIRGAP_KEY_DIR";

/// Resolves the directory holding private key material.
///
/// Precedence:
/// 1. `$AIRGAP_KEY_DIR` if set.
/// 2. A sibling `keys` directory next to the store dir (e.g.
///!    `/var/lib/airgap-server` -> `/var/lib/airgap-server-keys`).
///    A sibling is used rather than a child so the key material is not
///    reachable by any code that walks the store tree.
///
/// The directory is created with `0700` if missing.
pub fn key_dir(store_dir: &Path) -> PathBuf {
    let dir = match std::env::var(KEY_DIR_ENV) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => sibling_keys_dir(store_dir),
    };
    let _ = ensure_dir(&dir, DIR_MODE);
    dir
}

/// Default key directory: `<store_dir>-keys`.
pub fn sibling_keys_dir(store_dir: &Path) -> PathBuf {
    let mut name = store_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "data".to_string());
    name.push_str("-keys");
    store_dir
        .parent()
        .map(|p| p.join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Creates `dir` (and parents) if missing and sets mode `mode`.
///
/// Returns the path on success. An existing directory is left in place but
/// its mode is tightened to at most `mode`, so a world-readable store left
/// over from an earlier run is corrected on startup.
pub fn ensure_dir(dir: &Path, mode: u32) -> std::io::Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    tighten(dir, mode, true)?;
    Ok(dir.to_path_buf())
}

/// Tightens permissions on an existing path to at most `mode`.
///
/// `is_dir` selects the trailing execute bit that directories need in order
/// to be traversable. Modes are only ever tightened, never loosened: if the
/// current mode is already more restrictive it is left alone.
pub fn tighten(path: &Path, mode: u32, is_dir: bool) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        // Refuse to follow symlinks when adjusting permissions; a symlinked
        // key path could otherwise be used to retarget the chmod.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to chmod symlink {}", path.display()),
        ));
    }
    let current = meta.permissions().mode() & 0o7777;
    let mut want = current & mode;
    if is_dir {
        // Preserve owner execute only if it was already granted by `mode`.
        want = (current & mode & !0o111) | (mode & 0o100);
    }
    if want != current {
        fs::set_permissions(path, fs::Permissions::from_mode(want))?;
    }
    Ok(())
}

/// Writes `contents` to `path` with mode `KEY_MODE`, creating parents.
///
/// Uses a temp file + rename so a crash mid-write cannot leave a partially
/// written key file behind. The temp name is the full filename with `.tmp`
/// appended — deliberately *not* `Path::with_extension`, which would collapse
/// distinct names onto the same temp path (`export-signing-key` and
/// `export-signing-key.pem` would both become `export-signing-key.tmp`).
pub fn write_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent, DIR_MODE)?;
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    fs::write(&tmp, contents)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(KEY_MODE))?;
    fs::rename(&tmp, path)?;
    // Rename preserves the temp file's mode, but set it again defensively in
    // case the destination already existed with looser permissions.
    fs::set_permissions(path, fs::Permissions::from_mode(KEY_MODE))?;
    Ok(())
}

/// Reports the mode of a path, or `None` if it does not exist.
pub fn mode_of(path: &Path) -> Option<u32> {
    fs::symlink_metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

/// True when the path is readable by group or other.
pub fn is_world_or_group_readable(path: &Path) -> bool {
    matches!(mode_of(path), Some(m) if m & 0o077 != 0)
}

/// Audits the store tree and returns human-readable warnings for anything
/// that is too permissive or holds key material in the wrong place.
///
/// This is advisory: startup logs the findings but does not refuse to run,
/// so an operator can see every problem in one pass and fix them.
pub fn audit_store_tree(store_dir: &Path, key_dir: &Path) -> Vec<String> {
    let mut findings = Vec::new();

    if let Some(mode) = mode_of(store_dir) {
        if mode & 0o077 != 0 {
            findings.push(format!(
                "store dir {} has mode {:04o}; tighten to 0700 (chmod 700 {})",
                store_dir.display(),
                mode,
                store_dir.display()
            ));
        }
    }

    // Private key material must not sit inside the web-facing store dir.
    // Check the known CA locations plus the `airgap-keys` layout, whose
    // private halves are named `<role>-signing-key`.
    for name in ["ca-key.pem", "server-key.pem"] {
        for candidate in [store_dir.join("ca").join(name), store_dir.join(name)] {
            if candidate.exists() {
                findings.push(format!(
                    "private key {} found inside the store dir; move it to {} and restrict to 0600",
                    candidate.display(),
                    key_dir.join(name).display()
                ));
            }
        }
    }
    let legacy_keys = store_dir.join("keys");
    if let Ok(entries) = std::fs::read_dir(&legacy_keys) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_private = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-signing-key"));
            if is_private && path.is_file() {
                findings.push(format!(
                    "private signing key {} found inside the store dir; move it to {} and \
                     restrict to 0600",
                    path.display(),
                    key_dir.join("keys").display()
                ));
            }
        }
    }

    // Agent mTLS private keys.
    let legacy_certs = store_dir.join("certs");
    if let Ok(entries) = std::fs::read_dir(&legacy_certs) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_private = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-key.pem"));
            if is_private && path.is_file() {
                findings.push(format!(
                    "agent private key {} found inside the store dir; move it to {} and \
                     restrict to 0600",
                    path.display(),
                    key_dir.join("certs").display()
                ));
            }
        }
    }

    if let Some(mode) = mode_of(key_dir) {
        if mode & 0o077 != 0 {
            findings.push(format!(
                "key dir {} has mode {:04o}; tighten to 0700 (chmod 700 {})",
                key_dir.display(),
                mode,
                key_dir.display()
            ));
        }
    }

    findings
}

/// Recursively tightens permissions across a tree: directories to `0700`,
/// files to `0600`. Intended for the key directory only.
pub fn harden_tree(root: &Path) -> std::io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    // Tighten the root itself, not just its children.
    let meta = fs::symlink_metadata(root)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to traverse symlinked directory {}", root.display()),
        ));
    }
    if meta.is_dir() {
        tighten(root, DIR_MODE, true)?;
    } else {
        tighten(root, KEY_MODE, false)?;
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            tighten(&path, DIR_MODE, true)?;
            harden_tree(&path)?;
        } else {
            tighten(&path, KEY_MODE, false)?;
        }
    }
    Ok(())
}

/// Moves a legacy key file from `from` into the key directory at `to`,
/// returning the new path. Used to relocate `ca-key.pem` / `server-key.pem`
/// out of `<store>/ca/` on first run after an upgrade.
pub fn relocate_key(from: &Path, to: &Path) -> std::io::Result<PathBuf> {
    if let Some(parent) = to.parent() {
        ensure_dir(parent, DIR_MODE)?;
    }
    if to.exists() {
        // Destination already present: drop the legacy copy only if the
        // contents match, otherwise keep both and let the operator decide.
        let (a, b) = (fs::read(from), fs::read(to));
        if let (Ok(a), Ok(b)) = (a, b) {
            if a == b {
                let _ = fs::remove_file(from);
                return Ok(to.to_path_buf());
            }
        }
        return Ok(from.to_path_buf());
    }
    fs::rename(from, to)?;
    fs::set_permissions(to, fs::Permissions::from_mode(KEY_MODE))?;
    Ok(to.to_path_buf())
}
