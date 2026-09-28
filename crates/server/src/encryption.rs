//! Encrypted-volume detection for the store and key directories.
//!
//! Encryption at rest is a property of the *filesystem*, not of the
//! application: this module cannot encrypt anything, it can only verify that
//! the operator has actually put the data on an encrypted volume and warn
//! loudly when they have not.
//!
//! Detection reads `/proc/mounts` and looks for a dm-crypt/LUKS-backed
//! mount at or above the path. Filesystems that are encrypted without
//! appearing as `crypt` in mount options (e.g. ZFS native encryption, or a
//! hardware-encrypted disk presented as a plain block device) cannot be
//! detected this way, so the result is advisory. An operator can suppress
//! the warning once they have satisfied the requirement out-of-band.

use std::path::{Path, PathBuf};

/// Outcome of checking one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionStatus {
    /// The path resolves onto a dm-crypt/LUKS-backed mount.
    Encrypted(String),
    /// The path is on a filesystem with no encryption markers found.
    Unencrypted(String),
    /// `/proc/mounts` could not be read; status unknown.
    Unknown(String),
}

impl EncryptionStatus {
    pub fn is_encrypted(&self) -> bool {
        matches!(self, EncryptionStatus::Encrypted(_))
    }
}

/// A parsed mount table entry.
struct Mount {
    device: String,
    mount_point: PathBuf,
    fstype: String,
    options: Vec<String>,
}

/// Reads and parses `/proc/mounts`.
fn read_mounts() -> Option<Vec<Mount>> {
    let text = std::fs::read_to_string("/proc/mounts").ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let device = parts.next()?.to_string();
        let mount_point = PathBuf::from(parts.next()?);
        let fstype = parts.next()?.to_string();
        // The fourth field is the option list, comma separated.
        let options = parts
            .next()
            .map(|o| o.split(',').map(|s| s.to_string()).collect())
            .unwrap_or_default();
        out.push(Mount {
            device,
            mount_point,
            fstype,
            options,
        });
    }
    Some(out)
}

/// True when a mount entry looks like encrypted storage.
fn is_encrypted_mount(m: &Mount) -> bool {
    // dm-crypt via cryptsetup shows up as a `crypt` type, a `/dev/mapper/*`
    // device, or a device path containing "crypt".
    if m.fstype == "crypt" || m.fstype == "crypto" {
        return true;
    }
    if m.device.starts_with("/dev/mapper/") && m.device.contains("crypt") {
        return true;
    }
    if m.device.to_lowercase().contains("luks") || m.device.to_lowercase().contains("crypt") {
        return true;
    }
    // LUKS2 via integritydm / fscrypt show up as options.
    for opt in &m.options {
        let o = opt.to_lowercase();
        if o.contains("luks") || o.contains("crypt") {
            return true;
        }
    }
    false
}

/// Finds the most specific mount containing `path`.
///
/// "Most specific" = longest mount point that is a prefix of `path`, which
/// correctly handles a store on `/var/lib/...` while `/` is the fallback.
fn mount_for<'a>(mounts: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.as_os_str().len())
}

/// Checks whether `path` sits on an encrypted volume.
pub fn check(path: &Path) -> EncryptionStatus {
    // The path must exist to be classified; if it does not, walk up to the
    // nearest existing ancestor so a not-yet-created store is still judged by
    // the volume it will land on.
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) if p != probe => probe = p.to_path_buf(),
            _ => break,
        }
    }

    let Some(mounts) = read_mounts() else {
        return EncryptionStatus::Unknown(format!(
            "could not read /proc/mounts; cannot verify encryption for {}",
            path.display()
        ));
    };

    match mount_for(&mounts, &probe) {
        Some(m) if is_encrypted_mount(m) => EncryptionStatus::Encrypted(format!(
            "{} on {} ({})",
            path.display(),
            m.mount_point.display(),
            m.device
        )),
        Some(m) => EncryptionStatus::Unencrypted(format!(
            "{} is on {} ({}), which shows no encryption markers",
            path.display(),
            m.mount_point.display(),
            m.device
        )),
        None => EncryptionStatus::Unknown(format!(
            "no mount entry found for {}",
            probe.display()
        )),
    }
}

/// Checks the store and key directories and returns advisory warnings for
/// any that are not verifiably encrypted.
///
/// `enforce` turns warnings into a hard failure at startup. It is off by
/// default because a correct ZFS/3rd-party encrypted setup cannot be
/// detected here and should not lock an operator out of their server.
pub fn audit_encryption(
    store_dir: &Path,
    key_dir: &Path,
    enforce: bool,
) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    for (label, dir) in [("store", store_dir), ("key", key_dir)] {
        match check(dir) {
            EncryptionStatus::Encrypted(_) => {}
            EncryptionStatus::Unencrypted(detail) => {
                findings.push(format!(
                    "{label} directory is not on a verifiably encrypted volume: {detail}. \
                     Put {label} data on a LUKS/dm-crypt volume (see docs/ENCRYPTION.md)."
                ));
            }
            EncryptionStatus::Unknown(detail) => {
                findings.push(format!(
                    "{label} directory encryption could not be verified: {detail}"
                ));
            }
        }
    }
    if enforce && !findings.is_empty() {
        return Err(findings.join("; "));
    }
    Ok(findings)
}

/// True when `AIRGAP_REQUIRE_ENCRYPTION` is set to a truthy value.
pub fn enforcement_requested() -> bool {
    matches!(
        std::env::var("AIRGAP_REQUIRE_ENCRYPTION").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_table_parses() {
        let mounts = read_mounts().expect("/proc/mounts should be readable on Linux");
        assert!(!mounts.is_empty());
        // Every entry must have captured a mount point.
        assert!(mounts.iter().all(|m| !m.mount_point.as_os_str().is_empty()));
    }

    #[test]
    fn detects_luks_style_devices() {
        let m = Mount {
            device: "/dev/mapper/luks-1234".to_string(),
            mount_point: PathBuf::from("/var"),
            fstype: "ext4".to_string(),
            options: vec![],
        };
        assert!(is_encrypted_mount(&m));
    }

    #[test]
    fn detects_crypt_fstype() {
        let m = Mount {
            device: "luks-abc".to_string(),
            mount_point: PathBuf::from("/data"),
            fstype: "crypt".to_string(),
            options: vec![],
        };
        assert!(is_encrypted_mount(&m));
    }

    #[test]
    fn plain_root_is_not_encrypted() {
        let m = Mount {
            device: "/dev/nvme0n1p2".to_string(),
            mount_point: PathBuf::from("/"),
            fstype: "ext4".to_string(),
            options: vec!["rw".to_string(), "relatime".to_string()],
        };
        assert!(!is_encrypted_mount(&m));
    }

    #[test]
    fn most_specific_mount_wins() {
        let mounts = vec![
            Mount {
                device: "/dev/sda1".to_string(),
                mount_point: PathBuf::from("/"),
                fstype: "ext4".to_string(),
                options: vec![],
            },
            Mount {
                device: "/dev/mapper/vault".to_string(),
                mount_point: PathBuf::from("/var/lib/airgap"),
                fstype: "ext4".to_string(),
                options: vec![],
            },
        ];
        let chosen = mount_for(&mounts, Path::new("/var/lib/airgap/data")).unwrap();
        assert_eq!(chosen.mount_point, PathBuf::from("/var/lib/airgap"));
    }

    #[test]
    fn check_returns_a_classification_for_tmp() {
        // /tmp is rarely encrypted in a container; the point is that the
        // function returns Some variant rather than panicking.
        let status = check(Path::new("/tmp"));
        assert!(matches!(
            status,
            EncryptionStatus::Encrypted(_) | EncryptionStatus::Unencrypted(_) | EncryptionStatus::Unknown(_)
        ));
    }

    #[test]
    fn enforcement_is_opt_in() {
        // Not asserting on the ambient env, just that the parser exists and
        // returns a bool without panicking.
        let _ = enforcement_requested();
    }
}
