//! M6 — Endpoint Agent revert capability.
//!
//! Extends the existing wired-system agent with an admin-initiated revert
//! command (distinct from the failed-install auto-rollback). The agent
//! receives `RevertCommand` over the existing mTLS channel, executes the
//! appropriate platform-specific revert, and reports the outcome honestly.

use airgap_proto::{DistroFamily, RevertCommand, RevertOutcome};
use crate::client::Client;

/// Trait implemented by platform-specific revert handlers.
pub trait RevertHandler {
    fn revert(&self, package: &str, target_version: &str) -> RevertOutcome;
}

/// Linux dnf revert handler (RHEL/Rocky).
pub struct LinuxDnfRevertHandler;

/// Linux dpkg revert handler (Debian/Ubuntu).
pub struct LinuxDpkgRevertHandler;

/// Windows KB revert handler.
pub struct WindowsKbRevertHandler;

impl RevertHandler for LinuxDnfRevertHandler {
    fn revert(&self, package: &str, target_version: &str) -> RevertOutcome {
        if !is_safe_package_name(package) {
            return RevertOutcome::Failed {
                reason: format!("unsafe package name: {package}"),
            };
        }

        let output = std::process::Command::new("dnf")
            .args([
                "-y",
                "downgrade",
                &format!("{package}-{target_version}"),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                // Verify the downgrade by checking the installed version.
                let verify = std::process::Command::new("rpm")
                    .args(["-q", "--qf", "%{VERSION}-%{RELEASE}", package])
                    .output();
                match verify {
                    Ok(v) if v.status.success() => {
                        let installed = String::from_utf8_lossy(&v.stdout).trim().to_string();
                        if installed.contains(target_version) {
                            RevertOutcome::Success
                        } else {
                            RevertOutcome::Failed {
                                reason: format!(
                                    "downgrade ran but version mismatch: expected {}, installed {}",
                                    target_version, installed
                                ),
                            }
                        }
                    }
                    Ok(_) => RevertOutcome::Failed {
                        reason: "downgrade succeeded but version verification cmd failed".into(),
                    },
                    Err(e) => RevertOutcome::Failed {
                        reason: format!("version verification failed: {e}"),
                    },
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .rev()
                    .take(10)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                RevertOutcome::Failed {
                    reason: format!("dnf downgrade failed: {stderr}"),
                }
            }
            Err(e) => RevertOutcome::Failed {
                reason: format!("failed to spawn dnf: {e}"),
            },
        }
    }
}

impl RevertHandler for LinuxDpkgRevertHandler {
    fn revert(&self, package: &str, target_version: &str) -> RevertOutcome {
        if !is_safe_package_name(package) {
            return RevertOutcome::Failed {
                reason: format!("unsafe package name: {package}"),
            };
        }

        // Check if a prior .deb is available in the apt cache.
        let cache_path = format!("/var/cache/apt/archives/{package}_{target_version}_*.deb");
        let entries: Vec<std::path::PathBuf> = match glob::glob(&cache_path) {
            Ok(paths) => paths.filter_map(|e| e.ok()).take(1).collect(),
            Err(_) => Vec::new(),
        };

        if entries.is_empty() {
            return RevertOutcome::Failed {
                reason: format!(
                    "prior artifact for {package}={target_version} not in apt cache; "
                ),
            };
        }

        let deb_path = &entries[0];
        let output = std::process::Command::new("dpkg")
            .args(["-i", deb_path.to_str().unwrap_or("")])
            .output();

        match output {
            Ok(out) if out.status.success() => RevertOutcome::Success,
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                RevertOutcome::Failed {
                    reason: format!("dpkg reinstall failed: {stderr}"),
                }
            }
            Err(e) => RevertOutcome::Failed {
                reason: format!("failed to spawn dpkg: {e}"),
            },
        }
    }
}

impl RevertHandler for WindowsKbRevertHandler {
    fn revert(&self, package: &str, _target_version: &str) -> RevertOutcome {
        // On Windows, "package" is a KB identifier (e.g., KB5039227).
        let kb = package.to_uppercase();
        if !kb.starts_with("KB") || !is_safe_package_name(&kb) {
            return RevertOutcome::Failed {
                reason: format!("invalid KB identifier: {package}"),
            };
        }

        let output = std::process::Command::new("wusa.exe")
            .args(["/uninstall", &format!("/kb:{kb}"), "/quiet", "/norestart"])
            .output();

        match output {
            Ok(out) if out.status.success() => RevertOutcome::Success,
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);

                // wusa returns specific exit codes for non-uninstallable updates.
                // Exit code 0x80070422 = ERROR_SERVICE_DISABLED (commonly means
                // the KB is permanent / superseded and cannot be uninstalled).
                if out.status.code() == Some(0x80070422u32 as i32)
                    || stderr.contains("not uninstallable")
                    || stderr.contains("permanent")
                {
                    return RevertOutcome::NotRevertible {
                        reason: format!(
                            "KB {kb} is permanent or superseded; cannot be uninstalled"
                        ),
                    };
                }

                RevertOutcome::Failed {
                    reason: format!("wusa uninstall failed: {stderr}"),
                }
            }
            Err(e) => RevertOutcome::Failed {
                reason: format!("failed to spawn wusa: {e}"),
            },
        }
    }
}

/// Check that a package name contains only safe characters.
fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c))
}

/// Select the appropriate revert handler for the current distro.
pub fn select_handler_for_distro(family: DistroFamily) -> Box<dyn RevertHandler> {
    match family {
        DistroFamily::Debian => Box::new(LinuxDpkgRevertHandler),
        DistroFamily::Rhel => Box::new(LinuxDnfRevertHandler),
        DistroFamily::Windows => Box::new(WindowsKbRevertHandler),
        DistroFamily::Other => Box::new(LinuxDnfRevertHandler),
    }
}

/// Execute a single revert command received from the server (M5).
/// Delegates to the platform-specific handler and returns the outcome.
pub async fn execute_revert(
    _client: &Client,
    _agent_id: &str,
    cmd: &RevertCommand,
) -> RevertOutcome {
    let family = crate::inventory::collect().await.family;
    let handler = select_handler_for_distro(family);
    handler.revert(&cmd.package, &cmd.target_version)
}
