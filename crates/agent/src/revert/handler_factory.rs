//! Factory for selecting the correct revert handler based on OS.

use super::{
    LinuxDnfRevertHandler, LinuxDpkgRevertHandler, RevertHandler, RevertOutcome,
    WindowsKbRevertHandler,
};
use airgap_proto::DistroFamily;

/// Which family of handler to use.
pub enum RevertHandlerKind {
    Dnf,
    Dpkg,
    WindowsKb,
}

/// Select the appropriate revert handler for the given distro family.
pub fn select_handler(family: &DistroFamily) -> RevertHandlerKind {
    match family {
        DistroFamily::Rhel => RevertHandlerKind::Dnf,
        DistroFamily::Debian => RevertHandlerKind::Dpkg,
        DistroFamily::Windows => RevertHandlerKind::WindowsKb,
        DistroFamily::Other => RevertHandlerKind::Dnf,
    }
}

/// Execute a revert using the appropriate handler for the given family.
pub fn execute_revert(
    family: &DistroFamily,
    package: &str,
    target_version: &str,
) -> RevertOutcome {
    let handler_kind = select_handler(family);
    match handler_kind {
        RevertHandlerKind::Dnf => LinuxDnfRevertHandler.revert(package, target_version),
        RevertHandlerKind::Dpkg => LinuxDpkgRevertHandler.revert(package, target_version),
        RevertHandlerKind::WindowsKb => WindowsKbRevertHandler.revert(package, target_version),
    }
}
