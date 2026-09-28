//! Revocation matching for M5.
//!
//! When a new inbound bundle's revocations list contains an entry matching
//! a package/version currently reported as installed on an endpoint,
//! produce a `RevocationAlert`. This is informational — it does NOT
//! auto-trigger a revert (that requires explicit admin action via M7).

use std::collections::HashMap;

use airgap_contracts::{InstalledPackage, Revocation};

use super::{RevocationAlert, PackageState};

/// Check a single endpoint's package set against the revocation list.
/// Returns one `RevocationAlert` per revoked package the endpoint is running.
pub fn match_revocations_for_endpoint(
    endpoint_id: &str,
    reported: &[InstalledPackage],
    revocations: &[Revocation],
) -> Vec<RevocationAlert> {
    let mut alerts = Vec::new();

    for rev in revocations {
        for pkg in reported {
            if pkg.name == rev.package && pkg.version == rev.version {
                alerts.push(RevocationAlert {
                    endpoint_id: endpoint_id.to_string(),
                    package: pkg.name.clone(),
                    revoked_version: pkg.version.clone(),
                    reason: rev.reason.clone(),
                    matched_at: now_iso(),
                });
            }
        }
    }
    alerts
}

/// Check all endpoints against revocations and return every alert.
pub fn match_all_endpoints(
    endpoints: &[(String, Vec<InstalledPackage>)],
    revocations: &[Revocation],
) -> Vec<RevocationAlert> {
    let mut all = Vec::new();
    for (endpoint_id, packages) in endpoints {
        all.extend(match_revocations_for_endpoint(
            endpoint_id,
            packages,
            revocations,
        ));
    }
    all
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
