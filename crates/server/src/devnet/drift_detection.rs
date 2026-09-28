//! Drift/tamper detection for M5.
//!
//! Compares each endpoint's last-reported package state (from the
//! existing `/inventory` endpoint) against DevNet's expected state
//! (derived from the last approved inbound bundle). Any mismatch
//! produces a distinct `DriftAlert`.

use std::collections::HashMap;

use airgap_contracts::InboundCatalog;

use super::{DriftAlert, PackageState};

/// Build the expected package set from the last approved inbound
/// catalog. Each release's `package` → `version` is the source of truth.
pub fn build_expected_versions(catalog: &InboundCatalog) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for release in &catalog.releases {
        map.insert(release.package.clone(), release.version.clone());
    }
    map
}

/// Detect drift between an endpoint's reported packages and the expected
/// versions from the last approved bundle.
///
/// `endpoint_id` — the agent identifier (e.g. "agent-ws-07")
/// `reported`  — packages the agent last reported as installed
/// `expected`  — expected versions from the inbound catalog
pub fn detect_drift(
    endpoint_id: &str,
    reported: &[PackageState],
    expected: &HashMap<String, String>,
) -> Vec<DriftAlert> {
    let mut alerts = Vec::new();

    for pkg in reported {
        if let Some(expected_ver) = expected.get(&pkg.name) {
            if &pkg.version != expected_ver {
                alerts.push(DriftAlert {
                    endpoint_id: endpoint_id.to_string(),
                    package: pkg.name.clone(),
                    expected_version: expected_ver.clone(),
                    reported_version: pkg.version.clone(),
                    detected_at: now_iso(),
                });
            }
        }
    }
    alerts
}

/// Detect drift from raw `InstalledPackage` lists (what agents actually
/// report back over the mTLS API).
pub fn detect_drift_from_inventory(
    endpoint_id: &str,
    reported: &[airgap_contracts::InstalledPackage],
    expected: &HashMap<String, String>,
) -> Vec<DriftAlert> {
    let mut alerts = Vec::new();

    for pkg in reported {
        if let Some(expected_ver) = expected.get(&pkg.name) {
            if pkg.version != *expected_ver {
                alerts.push(DriftAlert {
                    endpoint_id: endpoint_id.to_string(),
                    package: pkg.name.clone(),
                    expected_version: expected_ver.clone(),
                    reported_version: pkg.version.clone(),
                    detected_at: now_iso(),
                });
            }
        }
    }
    alerts
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
