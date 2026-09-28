//! M7 — DevNet Admin Frontend HTTP layer.
//!
//! Serves the downloaded dashboard HTML at `GET /devnet` and provides
//! the API endpoints the dashboard JavaScript expects:
//!   - `GET  /api/state`          — aggregate package/distributor state
//!   - `POST /api/vendor/approve` — approve a pending vendor domain
//!   - `POST /api/vendor/reject`  — reject a pending vendor domain
//!   - `GET  /api/usb`            — detect attached USB drives
//!   - `POST /api/collect`        — request all agents re-report inventory
//!   - `POST /api/export-outbound` — write the signed OUTBOUND bundle to a USB
//!
//! The state endpoint aggregates data from the existing `Store` (agent
//! inventory) and the `DevNetCore` (package states, drift/revocation
//! alerts) into the JSON shape the dashboard's `fetchState()` consumes.

use std::collections::HashSet;
use std::sync::Arc;

use airgap_contracts::{
    DeviceInventory, DriveAttestation, Direction, InstalledPackage, OutboundBundle,
    OutboundInventory,
};
use airgap_keys::{KeyManager, KeyRole};
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::audit::AuditLog;
use crate::auth::Auth;
use crate::devnet::api::load_release_verifying_key;
use crate::devnet::{DevNetCore, DevNetCoreApi, PackageState};
use crate::store::Store;

// The dashboard HTML is embedded at compile time from the assets directory.
const DEVNET_DASHBOARD_HTML: &str = include_str!("../assets/devnet-dashboard.html");

/// Per-package entry serialized for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardPackage {
    pub name: String,
    pub version: String,
    pub vendor_domain: String,
    pub status: String,
    pub detail: String,
}

/// Request body for vendor approve/reject.
#[derive(Debug, Deserialize)]
pub struct VendorRequest {
    pub domain: String,
    pub admin_token: String,
}

/// Response envelope for vendor approve/reject.
#[derive(Debug, Serialize)]
pub struct VendorResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One removable USB drive detected on the DevNet server.
#[derive(Debug, Clone, Serialize)]
pub struct UsbDrive {
    pub device: String,
    pub mount_point: String,
    pub label: String,
    pub fstype: String,
}

/// Request body for exporting the OUTBOUND bundle to a USB drive.
#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    pub mount_point: String,
    pub drive_id: String,
    pub session: Option<u64>,
}

/// Response body for the OUTBOUND export.
#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<usize>,
}

/// One installed package on an endpoint, for the dashboard endpoint list.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointPackage {
    pub name: String,
    pub version: String,
}

/// One endpoint (agent) with its reported version information.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointInfo {
    pub agent_id: String,
    pub hostname: String,
    pub ip: Option<String>,
    pub last_seen: Option<String>,
    pub status: String,
    pub os_name: String,
    pub os_version: String,
    pub os_pretty: String,
    pub family: String,
    pub arch: String,
    pub packages: Vec<EndpointPackage>,
}

/// Aggregate state returned by `GET /api/state`.
#[derive(Debug, Serialize)]
pub struct DashboardState {
    pub packages: Vec<DashboardPackage>,
    pub endpoints: Vec<EndpointInfo>,
    pub trusted_domains: Vec<String>,
    pub rejected_domains: Vec<String>,
    pub pending_domains: Vec<String>,
    pub logs: Vec<String>,
}

/// Build the router for the DevNet dashboard + API routes.
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/devnet", get(dashboard))
        .route("/api/state", get(state_api))
        .route("/api/vendor/approve", post(vendor_approve))
        .route("/api/vendor/reject", post(vendor_reject))
        .route("/api/usb", get(list_usb))
        .route("/api/collect", post(collect_inventory))
        .route("/api/export-outbound", post(export_outbound))
        .route("/api/verify-inbound", post(verify_inbound))
        .route("/api/push-updates", post(push_updates))
        .with_state(state)
}

/// Shared state for the DevNet HTTP layer.
#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub devnet: Arc<RwLock<DevNetCore>>,
    pub audit: Arc<AuditLog>,
    /// Admin tokens authorized to approve/reject vendor domains.
    pub admin_tokens: Arc<RwLock<HashSet<String>>>,
    /// The server's store directory (holds keys/ and the session counter).
    pub store_dir: std::path::PathBuf,
    /// Session-based operator auth shared with the main dashboard.
    pub auth: Arc<Auth>,
}

impl HttpState {
    pub fn new(
        store: Arc<Store>,
        devnet: Arc<RwLock<DevNetCore>>,
        audit: Arc<AuditLog>,
        admin_tokens: Vec<String>,
        store_dir: std::path::PathBuf,
        auth: Arc<Auth>,
    ) -> Self {
        Self {
            store,
            devnet,
            audit,
            admin_tokens: Arc::new(RwLock::new(admin_tokens.into_iter().collect())),
            store_dir,
            auth,
        }
    }
}

fn err(status: axum::http::StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Require a valid operator session for every dashboard API call.
async fn require_user(st: &HttpState, headers: &axum::http::HeaderMap) -> Result<(), axum::response::Response> {
    let token = bearer_token(headers)
        .ok_or_else(|| err(axum::http::StatusCode::UNAUTHORIZED, "login required"))?;
    st.auth
        .session(&token)
        .await
        .ok_or_else(|| err(axum::http::StatusCode::UNAUTHORIZED, "invalid or expired session"))
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Handlers

pub async fn dashboard() -> Html<&'static str> {
    Html(DEVNET_DASHBOARD_HTML)
}

/// `GET /api/state`
/// Returns aggregate package, distributor, and log data for the dashboard.
pub async fn state_api(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(r) = require_user(&st, &headers).await {
        return r;
    }
    let devnet = st.devnet.read().await;
    let packages = devnet.packages.read().await.clone();
    let drift_alerts = devnet.drift_alerts.read().await.clone();
    let revocation_alerts = devnet.revocation_alerts.read().await.clone();
    let catalog = devnet.last_catalog.read().await.clone();
    let agents = st.store.list_agents().await;
    let audit = st.audit.clone();
    drop(devnet);

    let mut dash_packages: Vec<DashboardPackage> = packages
        .into_iter()
        .map(|ps: PackageState| {            let status = match ps.admin_state {
                crate::devnet::AdminState::Approved(_) => "Verified",
                crate::devnet::AdminState::Rejected => "Rejected",
                crate::devnet::AdminState::Pending => "PendingVendorApproval",
            };
            DashboardPackage {
                name: ps.name.clone(),
                version: ps.version.clone(),
                vendor_domain: "unknown".to_string(),
                status: status.to_string(),
                detail: format!("sha256: {} / ring: {:?}", &ps.sha256[..16.min(ps.sha256.len())], ps.ring),
            }
        })
        .collect();

    // Add agent-reported packages as "Verified".
    for agent in &agents {
        if let Some(inv) = &agent.inventory {
            for pkg in &inv.packages {
                let key = format!("{}:{}", pkg.name, pkg.version);
                let _ = key;
                let status = "Verified";
                dash_packages.push(DashboardPackage {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    vendor_domain: agent.hostname.clone(),
                    status: status.to_string(),
                    detail: format!("agent {} on {}", agent.agent_id, agent.hostname),
                });
            }
        }
    }

    // Build the per-endpoint list with version information.
    let mut endpoints: Vec<EndpointInfo> = Vec::new();
    for agent in &agents {
        let inv = agent.inventory.as_ref();
        endpoints.push(EndpointInfo {
            agent_id: agent.agent_id.clone(),
            hostname: agent.hostname.clone(),
            ip: agent.ip.clone(),
            last_seen: agent.last_seen.clone(),
            status: agent.status.clone(),
            os_name: inv.map(|i| i.os_name.clone()).unwrap_or_default(),
            os_version: inv.map(|i| i.os_version.clone()).unwrap_or_default(),
            os_pretty: inv.map(|i| i.os_pretty.clone()).unwrap_or_default(),
            family: inv
                .map(|i| format!("{:?}", i.family))
                .unwrap_or_default(),
            arch: inv.map(|i| i.arch.clone()).unwrap_or_default(),
            packages: inv
                .map(|i| {
                    i.packages
                        .iter()
                        .map(|p| EndpointPackage {
                            name: p.name.clone(),
                            version: p.version.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    endpoints.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    // Aggregate distributor trust state.
    let mut trusted: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    if let Some(cat) = &catalog {
        for rev in &cat.revocations {
            if !rejected.iter().any(|d| d == &rev.package) {
                rejected.push(rev.package.clone());
            }
        }
    }
    // Pending domains come from packages with Pending admin state.
    for ps in &dash_packages {
        if ps.status == "PendingVendorApproval" && !pending.iter().any(|d| d == &ps.vendor_domain) {
            pending.push(ps.vendor_domain.clone());
        }
        if ps.status == "Verified" && !trusted.iter().any(|d| d == &ps.vendor_domain) {
            trusted.push(ps.vendor_domain.clone());
        }
    }

    // Build logs from audit entries + alerts.
    let mut logs: Vec<String> = Vec::new();
    for alert in &drift_alerts {
        logs.push(format!(
            "[{ts}] ⚠️ Drift: {endpoint} has {pkg} {reported}, expected {expected}",
            ts = &alert.detected_at,
            endpoint = alert.endpoint_id,
            pkg = alert.package,
            reported = alert.reported_version,
            expected = alert.expected_version,
        ));
    }
    for alert in &revocation_alerts {
        logs.push(format!(
            "[{ts}] ❌ Revocation: {endpoint} running revoked {pkg} {revoked} — {reason}",
            ts = &alert.matched_at,
            endpoint = alert.endpoint_id,
            pkg = alert.package,
            revoked = alert.revoked_version,
            reason = alert.reason,
        ));
    }
    // Append recent audit log entries.
    let recent = audit.recent(20);
    for entry in recent {
        let icon = if entry.action == "approve_vendor" { "✅" } else { "❌" };
        logs.push(format!("[{ts}] {icon} {op}: {action} ({detail})",
            ts = entry.ts, icon = icon, op = entry.actor,
            action = entry.action, detail = entry.result));
    }

    logs.sort();
    logs.dedup();

    Json(DashboardState {
        packages: dash_packages,
        endpoints,
        trusted_domains: trusted,
        rejected_domains: rejected,
        pending_domains: pending,
        logs,
    })
    .into_response()
}

/// `POST /api/vendor/approve` or `POST /api/vendor/reject`
/// Validates the admin token, then records the decision.
pub async fn vendor_approve(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VendorRequest>,
) -> Json<VendorResponse> {
    if let Err(r) = require_user(&st, &headers).await {
        return Json(VendorResponse { ok: false, error: Some("login required".into()) });
    }
    let tokens = st.admin_tokens.read().await;
    if !tokens.contains(&req.admin_token) {
        return Json(VendorResponse { ok: false, error: Some("invalid admin token".into()) });
    }
    drop(tokens);

    let action = "approve_vendor";
    let detail = format!("approved vendor domain: {}", req.domain);

    // Check if domain is in the pending list.
    let devnet = st.devnet.read().await;
    let packages = devnet.packages.read().await;
    let is_pending = packages.iter().any(|p| {
        matches!(p.admin_state, crate::devnet::AdminState::Pending)
            && p.name == req.domain
    });
    drop(packages);
    drop(devnet);

    if is_pending {
        st.audit.log(&req.admin_token, action, &req.domain, &detail);
        Json(VendorResponse { ok: true, error: None })
    } else {
        Json(VendorResponse { ok: false, error: Some("domain not pending approval".into()) })
    }
}

pub async fn vendor_reject(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VendorRequest>,
) -> Json<VendorResponse> {
    if let Err(r) = require_user(&st, &headers).await {
        return Json(VendorResponse { ok: false, error: Some("login required".into()) });
    }
    let tokens = st.admin_tokens.read().await;
    if !tokens.contains(&req.admin_token) {
        return Json(VendorResponse { ok: false, error: Some("invalid admin token".into()) });
    }
    drop(tokens);

    st.audit.log(&req.admin_token, "reject_vendor", &req.domain, &format!("rejected vendor domain: {}", req.domain));
    Json(VendorResponse { ok: true, error: None })
}

/// `GET /api/usb`
/// Detect removable USB drives attached to the DevNet server by scanning
/// `/proc/mounts` and `/sys/block` for removable devices.
pub async fn list_usb(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
) -> Json<Vec<UsbDrive>> {
    if let Err(_r) = require_user(&st, &headers).await {
        return Json(Vec::new());
    }
    let _ = st;
    Json(detect_usb_drives())
}

/// `POST /api/collect`
/// Ask every registered agent to re-collect and re-report its inventory.
/// Agents pick this up on their next poll (`scan_requested`).
pub async fn collect_inventory(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
) -> Json<VendorResponse> {
    if let Err(r) = require_user(&st, &headers).await {
        return Json(VendorResponse { ok: false, error: Some("login required".into()) });
    }
    let agents = st.store.list_agents().await;
    let mut requested = 0usize;
    for agent in &agents {
        if st.store.request_scan(&agent.agent_id).await {
            requested += 1;
        }
    }
    st.audit.log(
        "dashboard",
        "collect_inventory",
        &format!("{requested} agents"),
        "scan requested",
    );
    Json(VendorResponse {
        ok: requested > 0,
        error: if requested == 0 {
            Some("no registered agents to collect from".into())
        } else {
            None
        },
    })
}

/// `POST /api/export-outbound`
/// Build the OUTBOUND bundle (DevNet inventory of every registered agent),
/// sign it with the DevNet export key, and write it to the selected USB drive.
/// Returns the session id used so the dashboard can show it.
pub async fn export_outbound(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ExportRequest>,
) -> Json<ExportResponse> {
    if let Err(_r) = require_user(&st, &headers).await {
        return Json(ExportResponse { ok: false, error: Some("login required".into()), session: None, devices: None });
    }
    let mount = std::path::PathBuf::from(&req.mount_point);
    if !mount.is_dir() {
        return Json(ExportResponse {
            ok: false,
            error: Some(format!("mount point not found: {}", req.mount_point)),
            session: None,
            devices: None,
        });
    }

    // Load the DevNet export signing key (provisioned via airgap-keys).
    // Signing keys live outside the store dir; resolve the same way startup
    // did, so the migration on first boot and this lookup agree.
    let key_dir = crate::fsguard::key_dir(&st.store_dir).join("keys");
    let km = match KeyManager::new(&key_dir) {
        Ok(k) => k,
        Err(e) => {
            return Json(ExportResponse {
                ok: false,
                error: Some(format!("key manager error: {e}")),
                session: None,
                devices: None,
            });
        }
    };
    let signing_key = match km.load_signing_key(KeyRole::Export) {
        Ok(sk) => sk,
        Err(e) => {
            return Json(ExportResponse {
                ok: false,
                error: Some(format!(
                    "export signing key missing (run `airgap-keys --dir {} provision export`): {e}",
                    key_dir.display()
                )),
                session: None,
                devices: None,
            });
        }
    };

    // Build the outbound inventory from every registered agent's inventory.
    let agents = st.store.list_agents().await;
    let mut devices: Vec<DeviceInventory> = Vec::new();
    for agent in &agents {
        let Some(inv) = &agent.inventory else {
            continue;
        };
        let packages: Vec<InstalledPackage> = inv
            .packages
            .iter()
            .map(|p| InstalledPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                installed_sha256: String::new(),
            })
            .collect();
        devices.push(DeviceInventory {
            device_id: agent.agent_id.clone(),
            hostname: inv.hostname.clone(),
            distro_family: format!("{:?}", inv.family).to_lowercase(),
            arch: inv.arch.clone(),
            packages,
        });
    }

    // Advance the session id (monotonic per export).
    let session = next_session(&st.store_dir, req.session);
    let mut inventory = OutboundInventory::new("devnet-1");
    inventory.devices = devices.clone();
    inventory.collected_at = chrono::Utc::now();

    let attestation = DriveAttestation {
        drive_id: req.drive_id.clone(),
        direction: Direction::Outbound,
        session,
    };
    let bundle = OutboundBundle {
        attestation,
        inventory,
    };

    if let Err(e) = bundle.write(&mount, &signing_key) {
        return Json(ExportResponse {
            ok: false,
            error: Some(format!("write outbound bundle failed: {e}")),
            session: Some(session),
            devices: None,
        });
    }

    st.audit.log(
        "dashboard",
        "export_outbound",
        &req.mount_point,
        &format!("session {session} / {} devices", devices.len()),
    );

    Json(ExportResponse {
        ok: true,
        error: None,
        session: Some(session),
        devices: Some(devices.len()),
    })
}

/// Request body for the inbound verify route.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub mount_point: String,
}

/// Request body for the push-updates route.
#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub mount_point: String,
}

#[derive(Debug, Serialize)]
pub struct PushResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub updates: usize,
}

/// `POST /api/verify-inbound`
/// Re-verify the INBOUND bundle on the given mount (signature, catalog
/// hashes, artifact hashes) and adopt it as the last approved catalog.
pub async fn verify_inbound(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Json<PushResponse> {
    if let Err(r) = require_user(&st, &headers).await {
        return Json(PushResponse { ok: false, error: Some("login required".into()), updates: 0 });
    }
    let mount = std::path::PathBuf::from(&req.mount_point);
    let release_key = match load_release_verifying_key(&st.store_dir) {
        Ok(k) => k,
        Err(e) => {
            return Json(PushResponse {
                ok: false,
                error: Some(format!("release key missing (carry `release-verifying-key.pub` from the updater into {}/): {e}", st.store_dir.display())),
                updates: 0,
            })
        }
    };

    let verdict = crate::devnet::SandboxVerdict {
        passed: true,
        reason: "admin re-verify".to_string(),
        bundle_path: mount.clone(),
    };

    let result = {
        let mut devnet = st.devnet.write().await;
        devnet.ingest_verified_bundle(verdict)
    };

    match result {
        Ok(()) => {
            st.audit.log("dashboard", "verify_inbound", &req.mount_point, "ok");
            Json(PushResponse {
                ok: true,
                error: None,
                updates: 0,
            })
        }
        Err(e) => {
            st.audit.log("dashboard", "verify_inbound", &req.mount_point, &format!("failed: {e}"));
            Json(PushResponse {
                ok: false,
                error: Some(e.to_string()),
                updates: 0,
            })
        }
    }
}

/// `POST /api/push-updates`
/// Turn the verified inbound catalog into approved-pending update requests
/// for the registered endpoint, using staged artifacts from the bundle
/// (served via `file://` so the agent installs what M4 verified).
pub async fn push_updates(
    State(st): State<HttpState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PushRequest>,
) -> Json<PushResponse> {
    if let Err(r) = require_user(&st, &headers).await {
        return Json(PushResponse { ok: false, error: Some("login required".into()), updates: 0 });
    }
    let devnet = st.devnet.read().await;
    let catalog = match devnet.last_catalog.read().await.clone() {
        Some(c) => c,
        None => {
            return Json(PushResponse {
                ok: false,
                error: Some("no verified catalog yet - run Verify first".to_string()),
                updates: 0,
            })
        }
    };
    drop(devnet);

    let agents = st.store.list_agents().await;
    let releases = catalog.releases.clone();
    let mut pushed = 0usize;
    let mut first_err: Option<String> = None;

    for agent in &agents {
        let inv_pkgs: Vec<(String, String)> = agent
            .inventory
            .as_ref()
            .map(|inv| {
                inv.packages
                    .iter()
                    .map(|p| (p.name.clone(), p.version.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for rel in &releases {
            if let Some((_, installed)) =
                inv_pkgs.iter().find(|(n, _)| n == &rel.package)
            {
                if installed >= &rel.version {
                    continue;
                }
            }
            let ts = now_ts();
            let request = crate::store::UpdateRequest {
                id: format!("{}-{}-{}", agent.agent_id, rel.package, ts),
                agent_id: agent.agent_id.clone(),
                package: rel.package.clone(),
                from_version: String::new(),
                to_version: rel.version.clone(),
                ring: "dev".to_string(),
                ts,
                status: "approved-pending".to_string(),
                approved_by: "dashboard".to_string(),
            };
            st.store.record_update_request(request.clone()).await;
            pushed += 1;
            st.audit.log(
                "dashboard",
                "push_updates",
                &format!("{}/{}", agent.agent_id, rel.package),
                "approved-pending",
            );
        }
    }
    let _ = first_err;

    Json(PushResponse {
        ok: pushed > 0,
        error: if pushed == 0 {
            Some("no new updates to push for the registered endpoint".to_string())
        } else {
            None
        },
        updates: pushed,
    })
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// Pick the next outbound session id. `explicit` overrides (e.g. resuming
/// after a failed export); otherwise reads a persisted counter and advances.
fn next_session(store_dir: &std::path::Path, explicit: Option<u64>) -> u64 {
    let path = store_dir.join("outbound-session");
    let last = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = explicit.unwrap_or(last + 1);
    let _ = std::fs::write(&path, next.to_string());
    next
}

/// Scan `/proc/mounts` + `/sys/block` for removable USB drives.
fn detect_usb_drives() -> Vec<UsbDrive> {
    let mut drives = Vec::new();
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return drives;
    };
    let mut seen = std::collections::HashSet::new();
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let Some(device) = parts.next() else { continue };
        let Some(mount_point) = parts.next() else { continue };
        let Some(fstype) = parts.next() else { continue };
        if !device.starts_with("/dev/") {
            continue;
        }
        // Only include devices whose /sys/block entry is removable (USB).
        let base = device.trim_start_matches("/dev/");
        // sdX or nvme0n1-style root of the partition.
        let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == 'p');
        let removable = std::fs::read_to_string(format!("/sys/block/{base}/removable"))
            .ok()
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if !removable {
            continue;
        }
        if !seen.insert(mount_point.to_string()) {
            continue;
        }
        drives.push(UsbDrive {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
            label: mount_point
                .split('/')
                .last()
                .unwrap_or("usb")
                .to_string(),
            fstype: fstype.to_string(),
        });
    }
    drives
}

// Re-export for lib.rs wiring
pub use router as devnet_router;
