use std::collections::HashMap;
use std::sync::Arc;

use airgap_proto::{
    ArtifactRequest, EnrollRequest, EnrollResponse, InventoryRequest, InventoryResponse,
    OsInventory, PollRequest, PollResponse, RegisterRequest, RegisterResponse, ReportRequest,
    ReportResponse,
};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio::sync::Mutex;

use crate::audit::AuditLog;
use crate::ca::Ca;
use crate::catalog::{self, Catalog};
use crate::store::{AgentRecord, ReportRecord, Store};
use crate::tls::ClientIdentity;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub ca: Arc<Mutex<Ca>>,
    pub cert_dir: std::path::PathBuf,
    pub store_dir: std::path::PathBuf,
    pub catalog: Arc<Catalog>,
    pub audit: Arc<AuditLog>,
    pub rate: RateLimiter,
}

/// Simple in-memory fixed-window rate limiter, one bucket per key.
#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, (u64, u32)>>>,
}

impl RateLimiter {
    pub async fn check(&self, key: &str, limit: u32, window_secs: u64) -> bool {
        let now = now_ts_num();
        let mut m = self.inner.lock().await;
        let entry = m.entry(key.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= window_secs {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

fn err<S: Into<String>>(status: StatusCode, msg: S) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn require_auth(identity: &ClientIdentity) -> Result<String, Response> {
    match (&identity.cn, identity.authenticated) {
        (Some(cn), true) if !cn.is_empty() => Ok(cn.clone()),
        _ => Err(err(
            StatusCode::UNAUTHORIZED,
            "a valid client certificate is required",
        )),
    }
}

#[axum::debug_handler]
pub async fn enroll(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<EnrollRequest>,
) -> Response {
    let peer = identity.peer.clone().unwrap_or_default();
    if !st.rate.check(&format!("enroll:{peer}"), 20, 60).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    if !st.store.check_token(&req.token).await {
        st.audit.log("unknown", "enroll", &peer, "invalid_token");
        return err(StatusCode::UNAUTHORIZED, "invalid enrollment token");
    }
    let agent_id = format!("agent-{}", req.hostname.trim().to_lowercase());
    if st.store.is_revoked(&agent_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "this agent has been revoked; contact an administrator",
        );
    }
    let mut ca = st.ca.lock().await;
    match ca.issue_client(&agent_id, &st.cert_dir) {
        Ok((cert, key)) => {
            ca.save_serial(&st.cert_dir);
            st.audit.log(
                &agent_id,
                "enroll",
                &agent_id,
                "ok",
            );
            let resp = EnrollResponse {
                agent_id: agent_id.clone(),
                cert: cert.pem(),
                cert_key: key.serialize_pem(),
                ca_cert: ca.ca_cert_pem(),
            };
            let record = AgentRecord {
                agent_id,
                hostname: req.hostname,
                inventory: None,
                last_seen: None,
                status: "enrolled".to_string(),
                ip: identity.peer,
                scan_requested: None,
            };
            st.store.register_agent(record).await;
            Json(resp).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn register(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<RegisterRequest>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if cn != req.agent_id {
        return err(
            StatusCode::FORBIDDEN,
            "agent_id does not match client certificate",
        );
    }
    let record = AgentRecord {
        agent_id: req.agent_id.clone(),
        hostname: sanitize_str(&req.inventory.hostname, 255),
        inventory: Some(sanitize_inventory(req.inventory)),
        last_seen: Some(now_ts()),
        status: "registered".to_string(),
        ip: identity.peer,
        scan_requested: None,
    };
    st.store.register_agent(record).await;
    tracing::info!("agent registered: {cn}");
    st.audit.log(cn.as_str(), "register", cn.as_str(), "ok");
    Json(RegisterResponse {
        accepted: true,
        agent_id: cn,
    })
    .into_response()
}

pub async fn inventory(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<InventoryRequest>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if cn != req.agent_id {
        return err(StatusCode::FORBIDDEN, "agent_id does not match certificate");
    }
    let ok = st
        .store
        .update_inventory(&cn, sanitize_inventory(req.inventory), identity.peer)
        .await;
    if !ok {
        return err(StatusCode::NOT_FOUND, "agent not registered");
    }
    st.store.clear_scan(&cn).await;
    Json(InventoryResponse { accepted: true }).into_response()
}

pub async fn poll(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<PollRequest>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if cn != req.agent_id {
        return err(StatusCode::FORBIDDEN, "agent_id does not match certificate");
    }
    let updates = st.store.pending_updates_for_agent(&cn).await;
    let scan_requested = st.store.scan_pending(&cn).await;
    Json(PollResponse {
        updates,
        scan_requested,
    })
    .into_response()
}

pub async fn health(State(st): State<ApiState>) -> Response {
    let agents = st.store.list_agents().await;
    let pending = st
        .store
        .update_requests()
        .await
        .iter()
        .filter(|u| u.status == "approved-pending")
        .count();
    let status = st.catalog.status().await;
    Json(serde_json::json!({
        "status": "ok",
        "agents": agents.len(),
        "pending_approvals": pending,
        "last_catalog_sync": status.last_sync,
        "catalog_syncing": status.syncing,
    }))
    .into_response()
}

pub async fn report(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<ReportRequest>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if !st.rate.check(&format!("report:{cn}"), 60, 60).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    if cn != req.agent_id {
        return err(StatusCode::FORBIDDEN, "agent_id does not match certificate");
    }
    let req_id = req.update_id.clone();
    let code = req.status.code.clone();
    st.store
        .record_report(ReportRecord {
            agent_id: req.agent_id,
            update_id: req_id.clone(),
            status: req.status,
            ts: now_ts(),
        })
        .await;
    let next_status = if code == "ok" { "done" } else { "failed" };
    st.store.mark_update_status(&req_id, next_status).await;
    st.audit.log(&cn, "update_result", &req_id, next_status);
    Json(ReportResponse { accepted: true }).into_response()
}

const MAX_ARTIFACT_BYTES: usize = 1024 * 1024 * 1024;

/// Serves the actual .rpm/.deb for an approved-pending update by proxying it
/// from the whitelisted upstream source. The server is the only online host;
/// agents on isolated networks fetch the artifact over mTLS and install from
/// the local file. Only approved updates are served, and only to their
/// target agent. Fetched artifacts are cached on disk by update id.
pub async fn artifact(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<ArtifactRequest>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if cn != req.agent_id {
        return err(
            StatusCode::FORBIDDEN,
            "agent_id does not match client certificate",
        );
    }
    if !st.rate.check(&format!("artifact:{cn}"), 240, 60).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    let family = req.family.to_lowercase();
    if family != "rhel" && family != "debian" && family != "windows" {
        return err(StatusCode::BAD_REQUEST, "unsupported family");
    }
    let Some(update) = st.store.update_request(&req.update_id).await else {
        return err(StatusCode::NOT_FOUND, "update not found");
    };
    if update.agent_id != req.agent_id {
        return err(
            StatusCode::FORBIDDEN,
            "update does not belong to this agent",
        );
    }
    if update.status != "approved-pending" {
        return err(
            StatusCode::FORBIDDEN,
            "update is not approved for install",
        );
    }

    let artifact_dir = st.store_dir.join("artifacts");
    let cached = artifact_dir.join(&req.update_id);
    if let Ok(bytes) = tokio::fs::read(&cached).await {
        if !bytes.is_empty() {
            return artifact_response(&artifact_filename(&update.package, &family), &bytes);
        }
    }

    let sources = st.store.enabled_sources().await;
    let Some(url) = st
        .catalog
        .artifact_url(&family, &update.package, &sources)
        .await
    else {
        return err(
            StatusCode::NOT_FOUND,
            format!(
                "no artifact location known for {}; refresh the catalog",
                update.package
            ),
        );
    };

    if let Some(local) = url.strip_prefix("file://") {
        let bytes = match tokio::fs::read(local).await {
            Ok(b) => b,
            Err(e) => {
                return err(
                    StatusCode::NOT_FOUND,
                    format!("staged artifact unavailable on server: {e}"),
                )
            }
        };
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return err(StatusCode::BAD_GATEWAY, "artifact is empty or too large");
        }
        let _ = tokio::fs::create_dir_all(&artifact_dir).await;
        let _ = tokio::fs::write(&cached, &bytes).await;
        st.audit.log(&cn, "artifact", &update.package, local);
        return artifact_response(&artifact_filename(&update.package, &family), &bytes);
    }

    let client = catalog::build_client(&sources);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("upstream fetch failed: {e}"),
            )
        }
    };
    let status = resp.status();
    if !status.is_success() {
        return err(
            StatusCode::BAD_GATEWAY,
            format!("upstream fetch failed: HTTP {status}"),
        );
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_ARTIFACT_BYTES as u64 {
            return err(StatusCode::BAD_GATEWAY, "artifact too large");
        }
    }
    let bytes = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("artifact read failed: {e}"),
            )
        }
    };
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
        return err(StatusCode::BAD_GATEWAY, "artifact is empty or too large");
    }

    let _ = tokio::fs::create_dir_all(&artifact_dir).await;
    let _ = tokio::fs::write(&cached, &bytes).await;
    st.audit.log(&cn, "artifact", &update.package, &url);
    artifact_response(&artifact_filename(&update.package, &family), &bytes)
}

fn artifact_filename(pkg: &str, family: &str) -> String {
    let base = if pkg.chars().all(|c| c.is_ascii_alphanumeric() || "+._-".contains(c)) {
        pkg
    } else {
        "package"
    };
    let ext = if family == "debian" {
        "deb"
    } else if family == "windows" {
        "msu"
    } else {
        "rpm"
    };
    format!("{base}.{ext}")
}

fn artifact_response(filename: &str, bytes: &[u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header("x-artifact-filename", filename)
        .body(axum::body::Body::from(bytes.to_vec()))
        .unwrap_or_else(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build artifact response",
            )
        })
}

fn now_ts() -> String {
    now_ts_num().to_string()
}

fn now_ts_num() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Strips control characters and truncates untrusted agent-supplied fields
/// before they are stored or rendered, to prevent stored-XSS via inventory.
fn sanitize_str(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn sanitize_inventory(mut inv: OsInventory) -> OsInventory {
    inv.hostname = sanitize_str(&inv.hostname, 255);
    inv.os_name = sanitize_str(&inv.os_name, 100);
    inv.os_version = sanitize_str(&inv.os_version, 100);
    inv.os_pretty = sanitize_str(&inv.os_pretty, 200);
    inv.arch = sanitize_str(&inv.arch, 50);
    inv.kernel = sanitize_str(&inv.kernel, 100);
    inv.bootloader = sanitize_str(&inv.bootloader, 100);
    for p in inv.packages.iter_mut() {
        p.name = sanitize_str(&p.name, 200);
        p.version = sanitize_str(&p.version, 200);
        p.arch = sanitize_str(&p.arch, 50);
        p.source = sanitize_str(&p.source, 200);
    }
    inv.repos = inv.repos.iter().map(|r| sanitize_str(r, 200)).collect();
    inv
}
