use std::collections::HashMap;
use std::sync::Arc;

use airgap_proto::{
    EnrollRequest, EnrollResponse, InventoryRequest, InventoryResponse, OsInventory, PollRequest,
    PollResponse, RegisterRequest, RegisterResponse, ReportRequest, ReportResponse,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio::sync::Mutex;

use crate::audit::AuditLog;
use crate::ca::Ca;
use crate::catalog::Catalog;
use crate::store::{AgentRecord, ReportRecord, Store};
use crate::tls::ClientIdentity;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub ca: Arc<Mutex<Ca>>,
    pub cert_dir: std::path::PathBuf,
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

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
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
    Json(InventoryResponse { accepted: true }).into_response()
}

pub async fn poll(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(_req): Json<PollRequest>,
) -> Response {
    let _cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    let updates = st.store.pending_updates().await;
    Json(PollResponse { updates }).into_response()
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
    st.store
        .record_report(ReportRecord {
            agent_id: req.agent_id,
            update_id: req.update_id,
            status: req.status,
            ts: now_ts(),
        })
        .await;
    Json(ReportResponse { accepted: true }).into_response()
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
