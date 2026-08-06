use std::sync::Arc;

use airgap_proto::{
    EnrollRequest, EnrollResponse, InventoryRequest, InventoryResponse, PollRequest, PollResponse,
    RegisterRequest, RegisterResponse, ReportRequest, ReportResponse,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::audit::AuditLog;
use crate::ca::Ca;
use crate::catalog::Catalog;
use crate::store::{AgentRecord, ReportRecord, Store};
use crate::tls::ClientIdentity;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub ca: Arc<tokio::sync::Mutex<Ca>>,
    pub cert_dir: std::path::PathBuf,
    pub catalog: Arc<Catalog>,
    pub audit: Arc<AuditLog>,
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
    if !st.store.check_token(&req.token).await {
        return err(StatusCode::UNAUTHORIZED, "invalid enrollment token");
    }
    let agent_id = format!("agent-{}", req.hostname.trim().to_lowercase());
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
        hostname: req.inventory.hostname.clone(),
        inventory: Some(req.inventory),
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
        .update_inventory(&cn, req.inventory, identity.peer)
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
