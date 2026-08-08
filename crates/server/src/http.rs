use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use airgap_proto::OsInventory;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::audit::AuditLog;
use crate::auth::{Auth, Session};
use crate::catalog::{Catalog, LatestPackage};
use crate::provision::ScanJob;
use crate::store::{AgentRecord, Credential, Network, Policy, Source, Store, UpdateRequest};

#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub catalog: Arc<Catalog>,
    pub audit: Arc<AuditLog>,
    pub auth: Arc<Auth>,
    pub store_dir: PathBuf,
    pub server_url: String,
    pub scan: Arc<RwLock<Option<ScanJob>>>,
}

pub async fn serve(
    addr: std::net::SocketAddr,
    router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("dashboard listening on http://{addr}");
    axum::serve(listener, router).await.map_err(|e| e.into())
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn sanitize_str(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

async fn current_user(st: &HttpState, headers: &HeaderMap) -> Result<Session, Response> {
    let token = bearer_token(headers)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "login required"))?;
    st.auth
        .session(&token)
        .await
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired session"))
}

async fn require_role(
    st: &HttpState,
    headers: &HeaderMap,
    min_role: &str,
) -> Result<Session, Response> {
    let session = current_user(st, headers).await?;
    if !Auth::role_allows(&session, min_role) {
        return Err(err(StatusCode::FORBIDDEN, "insufficient role"));
    }
    Ok(session)
}

fn pkg_update_available(
    inv: &OsInventory,
    name: &str,
    version: &str,
    catalog: &HashMap<String, LatestPackage>,
) -> bool {
    let family = format!("{:?}", inv.family).to_lowercase();
    // Windows updates are tracked by KB membership, not version: a KB is
    // "available" when it exists in the catalog but is not installed, which
    // is computed separately (see windows_updates_available). Installed KBs
    // are always up to date here.
    if family == "windows" {
        return false;
    }
    match (catalog.get(&crate::catalog::key_of(&family, name)), version.is_empty()) {
        (Some(l), false) => l.version != version,
        _ => false,
    }
}

/// For Windows agents the catalog holds KB updates; one is available when it
/// is in the catalog but not in the installed package set.
fn windows_updates_available(
    inv: &OsInventory,
    catalog: &HashMap<String, LatestPackage>,
) -> usize {
    let installed: std::collections::HashSet<String> = inv
        .packages
        .iter()
        .map(|p| p.name.to_lowercase())
        .collect();
    catalog
        .values()
        .filter(|l| l.family.eq_ignore_ascii_case("windows"))
        .filter(|l| !installed.contains(&l.name.to_lowercase()))
        .count()
}

#[derive(Serialize)]
struct DeviceSummary {
    id: String,
    hostname: String,
    os_pretty: String,
    os_name: String,
    os_version: String,
    family: String,
    arch: String,
    kernel: String,
    bootloader: String,
    ip: Option<String>,
    last_seen: Option<String>,
    status: String,
    packages: usize,
    updates_available: usize,
    scan_requested: Option<String>,
}

fn summarize(r: AgentRecord, catalog: &HashMap<String, LatestPackage>) -> DeviceSummary {
    let inv = r.inventory.clone();
    let updates_available = inv.as_ref().map(|i| {
        let family = format!("{:?}", i.family).to_lowercase();
        if family == "windows" {
            windows_updates_available(i, catalog)
        } else {
            i.packages
                .iter()
                .filter(|p| pkg_update_available(i, &p.name, &p.version, catalog))
                .count()
        }
    }).unwrap_or(0);
    DeviceSummary {
        id: r.agent_id,
        hostname: r.hostname,
        os_pretty: inv.as_ref().map(|i| i.os_pretty.clone()).unwrap_or_default(),
        os_name: inv.as_ref().map(|i| i.os_name.clone()).unwrap_or_default(),
        os_version: inv.as_ref().map(|i| i.os_version.clone()).unwrap_or_default(),
        family: format!("{:?}", inv.as_ref().map(|i| i.family).unwrap_or_default())
            .to_lowercase(),
        arch: inv.as_ref().map(|i| i.arch.clone()).unwrap_or_default(),
        kernel: inv.as_ref().map(|i| i.kernel.clone()).unwrap_or_default(),
        bootloader: inv.as_ref().map(|i| i.bootloader.clone()).unwrap_or_default(),
        ip: r.ip,
        last_seen: r.last_seen,
        status: r.status,
        packages: inv.map(|i| i.packages.len()).unwrap_or(0),
        updates_available,
        scan_requested: r.scan_requested,
    }
}

#[derive(Serialize)]
struct PkgRow {
    name: String,
    installed: String,
    arch: String,
    source: String,
    latest: Option<String>,
    update_available: bool,
    policy: String,
}

pub async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

pub async fn devices(
    State(st): State<HttpState>,
    headers: HeaderMap,
) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let agents = st.store.list_agents().await;
    let catalog = st.catalog.snapshot().await;
    let devs: Vec<DeviceSummary> = agents
        .into_iter()
        .map(|a| summarize(a, &catalog))
        .collect();
    Json(devs).into_response()
}

pub async fn device_packages(
    State(st): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let agent = match st.store.get_agent(&id).await {
        Some(a) => a,
        None => return err(StatusCode::NOT_FOUND, "device not found"),
    };
    let Some(inv) = agent.inventory else {
        return Json(serde_json::json!({ "agent_id": id, "packages": [] })).into_response();
    };
    let catalog = st.catalog.snapshot().await;
    let policy = st.store.policy_snapshot().await;

    let mut rows: Vec<PkgRow> = inv
        .packages
        .iter()
        .map(|p| {
            let family = format!("{:?}", inv.family).to_lowercase();
            let latest = catalog
                .get(&crate::catalog::key_of(&family, &p.name))
                .map(|l| l.version.clone());
            let update_available = pkg_update_available(&inv, &p.name, &p.version, &catalog);
            PkgRow {
                name: p.name.clone(),
                installed: p.version.clone(),
                arch: p.arch.clone(),
                source: p.source.clone(),
                latest,
                update_available,
                policy: if policy_allows_local(&policy, &p.name) {
                    "allow".to_string()
                } else {
                    "deny".to_string()
                },
            }
        })
        .collect();
    // Windows: surface catalog KBs that are not yet installed so an
    // operator can approve them (a KB is "available" by membership).
    let family = format!("{:?}", inv.family).to_lowercase();
    if family == "windows" {
        let installed: std::collections::HashSet<String> = inv
            .packages
            .iter()
            .map(|p| p.name.to_lowercase())
            .collect();
        let mut avail: Vec<&LatestPackage> = catalog
            .values()
            .filter(|l| l.family.eq_ignore_ascii_case("windows"))
            .filter(|l| !installed.contains(&l.name.to_lowercase()))
            .collect();
        avail.sort_by(|a, b| a.name.cmp(&b.name));
        for l in avail {
            rows.push(PkgRow {
                name: l.name.clone(),
                installed: String::new(),
                arch: l.arch.clone(),
                source: l.repo.clone(),
                latest: Some(l.version.clone()),
                update_available: true,
                policy: if policy_allows_local(&policy, &l.name) {
                    "allow".to_string()
                } else {
                    "deny".to_string()
                },
            });
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    Json(serde_json::json!({
        "agent_id": id,
        "hostname": agent.hostname,
        "packages": rows,
    }))
    .into_response()
}

pub async fn refresh_catalog(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_APPROVER).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let sources = st.store.enabled_sources().await;
    let client = crate::catalog::build_client(&sources);
    match st.catalog.sync(&client, &sources).await {
        Ok(report) => {
            st.audit
                .log(&session.operator, "catalog_refresh", "upstream", "ok");
            Json(report).into_response()
        }
        Err(e) => {
            st.audit
                .log(&session.operator, "catalog_refresh", "upstream", "failed");
            err(StatusCode::BAD_GATEWAY, &e)
        }
    }
}

pub async fn refresh_status(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.catalog.status().await).into_response()
}

pub async fn health(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
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
        "catalog_phase": status.phase,
    }))
    .into_response()
}

pub async fn audit_log(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.audit.recent(500)).into_response()
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

pub async fn login(State(st): State<HttpState>, Json(body): Json<LoginBody>) -> Response {
    match st.auth.login(&body.username, &body.password).await {
        Some(s) => {
            st.audit.log(&s.operator, "login", "dashboard", "ok");
            Json(serde_json::json!({
                "token": s.token,
                "operator": s.operator,
                "role": s.role,
            }))
            .into_response()
        }
        None => {
            st.audit
                .log(&body.username, "login", "dashboard", "failed");
            err(StatusCode::UNAUTHORIZED, "invalid credentials")
        }
    }
}

pub async fn logout(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    if let Some(token) = bearer_token(&headers) {
        st.auth.logout(&token).await;
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn me(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    match current_user(&st, &headers).await {
        Ok(s) => Json(serde_json::json!({ "operator": s.operator, "role": s.role })).into_response(),
        Err(r) => r,
    }
}

pub async fn list_operators(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.auth.list_operators().await).into_response()
}

#[derive(Deserialize)]
pub struct CreateOperatorBody {
    pub name: String,
    pub password: String,
    pub role: String,
}

pub async fn create_operator(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateOperatorBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if body.name.trim().is_empty() || body.password.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "name and password are required");
    }
    match st
        .auth
        .create_operator(body.name.trim(), &body.password, &body.role)
        .await
    {
        Ok(()) => {
            st.audit
                .log(&session.operator, "operator_create", body.name.trim(), "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

pub async fn delete_operator(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if name == session.operator {
        return err(StatusCode::BAD_REQUEST, "cannot delete your own account");
    }
    match st.auth.delete_operator(&name).await {
        true => {
            st.audit.log(&session.operator, "operator_delete", &name, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "operator not found"),
    }
}

pub async fn get_policy(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.store.policy_snapshot().await).into_response()
}

#[derive(Deserialize)]
pub struct SetPolicyBody {
    pub default_deny: bool,
}

pub async fn set_policy(State(st): State<HttpState>, headers: HeaderMap, Json(b): Json<SetPolicyBody>) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    st.store.set_policy_default_deny(b.default_deny).await;
    st.audit
        .log(&session.operator, "policy_set", "default_deny", &format!("{}", b.default_deny));
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct PolicyEntryBody {
    pub package: String,
    pub action: String,
    pub note: Option<String>,
}

pub async fn upsert_policy_entry(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(b): Json<PolicyEntryBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !matches!(b.action.as_str(), "allow" | "deny") {
        return err(StatusCode::BAD_REQUEST, "action must be 'allow' or 'deny'");
    }
    if b.package.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "package is required");
    }
    st.store
        .upsert_policy_entry(b.package.trim(), &b.action, b.note.as_deref().unwrap_or(""))
        .await;
    st.audit
        .log(&session.operator, "policy_entry", b.package.trim(), &b.action);
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn delete_policy_entry(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if st.store.delete_policy_entry(&name).await {
        st.audit
            .log(&session.operator, "policy_entry_delete", &name, "ok");
        Json(serde_json::json!({ "ok": true })).into_response()
    } else {
        err(StatusCode::NOT_FOUND, "policy entry not found")
    }
}

pub async fn rings(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let ups = st.store.update_requests().await;
    let mut groups: HashMap<String, Vec<UpdateRequest>> = HashMap::new();
    for u in ups {
        groups.entry(u.ring.clone()).or_default().push(u);
    }
    for v in groups.values_mut() {
        v.sort_by(|a, b| b.ts.cmp(&a.ts));
    }
    Json(serde_json::json!({
        "dev": groups.get("dev").cloned().unwrap_or_default(),
        "staging": groups.get("staging").cloned().unwrap_or_default(),
        "prod": groups.get("prod").cloned().unwrap_or_default(),
    }))
    .into_response()
}

pub async fn promote_update(
    State(st): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_APPROVER).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.promote_update(&id).await {
        Ok(r) => {
            st.audit.log(&session.operator, "ring_promote", &id, &r.ring);
            Json(r).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

pub async fn search_catalog(
    State(st): State<HttpState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let q = params.get("q").cloned().unwrap_or_default().to_lowercase();
    let page = params
        .get("page")
        .and_then(|p| p.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let per = params
        .get("per")
        .and_then(|p| p.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let snap = st.catalog.snapshot().await;
    let mut items: Vec<LatestPackage> = snap.into_values().collect();
    if !q.is_empty() {
        items.retain(|p| p.name.to_lowercase().contains(&q));
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let total = items.len();
    let start = (page - 1) * per;
    let page_items: Vec<LatestPackage> = items.into_iter().skip(start).take(per).collect();
    Json(serde_json::json!({
        "total": total,
        "page": page,
        "per": per,
        "items": page_items,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct RevokeBody {
    pub reason: Option<String>,
}

pub async fn revoke_agent(
    State(st): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(b): Json<RevokeBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let reason = b.reason.unwrap_or_default();
    match st.store.revoke_agent(&id, &reason).await {
        true => {
            st.audit.log(&session.operator, "agent_revoke", &id, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::CONFLICT, "agent already revoked"),
    }
}

pub async fn list_revoked(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.store.list_revoked().await).into_response()
}

fn policy_allows_local(p: &Policy, name: &str) -> bool {
    match p.entries.get(&name.to_lowercase()) {
        Some(e) => e.action == "allow",
        None => !p.default_deny,
    }
}

pub async fn scan_device(
    State(st): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_APPROVER).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.request_scan(&id).await {
        true => {
            st.audit.log(&session.operator, "scan_request", &id, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "device not found"),
    }
}

pub async fn list_sources(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.store.list_sources().await).into_response()
}

#[derive(Deserialize)]
pub struct SourceBody {
    pub name: String,
    pub family: String,
    pub kind: String,
    pub base_url: String,
    pub suite: Option<String>,
    #[serde(default)]
    pub kbs: Option<Vec<String>>,
}

pub async fn add_source(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(b): Json<SourceBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if b.name.trim().is_empty() || b.base_url.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "name and base_url are required");
    }
    if !matches!(b.kind.as_str(), "apt" | "dnf" | "wucatalog" | "none") {
        return err(
            StatusCode::BAD_REQUEST,
            "kind must be 'apt', 'dnf', 'wucatalog' or 'none'",
        );
    }
    if b.kind == "wucatalog" && b.family.to_lowercase() != "windows" {
        return err(StatusCode::BAD_REQUEST, "wucatalog sources must use family 'windows'");
    }
    let kbs: Vec<String> = b
        .kbs
        .unwrap_or_default()
        .iter()
        .map(|k| sanitize_str(k, 50))
        .filter(|k| !k.trim().is_empty())
        .map(|k| k.trim().to_uppercase())
        .collect();
    let source = Source {
        name: sanitize_str(&b.name, 100),
        family: sanitize_str(&b.family, 50),
        kind: b.kind.clone(),
        base_url: sanitize_str(&b.base_url, 500),
        suite: sanitize_str(b.suite.as_deref().unwrap_or(""), 100),
        kbs,
        enabled: true,
    };
    st.store.upsert_source(source).await;
    st.audit
        .log(&session.operator, "source_add", &b.name, &b.kind);
    Json(serde_json::json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct SourceToggleBody {
    pub enabled: bool,
}

pub async fn toggle_source(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(b): Json<SourceToggleBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.set_source_enabled(&name, b.enabled).await {
        true => {
            st.audit.log(&session.operator, "source_toggle", &name, &format!("{}", b.enabled));
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "source not found"),
    }
}

pub async fn delete_source(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.delete_source(&name).await {
        true => {
            st.audit.log(&session.operator, "source_delete", &name, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "source not found"),
    }
}

#[derive(Deserialize)]
pub struct UpdateBody {
    pub agent_id: String,
    pub package: String,
}

pub async fn list_credentials(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.store.list_credentials().await).into_response()
}

#[derive(Deserialize)]
pub struct CredentialBody {
    pub name: String,
    pub username: String,
    pub password: String,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub note: Option<String>,
}

pub async fn upsert_credential(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(b): Json<CredentialBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let name = sanitize_str(&b.name, 100);
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        return err(StatusCode::BAD_REQUEST, "name must use letters, digits, -_.@");
    }
    if b.username.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "username is required");
    }
    if b.password.is_empty() {
        return err(StatusCode::BAD_REQUEST, "password is required");
    }
    let credential = Credential {
        name,
        username: sanitize_str(b.username.trim(), 100),
        password: b.password,
        port: b.port.unwrap_or(22).clamp(1, 65535),
        domain: sanitize_str(b.domain.as_deref().unwrap_or(""), 100),
        note: sanitize_str(b.note.as_deref().unwrap_or(""), 200),
    };
    st.store.upsert_credential(credential).await;
    st.audit
        .log(&session.operator, "credential_save", &b.name, "ok");
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn delete_credential(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.delete_credential(&name).await {
        true => {
            st.audit.log(&session.operator, "credential_delete", &name, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "credential not found"),
    }
}

pub async fn list_networks(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(st.store.list_networks().await).into_response()
}

#[derive(Deserialize)]
pub struct NetworkBody {
    pub name: String,
    pub cidr: String,
}

pub async fn add_network(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(b): Json<NetworkBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let name = sanitize_str(&b.name, 100);
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c)) {
        return err(StatusCode::BAD_REQUEST, "name must use letters, digits, -_.@");
    }
    let cidr = sanitize_str(&b.cidr, 64);
    if let Err(e) = crate::provision::parse_cidr(&cidr) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    let network = Network {
        name,
        cidr,
        last_scanned: String::new(),
    };
    st.store.upsert_network(network).await;
    st.audit.log(&session.operator, "network_add", &b.cidr, "ok");
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn delete_network(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match st.store.delete_network(&name).await {
        true => {
            st.audit.log(&session.operator, "network_delete", &name, "ok");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        false => err(StatusCode::NOT_FOUND, "network not found"),
    }
}

pub async fn scan_network(
    State(st): State<HttpState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let network = match st
        .store
        .list_networks()
        .await
        .into_iter()
        .find(|n| n.name == name)
    {
        Some(n) => n,
        None => return err(StatusCode::NOT_FOUND, "network not found"),
    };
    {
        let scan = st.scan.read().await;
        if let Some(job) = scan.as_ref() {
            if job.running {
                return err(StatusCode::CONFLICT, "a discovery scan is already running");
            }
        }
    }
    let started = now_ts();
    *st.scan.write().await = Some(ScanJob {
        network: network.cidr.clone(),
        started: started.clone(),
        running: true,
        hosts: vec![],
        error: String::new(),
    });
    st.audit
        .log(&session.operator, "provision_scan", &network.cidr, "started");
    let scan_state = st.scan.clone();
    let store = st.store.clone();
    let audit = st.audit.clone();
    let net_name = network.name.clone();
    let net_cidr = network.cidr.clone();
    tokio::spawn(async move {
        let result = crate::provision::scan_network(&net_cidr).await;
        let mut job = scan_state.write().await;
        if let Some(j) = job.as_mut() {
            match result {
                Ok(fresh) => {
                    let old = store.list_discovery().await;
                    let merged = crate::provision::merge_discovery(&old, fresh);
                    store.save_discovery(merged.clone()).await;
                    store.set_network_scanned(&net_name, &started).await;
                    j.hosts = merged;
                    j.running = false;
                    j.error = String::new();
                    audit.log(
                        "system",
                        "provision_scan",
                        &net_cidr,
                        &format!("ok:{} hosts", j.hosts.len()),
                    );
                }
                Err(e) => {
                    j.running = false;
                    j.error = e;
                    audit.log("system", "provision_scan", &net_cidr, "failed");
                }
            }
        }
    });
    Json(serde_json::json!({ "ok": true, "network": network.cidr })).into_response()
}

pub async fn provision_status(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let networks = st.store.list_networks().await;
    let hosts = st.store.list_discovery().await;
    let credentials = st.store.list_credentials().await;
    let scan = st.scan.read().await.clone();
    let binary = st.store.agent_binary_present().await;
    Json(serde_json::json!({
        "networks": networks,
        "hosts": hosts,
        "credentials": credentials,
        "scan": scan,
        "agent_binary": binary.map(|size| serde_json::json!({ "present": true, "size": size }))
            .unwrap_or_else(|| serde_json::json!({ "present": false, "size": 0 })),
        "server_url": st.server_url,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ProvisionBody {
    pub credential: String,
}

pub async fn provision_host(
    State(st): State<HttpState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
    Json(b): Json<ProvisionBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let credential = match st.store.get_credential(&b.credential).await {
        Some(c) => c,
        None => return err(StatusCode::NOT_FOUND, "credential not found"),
    };
    match crate::provision::provision_host(
        &st.store,
        &st.store_dir,
        &st.server_url,
        &ip,
        &credential,
    )
    .await
    {
        Ok(outcome) => {
            st.store
                .mark_discovery_provisioned(
                    &ip,
                    &outcome.hostname,
                    &outcome.agent_id,
                    if outcome.ok { "" } else { &outcome.detail },
                )
                .await;
            st.audit.log(
                &session.operator,
                "provision_push",
                &format!("{ip}->{}", outcome.agent_id),
                if outcome.ok { "ok" } else { "partial" },
            );
            Json(serde_json::json!({
                "ok": outcome.ok,
                "agent_id": outcome.agent_id,
                "hostname": outcome.hostname,
                "detail": outcome.detail,
            }))
            .into_response()
        }
        Err(e) => {
            st.store.mark_discovery_provisioned(&ip, "", "", &e).await;
            st.audit.log(&session.operator, "provision_push", &ip, "failed");
            err(StatusCode::BAD_GATEWAY, &e)
        }
    }
}

pub async fn upload_agent_binary(
    State(st): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_ADMIN).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if body.len() < 100_000 || body.len() > 64 * 1024 * 1024 {
        return err(StatusCode::BAD_REQUEST, "agent binary must be 100KB..64MB");
    }
    match st.store.write_agent_binary(&body).await {
        Ok(()) => {
            st.audit
                .log(&session.operator, "agent_binary_upload", "provision", &format!("{}", body.len()));
            Json(serde_json::json!({ "ok": true, "size": body.len() })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn request_update(
    State(st): State<HttpState>,
    headers: HeaderMap,
    Json(req): Json<UpdateBody>,
) -> Response {
    let session = match require_role(&st, &headers, crate::auth::ROLE_APPROVER).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let agent = match st.store.get_agent(&req.agent_id).await {
        Some(a) => a,
        None => return err(StatusCode::NOT_FOUND, "device not found"),
    };
    let Some(inv) = agent.inventory else {
        return err(StatusCode::BAD_REQUEST, "device has no inventory");
    };
    let key = req.package.to_lowercase();
    let family = format!("{:?}", inv.family).to_lowercase();
    let is_windows = family == "windows";
    let installed = inv
        .packages
        .iter()
        .find(|p| p.name.to_lowercase() == key);
    if installed.is_none() && !is_windows {
        return err(StatusCode::NOT_FOUND, "package not installed on device");
    }
    // Windows updates are tracked by KB membership: installing a KB that is
    // already present is a no-op, so refuse the approval.
    if is_windows && installed.is_some() {
        return err(StatusCode::BAD_REQUEST, "update already installed on device");
    }
    let Some(latest) = st
        .catalog
        .latest(&key, &family)
        .await
    else {
        return err(StatusCode::NOT_FOUND, "no upstream package known - refresh catalog first");
    };
    if !is_windows && latest.version == installed.unwrap().version {
        return err(StatusCode::BAD_REQUEST, "already up to date");
    }
    if !st.store.policy_allows(&key).await {
        return err(
            StatusCode::FORBIDDEN,
            "blocked by source policy (not in allowlist / default-deny is on)",
        );
    }

    let ts = now_ts();
    let request = UpdateRequest {
        id: format!("{}-{}-{}", req.agent_id, key, ts),
        agent_id: req.agent_id,
        package: req.package,
        from_version: installed.map(|p| p.version.clone()).unwrap_or_default(),
        to_version: latest.version,
        ring: "dev".to_string(),
        ts,
        status: "approved-pending".to_string(),
        approved_by: session.operator.clone(),
    };
    st.store.record_update_request(request.clone()).await;
    st.audit.log(
        &session.operator,
        "approve_update",
        &format!("{}/{}", request.agent_id, request.package),
        "approved-pending",
    );
    tracing::info!("update approved for {}/{}: {} -> {}", request.agent_id, request.package, request.from_version, request.to_version);
    Json(request).into_response()
}

pub async fn pending_updates(State(st): State<HttpState>, headers: HeaderMap) -> Response {
    let _session = match current_user(&st, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let updates = st.store.update_requests().await;
    Json(updates).into_response()
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenUpdater &middot; Dashboard</title>
<style>
  :root { --bg:#0f172a; --panel:#1e293b; --line:#334155; --txt:#e2e8f0; --mut:#94a3b8;
          --ok:#22c55e; --upd:#f59e0b; --ac:#38bdf8; --red:#ef4444; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--bg); color:var(--txt); }
  header { display:flex; align-items:center; gap:16px; padding:14px 20px; background:var(--panel);
           border-bottom:1px solid var(--line); position:sticky; top:0; z-index:20; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; }
  header .srv { color:var(--mut); font-size:13px; }
  header .health { display:flex; align-items:center; gap:8px; font-size:12px; color:var(--mut); }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; background:var(--mut); }
  .dot.ok { background:var(--ok); box-shadow:0 0 6px var(--ok); }
  .dot.bad { background:var(--red); box-shadow:0 0 6px var(--red); }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .bg-online { background:#052e16; color:var(--ok); } .bg-idle { background:#1e293b; color:var(--mut); }
  .bg-upd { background:#431407; color:var(--upd); }
  button { background:var(--ac); color:#082f49; border:0; border-radius:6px; padding:7px 12px;
           font-weight:700; cursor:pointer; font-family:inherit; }
  button.ghost { background:transparent; color:var(--ac); border:1px solid var(--ac); }
  button:disabled { opacity:.5; cursor:default; }
  input,select { background:#0b1526; border:1px solid var(--line); color:var(--txt); border-radius:6px;
                 padding:8px 10px; font-family:inherit; font-size:13px; }
  main { padding:20px; max-width:1200px; margin:0 auto; }
  .headline { display:flex; align-items:baseline; gap:10px; }
  .headline h2 { font-size:15px; margin:0; } .muted { color:var(--mut); }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; margin-top:16px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; cursor:pointer;
          transition:border-color .15s; }
  .card:hover { border-color:var(--ac); }
  .card .top { display:flex; align-items:center; gap:10px; }
  .card h3 { margin:0; font-size:14px; }
  .card .id { color:var(--mut); font-size:11px; margin-top:2px; word-break:break-all; }
  .card .meta { margin-top:10px; font-size:12px; color:var(--mut); display:grid; grid-template-columns:auto 1fr; gap:3px 10px; }
  .card .badges { margin-top:10px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .icon { width:34px; height:34px; border-radius:50%; flex:0 0 34px; display:flex; align-items:center; justify-content:center;
          font-weight:800; font-size:15px; color:#0f172a; }
  .empty { padding:40px 20px; text-align:center; color:var(--mut); border:1px dashed var(--line); border-radius:8px; margin-top:16px; }
  #backdrop { position:fixed; inset:0; background:rgba(2,6,23,.6); z-index:30; display:none; }
  #drawer { position:fixed; top:0; right:0; bottom:0; width:min(680px,100vw); background:var(--bg); border-left:1px solid var(--line);
            z-index:40; transform:translateX(100%); transition:transform .2s ease; display:flex; flex-direction:column; }
  #drawer.open { transform:none; }
  #drawer header { position:static; border-bottom:1px solid var(--line); padding:14px 18px; }
  #drawer .body { overflow-y:auto; padding:16px 18px; flex:1; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); font-size:12px; }
  th { color:var(--mut); text-transform:uppercase; font-size:10px; letter-spacing:.5px; position:sticky; top:0; background:var(--bg); }
  .chip { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .chip.ok { background:#052e16; color:var(--ok); } .chip.upd { background:#431407; color:var(--upd); }
  .chip.blocked { background:#3f1d1d; color:var(--red); }
  .ringpipe { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-top:16px; }
  .ringcol { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
  .ringcard { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:10px; margin-bottom:8px; font-size:12px; }
  #catPages { display:flex; gap:6px; } #catPages .active { color:var(--ac); border-color:var(--ac); }
  .ok { color:var(--ok); } .upd { color:var(--upd); } .mut { color:var(--mut); }
  #toasts { position:fixed; bottom:18px; right:18px; z-index:60; display:flex; flex-direction:column; gap:8px; }
  .toast { background:var(--panel); border:1px solid var(--line); border-left:3px solid var(--ac); padding:10px 14px;
           border-radius:6px; font-size:13px; max-width:420px; box-shadow:0 6px 20px rgba(0,0,0,.4); animation:fadein .2s; }
  .toast.err { border-left-color:var(--red); } .toast.ok { border-left-color:var(--ok); }
  @keyframes fadein { from { opacity:0; transform:translateY(6px);} to {opacity:1; transform:none;} }
  #syncPanel { display:none; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 16px; margin-top:16px; }
  #syncPanel .bar { height:6px; background:#0b1526; border-radius:4px; overflow:hidden; margin-top:8px; }
  #syncPanel .fill { height:100%; width:0; background:var(--ac); animation:grow 60s linear forwards; }
  @keyframes grow { from { width:0; } to { width:100%; } }
  .row { display:flex; justify-content:space-between; gap:10px; padding:5px 0; border-bottom:1px dashed var(--line); font-size:12px; }
  .layout { display:flex; gap:20px; }
  nav { flex:0 0 170px; display:flex; flex-direction:column; gap:6px; }
  nav button { text-align:left; background:transparent; color:var(--txt); border:1px solid transparent; font-weight:600; }
  nav button.active { background:var(--panel); border-color:var(--line); color:var(--ac); }
  nav button small { display:block; color:var(--mut); font-weight:400; font-size:11px; }
  .view { flex:1; min-width:0; display:none; } .view.active { display:block; }
  #login { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:var(--bg); z-index:100; }
  #login .box { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:28px; width:340px; }
  #login h1 { font-size:20px; margin:0 0 4px; } #login p { color:var(--mut); font-size:12px; margin:0 0 18px; }
  #login .fld { margin-bottom:12px; } #login label { display:block; font-size:11px; color:var(--mut); margin-bottom:4px; }
  #login input { width:100%; }
  #login .err { color:var(--red); font-size:12px; min-height:16px; margin-top:8px; }
  .toolbar { display:flex; gap:10px; align-items:center; margin:16px 0; flex-wrap:wrap; }
  .timeline { display:flex; flex-direction:column; gap:8px; margin-top:12px; }
  .evt { display:flex; gap:12px; align-items:baseline; background:var(--panel); border:1px solid var(--line);
         border-radius:6px; padding:10px 12px; font-size:12px; }
  .evt .t { color:var(--mut); white-space:nowrap; } .evt .a { font-weight:700; } .evt .act { color:var(--ac); }
  .evt .tg { color:var(--mut); word-break:break-all; } .evt .r { margin-left:auto; }
</style>
</head>
<body>
<div id="login">
  <div class="box">
    <h1>OpenUpdater</h1>
    <p>sign in to the update dashboard</p>
    <div class="fld"><label>Username</label><input id="user" autocomplete="username"></div>
    <div class="fld"><label>Password</label><input id="pass" type="password" autocomplete="current-password"></div>
    <button style="width:100%" onclick="doLogin()">Sign in</button>
    <div class="err" id="loginErr"></div>
  </div>
</div>

<div id="app" style="display:none">
<header>
  <h1>OpenUpdater</h1>
  <span class="health"><span class="dot" id="healthDot"></span><span id="healthTxt">checking&hellip;</span></span>
  <span class="srv">server: <b id="srvHost"></b></span>
  <span class="health">last catalog sync: <b id="lastSync" class="mut">never</b></span>
  <span style="flex:1"></span>
  <span class="health">signed in: <b id="whoami"></b> <span class="badge bg-idle" id="roleBadge"></span></span>
  <button class="ghost" onclick="doLogout()">Sign out</button>
</header>
<main>
  <div class="layout">
    <nav>
      <button class="active" data-view="devices" onclick="showView('devices')">Devices<small>fleet inventory &amp; versions</small></button>
      <button data-view="approvals" onclick="showView('approvals')">Approvals<small>pending update requests</small></button>
      <button data-view="rings" onclick="showView('rings')">Rings<small>dev &rarr; staging &rarr; prod</small></button>
      <button data-view="catalog" onclick="showView('catalog')">Catalog<small>upstream package versions</small></button>
      <button data-view="audit" onclick="showView('audit')">Audit log<small>who did what</small></button>
      <button data-view="policy" id="navPolicy" style="display:none" onclick="showView('policy')">Policy<small>allowlist / default-deny (admin)</small></button>
      <button data-view="sources" id="navSources" style="display:none" onclick="showView('sources')">Sources<small>whitelisted upstreams (admin)</small></button>
      <button data-view="provision" id="navProvision" style="display:none" onclick="showView('provision')">Provision<small>discover &amp; push agents (admin)</small></button>
      <button data-view="operators" id="navOperators" style="display:none" onclick="showView('operators')">Operators<small>accounts &amp; roles (admin)</small></button>
    </nav>

    <div class="view active" id="viewDevices">
      <div class="headline">
        <h2>Devices</h2><span class="muted" id="devCount"></span>
        <span class="muted" style="margin-left:auto">click a device to view its packages</span>
      </div>
      <div class="toolbar">
        <button onclick="refreshCatalog()" id="refreshBtn">Refresh package catalog</button>
        <button class="ghost" onclick="loadDevices()">Refresh devices</button>
        <button class="ghost" onclick="scanAll()">Scan all devices</button>
      </div>
      <div id="syncPanel">
        <b>Syncing package catalog from upstream&hellip;</b>
        <div class="mut" id="syncPhase">starting</div>
        <div class="bar"><div class="fill"></div></div>
      </div>
      <div class="grid" id="devGrid"></div>
      <div class="empty" id="emptyState" style="display:none">
        No devices enrolled yet. See MANUAL.txt for enrollment steps — copy the server CA
        (ca.pem) to each agent, then run the agent once with AIRGAP_ENROLL_TOKEN.
      </div>
    </div>

    <div class="view" id="viewApprovals">
      <div class="headline"><h2>Approvals</h2><span class="muted" id="apprCount"></span></div>
      <div class="empty" id="apprEmpty" style="display:none">No update requests yet. Approve an update from a device&rsquo;s packages drawer.</div>
      <table style="margin-top:12px">
        <thead><tr><th>When</th><th>Package</th><th>Device</th><th>From &rarr; To</th><th>Ring</th><th>Approved by</th><th>Status</th></tr></thead>
        <tbody id="apprBody"></tbody>
      </table>
    </div>

    <div class="view" id="viewRings">
      <div class="headline"><h2>Rings</h2><span class="muted">promote a release down the pipeline: dev &rarr; staging &rarr; prod</span></div>
      <div class="empty" id="ringEmpty" style="display:none">No releases available yet. Push packages to the server repo, then refresh the package catalog.</div>
      <div class="ringpipe" id="ringPipe"></div>
    </div>

    <div class="view" id="viewCatalog">
      <div class="headline"><h2>Catalog</h2><span class="muted" id="catCount"></span></div>
      <div class="toolbar">
        <input id="catSearch" placeholder="search packages" oninput="debouncedSearch()" onkeydown="if(event.key==='Enter')searchCatalog(1)">
        <button onclick="searchCatalog(1)">Search</button>
        <button class="ghost" onclick="loadCatalog(1, '')">Reset</button>
      </div>
      <div class="empty" id="catEmpty" style="display:none">No packages in the catalog. Refresh the package catalog from Devices.</div>
      <table style="margin-top:12px">
        <thead><tr><th>Family</th><th>Package</th><th>Version</th><th>Ring</th><th>Updated</th></tr></thead>
        <tbody id="catBody"></tbody>
      </table>
      <div class="toolbar" id="catPages"></div>
    </div>

    <div class="view" id="viewAudit">
      <div class="headline"><h2>Audit log</h2></div>
      <div class="toolbar">
        <input id="auditActor" placeholder="filter by operator" oninput="renderAudit()">
        <select id="auditAction" onchange="renderAudit()">
          <option value="">all actions</option>
          <option>login</option><option>approve_update</option><option>ring_promote</option>
          <option>catalog_refresh</option><option>operator_create</option><option>operator_delete</option>
          <option>policy_set</option><option>policy_entry</option><option>policy_entry_delete</option>
          <option>agent_revoke</option><option>scan_request</option>
          <option>source_add</option><option>source_toggle</option><option>source_delete</option>
          <option>enroll</option><option>register</option>
        </select>
      </div>
      <div class="empty" id="auditEmpty" style="display:none">No audit entries yet.</div>
      <div class="timeline" id="auditBody"></div>
    </div>

    <div class="view" id="viewOperators">
      <div class="headline"><h2>Operators</h2></div>
      <table style="margin-top:12px">
        <thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead>
        <tbody id="opsBody"></tbody>
      </table>
      <div class="card" style="margin-top:16px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Create operator</h3>
        <div class="toolbar" style="margin:0">
          <input id="opName" placeholder="username">
          <input id="opPass" type="password" placeholder="password">
          <select id="opRole"><option value="viewer">viewer</option><option value="approver">approver</option><option value="admin">admin</option></select>
          <button onclick="createOp()">Create</button>
        </div>
      </div>
    </div>

    <div class="view" id="viewPolicy">
      <div class="headline"><h2>Source policy</h2><span class="muted">package allowlist; when default-deny is on, unlisted packages are blocked from updates</span></div>
      <div class="card" style="margin-top:8px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Default rule</h3>
        <div class="toolbar" style="margin:0">
          <select id="polMode">
            <option value="allow">allow by default</option>
            <option value="deny">deny by default</option>
          </select>
          <button onclick="setPolicyMode()">Save</button>
        </div>
      </div>
      <table style="margin-top:12px">
        <thead><tr><th>Package</th><th>Action</th><th></th></tr></thead>
        <tbody id="polBody"></tbody>
      </table>
      <div class="card" style="margin-top:16px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Add rule</h3>
        <div class="toolbar" style="margin:0">
          <input id="polName" placeholder="package name, e.g. openssl-libs">
          <select id="polAction"><option value="deny">deny</option><option value="allow">allow</option></select>
          <button onclick="addPolicy()">Add rule</button>
        </div>
      </div>
    </div>

    <div class="view" id="viewSources">
      <div class="headline"><h2>Upstream sources</h2><span class="muted">whitelist where the catalog may download from; only enabled sources are synced</span></div>
      <div class="empty" id="srcEmpty" style="display:none">No sources configured. Add at least one apt or dnf source so the catalog sync has something to fetch.</div>
      <table style="margin-top:12px">
        <thead><tr><th>Name</th><th>Family</th><th>Kind</th><th>Base URL</th><th>Suite</th><th>KBs</th><th>Status</th><th></th></tr></thead>
        <tbody id="srcBody"></tbody>
      </table>
      <div class="card" style="margin-top:16px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Add / update source</h3>
        <div class="toolbar" style="margin:0">
          <input id="srcName" placeholder="name, e.g. windows-wsus">
          <select id="srcFamily">
            <option value="debian">debian</option>
            <option value="rhel">rhel</option>
            <option value="windows">windows</option>
            <option value="other">other</option>
          </select>
          <select id="srcKind">
            <option value="apt">apt</option>
            <option value="dnf">dnf</option>
            <option value="wucatalog">wucatalog (Microsoft Update Catalog)</option>
            <option value="none">none (stored only)</option>
          </select>
          <input id="srcUrl" placeholder="base URL, e.g. http://host/repo" style="flex:1;min-width:240px">
          <input id="srcSuite" placeholder="suite (apt only, e.g. noble)">
          <input id="srcKbs" placeholder="KB list (wucatalog only, comma-separated, e.g. KB5039227)">
          <button onclick="addSource()">Save source</button>
        </div>
        <p class="muted" style="margin:8px 0 0;font-size:11px">apt sources need the base URL + suite (components main/universe, arch amd64). dnf sources need the base URL of the repo dir. wucatalog sources are the Windows answer to WSUS: point at the Microsoft Update Catalog and list the KBs to track - the server syncs them and serves the .msu to agents, no separate update service required. "none" stores a source without syncing it yet.</p>
      </div>
    </div>

    <div class="view" id="viewProvision">
      <div class="headline"><h2>Provision</h2><span class="muted">discover devices on a network, then push the agent to them over SSH</span></div>
      <div class="card" style="margin-top:8px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Networks</h3>
        <div class="toolbar" style="margin:0">
          <input id="netName" placeholder="name, e.g. lab">
          <input id="netCidr" placeholder="CIDR, e.g. 172.16.5.0/24">
          <button onclick="addNetwork()">Add network</button>
        </div>
        <table style="margin-top:8px">
          <thead><tr><th>Name</th><th>CIDR</th><th>Last scanned</th><th></th></tr></thead>
          <tbody id="netBody"></tbody>
        </table>
      </div>
      <div class="card" style="margin-top:12px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">Agent binary</h3>
        <div class="toolbar" style="margin:0">
          <input type="file" id="agentBin">
          <button onclick="uploadBinary()">Upload agent binary</button>
          <span class="muted" id="binState"></span>
        </div>
        <p class="muted" style="margin:8px 0 0;font-size:11px">This is the airgap-agent binary that gets installed on discovered Linux devices. Build it with <b>cargo build --release --target x86_64-unknown-linux-musl</b>.</p>
      </div>
      <div class="headline" style="margin-top:16px"><h2>Discovered hosts</h2><span class="muted" id="hostCount"></span></div>
      <div class="toolbar">
        <button class="ghost" onclick="loadProvision()">Refresh</button>
        <span class="mut" id="scanState"></span>
      </div>
      <div class="empty" id="hostEmpty" style="display:none">Nothing discovered yet. Add a network above and scan it.</div>
      <table style="margin-top:12px">
        <thead><tr><th>IP</th><th>Ports</th><th>Family</th><th>Hostname</th><th>Status</th><th></th></tr></thead>
        <tbody id="hostBody"></tbody>
      </table>
      <div class="card" style="margin-top:16px;cursor:default">
        <h3 style="margin:0 0 10px;font-size:14px">SSH credentials</h3>
        <div class="toolbar" style="margin:0;flex-wrap:wrap">
          <input id="credName" placeholder="name">
          <input id="credUser" placeholder="username">
          <input id="credPass" type="password" placeholder="password">
          <input id="credPort" placeholder="port (22)" style="width:90px">
          <input id="credDomain" placeholder="domain (optional, future AD)">
          <button onclick="addCredential()">Save credential</button>
        </div>
        <table style="margin-top:8px">
          <thead><tr><th>Name</th><th>User</th><th>Port</th><th>Domain</th><th></th></tr></thead>
          <tbody id="credBody"></tbody>
        </table>
        <p class="muted" style="margin:8px 0 0;font-size:11px">Passwords live in credentials.json on the server and are never sent back to the browser. Windows hosts (ports 445/5985/3389) are listed but can't be provisioned yet &mdash; a Windows agent is a separate milestone.</p>
      </div>
    </div>
  </div>
</main>
</div>

<div id="backdrop" onclick="closeDrawer()"></div>
<div id="drawer">
  <header>
    <div style="flex:1">
      <div style="display:flex;align-items:center;gap:8px"><h1 id="drvHost" style="font-size:15px"></h1><span id="drvBadge"></span></div>
      <div class="srv" id="drvMeta"></div>
    </div>
    <button class="ghost danger" id="drvRevoke" onclick="confirmRevoke()" style="display:none">Revoke</button>
    <button class="ghost" onclick="closeDrawer()">Close</button>
  </header>
  <div class="body">
    <div class="muted" id="drvCount" style="margin-bottom:8px"></div>
    <table>
      <thead><tr>
        <th onclick="sortRows('name')">Package &darr;&uarr;</th>
        <th onclick="sortRows('installed')">Installed</th>
        <th onclick="sortRows('latest')">Latest</th>
        <th onclick="sortRows('policy')">Policy</th>
        <th>Status</th>
        <th></th>
      </tr></thead>
      <tbody id="drvBody"></tbody>
    </table>
  </div>
</div>
<div id="toasts"></div>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const tokenKey = 'ou_token';
let role = '';

function toast(msg, type){
  const t = document.createElement('div');
  t.className = 'toast '+(type||'');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(()=>{ t.remove(); }, 5000);
}

function api(path, opts){
  const headers = Object.assign({}, (opts&&opts.headers)||{});
  const t = localStorage.getItem(tokenKey);
  if(t) headers['Authorization'] = 'Bearer '+t;
  if(opts && opts.body) headers['Content-Type'] = 'application/json';
  return fetch(path, Object.assign({}, opts, {headers})).then(async res=>{
    if(res.status===401 && path !== '/api/login'){ showLogin(); throw new Error('session expired - sign in again'); }
    if(!res.ok){ let m=''; try{ m=(await res.json()).error||m; }catch(_){} throw new Error(m||res.status); }
    return res.json();
  });
}

function rel(ts){
  if(!ts) return 'never';
  const s = parseInt(ts,10); if(isNaN(s)) return esc(ts);
  const d = Math.max(0, Math.floor(Date.now()/1000) - s);
  if(d < 60) return d+'s ago';
  if(d < 3600) return Math.floor(d/60)+'m ago';
  if(d < 86400) return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

function familyIcon(f){
  const m = { debian:'D', rhel:'R', windows:'W', other:'?' };
  const c = { debian:'#a1005e', rhel:'#f8f8f8', windows:'#38bdf8', other:'#64748b' };
  return '<span class="icon" style="background:'+(c[f]||'#64748b')+'">'+(m[f]||'?')+'</span>';
}

function statusPill(s){
  if(s === 'online') return '<span class="badge bg-online">online</span>';
  if(s === 'enrolled' || s === 'registered') return '<span class="badge bg-upd">'+esc(s)+'</span>';
  return '<span class="badge bg-idle">'+esc(s||'unknown')+'</span>';
}

async function doLogin(){
  const u = $('#user').value.trim(), p = $('#pass').value;
  $('#loginErr').textContent = '';
  try{
    const r = await api('/api/login', {method:'POST', body: JSON.stringify({username:u, password:p})});
    localStorage.setItem(tokenKey, r.token);
    role = r.role;
    enterApp(r.operator, r.role);
    loadDevices(); loadHealth();
  }catch(e){ $('#loginErr').textContent = e.message; }
}

function showLogin(){
  $('#app').style.display = 'none';
  $('#login').style.display = 'flex';
}

function enterApp(op, r){
  role = r;
  $('#app').style.display = 'block';
  $('#login').style.display = 'none';
  $('#whoami').textContent = op;
  $('#roleBadge').textContent = r;
  $('#navOperators').style.display = r === 'admin' ? 'block' : 'none';
  $('#navPolicy').style.display = r === 'admin' ? 'block' : 'none';
  $('#navSources').style.display = r === 'admin' ? 'block' : 'none';
  $('#navProvision').style.display = r === 'admin' ? 'block' : 'none';
  $('#user').value=''; $('#pass').value='';
}

async function doLogout(){
  try{ await api('/api/logout', {method:'POST'}); }catch(_){}
  localStorage.removeItem(tokenKey);
  showLogin();
}

function showView(v){
  document.querySelectorAll('.view').forEach(el=>el.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  $('#view'+v.charAt(0).toUpperCase()+v.slice(1)).classList.add('active');
  document.querySelector('nav button[data-view="'+v+'"]').classList.add('active');
  if(v==='devices'){ loadDevices(); }
  if(v==='approvals'){ loadApprovals(); }
  if(v==='rings'){ loadRings(); }
  if(v==='catalog'){ searchCatalog(1); }
  if(v==='audit'){ loadAudit(); }
  if(v==='operators'){ loadOperators(); }
  if(v==='policy'){ loadPolicy(); }
  if(v==='sources'){ loadSources(); }
  if(v==='provision'){ loadProvision(); }
}

async function boot(){
  $('#srvHost').textContent = location.host;
  const t = localStorage.getItem(tokenKey);
  if(!t){ showLogin(); return; }
  try{
    const me = await api('/api/me');
    enterApp(me.operator, me.role);
    loadDevices(); loadHealth(); loadApprovals();
  }catch(_){ localStorage.removeItem(tokenKey); showLogin(); }
}

async function loadHealth(){
  try{
    const h = await api('/api/health');
    $('#healthDot').className = 'dot ok';
    $('#healthTxt').textContent = (h.catalog_syncing?'syncing catalog, ':'') + h.agents + ' device' + (h.agents===1?'':'s');
    $('#lastSync').textContent = rel(h.last_catalog_sync);
    if(h.catalog_syncing) showSync(h.catalog_phase);
  }catch(e){
    $('#healthDot').className = 'dot bad';
    $('#healthTxt').textContent = 'unreachable';
  }
}

async function loadDevices(){
  try{
    const devs = await api('/api/devices');
    $('#devCount').textContent = '('+devs.length+')';
    $('#emptyState').style.display = devs.length ? 'none' : 'block';
    $('#devGrid').innerHTML = devs.map(d=>`
      <div class="card" onclick="openDrawer('${esc(d.id)}')">
        <div class="top">${familyIcon(d.family)}
          <div style="min-width:0">
            <h3>${esc(d.hostname)||'&ndash;'}</h3>
            <div class="id">${esc(d.id)}</div>
          </div>
        </div>
        <div class="meta">
          <span>OS</span><span>${esc(d.os_pretty)||'&ndash;'}</span>
          <span>Arch / kernel</span><span>${esc(d.arch)||'&ndash;'} / ${esc(d.kernel)||'&ndash;'}</span>
          <span>Bootloader</span><span>${esc(d.bootloader)||'&ndash;'}</span>
          <span>IP</span><span>${esc(d.ip)||'&ndash;'}</span>
          <span>Last seen</span><span data-ls="${esc(d.last_seen)}">${rel(d.last_seen)}</span>
          <span>Packages</span><span>${d.packages}</span>
        </div>
        <div class="badges">
          ${statusPill(d.status)}
          ${d.scan_requested?'<span class="badge bg-upd">scan pending</span>':''}
          ${d.updates_available>0
            ? '<span class="badge bg-upd">'+d.updates_available+' update'+(d.updates_available===1?'':'s')+' available</span>'
            : '<span class="badge bg-idle">up to date</span>'}
        </div>
        <div style="display:flex;gap:8px;margin-top:12px">
          <button class="ghost" style="flex:1" onclick="event.stopPropagation();scanDevice('${esc(d.id)}')">Scan for updates</button>
          <button class="ghost" style="flex:1" onclick="event.stopPropagation();openDrawer('${esc(d.id)}')">View packages</button>
        </div>
      </div>`).join('');
  }catch(e){ toast('Failed to load devices: '+e.message, 'err'); }
}

let drawerId = null, drawerRows = [], drawerSort = {key:'name', dir:1};

async function openDrawer(id){
  $('#drawer').classList.add('open');
  $('#backdrop').style.display='block';
  drawerId = id;
  $('#drvBody').innerHTML = '<tr><td colspan="6" class="mut">loading packages&hellip;</td></tr>';
  try{
    const data = await api('/api/devices/'+encodeURIComponent(id)+'/packages');
    const upds = data.packages.filter(p=>p.update_available);
    $('#drvHost').textContent = data.hostname;
    $('#drvBadge').innerHTML = upds.length
      ? '<span class="badge bg-upd">'+upds.length+' update'+(upds.length===1?'':'s')+'</span>'
      : '<span class="badge bg-idle">up to date</span>';
    $('#drvMeta').textContent = id;
    $('#drvCount').textContent = data.packages.length + ' packages installed';
    $('#drvRevoke').style.display = role === 'admin' ? 'inline-block' : 'none';
    drawerRows = data.packages;
    drawerSort = {key:'name', dir:1};
    renderDrawerRows();
  }catch(e){
    $('#drvBody').innerHTML = '<tr><td colspan="6" class="upd">Failed to load: '+esc(e.message)+'</td></tr>';
  }
}

function renderDrawerRows(){
  const rows = drawerRows.slice();
  const k = drawerSort.key;
  rows.sort((a,b)=>{
    const va = (a[k]||'').toString().toLowerCase(), vb = (b[k]||'').toString().toLowerCase();
    if(k==='installed') return (a[k]<b[k]?-1:a[k]>b[k]?1:0)*drawerSort.dir;
    if(k==='latest') return ((a[k]||'').localeCompare((b[k]||''), undefined, {numeric:true}))*drawerSort.dir;
    return va.localeCompare(vb)*drawerSort.dir;
  });
  $('#drvBody').innerHTML = rows.map(p=>`
    <tr>
      <td>${esc(p.name)}</td>
      <td>${esc(p.installed)}</td>
      <td class="${p.update_available?'upd':'ok'}">${p.latest?esc(p.latest):'<span class="muted">unknown</span>'}</td>
      <td>${p.policy==='allow'?'<span class="chip ok">allow</span>':'<span class="chip upd">blocked</span>'}</td>
      <td>${p.update_available?'<span class="chip upd">update available</span>':'<span class="chip ok">up to date</span>'}</td>
      <td>${(p.update_available && (role==='approver'||role==='admin'))?`<button class="ghost" onclick="askUpdate('${esc(drawerId)}','${esc(p.name)}')">Approve</button>`:(p.update_available?'<span class="muted">approver role needed</span>':'')}</td>
    </tr>`).join('');
}

function sortRows(key){
  if(drawerSort.key===key) drawerSort.dir *= -1; else drawerSort = {key, dir:1};
  renderDrawerRows();
}

async function confirmRevoke(){
  if(!drawerId) return;
  const reason = prompt('Revoke agent '+drawerId+'? Any reason (optional):','');
  if(reason === null) return;
  try{
    await api('/api/agents/'+encodeURIComponent(drawerId)+'/revoke', {method:'POST', body: JSON.stringify({reason})});
    toast('Agent '+drawerId+' revoked', 'ok');
    closeDrawer();
    loadDevices();
  }catch(e){ toast('Revoke failed: '+e.message, 'err'); }
}

function closeDrawer(){
  $('#drawer').classList.remove('open');
  $('#backdrop').style.display='none';
}

async function askUpdate(agentId, pkg){
  if(!confirm('Approve updating '+pkg+' on '+agentId+'?')) return;
  try{
    const r = await api('/api/update', {method:'POST', body: JSON.stringify({agent_id:agentId, package:pkg})});
    toast(pkg+': '+r.from_version+' -> '+r.to_version+' approved ('+r.status+')', 'ok');
    loadHealth(); loadDevices(); loadApprovals();
    if($('#drawer').classList.contains('open')) openDrawer(agentId);
  }catch(e){ toast('Update request failed: '+e.message, 'err'); }
}

let syncing = false;
function showSync(phase){
  $('#syncPanel').style.display='block';
  $('#syncPhase').innerHTML = phase + ' &hellip; please wait, this can take a minute';
  $('#refreshBtn').disabled = true;
}
function hideSync(){
  $('#syncPanel').style.display='none';
  $('#refreshBtn').disabled = false;
}

async function refreshCatalog(){
  if(syncing) return; syncing = true;
  showSync('starting');
  const start = Date.now();
  const poll = setInterval(async ()=>{
    try{
      const s = await api('/api/refresh/status');
      if(s.syncing) showSync(s.phase);
    }catch(_){}
  }, 1500);
  try{
    const r = await api('/api/refresh', {method:'POST'});
    toast('Catalog refreshed: '+r.packages+' packages (apt '+r.apt+', dnf '+r.dnf+(r.windows?', windows '+r.windows:'')+')', 'ok');
    loadDevices();
  }catch(e){
    toast('Refresh failed: '+e.message, 'err');
  }
  clearInterval(poll);
  hideSync(); syncing = false;
  loadHealth();
}

async function loadApprovals(){
  try{
    const upds = await api('/api/updates');
    $('#apprCount').textContent = '('+upds.length+')';
    $('#apprEmpty').style.display = upds.length ? 'none' : 'block';
    $('#apprBody').innerHTML = upds.slice().reverse().map(u=>`
      <tr>
        <td class="mut">${rel(u.ts)}</td>
        <td><b>${esc(u.package)}</b></td>
        <td>${esc(u.agent_id)}</td>
        <td>${esc(u.from_version)} &rarr; ${esc(u.to_version)}</td>
        <td><span class="badge bg-idle">${esc(u.ring)}</span></td>
        <td>${esc(u.approved_by||'&ndash;')}</td>
        <td><span class="chip upd">${esc(u.status)}</span></td>
      </tr>`).join('');
  }catch(e){ toast('Failed to load approvals: '+e.message, 'err'); }
}

let auditCache = [];
async function loadAudit(){
  try{
    auditCache = await api('/api/audit');
    renderAudit();
  }catch(e){ toast('Failed to load audit log: '+e.message, 'err'); }
}
function renderAudit(){
  const actor = ($('#auditActor').value||'').toLowerCase();
  const action = $('#auditAction').value;
  const rows = auditCache.filter(e=> (!actor || (e.actor||'').toLowerCase().includes(actor)) && (!action || e.action===action));
  $('#auditEmpty').style.display = rows.length ? 'none' : 'block';
  $('#auditBody').innerHTML = rows.map(e=>`
    <div class="evt">
      <span class="t">${rel(e.ts)}</span>
      <span class="a">${esc(e.actor||'&ndash;')}</span>
      <span class="act">${esc(e.action)}</span>
      <span class="tg">${esc(e.target||'')}</span>
      <span class="r ${e.result==='ok'?'ok':'upd'}">${esc(e.result)}</span>
    </div>`).join('');
}

async function loadOperators(){
  try{
    const ops = await api('/api/operators');
    $('#opsBody').innerHTML = ops.map(o=>`
      <tr>
        <td>${esc(o.name)}</td>
        <td><span class="badge ${o.role==='admin'?'bg-upd':'bg-idle'}">${esc(o.role)}</span></td>
        <td class="mut">${rel(o.created_at)}</td>
        <td>${o.name===$('#whoami').textContent?'':`<button class="ghost" onclick="delOp('${esc(o.name)}')">Delete</button>`}</td>
      </tr>`).join('');
  }catch(e){ toast('Failed to load operators: '+e.message, 'err'); }
}

async function createOp(){
  const name = $('#opName').value.trim(), pw = $('#opPass').value, r = $('#opRole').value;
  try{
    await api('/api/operators', {method:'POST', body: JSON.stringify({name, password:pw, role:r})});
    toast('Operator '+name+' created', 'ok');
    $('#opName').value=''; $('#opPass').value='';
    loadOperators();
  }catch(e){ toast('Create failed: '+e.message, 'err'); }
}

async function delOp(name){
  if(!confirm('Delete operator '+name+'?')) return;
  try{
    await api('/api/operators/'+encodeURIComponent(name), {method:'DELETE'});
    toast('Operator '+name+' deleted', 'ok');
    loadOperators();
  }catch(e){ toast('Delete failed: '+e.message, 'err'); }
}

const RING_COLS = ['dev', 'staging', 'prod'];
async function loadRings(){
  try{
    const groups = await api('/api/rings');
    const has = Object.values(groups).some(a=>a.length);
    $('#ringEmpty').style.display = has ? 'none' : 'block';
    $('#ringPipe').innerHTML = RING_COLS.map((r,i)=>{
      const items = (groups[r]||[]);
      const canPromote = (role==='approver'||role==='admin') && i < 2;
      return `<div class="ringcol">
        <h3 style="font-size:14px;margin:0 0 10px;text-transform:capitalize">${esc(r)} <span class="badge bg-idle">${items.length}</span></h3>
        ${items.length ? items.map(u=>`
          <div class="ringcard">
            <b>${esc(u.package)}</b>
            <div class="id">${esc(u.agent_id)}</div>
            <div class="mut">${esc(u.from_version)} &rarr; <b>${esc(u.to_version)}</b></div>
            <div class="mut">approved by ${esc(u.approved_by||'&ndash;')} &middot; ${rel(u.ts)}</div>
            ${canPromote ? `<button class="ghost" style="margin-top:8px" onclick="promote('${esc(u.id)}')">Promote to ${RING_COLS[i+1]}</button>` : ''}
          </div>`).join('') : '<div class="mut">empty</div>'}
      </div>`;
    }).join('');
  }catch(e){ toast('Failed to load rings: '+e.message, 'err'); }
}

async function promote(id){
  if(!confirm('Promote this release to the next ring?')) return;
  try{
    const r = await api('/api/update/'+encodeURIComponent(id)+'/promote', {method:'POST'});
    toast('Promoted '+r.package+' to '+r.ring, 'ok');
    loadRings(); loadApprovals(); loadDevices();
  }catch(e){ toast('Promote failed: '+e.message, 'err'); }
}

let catTimer = null;
function debouncedSearch(){
  clearTimeout(catTimer);
  catTimer = setTimeout(()=> searchCatalog(1), 300);
}
async function searchCatalog(page){
  const q = $('#catSearch') ? $('#catSearch').value.trim() : '';
  try{
    const r = await api('/api/catalog?q='+encodeURIComponent(q)+'&page='+page+'&per=100');
    $('#catCount').textContent = '('+r.total+' packages'+(q?' matching &ldquo;'+esc(q)+'&rdquo;':'')+')';
    $('#catEmpty').style.display = r.items.length ? 'none' : 'block';
    $('#catBody').innerHTML = r.items.map(p=>`
      <tr>
        <td>${familyIcon(p.family)}</td>
        <td><b>${esc(p.name)}</b></td>
        <td>${esc(p.version)}</td>
        <td><span class="badge bg-idle">${esc(p.ring||'')}</span></td>
        <td class="mut">${rel(p.ts)}</td>
      </tr>`).join('');
    const pages = Math.max(1, Math.ceil(r.total/r.per));
    $('#catPages').innerHTML = (pages>1 ? Array.from({length:pages},(_,i)=>
      `<button class="ghost ${i+1===page?'active':''}" onclick="searchCatalog(${i+1})">${i+1}</button>`).join('') : '');
  }catch(e){ toast('Failed to load catalog: '+e.message, 'err'); }
}

async function loadPolicy(){
  try{
    const p = await api('/api/policy');
    $('#polMode').value = p.default_deny ? 'deny' : 'allow';
    const entries = Object.entries(p.entries||{});
    $('#polBody').innerHTML = entries.map(([name,e])=>`
      <tr>
        <td><b>${esc(name)}</b>${e.note?'<div class="mut">'+esc(e.note)+'</div>':''}</td>
        <td><span class="badge ${e.action==='allow'?'bg-online':'bg-upd'}">${esc(e.action)}</span></td>
        <td><button class="ghost" onclick="delPolicy('${esc(name)}')">Delete</button></td>
      </tr>`).join('') || '<tr><td colspan="3" class="mut">no explicit rules &mdash; all packages follow the default rule</td></tr>';
  }catch(e){ toast('Failed to load policy: '+e.message, 'err'); }
}

async function setPolicyMode(){
  const deny = $('#polMode').value === 'deny';
  if(!confirm(deny?'Enable default-deny? Only allowlisted packages will be updatable.':'Set default to allow?')) return;
  try{
    await api('/api/policy', {method:'POST', body: JSON.stringify({default_deny: deny})});
    toast('Default rule saved: '+(deny?'deny all':'allow all'), 'ok');
    loadPolicy(); loadDevices();
  }catch(e){ toast('Save failed: '+e.message, 'err'); }
}

async function addPolicy(){
  const name = $('#polName').value.trim();
  const action = $('#polAction').value;
  if(!name) return;
  try{
    await api('/api/policy/entries', {method:'POST', body: JSON.stringify({package: name, action})});
    toast('Rule added: '+name+' -> '+action, 'ok');
    $('#polName').value='';
    loadPolicy(); loadDevices();
  }catch(e){ toast('Add failed: '+e.message, 'err'); }
}

async function delPolicy(name){
  if(!confirm('Delete rule for '+name+'?')) return;
  try{
    await api('/api/policy/entries/'+encodeURIComponent(name), {method:'DELETE'});
    toast('Rule deleted: '+name, 'ok');
    loadPolicy(); loadDevices();
  }catch(e){ toast('Delete failed: '+e.message, 'err'); }
}

async function scanDevice(id){
  try{
    await api('/api/devices/'+encodeURIComponent(id)+'/scan', {method:'POST'});
    toast('Scan requested for '+id+' - the agent will re-check on its next poll (within ~1 min)', 'ok');
    loadDevices();
  }catch(e){ toast('Scan failed: '+e.message, 'err'); }
}

async function scanAll(){
  const devs = await api('/api/devices');
  if(!devs.length){ toast('No devices enrolled yet', 'err'); return; }
  let ok = 0, fail = 0;
  for(const d of devs){
    try{ await api('/api/devices/'+encodeURIComponent(d.id)+'/scan', {method:'POST'}); ok++; }
    catch(_){ fail++; }
  }
  toast('Scan requested for '+ok+' device'+(ok===1?'':'s')+(fail?', '+fail+' failed':''), ok?'ok':'err');
  loadDevices();
}

async function loadSources(){
  try{
    const srcs = await api('/api/sources');
    $('#srcEmpty').style.display = srcs.length ? 'none' : 'block';
    $('#srcBody').innerHTML = srcs.map(s=>`
      <tr>
        <td><b>${esc(s.name)}</b></td>
        <td>${esc(s.family)}</td>
        <td><span class="badge bg-idle">${esc(s.kind)}</span></td>
        <td class="mut" style="word-break:break-all">${esc(s.base_url)}</td>
        <td class="mut">${esc(s.suite)||'&ndash;'}</td>
        <td class="mut">${esc((s.kbs||[]).join(', '))||'&ndash;'}</td>
        <td>${s.enabled?'<span class="badge bg-online">enabled</span>':'<span class="badge bg-idle">disabled</span>'}</td>
        <td style="white-space:nowrap">
          <button class="ghost" onclick="toggleSource('${esc(s.name)}', ${!s.enabled})">${s.enabled?'Disable':'Enable'}</button>
          <button class="ghost" onclick="delSource('${esc(s.name)}')">Delete</button>
        </td>
      </tr>`).join('');
  }catch(e){ toast('Failed to load sources: '+e.message, 'err'); }
}

async function addSource(){
  const name = $('#srcName').value.trim();
  const url = $('#srcUrl').value.trim();
  const family = $('#srcFamily').value;
  const kind = $('#srcKind').value;
  const suite = $('#srcSuite').value.trim();
  const kbs = $('#srcKbs').value.split(',').map(s=>s.trim().toUpperCase()).filter(Boolean);
  if(!name || !url){ toast('Name and base URL are required', 'err'); return; }
  try{
    await api('/api/sources', {method:'POST', body: JSON.stringify({name, family, kind, base_url: url, suite, kbs})});
    toast('Source '+name+' saved', 'ok');
    $('#srcName').value=''; $('#srcUrl').value=''; $('#srcSuite').value=''; $('#srcKbs').value='';
    loadSources();
  }catch(e){ toast('Save failed: '+e.message, 'err'); }
}

async function toggleSource(name, enabled){
  try{
    await api('/api/sources/'+encodeURIComponent(name), {method:'POST', body: JSON.stringify({enabled})});
    toast(name+' '+(enabled?'enabled':'disabled'), 'ok');
    loadSources();
  }catch(e){ toast('Update failed: '+e.message, 'err'); }
}

async function delSource(name){
  if(!confirm('Delete source '+name+'?')) return;
  try{
    await api('/api/sources/'+encodeURIComponent(name), {method:'DELETE'});
    toast('Source '+name+' deleted', 'ok');
    loadSources();
  }catch(e){ toast('Delete failed: '+e.message, 'err'); }
}

let provData = null, provTimer = null;

function byId(id){ return document.getElementById(id); }

async function loadProvision(){
  try{
    provData = await api('/api/provision');
    renderProvNetworks();
    renderProvHosts();
    renderProvCreds();
    renderProvBin();
    renderProvScan();
  }catch(e){ toast('Failed to load provision: '+e.message, 'err'); }
}

function renderProvScan(){
  const s = provData && provData.scan;
  if(!s){ $('#scanState').textContent = ''; return; }
  if(s.running) $('#scanState').innerHTML = 'scanning '+esc(s.network)+'&hellip;';
  else if(s.error) $('#scanState').innerHTML = '<span class="upd">last scan failed: '+esc(s.error)+'</span>';
  else $('#scanState').innerHTML = 'last scan of '+esc(s.network)+' ('+s.hosts.length+' hosts) '+rel(s.started);
}

function renderProvNetworks(){
  const nets = (provData&&provData.networks)||[];
  $('#netBody').innerHTML = nets.map(n=>`
    <tr>
      <td><b>${esc(n.name)}</b></td>
      <td>${esc(n.cidr)}</td>
      <td class="mut">${rel(n.last_scanned)}</td>
      <td style="white-space:nowrap">
        <button class="ghost" onclick="scanNetwork('${esc(n.name)}')">Scan now</button>
        <button class="ghost" onclick="delNetwork('${esc(n.name)}')">Delete</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="4" class="mut">no networks yet</td></tr>';
}

async function addNetwork(){
  const name = $('#netName').value.trim(), cidr = $('#netCidr').value.trim();
  if(!name || !cidr){ toast('Name and CIDR are required', 'err'); return; }
  try{
    await api('/api/networks', {method:'POST', body: JSON.stringify({name, cidr})});
    toast('Network '+name+' added', 'ok');
    $('#netName').value=''; $('#netCidr').value='';
    loadProvision();
  }catch(e){ toast('Add failed: '+e.message, 'err'); }
}

async function scanNetwork(name){
  try{
    await api('/api/networks/'+encodeURIComponent(name)+'/scan', {method:'POST'});
    toast('Scanning '+name+' in the background&hellip;', 'ok');
    loadProvision();
    if(provTimer) clearInterval(provTimer);
    provTimer = setInterval(()=>{
      loadProvision();
      if(provData && provData.scan && !provData.scan.running){ clearInterval(provTimer); provTimer=null; }
    }, 2000);
  }catch(e){ toast('Scan failed: '+e.message, 'err'); }
}

async function delNetwork(name){
  if(!confirm('Delete network '+name+'?')) return;
  try{
    await api('/api/networks/'+encodeURIComponent(name), {method:'DELETE'});
    toast('Network '+name+' deleted', 'ok');
    loadProvision();
  }catch(e){ toast('Delete failed: '+e.message, 'err'); }
}

function renderProvBin(){
  const b = provData && provData.agent_binary;
  $('#binState').textContent = b && b.present
    ? (b.size/1024/1024).toFixed(2)+' MB uploaded'
    : 'no agent binary uploaded yet';
}

async function uploadBinary(){
  const f = $('#agentBin').files[0];
  if(!f){ toast('Choose the airgap-agent binary first', 'err'); return; }
  const t = localStorage.getItem(tokenKey);
  try{
    const res = await fetch('/api/provision/agent-binary', {
      method:'PUT',
      headers:{'Authorization':'Bearer '+t},
      body: f
    });
    const j = await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(j.error||res.status);
    toast('Agent binary uploaded ('+(j.size/1024/1024).toFixed(2)+' MB)', 'ok');
    loadProvision();
  }catch(e){ toast('Upload failed: '+e.message, 'err'); }
}

function renderProvHosts(){
  const hosts = (provData&&provData.hosts)||[];
  $('#hostCount').textContent = '('+hosts.length+')';
  $('#hostEmpty').style.display = hosts.length ? 'none' : 'block';
  const creds = (provData&&provData.credentials)||[];
  $('#hostBody').innerHTML = hosts.map(h=>{
    const fam = h.family||'unknown';
    const windows = fam==='windows';
    const status = h.provisioned
      ? '<span class="badge bg-online">provisioned'+(h.agent_id?' '+esc(h.agent_id):'')+'</span>'
      : (h.error ? '<span class="badge bg-upd">failed</span>' : '<span class="badge bg-idle">not provisioned</span>');
    const credOptions = creds.map(c=>`<option value="${esc(c.name)}">${esc(c.name)}</option>`).join('');
    const action = windows
      ? '<span class="mut">Windows agent not built yet</span>'
      : (creds.length
          ? `<select id="credsel_${esc(h.ip)}">${credOptions}</select> <button class="ghost" onclick="provisionHost('${esc(h.ip)}')">Provision</button>`
          : '<span class="mut">add a credential first</span>');
    return `<tr>
      <td><b>${esc(h.ip)}</b></td>
      <td class="mut">${(h.ports||[]).join(', ')}</td>
      <td>${esc(fam)}</td>
      <td>${esc(h.hostname)||'&ndash;'}</td>
      <td>${status}</td>
      <td style="white-space:nowrap">${action}</td>
    </tr>`;
  }).join('');
}

async function provisionHost(ip){
  const sel = byId('credsel_'+ip);
  if(!sel){ toast('No credential selected', 'err'); return; }
  const cred = sel.value;
  if(!confirm('Push the agent to '+ip+' using credential "'+cred+'"? This installs /usr/local/bin/airgap-agent and starts it.')) return;
  try{
    toast('Provisioning '+ip+'&hellip;', '');
    const r = await api('/api/provision/'+encodeURIComponent(ip), {method:'POST', body: JSON.stringify({credential: cred})});
    toast((r.ok?'Provisioned ':'Partial: ')+ip+' &rarr; '+r.agent_id+(r.ok?'':': '+r.detail), r.ok?'ok':'err');
    loadProvision(); loadDevices();
  }catch(e){ toast('Provision failed: '+e.message, 'err'); }
}

function renderProvCreds(){
  const creds = (provData&&provData.credentials)||[];
  $('#credBody').innerHTML = creds.map(c=>`
    <tr>
      <td><b>${esc(c.name)}</b></td>
      <td>${esc(c.username)}</td>
      <td>${esc(c.port)}</td>
      <td>${esc(c.domain)||'&ndash;'}</td>
      <td><button class="ghost" onclick="delCredential('${esc(c.name)}')">Delete</button></td>
    </tr>`).join('') || '<tr><td colspan="5" class="mut">no credentials yet</td></tr>';
}

async function addCredential(){
  const name = $('#credName').value.trim(), user = $('#credUser').value.trim(), pass = $('#credPass').value;
  if(!name || !user || !pass){ toast('Name, username and password are required', 'err'); return; }
  const port = parseInt($('#credPort').value,10) || 22;
  const domain = $('#credDomain').value.trim();
  try{
    await api('/api/credentials', {method:'POST', body: JSON.stringify({name, username:user, password:pass, port, domain})});
    toast('Credential '+name+' saved', 'ok');
    ['credName','credUser','credPass','credPort','credDomain'].forEach(i=>byId(i).value='');
    loadProvision();
  }catch(e){ toast('Save failed: '+e.message, 'err'); }
}

async function delCredential(name){
  if(!confirm('Delete credential '+name+'?')) return;
  try{
    await api('/api/credentials/'+encodeURIComponent(name), {method:'DELETE'});
    toast('Credential '+name+' deleted', 'ok');
    loadProvision();
  }catch(e){ toast('Delete failed: '+e.message, 'err'); }
}

setInterval(()=>{ document.querySelectorAll('[data-ls]').forEach(el=>{ el.textContent = rel(el.dataset.ls); }); }, 15000);
setInterval(loadHealth, 30000);
$('#pass').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });

boot();
</script>
</body>
</html>
"#;
