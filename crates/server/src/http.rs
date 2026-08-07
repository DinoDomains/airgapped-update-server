use std::collections::HashMap;
use std::sync::Arc;

use airgap_proto::OsInventory;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::audit::AuditLog;
use crate::auth::{Auth, Session};
use crate::catalog::{Catalog, LatestPackage};
use crate::store::{AgentRecord, Store, UpdateRequest};

#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub catalog: Arc<Catalog>,
    pub audit: Arc<AuditLog>,
    pub auth: Arc<Auth>,
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
    match (catalog.get(&crate::catalog::key_of(&family, name)), version.is_empty()) {
        (Some(l), false) => l.version != version,
        _ => false,
    }
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
}

fn summarize(r: AgentRecord, catalog: &HashMap<String, LatestPackage>) -> DeviceSummary {
    let inv = r.inventory.clone();
    let updates_available = inv
        .as_ref()
        .map(|i| {
            i.packages
                .iter()
                .filter(|p| pkg_update_available(i, &p.name, &p.version, catalog))
                .count()
        })
        .unwrap_or(0);
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
            }
        })
        .collect();
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
    let client = crate::catalog::build_client();
    match st.catalog.sync(&client).await {
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

#[derive(Deserialize)]
pub struct UpdateBody {
    pub agent_id: String,
    pub package: String,
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
    let Some(installed) = inv
        .packages
        .iter()
        .find(|p| p.name.to_lowercase() == key)
    else {
        return err(StatusCode::NOT_FOUND, "package not installed on device");
    };
    let Some(latest) = st
        .catalog
        .latest(&key, &format!("{:?}", inv.family).to_lowercase())
        .await
    else {
        return err(StatusCode::NOT_FOUND, "no upstream package known - refresh catalog first");
    };
    if latest.version == installed.version {
        return err(StatusCode::BAD_REQUEST, "already up to date");
    }

    let ts = now_ts();
    let request = UpdateRequest {
        id: format!("{}-{}-{}", req.agent_id, key, ts),
        agent_id: req.agent_id,
        package: req.package,
        from_version: installed.version.clone(),
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
      <button data-view="audit" onclick="showView('audit')">Audit log<small>who did what</small></button>
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

    <div class="view" id="viewAudit">
      <div class="headline"><h2>Audit log</h2></div>
      <div class="toolbar">
        <input id="auditActor" placeholder="filter by operator" oninput="renderAudit()">
        <select id="auditAction" onchange="renderAudit()">
          <option value="">all actions</option>
          <option>login</option><option>approve_update</option><option>catalog_refresh</option>
          <option>operator_create</option><option>operator_delete</option><option>enroll</option><option>register</option>
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
    <button class="ghost" onclick="closeDrawer()">Close</button>
  </header>
  <div class="body">
    <div class="muted" id="drvCount" style="margin-bottom:8px"></div>
    <table>
      <thead><tr><th>Package</th><th>Installed</th><th>Latest</th><th>Status</th><th></th></tr></thead>
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
  if(v==='audit'){ loadAudit(); }
  if(v==='operators'){ loadOperators(); }
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
          ${d.updates_available>0
            ? '<span class="badge bg-upd">'+d.updates_available+' update'+(d.updates_available===1?'':'s')+' available</span>'
            : '<span class="badge bg-idle">up to date</span>'}
        </div>
      </div>`).join('');
  }catch(e){ toast('Failed to load devices: '+e.message, 'err'); }
}

async function openDrawer(id){
  $('#drawer').classList.add('open');
  $('#backdrop').style.display='block';
  $('#drvBody').innerHTML = '<tr><td colspan="5" class="mut">loading packages&hellip;</td></tr>';
  try{
    const data = await api('/api/devices/'+encodeURIComponent(id)+'/packages');
    const upds = data.packages.filter(p=>p.update_available);
    $('#drvHost').textContent = data.hostname;
    $('#drvBadge').innerHTML = upds.length
      ? '<span class="badge bg-upd">'+upds.length+' update'+(upds.length===1?'':'s')+'</span>'
      : '<span class="badge bg-idle">up to date</span>';
    $('#drvMeta').textContent = id;
    $('#drvCount').textContent = data.packages.length + ' packages installed';
    $('#drvBody').innerHTML = data.packages.map(p=>`
      <tr>
        <td>${esc(p.name)}</td>
        <td>${esc(p.installed)}</td>
        <td class="${p.update_available?'upd':'ok'}">${p.latest?esc(p.latest):'<span class="muted">unknown</span>'}</td>
        <td>${p.update_available?'<span class="chip upd">update available</span>':'<span class="chip ok">up to date</span>'}</td>
        <td>${(p.update_available && (role==='approver'||role==='admin'))?`<button class="ghost" onclick="askUpdate('${esc(data.agent_id)}','${esc(p.name)}')">Approve &amp; update</button>`:(p.update_available?'<span class="muted">approver role needed</span>':'')}</td>
      </tr>`).join('');
  }catch(e){
    $('#drvBody').innerHTML = '<tr><td colspan="5" class="upd">Failed to load: '+esc(e.message)+'</td></tr>';
  }
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
    toast('Catalog refreshed: '+r.packages+' packages (apt '+r.apt+', dnf '+r.dnf+')', 'ok');
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

setInterval(()=>{ document.querySelectorAll('[data-ls]').forEach(el=>{ el.textContent = rel(el.dataset.ls); }); }, 15000);
setInterval(loadHealth, 30000);
$('#pass').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });

boot();
</script>
</body>
</html>
"#;
