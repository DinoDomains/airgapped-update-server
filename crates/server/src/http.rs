use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::catalog::Catalog;
use crate::store::{AgentRecord, Store, UpdateRequest};

#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub catalog: Arc<Catalog>,
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
}

impl From<AgentRecord> for DeviceSummary {
    fn from(r: AgentRecord) -> Self {
        let inv = r.inventory.clone();
        DeviceSummary {
            id: r.agent_id,
            hostname: r.hostname,
            os_pretty: inv.as_ref().map(|i| i.os_pretty.clone()).unwrap_or_default(),
            os_name: inv.as_ref().map(|i| i.os_name.clone()).unwrap_or_default(),
            os_version: inv.as_ref().map(|i| i.os_version.clone()).unwrap_or_default(),
            family: format!(
                "{:?}",
                inv.as_ref().map(|i| i.family).unwrap_or_default()
            )
            .to_lowercase(),
            arch: inv.as_ref().map(|i| i.arch.clone()).unwrap_or_default(),
            kernel: inv.as_ref().map(|i| i.kernel.clone()).unwrap_or_default(),
            bootloader: inv.as_ref().map(|i| i.bootloader.clone()).unwrap_or_default(),
            ip: r.ip,
            last_seen: r.last_seen,
            status: r.status,
            packages: inv.map(|i| i.packages.len()).unwrap_or(0),
        }
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

pub async fn devices(State(st): State<HttpState>) -> Response {
    let agents = st.store.list_agents().await;
    let devs: Vec<DeviceSummary> = agents.into_iter().map(DeviceSummary::from).collect();
    Json(devs).into_response()
}

pub async fn device_packages(
    State(st): State<HttpState>,
    Path(id): Path<String>,
) -> Response {
    let agent = match st.store.get_agent(&id).await {
        Some(a) => a,
        None => return err(StatusCode::NOT_FOUND, "device not found"),
    };
    let Some(inv) = agent.inventory else {
        return Json(serde_json::json!({ "agent_id": id, "packages": [] })).into_response();
    };
    let catalog = st.catalog.snapshot().await;
    let family = format!("{:?}", inv.family).to_lowercase();

    let mut rows: Vec<PkgRow> = inv
        .packages
        .into_iter()
        .map(|p| {
            let latest = catalog.get(&crate::catalog::key_of(&family, &p.name)).map(|l| l.version.clone());
            let update_available = match (&latest, p.version.is_empty()) {
                (Some(l), false) => l != &p.version,
                _ => false,
            };
            PkgRow {
                name: p.name,
                installed: p.version,
                arch: p.arch,
                source: p.source,
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

pub async fn refresh_catalog(State(st): State<HttpState>) -> Response {
    let client = crate::catalog::build_client();
    match st.catalog.sync(&client).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}

#[derive(Deserialize)]
pub struct UpdateBody {
    pub agent_id: String,
    pub package: String,
}

pub async fn request_update(
    State(st): State<HttpState>,
    Json(req): Json<UpdateBody>,
) -> Response {
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
    };
    st.store.record_update_request(request.clone()).await;
    tracing::info!("update approved for {}/{}: {} -> {}", request.agent_id, request.package, request.from_version, request.to_version);
    Json(request).into_response()
}

pub async fn pending_updates(State(st): State<HttpState>) -> Response {
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
           border-bottom:1px solid var(--line); position:sticky; top:0; }
  header h1 { font-size:18px; margin:0; }
  header .srv { color:var(--mut); font-size:13px; }
  button { background:var(--ac); color:#082f49; border:0; border-radius:6px; padding:7px 12px;
           font-weight:700; cursor:pointer; font-family:inherit; }
  button.ghost { background:transparent; color:var(--ac); border:1px solid var(--ac); }
  main { padding:20px; max-width:1200px; margin:0 auto; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); font-size:13px; }
  th { color:var(--mut); text-transform:uppercase; font-size:11px; letter-spacing:.5px; }
  tr.device { cursor:pointer; }
  tr.device:hover { background:#243349; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .ok { color:var(--ok); } .upd { color:var(--upd); } .mut { color:var(--mut); }
  .bg-ok { background:#052e16; color:var(--ok); } .bg-upd { background:#431407; color:var(--upd); }
  .bg-online { background:#052e16; color:var(--ok); } .bg-idle { background:#1e293b; color:var(--mut); }
  .pkg { cursor:pointer; } .pkg:hover { background:#243349; }
  .detail { display:none; }
  .detail.open { display:table-row; }
  .detail td { background:#0b1526; padding:16px 20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:16px; margin-top:20px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
  .card h3 { margin:0 0 8px; font-size:14px; }
  .row { display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px dashed var(--line); }
  .row:last-child { border-bottom:0; }
  .muted { color:var(--mut); }
  #notice { position:fixed; bottom:18px; left:50%; transform:translateX(-50%); background:var(--panel);
            border:1px solid var(--line); padding:10px 18px; border-radius:8px; display:none; }
</style>
</head>
<body>
<header>
  <h1>OpenUpdater</h1>
  <span class="srv">server: <b id="srvHost"></b></span>
  <span style="flex:1"></span>
  <button class="ghost" onclick="loadUpdates()">Pending approvals</button>
  <button onclick="refreshCatalog()">Refresh package catalog</button>
  <button onclick="loadDevices()">Refresh devices</button>
</header>
<main>
  <h2 style="font-size:15px;color:var(--mut)">Devices <span id="devCount" class="muted"></span></h2>
  <table>
    <thead><tr>
      <th>Device</th><th>OS</th><th>Arch / Kernel</th><th>IP</th><th>Last seen</th><th>Status</th><th>Packages</th>
    </tr></thead>
    <tbody id="devBody"></tbody>
  </table>
  <div id="updatesCard" style="display:none" class="card"></div>
</main>
<div id="notice"></div>
<script>
const $ = s => document.querySelector(s);
function notice(msg){ const n=$('#notice'); n.textContent=msg; n.style.display='block'; setTimeout(()=>n.style.display='none',4000); }

async function api(path, opts){
  const res = await fetch(path, opts);
  if(!res.ok){ let t=''; try{ t=(await res.json()).error||t; }catch(_){} throw new Error(t||res.status); }
  return res.json();
}

async function loadDevices(){
  try{
    const devs = await api('/api/devices');
    $('#devCount').textContent = '('+devs.length+')';
    $('#devBody').innerHTML = devs.map(d=>`
      <tr class="device" onclick="toggleDevice('${d.id}', this)">
        <td><b>${esc(d.hostname)}</b><div class="muted">${esc(d.id)}</div></td>
        <td>${esc(d.os_pretty)||'&ndash;'}</td>
        <td>${esc(d.arch)||'&ndash;'} / ${esc(d.kernel)||'&ndash;'}</td>
        <td>${esc(d.ip)||'&ndash;'}</td>
        <td class="muted">${esc(d.last_seen)||'&ndash;'}</td>
        <td><span class="badge ${d.status==='online'?'bg-online':'bg-idle'}">${esc(d.status)}</span></td>
        <td>${d.packages}</td>
      </tr>
      <tr class="detail" id="d-${d.id}"><td colspan="7"></td></tr>`).join('');
  }catch(e){ notice('Failed to load devices: '+e.message); }
}

async function toggleDevice(id, tr){
  const row = $('#d-'+id);
  const open = row.classList.contains('open');
  row.classList.toggle('open');
  if(open) return;
  row.querySelector('td').innerHTML = '<span class="muted">loading packages...</span>';
  try{
    const data = await api('/api/devices/'+encodeURIComponent(id)+'/packages');
    const upds = data.packages.filter(p=>p.update_available);
    row.querySelector('td').innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <b>${esc(data.hostname)}</b>
        <span>${upds.length} update${upds.length===1?'':'s'} available</span>
      </div>
      <table>
        <thead><tr><th>Package</th><th>Installed</th><th>Latest</th><th></th></tr></thead>
        <tbody>${data.packages.slice(0,300).map(p=>`
          <tr>
            <td>${esc(p.name)}</td>
            <td>${esc(p.installed)}</td>
            <td class="${p.update_available?'upd':'ok'}">${p.latest?esc(p.latest):'<span class="muted">unknown</span>'}</td>
            <td>${p.update_available?`<button class="ghost" onclick="askUpdate('${data.agent_id}','${esc(p.name)}')">Approve &amp; update</button>`:''}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }catch(e){ row.querySelector('td').innerHTML = '<span class="red">Failed to load: '+esc(e.message)+'</span>'; }
}

async function askUpdate(agentId, pkg){
  if(!confirm('Approve updating '+pkg+' on '+agentId+'?')) return;
  try{
    const r = await api('/api/update', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({agent_id:agentId, package:pkg})});
    notice('Approved: '+pkg+' '+r.from_version+' -> '+r.to_version+' (status: '+r.status+')');
  }catch(e){ notice('Update request failed: '+e.message); }
}

async function refreshCatalog(){
  notice('Refreshing package catalog from upstream (this can take a minute)...');
  try{
    const r = await api('/api/refresh', {method:'POST'});
    notice('Catalog refreshed: '+r.packages+' packages (apt '+r.apt+', dnf '+r.dnf+')');
    loadDevices();
  }catch(e){ notice('Refresh failed: '+e.message); }
}

async function loadUpdates(){
  try{
    const upds = await api('/api/updates');
    const card = $('#updatesCard');
    card.style.display = upds.length?'block':'none';
    card.innerHTML = '<h3>Pending update approvals ('+upds.length+')</h3>' + upds.slice().reverse().slice(0,50).map(u=>`
      <div class="row"><span>${esc(u.package)}</span>
        <span class="muted">${esc(u.agent_id)} ${esc(u.from_version)} &rarr; ${esc(u.to_version)} <b>${esc(u.status)}</b></span></div>`).join('');
  }catch(e){ notice('Failed to load approvals: '+e.message); }
}

function esc(s){ return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

$('#srvHost').textContent = location.host;
loadDevices(); loadUpdates();
</script>
</body>
</html>
"#;
