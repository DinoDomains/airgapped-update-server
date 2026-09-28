use std::collections::HashMap;
use std::sync::Arc;

use airgap_proto::{
    ArtifactRequest, EnrollRequest, EnrollResponse, InventoryRequest, InventoryResponse,
    OsInventory, PollRequest, PollResponse, RegisterRequest, RegisterResponse, ReportRequest,
    ReportResponse, RevertCommand, RevertReport,
};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
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
    /// Serializes full downloads per update_id so overlapping requests can
    /// never both append to the same cache file.
    pub artifact_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
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
    let revert_commands = pending_revert_commands(&st, &cn).await;
    Json(PollResponse {
        updates,
        scan_requested,
        revert_commands,
    })
    .into_response()
}

/// Read any revert commands persisted for this agent from the M5 devnet
/// dispatch directory (`store_dir/revert-commands/*.json`).
async fn pending_revert_commands(st: &ApiState, agent_id: &str) -> Vec<RevertCommand> {
    let dir = st.store_dir.join("revert-commands");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(data) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(cmd) = serde_json::from_str::<RevertCommand>(&data) else {
            continue;
        };
        if cmd.agent_id == agent_id {
            out.push(cmd);
        }
    }
    out
}

/// `POST /revert-report`
/// M6 agent reports the outcome of an admin-initiated revert. Record the
/// outcome in the audit log so M7's dashboard can show it.
pub async fn revert_report(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    Json(req): Json<RevertReport>,
) -> Response {
    let cn = match require_auth(&identity) {
        Ok(cn) => cn,
        Err(r) => return r,
    };
    if cn != req.agent_id {
        return err(StatusCode::FORBIDDEN, "agent_id does not match certificate");
    }
    st.audit.log(
        &req.agent_id,
        "revert_outcome",
        &format!("{}:{}", req.command_id, req.package),
        &format!("target: {} / {:?}", req.target_version, req.outcome),
    );
    Json(ReportResponse { accepted: true }).into_response()
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

const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Serves the actual .msu/.rpm/.deb for an approved-pending update by proxying
/// it from the whitelisted upstream source. The server is the only online host;
/// agents on isolated networks fetch the artifact over mTLS and install from
/// the local file. Only approved updates are served, and only to their target
/// agent.
///
/// The artifact is streamed (never buffered whole in RAM) and written to a
/// disk cache keyed by update id. A complete cache serves subsequent requests
/// directly from disk. Upstream fetches are resilient to CDN edge failures and
/// resume from the byte already cached when an edge dies mid-body. Client
/// `Range` headers are honored both from cache and upstream.
pub async fn artifact(
    State(st): State<ApiState>,
    identity: ClientIdentity,
    headers: axum::http::HeaderMap,
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
    let meta_path = artifact_dir.join(format!("{}.meta", req.update_id));

    // Complete cache: serve from disk, honoring the client's Range.
    if let Ok(meta) = tokio::fs::read_to_string(&meta_path).await {
        let meta: CacheMeta = match serde_json::from_str(&meta) {
            Ok(m) => m,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt cache meta"),
        };
        if let Ok(fm) = tokio::fs::metadata(&cached).await {
            if fm.len() == meta.total {
                return serve_cached_artifact(&cached, fm.len(), &headers, &update.package, &family).await;
            }
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

    // Local staged artifact: copy into the cache (streamed, then serve).
    if let Some(local) = url.strip_prefix("file://") {
        let _ = tokio::fs::create_dir_all(&artifact_dir).await;
        if let Err(e) = tokio::fs::copy(local, &cached).await {
            return err(
                StatusCode::NOT_FOUND,
                format!("staged artifact unavailable on server: {e}"),
            );
        }
        let size = tokio::fs::metadata(&cached).await.map(|m| m.len()).unwrap_or(0);
        let _ = tokio::fs::write(
            &meta_path,
            serde_json::to_string(&CacheMeta { total: size }).unwrap_or_default(),
        )
        .await;
        st.audit.log(&cn, "artifact", &update.package, local);
        return serve_cached_artifact(&cached, size, &headers, &update.package, &family).await;
    }

    // Partial cache: resume upstream from the bytes we already have.
    let _ = tokio::fs::create_dir_all(&artifact_dir).await;

    // Serialize downloads for this update so two concurrent requests can never
    // both append to the same cache file. The guard is held by the spawned
    // task for the entire download; a second request waits, then resumes from
    // the now-larger cached prefix.
    let lock = {
        let mut locks = st.artifact_locks.lock().await;
        locks
            .entry(req.update_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let fetch_guard = lock.lock_owned().await;

    let cached_bytes = tokio::fs::metadata(&cached).await.map(|m| m.len()).unwrap_or(0);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, String>>(64);
    let upstream_start = cached_bytes;

    let cache_path = cached.clone();
    let url_for_task = url.clone();
    let sources_for_task = sources.clone();
    let header_budget = std::time::Duration::from_secs(20);
    let edge_cache_path = st.store_dir.join("edges.json");
    let tx_stream = tx.clone();
    let tx_fail = tx.clone();
    tokio::spawn(async move {
        let _fetch_guard = fetch_guard;
        match catalog::stream_resilient(
            &sources_for_task,
            &url_for_task,
            upstream_start,
            header_budget,
            tx_stream,
            Some(&cache_path),
            Some(&edge_cache_path),
        )
        .await
        {
            Ok(Some(total)) => {
                let _ = tokio::fs::write(
                    cache_path.with_extension("meta"),
                    serde_json::to_string(&CacheMeta { total }).unwrap_or_default(),
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = tx_fail.send(Err(e)).await;
            }
        }
    });
    drop(tx);
    st.audit.log(&cn, "artifact", &update.package, &url);

    let total = tokio::fs::metadata(&cached).await.map(|m| m.len()).ok();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-artifact-filename", artifact_filename(&update.package, &family));
    if let Some(t) = total {
        builder = builder.header(header::CONTENT_LENGTH, t.to_string());
    }
    builder
        .body(axum::body::Body::from_stream(
            futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| {
                    let out = item.map_err(|e| std::io::Error::other(e));
                    (out, rx)
                })
            }),
        ))
        .unwrap_or_else(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to build artifact response"))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    total: u64,
}

#[derive(Clone, Copy)]
enum RangeSpec {
    All,
    Bytes(u64, u64),
}

fn parse_range(headers: &axum::http::HeaderMap, cached_bytes: u64) -> Option<RangeSpec> {
    let value = headers.get(header::RANGE)?.to_str().ok()?;
    let spec = value.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    if start >= cached_bytes {
        return None;
    }
    let end = if end.is_empty() {
        cached_bytes - 1
    } else {
        end.parse::<u64>().ok()?.min(cached_bytes - 1)
    };
    Some(RangeSpec::Bytes(start, end))
}

/// Streams a fully-cached artifact from disk, honoring a client `Range`.
async fn serve_cached_artifact(
    path: &std::path::Path,
    total: u64,
    headers: &axum::http::HeaderMap,
    package: &str,
    family: &str,
) -> Response {
    let spec = parse_range(headers, total).unwrap_or(RangeSpec::All);
    let (start, end) = match spec {
        RangeSpec::All => (0, total.saturating_sub(1)),
        RangeSpec::Bytes(s, e) => (s, e),
    };
    let len = if start > end { 0 } else { end - start + 1 };
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => {
            return err(StatusCode::NOT_FOUND, "cached artifact unavailable");
        }
    };
    let reader = tokio_util::io::ReaderStream::with_capacity(file, 128 * 1024);
    let body = axum::body::Body::from_stream(
        stream_with_offset(reader, start).take(len as usize),
    );
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-artifact-filename", artifact_filename(package, family));
    match spec {
        RangeSpec::All => {
            builder = builder
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, total.to_string());
        }
        RangeSpec::Bytes(s, e) => {
            builder = builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_LENGTH, len.to_string())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {s}-{e}/{total}"),
                );
        }
    }
    builder
        .body(body)
        .unwrap_or_else(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to build artifact response"))
}

/// Drops the first `skip` bytes of a byte-stream.
fn stream_with_offset<S>(stream: S, skip: u64) -> impl futures::Stream<Item = std::io::Result<bytes::Bytes>>
where
    S: futures::Stream<Item = std::io::Result<bytes::Bytes>> + Unpin,
{
    futures::stream::unfold(
        (stream, skip),
        |(mut stream, mut skip)| async move {
            loop {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let clen = chunk.len() as u64;
                        if skip >= clen {
                            skip -= clen;
                            continue;
                        }
                        let kept = chunk.slice((skip as usize)..);
                        skip = 0;
                        return Some((Ok(kept), (stream, skip)));
                    }
                    other => return Some((other?, (stream, skip))),
                }
            }
        },
    )
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
