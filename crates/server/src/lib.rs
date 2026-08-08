pub mod api;
pub mod audit;
pub mod auth;
pub mod ca;
pub mod catalog;
pub mod http;
pub mod provision;
pub mod store;
pub mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use crate::api::ApiState;
use crate::http::HttpState;

const DEFAULT_LISTEN: &str = "0.0.0.0:8443";
const DEFAULT_HTTP_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_STORE_DIR: &str = "data";

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listen: SocketAddr = std::env::var("AIRGAP_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_string())
        .parse()
        .expect("invalid listen address");

    let http_listen: SocketAddr = std::env::var("AIRGAP_HTTP_LISTEN")
        .unwrap_or_else(|_| DEFAULT_HTTP_LISTEN.to_string())
        .parse()
        .expect("invalid http listen address");

    let store_dir = PathBuf::from(
        std::env::var("AIRGAP_STORE_DIR").unwrap_or_else(|_| DEFAULT_STORE_DIR.to_string()),
    );
    let server_url = std::env::var("AIRGAP_SERVER_URL")
        .unwrap_or_else(|_| "https://172.16.5.20:8443".to_string());
    let cert_dir = store_dir.join("certs");

    let ca = Arc::new(Mutex::new(ca::Ca::load_or_create(&store_dir.join("ca"))?));
    let store = Arc::new(store::Store::load(&store_dir).await?);
    let catalog = Arc::new(catalog::Catalog::load(&store_dir).await?);
    let audit = Arc::new(audit::AuditLog::new(&store_dir));
    let auth = Arc::new(auth::Auth::load(&store_dir).await?);

    let api_state = ApiState {
        store: store.clone(),
        ca: ca.clone(),
        cert_dir: cert_dir.clone(),
        store_dir: store_dir.clone(),
        catalog: catalog.clone(),
        audit: audit.clone(),
        rate: api::RateLimiter::default(),
    };

    let api_app = Router::new()
        .route("/enroll", post(api::enroll))
        .route("/register", post(api::register))
        .route("/inventory", post(api::inventory))
        .route("/updates", post(api::poll))
        .route("/report", post(api::report))
        .route("/artifact", post(api::artifact))
        .route("/health", get(api::health))
        .with_state(api_state)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    let tls_config = ca.lock().await.tls_server_config()?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let api_task = tls::serve(listen, acceptor, api_app, store.clone());

    let http_state = HttpState {
        store: store.clone(),
        catalog: catalog.clone(),
        audit: audit.clone(),
        auth: auth.clone(),
        store_dir: store_dir.clone(),
        server_url,
        scan: Arc::new(tokio::sync::RwLock::new(None)),
    };
    let http_app = Router::new()
        .route("/", get(http::dashboard))
        .route("/api/devices", get(http::devices))
        .route("/api/devices/:id/packages", get(http::device_packages))
        .route("/api/refresh", post(http::refresh_catalog))
        .route("/api/refresh/status", get(http::refresh_status))
        .route("/api/update", post(http::request_update))
        .route("/api/updates", get(http::pending_updates))
        .route("/api/audit", get(http::audit_log))
        .route("/api/health", get(http::health))
        .route("/api/login", post(http::login))
        .route("/api/logout", post(http::logout))
        .route("/api/me", get(http::me))
        .route("/api/operators", get(http::list_operators))
        .route("/api/operators", post(http::create_operator))
        .route("/api/operators/:name", delete(http::delete_operator))
        .route("/api/policy", get(http::get_policy))
        .route("/api/policy", post(http::set_policy))
        .route("/api/policy/entries", post(http::upsert_policy_entry))
        .route(
            "/api/policy/entries/:name",
            delete(http::delete_policy_entry),
        )
        .route("/api/rings", get(http::rings))
        .route("/api/update/:id/promote", post(http::promote_update))
        .route("/api/catalog", get(http::search_catalog))
        .route("/api/agents/:id/revoke", post(http::revoke_agent))
        .route("/api/agents/revoked", get(http::list_revoked))
        .route("/api/devices/:id/scan", post(http::scan_device))
        .route("/api/sources", get(http::list_sources))
        .route("/api/sources", post(http::add_source))
        .route("/api/sources/:name", post(http::toggle_source))
        .route("/api/sources/:name", delete(http::delete_source))
        .route("/api/credentials", get(http::list_credentials))
        .route("/api/credentials", post(http::upsert_credential))
        .route("/api/credentials/:name", delete(http::delete_credential))
        .route("/api/networks", get(http::list_networks))
        .route("/api/networks", post(http::add_network))
        .route("/api/networks/:name", delete(http::delete_network))
        .route("/api/networks/:name/scan", post(http::scan_network))
        .route("/api/provision", get(http::provision_status))
        .route("/api/provision/:ip", post(http::provision_host))
        .route(
            "/api/provision/agent-binary",
            put(http::upload_agent_binary),
        )
        .with_state(http_state)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));
    let http_task = http::serve(http_listen, http_app);

    tokio::try_join!(api_task, http_task)?;
    Ok(())
}

/// Writes a gzipped tar backup of the state directory (CA, certs, JSON
/// stores, audit log) to `out`. Used by `airgap-server backup`.
pub fn backup(store_dir: &std::path::Path, out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if !store_dir.is_dir() {
        return Err(format!("store dir {} not found", store_dir.display()).into());
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(out)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    add_dir_to_tar(&mut tar, store_dir, store_dir)?;
    let enc = tar.into_inner()?;
    enc.finish()?;
    Ok(())
}

fn add_dir_to_tar(
    tar: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>,
    base: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let rel = path.strip_prefix(base)?;
        if path.is_dir() {
            tar.append_dir(&rel, &path)?;
            add_dir_to_tar(tar, base, &path)?;
        } else {
            tar.append_path_with_name(&path, &rel)?;
        }
    }
    Ok(())
}
