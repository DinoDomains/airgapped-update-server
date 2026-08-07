pub mod api;
pub mod audit;
pub mod auth;
pub mod ca;
pub mod catalog;
pub mod http;
pub mod store;
pub mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
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
        catalog: catalog.clone(),
        audit: audit.clone(),
    };

    let api_app = Router::new()
        .route("/enroll", post(api::enroll))
        .route("/register", post(api::register))
        .route("/inventory", post(api::inventory))
        .route("/updates", post(api::poll))
        .route("/report", post(api::report))
        .route("/health", get(api::health))
        .with_state(api_state)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    let tls_config = ca.lock().await.tls_server_config()?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let api_task = tls::serve(listen, acceptor, api_app);

    let http_state = HttpState {
        store: store.clone(),
        catalog: catalog.clone(),
        audit: audit.clone(),
        auth: auth.clone(),
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
        .with_state(http_state);
    let http_task = http::serve(http_listen, http_app);

    tokio::try_join!(api_task, http_task)?;
    Ok(())
}
