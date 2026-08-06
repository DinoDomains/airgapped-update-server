mod api;
mod ca;
mod store;
mod tls;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use api::ApiState;

const DEFAULT_LISTEN: &str = "0.0.0.0:8443";
const DEFAULT_STORE_DIR: &str = "data";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_server=info,axum=info".into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let listen: std::net::SocketAddr = std::env::var("AIRCAP_LISTEN")
        .ok()
        .or_else(|| std::env::var("AIRGAP_LISTEN").ok())
        .unwrap_or_else(|| DEFAULT_LISTEN.to_string())
        .parse()
        .expect("invalid listen address");

    let store_dir = PathBuf::from(
        std::env::var("AIRGAP_STORE_DIR").unwrap_or_else(|_| DEFAULT_STORE_DIR.to_string()),
    );
    let cert_dir = store_dir.join("certs");

    let ca = Arc::new(Mutex::new(ca::Ca::load_or_create(&store_dir.join("ca"))?));

    let store = Arc::new(store::Store::load(&store_dir).await?);

    let api_state = ApiState {
        store: store.clone(),
        ca: ca.clone(),
        cert_dir: cert_dir.clone(),
    };

    let app = Router::new()
        .route("/enroll", post(api::enroll))
        .route("/register", post(api::register))
        .route("/inventory", post(api::inventory))
        .route("/updates", post(api::poll))
        .route("/report", post(api::report))
        .route("/health", get(|| async { "ok" }))
        .with_state(api_state)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    let tls_config = ca.lock().await.tls_server_config()?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tls::serve(listen, acceptor, app).await
}
