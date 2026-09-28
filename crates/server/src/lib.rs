pub mod api;
pub mod audit;
pub mod auth;
pub mod ca;
pub mod catalog;
pub mod devnet;
pub mod devnet_http;
pub mod encryption;
pub mod fsguard;
pub mod http;
pub mod provision;
pub mod secrets;
pub mod store;
pub mod tls;

#[cfg(test)]
mod hardening_tests;

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

    // Private key material lives outside the web-facing store dir.
    let key_dir = fsguard::key_dir(&store_dir);
    migrate_legacy_keys(&store_dir, &key_dir);

    // Agent client certs carry private keys too, so they are issued into the
    // protected key directory rather than the web-facing store. Nothing reads
    // these back; they are written by `Ca::issue_client` and handed to the
    // enrolling agent over TLS.
    let cert_dir = key_dir.join("certs");

    // Report anything left too permissive, plus any key material that could
    // not be relocated automatically. Tighten the store dir first so the
    // audit reports the post-correction state rather than flagging a mode
    // that startup is about to fix.
    if let Err(e) = fsguard::ensure_dir(&store_dir, fsguard::DIR_MODE) {
        tracing::warn!(error = %e, "could not restrict the store directory");
    }
    for finding in fsguard::audit_store_tree(&store_dir, &key_dir) {
        tracing::warn!("store hardening: {finding}");
    }
    if let Err(e) = fsguard::harden_tree(&key_dir) {
        tracing::warn!(error = %e, "could not fully restrict the key directory");
    }

    // Encryption at rest is a filesystem property: verify the operator has
    // put the data on an encrypted volume. Advisory unless
    // AIRGAP_REQUIRE_ENCRYPTION is set, because ZFS-style encryption cannot
    // be detected from /proc/mounts and must not lock an operator out.
    match encryption::audit_encryption(
        &store_dir,
        &key_dir,
        encryption::enforcement_requested(),
    ) {
        Ok(findings) => {
            for f in findings {
                tracing::warn!("encryption at rest: {f}");
            }
        }
        Err(e) => {
            return Err(format!(
                "refusing to start: encryption at rest required but not satisfied: {e}"
            )
            .into());
        }
    }

    // The CA's private material is in the key dir; its public certificate is
    // mirrored into the store so agents can be served it.
    let ca = Arc::new(Mutex::new(ca::Ca::load_or_create(&key_dir)?));
    mirror_ca_public(&key_dir, &store_dir);
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
        artifact_locks: Default::default(),
    };

    let api_app = Router::new()
        .route("/enroll", post(api::enroll))
        .route("/register", post(api::register))
        .route("/inventory", post(api::inventory))
        .route("/updates", post(api::poll))
        .route("/report", post(api::report))
        .route("/revert-report", post(api::revert_report))
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

    let devnet_core = Arc::new(tokio::sync::RwLock::new(
        devnet::DevNetCore::new(store.clone(), audit.clone(), store_dir.clone()),
    ));
    let devnet_http_state = devnet_http::HttpState::new(
        store.clone(),
        devnet_core.clone(),
        audit.clone(),
        vec![std::env::var("AIRGAP_ADMIN_TOKEN").unwrap_or_default()],
        store_dir.clone(),
        auth.clone(),
    );
    let devnet_router = devnet_http::router(devnet_http_state);

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
        .merge(devnet_router)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));
    let http_task = http::serve(http_listen, http_app);

    tokio::try_join!(api_task, http_task)?;
    Ok(())
}

/// Moves private key material out of the store into the key directory.
///
/// Runs on every startup so an installation that predates the key-directory
/// split is upgraded in place. Public certificates are left where they are;
/// they are not secret.
///
/// Two layouts are handled:
///   - `<store>/ca/{ca,server}-key.pem` -> `<key-dir>/`
///   - `<store>/keys/*-signing-key`      -> `<key-dir>/keys/`
fn migrate_legacy_keys(store_dir: &std::path::Path, key_dir: &std::path::Path) {
    let legacy_ca = store_dir.join("ca");
    for name in ["ca-key.pem", "server-key.pem"] {
        let from = legacy_ca.join(name);
        if !from.exists() {
            continue;
        }
        match fsguard::relocate_key(&from, &key_dir.join(name)) {
            Ok(dest) => {
                if dest.starts_with(key_dir) {
                    tracing::info!(
                        "relocated private key {} -> {}",
                        from.display(),
                        dest.display()
                    );
                } else {
                    tracing::warn!(
                        "could not relocate {}: destination holds different key material; \
                         resolve manually before exposing the server",
                        from.display()
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, path = %from.display(), "failed to relocate private key"),
        }
    }

    // Signing keys: `airgap-keys` names them `<role>-signing-key` and stores
    // the matching public half as `<role>-verifying-key.pub`. Move only the
    // private half.
    let legacy_keys = store_dir.join("keys");
    let Ok(entries) = std::fs::read_dir(&legacy_keys) else {
        return;
    };
    let dest_dir = key_dir.join("keys");
    for entry in entries.flatten() {
        let from = entry.path();
        let Some(name) = from.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("-signing-key") || !from.is_file() {
            continue;
        }
        match fsguard::relocate_key(&from, &dest_dir.join(name)) {
            Ok(dest) if dest.starts_with(&dest_dir) => {
                tracing::info!("relocated signing key {} -> {}", from.display(), dest.display());
            }
            Ok(_) => tracing::warn!(
                "could not relocate signing key {}: destination holds different key material",
                from.display()
            ),
            Err(e) => {
                tracing::warn!(error = %e, path = %from.display(), "failed to relocate signing key")
            }
        }
    }

    // Agent client private keys: `<store>/certs/<agent>-key.pem` ->
    // `<key-dir>/certs/`. These are mTLS credentials for every enrolled agent,
    // so they are the most valuable thing in the store to move.
    let legacy_certs = store_dir.join("certs");
    let Ok(entries) = std::fs::read_dir(&legacy_certs) else {
        return;
    };
    let dest_dir = key_dir.join("certs");
    for entry in entries.flatten() {
        let from = entry.path();
        let Some(name) = from.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("-key.pem") || !from.is_file() {
            continue;
        }
        match fsguard::relocate_key(&from, &dest_dir.join(name)) {
            Ok(dest) if dest.starts_with(&dest_dir) => {
                tracing::info!("relocated agent key {} -> {}", from.display(), dest.display());
            }
            Ok(_) => tracing::warn!(
                "could not relocate agent key {}: destination holds different key material",
                from.display()
            ),
            Err(e) => {
                tracing::warn!(error = %e, path = %from.display(), "failed to relocate agent key")
            }
        }
    }
}

/// Copies the CA's public certificate into the store so the dashboard and
/// agent provisioning can read it without access to the key directory.
fn mirror_ca_public(key_dir: &std::path::Path, store_dir: &std::path::Path) {
    let dest_dir = store_dir.join("ca");
    if let Err(e) = fsguard::ensure_dir(&dest_dir, fsguard::DIR_MODE) {
        tracing::warn!(error = %e, "could not create public CA directory");
        return;
    }
    for name in ["ca.pem", "server.pem"] {
        let src = key_dir.join(name);
        let dst = dest_dir.join(name);
        if src.exists() {
            if let Err(e) = std::fs::copy(&src, &dst) {
                tracing::warn!(error = %e, "could not mirror public CA file {name}");
            }
        }
    }
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
