use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Request, Response};
use axum::Router;
use hyper::body::Incoming;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// Identity extracted from the client certificate on the TLS layer and
/// injected into each request handled on that connection.
#[derive(Debug, Clone, Default)]
pub struct ClientIdentity {
    pub cn: Option<String>,
    pub authenticated: bool,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for ClientIdentity {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<ClientIdentity>()
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Clone)]
struct WithClientIdentity {
    router: Router,
    identity: ClientIdentity,
}

impl hyper::service::Service<Request<Incoming>> for WithClientIdentity {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        req.extensions_mut().insert(self.identity.clone());
        let mut router = self.router.clone();
        Box::pin(async move { Ok(router.call(req).await?) })
    }
}

fn cert_cn(cert_der: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.to_string();
    Some(cn)
}

/// Runs an HTTPS accept loop that terminates mTLS and dispatches requests to
/// the axum router. The peer certificate CN is attached to every request.
pub async fn serve(
    addr: std::net::SocketAddr,
    tls: TlsAcceptor,
    router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("airgap server listening on {addr} (mTLS)");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let tls = tls.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = tls.accept(stream).await else {
                return;
            };
            let identity = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|c| cert_cn(c))
                .map(|cn| ClientIdentity {
                    cn: Some(cn),
                    authenticated: true,
                })
                .unwrap_or_default();

            let svc = WithClientIdentity { router, identity };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
            if let Err(e) = conn.await {
                tracing::debug!("connection ended: {e}");
            }
        });
    }
}
