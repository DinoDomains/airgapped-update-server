use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use airgap_proto::{
    ArtifactRequest, EnrollRequest, EnrollResponse, InventoryRequest, InventoryResponse,
    PollRequest, PollResponse, RegisterRequest, RegisterResponse, ReportRequest, ReportResponse,
};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("CA certificate not provisioned: {0}")]
    MissingCa(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server rejected request: {0}")]
    Api(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Client {
    server: String,
    agent_id: String,
    http: reqwest::Client,
}

/// A downloaded package artifact plus the filename the server derived from
/// the upstream source, so the agent can install it with dnf/dpkg.
pub struct ArtifactInfo {
    pub filename: String,
    pub bytes: Vec<u8>,
}

impl Client {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn cert_paths(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        (dir.join("client.pem"), dir.join("client-key.pem"))
    }

    pub async fn load_or_enroll(
        server: &str,
        state_dir: &Path,
    ) -> Result<Self, ClientError> {
        std::fs::create_dir_all(state_dir)?;

        let ca_path = state_dir.join("ca.pem");
        let ca_pem = std::fs::read_to_string(&ca_path)
            .map_err(|_| ClientError::MissingCa(ca_path.display().to_string()))?;
        let ca_cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;

        let (cert_path, key_path) = Self::cert_paths(state_dir);
        let identity = if cert_path.exists() && key_path.exists() {
            tracing::info!("using provisioned client certificate");
            Self::load_identity(&cert_path, &key_path)?
        } else {
            let token = std::env::var("AIRGAP_ENROLL_TOKEN").unwrap_or_default();
            if token.is_empty() {
                return Err(ClientError::Api(
                    "no client certificate and AIRGAP_ENROLL_TOKEN not set".to_string(),
                ));
            }
            tracing::info!("enrolling with token");
            let enroll = EnrollRequest {
                token,
                hostname: read_hostname(),
            };
            let resp = enroll_http(&Self::bootstrap_client(&ca_cert), server, &enroll).await?;
            std::fs::write(&cert_path, &resp.cert)?;
            std::fs::write(&key_path, &resp.cert_key)?;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            std::fs::write(state_dir.join("agent-id"), &resp.agent_id)?;
            Self::load_identity(&cert_path, &key_path)?
        };

        let agent_id = std::fs::read_to_string(state_dir.join("agent-id"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if agent_id.is_empty() {
            return Err(ClientError::Api("agent-id missing after enroll".to_string()));
        }

        let http = Self::build_client(ca_cert, identity);
        Ok(Client {
            server: server.trim_end_matches('/').to_string(),
            agent_id,
            http,
        })
    }

    fn load_identity(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<reqwest::Identity, ClientError> {
        let cert = std::fs::read_to_string(cert_path)?;
        let key = std::fs::read_to_string(key_path)?;
        Ok(reqwest::Identity::from_pem(format!("{cert}\n{key}").as_bytes())?)
    }

    fn build_client(
        ca: reqwest::Certificate,
        identity: reqwest::Identity,
    ) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(ca)
            .identity(identity)
            .build()
            .expect("failed to build http client")
    }

    fn bootstrap_client(ca: &reqwest::Certificate) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(ca.clone())
            .build()
            .expect("failed to build bootstrap http client")
    }

    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ClientError> {
        let url = format!("{}{}", self.server, path);
        let resp = self.http.post(&url).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("{status}: {text}")));
        }
        Ok(resp.json().await?)
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, ClientError> {
        self.post("/register", req).await
    }

    pub async fn inventory(
        &self,
        req: &InventoryRequest,
    ) -> Result<InventoryResponse, ClientError> {
        self.post("/inventory", req).await
    }

    pub async fn poll(&self, req: &PollRequest) -> Result<PollResponse, ClientError> {
        self.post("/updates", req).await
    }

    #[allow(dead_code)]
    pub async fn report(&self, req: &ReportRequest) -> Result<ReportResponse, ClientError> {
        self.post("/report", req).await
    }

    /// Fetches the package artifact for an approved update from the server.
    /// The server streams the .rpm/.deb it proxied from the whitelisted
    /// upstream source; the agent never needs direct internet access.
    pub async fn artifact(
        &self,
        agent_id: &str,
        update_id: &str,
        family: &str,
    ) -> Result<ArtifactInfo, ClientError> {
        let url = format!("{}/artifact", self.server);
        let req = ArtifactRequest {
            agent_id: agent_id.to_string(),
            update_id: update_id.to_string(),
            family: family.to_string(),
        };
        let resp = self.http.post(&url).json(&req).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("{status}: {text}")));
        }
        let filename = resp
            .headers()
            .get("x-artifact-filename")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "artifact.bin".to_string());
        let bytes = resp.bytes().await?.to_vec();
        Ok(ArtifactInfo { filename, bytes })
    }
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

async fn enroll_http(
    http: &reqwest::Client,
    server: &str,
    req: &EnrollRequest,
) -> Result<EnrollResponse, ClientError> {
    let url = format!("{}/enroll", server.trim_end_matches('/'));
    let resp = http.post(url).json(req).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(ClientError::Api(format!("{status}: {text}")));
    }
    Ok(resp.json().await?)
}
