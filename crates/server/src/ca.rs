use std::fs;
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

pub struct Ca {
    /// Reconstructed issuer used by rcgen to sign new certs. On first run this
    /// is the freshly generated CA; on later runs it is rebuilt from the
    /// persisted CA key so it stays usable as a signing issuer.
    issuer: Certificate,
    ca_key: KeyPair,
    /// The actual root CA certificate bytes served/trusted by clients.
    ca_der: CertificateDer<'static>,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
    next_serial: u64,
}

fn to_pkcs8_der(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

fn parse_cert_pem(path: &Path) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
    let pem = fs::read(path)?;
    let mut rd = std::io::BufReader::new(pem.as_slice());
    let mut certs = rustls_pemfile::certs(&mut rd);
    let Some(Ok(cert)) = certs.next() else {
        return Err(format!("no certificate found in {}", path.display()).into());
    };
    Ok(cert)
}

fn rebuild_issuer(
    ca_key_path: &Path,
    ca_pem_path: &Path,
) -> Result<(Certificate, KeyPair), Box<dyn std::error::Error>> {
    let key = KeyPair::from_pem(&fs::read_to_string(ca_key_path)?)?;
    let params = CertificateParams::from_ca_cert_pem(&fs::read_to_string(ca_pem_path)?)?;
    let cert = params.self_signed(&key)?;
    Ok((cert, key))
}

impl Ca {
    /// Loads the CA from `dir`, creating it if absent.
    ///
    /// `dir` is expected to be the out-of-store key directory (see
    /// `fsguard::key_dir`). Public material (`ca.pem`, `server.pem`) is
    /// copied into the store's `ca/` directory so it can be served to
    /// agents; private keys stay in the key directory at `0600`.
    pub fn load_or_create(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        crate::fsguard::ensure_dir(dir, crate::fsguard::DIR_MODE)?;
        let ca_pem_path = dir.join("ca.pem");
        let ca_key_path = dir.join("ca-key.pem");
        let srv_pem_path = dir.join("server.pem");
        let srv_key_path = dir.join("server-key.pem");
        let serial_path = dir.join("serial");

        let (issuer, ca_key, ca_der) = if ca_pem_path.exists() && ca_key_path.exists() {
            let (cert, key) = rebuild_issuer(&ca_key_path, &ca_pem_path)?;
            let der = parse_cert_pem(&ca_pem_path)?;
            (cert, key, der)
        } else {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec!["airgap-ca.internal".to_string()])?;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "Airgap Internal CA");
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let cert = params.self_signed(&key)?;
            fs::write(&ca_pem_path, cert.pem())?;
            // Private key: written via the guarded helper so it is 0600 even
            // if the process umask is permissive.
            crate::fsguard::write_secret(&ca_key_path, key.serialize_pem().as_bytes())?;
            let der = cert.der().clone();
            (cert, key, der)
        };

        let (server_cert_der, server_key_der) = if srv_pem_path.exists() && srv_key_path.exists() {
            let der = parse_cert_pem(&srv_pem_path)?;
            let key_pem = fs::read_to_string(&srv_key_path)?;
            let key = KeyPair::from_pem(&key_pem)?;
            (der, to_pkcs8_der(&key))
        } else {
            let (server_cert, server_key) = Self::generate_server(&issuer, &ca_key)?;
            fs::write(&srv_pem_path, server_cert.pem())?;
            crate::fsguard::write_secret(&srv_key_path, server_key.serialize_pem().as_bytes())?;
            (server_cert.der().clone(), to_pkcs8_der(&server_key))
        };

        // Defensive: tighten any key file that predates this change.
        for key in [&ca_key_path, &srv_key_path] {
            let _ = crate::fsguard::tighten(key, crate::fsguard::KEY_MODE, false);
        }

        let next_serial = fs::read_to_string(&serial_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(1);

        Ok(Ca {
            issuer,
            ca_key,
            ca_der,
            server_cert_der,
            server_key_der,
            next_serial,
        })
    }

    fn generate_server(
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> Result<(Certificate, KeyPair), rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut sans: Vec<String> = vec![
            "airgap-server.internal".to_string(),
            "172.16.5.20".to_string(),
            "172.16.237.133".to_string(),
            "127.0.0.1".to_string(),
        ];
        if let Ok(extra) = std::env::var("AIRGAP_SERVER_SANS") {
            for s in extra.split(',') {
                let s = s.trim();
                if !s.is_empty() && !sans.iter().any(|x| x == s) {
                    sans.push(s.to_string());
                }
            }
        }
        let mut params = CertificateParams::new(sans)?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "airgap-server");
        params.distinguished_name = dn;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, issuer, issuer_key)?;
        Ok((cert, key))
    }

    pub fn issue_client(
        &mut self,
        agent_id: &str,
        dir: &Path,
    ) -> Result<(Certificate, KeyPair), Box<dyn std::error::Error + Send + Sync>> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![agent_id.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, agent_id);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(self.next_serial.into());
        let cert = params.signed_by(&key, &self.issuer, &self.ca_key)?;
        self.next_serial += 1;
        crate::fsguard::ensure_dir(dir, crate::fsguard::DIR_MODE)?;
        // The agent private key is served back to the enrolling agent over
        // TLS and persisted server-side; keep it owner-only.
        fs::write(dir.join(format!("{agent_id}.pem")), cert.pem()).ok();
        crate::fsguard::write_secret(
            &dir.join(format!("{agent_id}-key.pem")),
            key.serialize_pem().as_bytes(),
        )?;
        Ok((cert, key))
    }

    pub fn save_serial(&self, dir: &Path) {
        fs::write(dir.join("serial"), self.next_serial.to_string()).ok();
    }

    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    pub fn ca_cert_pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            encode_b64(&self.ca_der)
        )
    }

    /// Builds a rustls ServerConfig that requires clients to present a cert
    /// signed by this CA. Clients without a certificate are tolerated so that
    /// /enroll can be reached; per-route auth is enforced in the API layer.
    /// TLS 1.2 is the minimum version and the cipher list is an explicit
    /// allowlist rather than rustls defaults.
    pub fn tls_server_config(&self) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        use rustls::crypto::ring::cipher_suite::{
            TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        };
        use rustls::version::{TLS12, TLS13};

        let mut roots = RootCertStore::empty();
        roots.add(self.ca_cert_der().clone())?;

        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()?;

        let ring = rustls::crypto::ring::default_provider();
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                TLS13_AES_256_GCM_SHA384,
                TLS13_AES_128_GCM_SHA256,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            ..ring.clone()
        });

        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server_cert_der.clone()],
                self.server_key_der.clone_key(),
            )?;
        Ok(config)
    }
}

fn encode_b64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}
