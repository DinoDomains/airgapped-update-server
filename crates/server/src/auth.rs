use std::collections::HashMap;
use std::path::{Path, PathBuf};

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

pub const ROLE_VIEWER: &str = "viewer";
pub const ROLE_APPROVER: &str = "approver";
pub const ROLE_ADMIN: &str = "admin";

const SESSION_TTL_SECS: u64 = 24 * 3600;

/// On-disk representation of a session. The raw token is never written;
/// `token_hash` is the SHA-256 digest used for lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    token_hash: String,
    operator: String,
    role: String,
    expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub name: String,
    pub pass_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Session {
    /// The raw bearer token, returned to the client exactly once at login.
    pub token: String,
    pub operator: String,
    pub role: String,
    pub expires: u64,
}

pub struct Auth {
    operators: RwLock<Vec<Operator>>,
    sessions: Mutex<HashMap<String, SessionRecord>>,
    operators_path: PathBuf,
    sessions_path: PathBuf,
}

impl Auth {
    pub async fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        crate::fsguard::ensure_dir(dir, crate::fsguard::DIR_MODE)?;
        let operators_path = dir.join("operators.json");
        let sessions_path = dir.join("sessions.json");
        let ops: Vec<Operator> = std::fs::read(&operators_path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        // Load persisted sessions, dropping any that already expired.
        let now: u64 = now_ts().parse().unwrap_or(0);
        let stored: Vec<SessionRecord> = std::fs::read(&sessions_path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        let sessions: HashMap<String, SessionRecord> = stored
            .into_iter()
            .filter(|s| s.expires >= now)
            .map(|s| (s.token_hash.clone(), s))
            .collect();
        let auth = Auth {
            operators: RwLock::new(ops),
            sessions: Mutex::new(sessions),
            operators_path,
            sessions_path,
        };
        if auth.operators.read().await.is_empty() {
            let pw = std::env::var("AIRGAP_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string());
            let hash = Auth::hash_password(&pw).map_err(|e| e.to_string())?;
            let admin = Operator {
                name: "admin".to_string(),
                pass_hash: hash,
                role: ROLE_ADMIN.to_string(),
                created_at: now_ts(),
            };
            auth.operators.write().await.push(admin);
            auth.save_operators().await;
            if pw == "admin" {
                tracing::warn!(
                    "created default operator 'admin' with the default password; \
                     set AIRGAP_ADMIN_PASSWORD before exposing this server"
                );
            } else {
                tracing::warn!("created default operator 'admin' from AIRGAP_ADMIN_PASSWORD");
            }
        }
        Ok(auth)
    }

    fn hash_password(pw: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .map(|h| h.to_string())
    }

    fn verify_password(pw: &str, hash: &str) -> bool {
        match PasswordHash::new(hash) {
            Ok(parsed) => Argon2::default()
                .verify_password(pw.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    }

    pub async fn login(&self, name: &str, pw: &str) -> Option<Session> {
        let ops = self.operators.read().await;
        let op = ops.iter().find(|o| o.name == name)?;
        if !Auth::verify_password(pw, &op.pass_hash) {
            return None;
        }
        let token = crate::secrets::random_token();
        let now: u64 = now_ts().parse().unwrap_or(0);
        let record = SessionRecord {
            token_hash: crate::secrets::digest(&token),
            operator: op.name.clone(),
            role: op.role.clone(),
            expires: now + SESSION_TTL_SECS,
        };
        let session = Session {
            token: token.clone(),
            operator: record.operator.clone(),
            role: record.role.clone(),
            expires: record.expires,
        };
        drop(ops);
        self.sessions
            .lock()
            .await
            .insert(crate::secrets::digest(&token), record);
        self.save_sessions().await;
        Some(session)
    }

    /// Resolves a presented bearer token to a live session.
    pub async fn session(&self, token: &str) -> Option<Session> {
        let hash = crate::secrets::digest(token);
        let mut sessions = self.sessions.lock().await;
        let now: u64 = now_ts().parse().unwrap_or(0);
        let expired = match sessions.get(&hash) {
            Some(s) => s.expires < now,
            None => return None,
        };
        if expired {
            sessions.remove(&hash);
            drop(sessions);
            self.save_sessions().await;
            return None;
        }
        let s = sessions.get(&hash)?;
        Some(Session {
            token: token.to_string(),
            operator: s.operator.clone(),
            role: s.role.clone(),
            expires: s.expires,
        })
    }

    pub async fn logout(&self, token: &str) {
        let removed = self
            .sessions
            .lock()
            .await
            .remove(&crate::secrets::digest(token))
            .is_some();
        if removed {
            self.save_sessions().await;
        }
    }

    /// Drops all sessions for an operator, e.g. after a password change.
    pub async fn revoke_operator_sessions(&self, name: &str) {
        {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|_, s| s.operator != name);
        }
        self.save_sessions().await;
    }

    pub async fn list_operators(&self) -> Vec<Operator> {
        self.operators.read().await.clone()
    }

    pub async fn get_operator(&self, name: &str) -> Option<Operator> {
        self.operators
            .read()
            .await
            .iter()
            .find(|o| o.name == name)
            .cloned()
    }

    pub async fn create_operator(&self, name: &str, pw: &str, role: &str) -> Result<(), String> {
        {
            let ops = self.operators.read().await;
            if ops.iter().any(|o| o.name == name) {
                return Err("operator already exists".to_string());
            }
        }
        if !matches!(role, "viewer" | "approver" | "admin") {
            return Err("invalid role".to_string());
        }
        if pw.len() < 12 {
            return Err("password must be at least 12 characters".to_string());
        }
        let hash = Auth::hash_password(pw).map_err(|e| e.to_string())?;
        let op = Operator {
            name: name.to_string(),
            pass_hash: hash,
            role: role.to_string(),
            created_at: now_ts(),
        };
        self.operators.write().await.push(op);
        self.save_operators().await;
        Ok(())
    }

    pub async fn delete_operator(&self, name: &str) -> bool {
        let mut ops = self.operators.write().await;
        let before = ops.len();
        ops.retain(|o| o.name != name);
        let removed = ops.len() != before;
        drop(ops);
        if removed {
            self.save_operators().await;
            self.revoke_operator_sessions(name).await;
        }
        removed
    }

    pub fn role_allows(session: &Session, min_role: &str) -> bool {
        let rank = |r: &str| match r {
            ROLE_ADMIN => 3,
            ROLE_APPROVER => 2,
            _ => 1,
        };
        rank(&session.role) >= rank(min_role)
    }

    async fn save_operators(&self) {
        let ops = self.operators.read().await.clone();
        write_atomic_private(&self.operators_path, &ops);
    }

    async fn save_sessions(&self) {
        let sessions: Vec<SessionRecord> = self
            .sessions
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        write_atomic_private(&self.sessions_path, &sessions);
    }
}

/// Writes JSON to `path` with `0600` via a temp file + rename, so a crash
/// mid-write cannot leave a truncated or world-readable file behind.
fn write_atomic_private<T: Serialize>(path: &Path, value: &T) {
    let data = match serde_json::to_vec_pretty(value) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "failed to serialize state");
            return;
        }
    };
    if let Err(e) = crate::fsguard::write_secret(path, &data) {
        tracing::error!(error = %e, path = %path.display(), "failed to persist state");
    }
}

fn gen_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
