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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub name: String,
    pub pass_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub token: String,
    pub operator: String,
    pub role: String,
    pub expires: u64,
}

pub struct Auth {
    operators: RwLock<Vec<Operator>>,
    sessions: Mutex<HashMap<String, Session>>,
    path: PathBuf,
}

impl Auth {
    pub async fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("operators.json");
        let ops: Vec<Operator> = std::fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        let auth = Auth {
            operators: RwLock::new(ops),
            sessions: Mutex::new(HashMap::new()),
            path,
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
            auth.save().await;
            tracing::warn!(
                "created default operator 'admin' (set AIRGAP_ADMIN_PASSWORD to change it)"
            );
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
        let token = gen_token();
        let now: u64 = now_ts().parse().unwrap_or(0);
        let s = Session {
            token: token.clone(),
            operator: op.name.clone(),
            role: op.role.clone(),
            expires: now + SESSION_TTL_SECS,
        };
        self.sessions.lock().await.insert(token, s.clone());
        Some(s)
    }

    pub async fn session(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().await;
        let s = sessions.get(token).cloned()?;
        let now: u64 = now_ts().parse().unwrap_or(0);
        if s.expires < now {
            sessions.remove(token);
            return None;
        }
        Some(s)
    }

    pub async fn logout(&self, token: &str) {
        self.sessions.lock().await.remove(token);
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
        let hash = Auth::hash_password(pw).map_err(|e| e.to_string())?;
        let op = Operator {
            name: name.to_string(),
            pass_hash: hash,
            role: role.to_string(),
            created_at: now_ts(),
        };
        self.operators.write().await.push(op);
        self.save().await;
        Ok(())
    }

    pub async fn delete_operator(&self, name: &str) -> bool {
        let mut ops = self.operators.write().await;
        let before = ops.len();
        ops.retain(|o| o.name != name);
        let removed = ops.len() != before;
        drop(ops);
        if removed {
            self.save().await;
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

    async fn save(&self) {
        let ops = self.operators.read().await.clone();
        let data = serde_json::to_vec_pretty(&ops).unwrap_or_default();
        let tmp = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("operators.json.tmp");
        if std::fs::write(&tmp, data).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
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
