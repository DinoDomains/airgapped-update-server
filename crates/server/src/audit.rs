use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(dir: &Path) -> Self {
        AuditLog {
            path: dir.join("audit.log"),
        }
    }

    pub fn log(&self, actor: &str, action: &str, target: &str, result: &str) {
        let entry = AuditEntry {
            ts: now_ts(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            result: result.to_string(),
        };
        if let Ok(line) = serde_json::to_string(&entry) {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        if let Ok(data) = std::fs::read_to_string(&self.path) {
            for line in data.lines().rev().take(limit) {
                if let Ok(e) = serde_json::from_str::<AuditEntry>(line) {
                    out.push(e);
                }
            }
        }
        out
    }
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
