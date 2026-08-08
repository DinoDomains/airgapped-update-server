use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("bubblewrap not found: install bubblewrap package")]
    BwrapNotFound,
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwrapConfig {
    pub ro_binds: Vec<(PathBuf, PathBuf)>,
    pub rw_binds: Vec<(PathBuf, PathBuf)>,
    pub tmpfs_dirs: Vec<PathBuf>,
    pub env_vars: Vec<(String, String)>,
    pub unshare_all: bool,
    pub die_with_parent: bool,
    pub no_new_privs: bool,
    pub cap_drop: Vec<String>,
    pub seccomp_filter: Option<PathBuf>,
}

impl Default for BwrapConfig {
    fn default() -> Self {
        Self {
            ro_binds: vec![],
            rw_binds: vec![],
            tmpfs_dirs: vec![],
            env_vars: vec![],
            unshare_all: true,
            die_with_parent: true,
            no_new_privs: true,
            cap_drop: vec!["all".to_string()],
            seccomp_filter: None,
        }
    }
}

#[derive(Clone)]
pub struct BwrapSandbox {
    config: BwrapConfig,
}

impl BwrapSandbox {
    pub fn new(config: BwrapConfig) -> Self {
        Self { config }
    }

    pub fn minimal() -> Self {
        let mut config = BwrapConfig::default();
        config.ro_binds = vec![
            ("/usr".into(), "/usr".into()),
            ("/lib".into(), "/lib".into()),
            ("/lib64".into(), "/lib64".into()),
            ("/etc".into(), "/etc".into()),
        ];
        config.tmpfs_dirs = vec!["/tmp".into(), "/run".into(), "/var/tmp".into()];
        config.env_vars = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/tmp".into()),
        ];
        Self { config }
    }

    pub fn with_ro_bind(mut self, src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Self {
        self.config.ro_binds.push((src.as_ref().to_path_buf(), dst.as_ref().to_path_buf()));
        self
    }

    pub fn with_rw_bind(mut self, src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Self {
        self.config.rw_binds.push((src.as_ref().to_path_buf(), dst.as_ref().to_path_buf()));
        self
    }

    pub fn with_tmpfs(mut self, path: impl AsRef<Path>) -> Self {
        self.config.tmpfs_dirs.push(path.as_ref().to_path_buf());
        self
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env_vars.push((key.into(), value.into()));
        self
    }

    pub fn run(&self, cmd: &[&str]) -> Result<std::process::Output, SandboxError> {
        if !self.bwrap_available() {
            return Err(SandboxError::BwrapNotFound);
        }

        let mut args = vec!["bwrap".to_string()];

        for (src, dst) in &self.config.ro_binds {
            args.push("--ro-bind".into());
            args.push(src.to_string_lossy().into_owned());
            args.push(dst.to_string_lossy().into_owned());
        }
        for (src, dst) in &self.config.rw_binds {
            args.push("--bind".into());
            args.push(src.to_string_lossy().into_owned());
            args.push(dst.to_string_lossy().into_owned());
        }
        for dir in &self.config.tmpfs_dirs {
            args.push("--tmpfs".into());
            args.push(dir.to_string_lossy().into_owned());
        }
        for (k, v) in &self.config.env_vars {
            args.push("--setenv".into());
            args.push(k.clone());
            args.push(v.clone());
        }
        if self.config.unshare_all {
            args.push("--unshare-all".into());
        }
        if self.config.die_with_parent {
            args.push("--die-with-parent".into());
        }
        if self.config.no_new_privs {
            args.push("--no-new-privs".into());
        }
        for cap in &self.config.cap_drop {
            args.push("--cap-drop".into());
            args.push(cap.clone());
        }
        if let Some(filter) = &self.config.seccomp_filter {
            args.push("--seccomp".into());
            args.push(filter.to_string_lossy().into_owned());
        }

        args.push("--".into());
        args.extend(cmd.iter().map(|s| s.to_string()));

        let output = Command::new("bwrap")
            .args(&args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::CommandFailed(stderr.to_string()));
        }
        Ok(output)
    }

    fn bwrap_available(&self) -> bool {
        Command::new("bwrap").arg("--version").output().is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedPackage {
    pub files: Vec<ExtractedFile>,
    pub total_size: u64,
    pub package_type: PackageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub path: String,
    pub size: u64,
    pub is_executable: bool,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PackageType {
    Msu,
    Cab,
    Rpm,
    Deb,
    Unknown,
}

pub fn detect_package_type(path: &Path) -> PackageType {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    match ext.as_str() {
        "msu" => PackageType::Msu,
        "cab" => PackageType::Cab,
        "rpm" => PackageType::Rpm,
        "deb" => PackageType::Deb,
        _ => PackageType::Unknown,
    }
}

pub fn verify_hash(path: &Path, expected_sha256: &str) -> Result<(), SandboxError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    let hash = hex::encode(hasher.finalize());
    if !hash.eq_ignore_ascii_case(expected_sha256) {
        return Err(SandboxError::VerificationFailed(format!(
            "hash mismatch: got {}, expected {}",
            hash, expected_sha256
        )));
    }
    Ok(())
}

pub fn extract_and_analyze(
    sandbox: &BwrapSandbox,
    package_path: &Path,
    expected_hash: Option<&str>,
) -> Result<ExtractedPackage, SandboxError> {
    if let Some(hash) = expected_hash {
        verify_hash(package_path, hash)?;
    }

    let pkg_type = detect_package_type(package_path);
    let extract_dir = PathBuf::from("/tmp/extract");
    let mut local_sandbox = sandbox.clone();
    local_sandbox.config.rw_binds.push(("/tmp".into(), "/tmp".into()));
    local_sandbox.config.tmpfs_dirs.push("/extract".into());

    let pkg_str = package_path.to_string_lossy().to_string();
    let (cmd, args): (&str, Vec<String>) = match pkg_type {
        PackageType::Msu => ("expand", vec!["-F:*".to_string(), "-d".to_string(), "/extract".to_string(), pkg_str.clone()]),
        PackageType::Cab => ("cabextract", vec!["-d".to_string(), "/extract".to_string(), pkg_str.clone()]),
        PackageType::Rpm => ("rpm2cpio", vec![pkg_str.clone()]),
        PackageType::Deb => ("dpkg-deb", vec!["-x".to_string(), pkg_str.clone(), "/extract".to_string()]),
        _ => return Err(SandboxError::VerificationFailed("unknown package type".into())),
    };

    let output = local_sandbox.run(&[cmd, &args.join(" ")])?;
    if !output.status.success() {
        return Err(SandboxError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    analyze_extracted(&extract_dir, pkg_type)
}

fn analyze_extracted(extract_dir: &Path, pkg_type: PackageType) -> Result<ExtractedPackage, SandboxError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    let mut files = Vec::new();
    let mut total_size = 0u64;

    for entry in walkdir::WalkDir::new(extract_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let rel_path = path.strip_prefix(extract_dir).unwrap_or(path).to_string_lossy().to_string();
            let metadata = entry.metadata().map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
            let size = metadata.len();
            total_size += size;
            let is_executable = metadata.permissions().mode() & 0o111 != 0;

            let mut hasher = Sha256::new();
            std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
            let sha256 = hex::encode(hasher.finalize());

            files.push(ExtractedFile {
                path: rel_path,
                size,
                is_executable,
                sha256,
            });
        }
    }

    // Static analysis checks
    let suspicious = check_suspicious_patterns(&files, pkg_type);
    if !suspicious.is_empty() {
        return Err(SandboxError::VerificationFailed(format!(
            "suspicious patterns found: {}",
            suspicious.join(", ")
        )));
    }

    Ok(ExtractedPackage {
        files,
        total_size,
        package_type: pkg_type,
    })
}

pub fn check_suspicious_patterns(files: &[ExtractedFile], pkg_type: PackageType) -> Vec<String> {
    let mut issues = Vec::new();

    for f in files {
        let path = f.path.to_lowercase();
        
        // Check for unexpected executable scripts in non-script locations
        if f.is_executable && !path.ends_with(".exe") && !path.ends_with(".dll") && !path.ends_with(".so") {
            if pkg_type != PackageType::Rpm && pkg_type != PackageType::Deb {
                issues.push(format!("unexpected executable: {}", f.path));
            }
        }

        // Windows-specific suspicious paths
        if pkg_type == PackageType::Msu || pkg_type == PackageType::Cab {
            if path.contains("..") || path.starts_with("/") {
                issues.push(format!("path traversal attempt: {}", f.path));
            }
            if path.contains("system32") && (path.ends_with(".ps1") || path.ends_with(".bat") || path.ends_with(".cmd")) {
                issues.push(format!("script in system32: {}", f.path));
            }
        }

        // Linux-specific
        if pkg_type == PackageType::Deb || pkg_type == PackageType::Rpm {
            if path.starts_with("/etc/cron") || path.starts_with("/etc/systemd") || path.starts_with("/etc/init") {
                issues.push(format!("system config modification: {}", f.path));
            }
        }
    }

    issues
}