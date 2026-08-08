#[cfg(not(windows))]
use std::path::Path;
use std::collections::BTreeMap;

use airgap_proto::{DistroFamily, OsInventory, Package};

fn hostname() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| {
                let out = std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                out.unwrap_or_else(|| "unknown".to_string())
            })
    }
}

fn kernel() -> String {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn arch() -> String {
    #[cfg(windows)]
    {
        std::env::var("PROCESSOR_ARCHITECTURE")
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/sys/kernel/arch")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty() && s != "unknown")
            .unwrap_or_else(|| {
                std::process::Command::new("uname")
                    .arg("-m")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            })
    }
}

fn bootloader() -> String {
    #[cfg(windows)]
    {
        "windows".to_string()
    }
    #[cfg(not(windows))]
    {
        if Path::new("/boot/grub2").exists() || Path::new("/boot/grub").exists() {
            "grub2".to_string()
        } else if Path::new("/boot/efi/EFI/systemd").exists()
            || Path::new("/usr/lib/systemd/boot").exists()
        {
            "systemd-boot".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

fn os_release() -> BTreeMap<String, String> {
    #[cfg(windows)]
    {
        let mut map = BTreeMap::new();
        if let Ok(out) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem) | Select-Object Caption,Version,BuildNumber | ConvertTo-Json",
            ])
            .output()
        {
            if let Ok(json) = String::from_utf8(out.stdout) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                    if let Some(caption) = v.get("Caption").and_then(|x| x.as_str()) {
                        map.insert("NAME".to_string(), caption.to_string());
                    }
                    if let Some(version) = v.get("Version").and_then(|x| x.as_str()) {
                        map.insert("VERSION_ID".to_string(), version.to_string());
                    }
                    if let Some(build) = v.get("BuildNumber").and_then(|x| x.as_str()) {
                        map.insert("BUILD_NUMBER".to_string(), build.to_string());
                    }
                }
            }
        }
        map
    }
    #[cfg(not(windows))]
    {
        let mut map = BTreeMap::new();
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    let v = v.trim().trim_matches('"');
                    map.insert(k.trim().to_string(), v.to_string());
                }
            }
        }
        map
    }
}

fn detect_family(os_name: &str) -> DistroFamily {
    let lower = os_name.to_lowercase();
    if lower.contains("red hat")
        || lower.contains("rocky")
        || lower.contains("alma")
        || lower.contains("fedora")
        || lower.contains("centos")
        || lower.contains("rhel")
    {
        DistroFamily::Rhel
    } else if lower.contains("debian") || lower.contains("ubuntu") {
        DistroFamily::Debian
    } else if lower.contains("windows") || lower.contains("server 20") {
        DistroFamily::Windows
    } else {
        DistroFamily::Other
    }
}

fn collect_packages_windows() -> Vec<Package> {
    let mut packages = Vec::new();
    if let Ok(out) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-HotFix | Select-Object HotFixID,InstalledOn,Description | ConvertTo-Json",
        ])
        .output()
    {
        if let Ok(json) = String::from_utf8(out.stdout) {
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(arr) = arr.as_array() {
                    for item in arr {
                        let hotfix_id = item
                            .get("HotFixID")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let installed_on = item
                            .get("InstalledOn")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = item
                            .get("Description")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !hotfix_id.is_empty() {
                            packages.push(Package {
                                name: hotfix_id,
                                version: installed_on,
                                arch: std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default(),
                                source: description,
                            });
                        }
                    }
                }
            }
        }
    }
    packages
}

fn collect_packages(family: &DistroFamily) -> Vec<Package> {
    #[cfg(windows)]
    {
        if matches!(family, DistroFamily::Windows) {
            return collect_packages_windows();
        }
    }
    let (cmd, args) = match family {
        DistroFamily::Rhel => (
            "rpm",
            vec!["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH} %{VENDOR}\n"],
        ),
        DistroFamily::Debian => ("dpkg-query", vec!["-W", "-f=${Package} ${Version} ${Architecture} ${Maintainer}\n"]),
        _ => return vec![],
    };
    let mut packages = Vec::new();
    if let Ok(out) = std::process::Command::new(cmd).args(&args).output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.split_whitespace();
                let name = parts.next().unwrap_or("").to_string();
                let version = parts.next().unwrap_or("").to_string();
                let pkg_arch = parts.next().unwrap_or("").to_string();
                let source = parts.collect::<Vec<_>>().join(" ");
                if !name.is_empty() {
                    packages.push(Package {
                        name,
                        version,
                        arch: pkg_arch,
                        source,
                    });
                }
            }
        }
    }
    packages
}

fn collect_repos(family: &DistroFamily) -> Vec<String> {
    #[cfg(windows)]
    {
        if matches!(family, DistroFamily::Windows) {
            return vec!["Microsoft Update".to_string(), "Windows Update".to_string()];
        }
    }
    let mut repos = Vec::new();
    match family {
        DistroFamily::Rhel => {
            let out = std::process::Command::new("dnf")
                .args(["repolist"])
                .output()
                .ok();
            if let Some(out) = out {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some(id) = line.split_whitespace().next() {
                        if !id.starts_with("repo")
                            && !id.starts_with("Updating")
                            && !id.starts_with("Available")
                        {
                            repos.push(id.to_string());
                        }
                    }
                }
            }
        }
        DistroFamily::Debian => {
            let out = std::process::Command::new("apt-cache")
                .args(["policy"])
                .output()
                .ok();
            if let Some(out) = out {
                let mut seen = std::collections::HashSet::new();
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some(rest) = line.trim().strip_prefix("Release.") {
                        let val = rest.split_whitespace().collect::<Vec<_>>().join(" ");
                        if seen.insert(val.clone()) {
                            repos.push(val);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    repos
}

pub async fn collect() -> OsInventory {
    let os = os_release();
    let os_name = os.get("NAME").cloned().unwrap_or_else(|| "unknown".to_string());
    let os_version = os.get("VERSION_ID").cloned().unwrap_or_else(|| "0".to_string());
    let os_pretty = os
        .get("PRETTY_NAME")
        .cloned()
        .or_else(|| os.get("VERSION").cloned())
        .unwrap_or_default();
    let family = detect_family(&os_name);
    let packages = collect_packages(&family);
    let repos = collect_repos(&family);

    OsInventory {
        hostname: hostname(),
        os_name,
        os_version,
        os_pretty,
        family,
        arch: arch(),
        kernel: kernel(),
        bootloader: bootloader(),
        packages,
        repos,
    }
}