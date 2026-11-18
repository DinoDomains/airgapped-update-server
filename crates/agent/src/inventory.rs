#[cfg(not(windows))]
use std::path::Path;
use std::collections::BTreeMap;

use airgap_proto::{DiskStorage, DistroFamily, NetworkInterface, OsInventory, Package};

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
                "Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json",
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
            "Get-HotFix | Select-Object @{n='HotFixID';e={$_.HotFixID}},@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}},@{n='Description';e={$_.Description}} | ConvertTo-Json",
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

fn collect_disks() -> Vec<DiskStorage> {
    let mut disks = Vec::new();
    #[cfg(not(windows))]
    {
        if let Ok(out) = std::process::Command::new("df").args(["-B1", "-P"]).output() {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let fs = parts[0];
                        // Skip virtual/pseudo filesystems
                        if fs.starts_with("dev") || fs == "run" || fs == "none" || fs == "tmpfs" || fs == "efivarfs" {
                            continue;
                        }
                        let total: u64 = parts[1].parse().unwrap_or(0);
                        let used: u64 = parts[2].parse().unwrap_or(0);
                        let avail: u64 = parts[3].parse().unwrap_or(0);
                        let cap_str = parts[4].trim_end_matches('%');
                        let used_percent: f32 = cap_str.parse().unwrap_or(0.0);
                        let mount_point = parts[5].to_string();

                        disks.push(DiskStorage {
                            mount_point,
                            filesystem: fs.to_string(),
                            total_bytes: total,
                            available_bytes: avail,
                            used_bytes: used,
                            used_percent,
                        });
                    }
                }
            }
        }
    }
    disks
}

fn collect_networks() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    #[cfg(not(windows))]
    {
        if let Ok(out) = std::process::Command::new("ip").args(["-j", "addr"]).output() {
            if out.status.success() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                    if let Some(arr) = val.as_array() {
                        for item in arr {
                            let name = item["ifname"].as_str().unwrap_or("").to_string();
                            if name.is_empty() || name == "lo" {
                                continue;
                            }
                            let mac = item["address"].as_str().map(|s| s.to_string());
                            let mut ips = Vec::new();
                            if let Some(addrs) = item["addr_info"].as_array() {
                                for a in addrs {
                                    if let Some(local) = a["local"].as_str() {
                                        ips.push(local.to_string());
                                    }
                                }
                            }
                            interfaces.push(NetworkInterface {
                                name,
                                ip_addresses: ips,
                                mac_address: mac,
                            });
                        }
                        if !interfaces.is_empty() {
                            return interfaces;
                        }
                    }
                }
            }
        }

        // Fallback: parse regular `ip addr`
        if let Ok(out) = std::process::Command::new("ip").arg("addr").output() {
            let mut cur_name = String::new();
            let mut cur_ips = Vec::new();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let line = line.trim();
                if let Some(idx) = line.find(": ") {
                    if !line.starts_with("inet") && line.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                        if !cur_name.is_empty() && cur_name != "lo" {
                            interfaces.push(NetworkInterface {
                                name: cur_name,
                                ip_addresses: cur_ips,
                                mac_address: None,
                            });
                            cur_ips = Vec::new();
                        }
                        let rest = &line[idx + 2..];
                        cur_name = rest.split(':').next().unwrap_or("").trim().to_string();
                    }
                }
                if line.starts_with("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        let ip = parts[1].split('/').next().unwrap_or("");
                        if !ip.is_empty() && ip != "127.0.0.1" {
                            cur_ips.push(ip.to_string());
                        }
                    }
                }
            }
            if !cur_name.is_empty() && cur_name != "lo" {
                interfaces.push(NetworkInterface {
                    name: cur_name,
                    ip_addresses: cur_ips,
                    mac_address: None,
                });
            }
        }
    }
    interfaces
}

fn detect_last_updated() -> Option<String> {
    #[cfg(not(windows))]
    {
        use std::fs;
        use chrono::{DateTime, Utc};

        let paths = [
            "/var/lib/dpkg/status",
            "/var/lib/rpm/rpmdb.sqlite",
            "/var/lib/rpm/Packages",
            "/var/lib/pacman/local",
        ];

        for p in paths {
            if let Ok(meta) = fs::metadata(p) {
                if let Ok(modified) = meta.modified() {
                    let dt: DateTime<Utc> = modified.into();
                    return Some(dt.to_rfc3339());
                }
            }
        }
    }
    None
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
    let disks = collect_disks();
    let networks = collect_networks();
    let last_updated_at = detect_last_updated();

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
        disks,
        networks,
        last_updated_at,
    }
}