use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::store::Source;
use airgap_proto::DistroFamily;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestPackage {
    pub name: String,
    pub version: String,
    pub family: String,
    pub repo: String,
    pub arch: String,
    /// Relative artifact path within the source (apt `Filename:` or dnf
    /// `location href`). Absent in catalogs synced by older builds.
    #[serde(default)]
    pub location: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatalogData {
    pub packages: HashMap<String, LatestPackage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub phase: String,
    pub started: Option<u64>,
    pub elapsed: u64,
    pub last: Option<SyncReport>,
    pub last_sync: Option<String>,
}

impl Default for SyncStatus {
    fn default() -> Self {
        SyncStatus {
            syncing: false,
            phase: "idle".to_string(),
            started: None,
            elapsed: 0,
            last: None,
            last_sync: None,
        }
    }
}

pub struct Catalog {
    dir: PathBuf,
    data: RwLock<CatalogData>,
    status: RwLock<SyncStatus>,
    syncing: Mutex<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub packages: usize,
    pub apt: usize,
    pub dnf: usize,
}

const APT_COMPONENTS: &[&str] = &["main", "universe"];
const APT_ARCH: &str = "amd64";

/// Builds a client that resolves every whitelisted upstream host to IPv4
/// only. Some mirrors (dl.rockylinux.org) advertise AAAA records but the
/// air-gapped server has no IPv6 route; without pinning, reqwest can stall
/// on IPv6.
pub fn build_client(sources: &[Source]) -> reqwest::Client {
    use std::net::ToSocketAddrs;
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90));
    for host in upstream_hosts(sources) {
        if let Ok(addr) = format!("{host}:80").to_socket_addrs() {
            if let Some(a) = addr.filter(|a| a.is_ipv4()).next() {
                builder = builder.resolve(&host, a);
            }
        }
    }
    builder.build().expect("failed to build http client")
}

fn upstream_hosts(sources: &[Source]) -> Vec<String> {
    let mut hosts = Vec::new();
    for s in sources {
        let base = s.base_url.trim_end_matches('/');
        let rest = base.strip_prefix("http://").or_else(|| base.strip_prefix("https://"));
        if let Some(h) = rest {
            if let Some(host) = h.split('/').next() {
                if !hosts.iter().any(|x| x == host) {
                    hosts.push(host.to_string());
                }
            }
        }
    }
    hosts
}

impl Catalog {
    pub async fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(dir)?;
        let data = tokio::fs::read(dir.join("catalog.json"))
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<CatalogData>(&b).ok())
            .unwrap_or_default();
        Ok(Catalog {
            dir: dir.to_path_buf(),
            data: RwLock::new(data),
            status: RwLock::new(SyncStatus::default()),
            syncing: Mutex::new(false),
        })
    }

    pub async fn snapshot(&self) -> HashMap<String, LatestPackage> {
        self.data.read().await.packages.clone()
    }

    pub async fn status(&self) -> SyncStatus {
        let mut st = self.status.read().await.clone();
        if let Some(started) = st.started {
            st.elapsed = now_secs().saturating_sub(started);
        }
        st
    }

    pub async fn latest(&self, name: &str, family: &str) -> Option<LatestPackage> {
        self.data
            .read()
            .await
            .packages
            .get(&key_of(family, name))
            .cloned()
    }

    /// Resolves the full upstream URL of the artifact (rpm/deb) for the
    /// newest known version of `name` in `family`, by joining the catalog's
    /// stored relative `location` with the matching whitelisted source's
    /// base URL. Returns None when the package is unknown or the catalog was
    /// synced before artifact locations were captured.
    pub async fn artifact_url(
        &self,
        family: &str,
        name: &str,
        sources: &[Source],
    ) -> Option<String> {
        let pkg = self.latest(name, family).await?;
        if pkg.location.is_empty() {
            return None;
        }
        let src = if family.eq_ignore_ascii_case("debian") {
            let suite = pkg.repo.split('/').next().unwrap_or("");
            sources
                .iter()
                .find(|s| s.kind == "apt" && s.suite == suite)
        } else {
            sources.iter().find(|s| s.kind == "dnf" && s.name == pkg.repo)
        }?;
        let base = src.base_url.trim_end_matches('/');
        Some(format!("{base}/{}", pkg.location.trim_start_matches('/')))
    }

    pub async fn sync(
        &self,
        client: &reqwest::Client,
        sources: &[Source],
    ) -> Result<SyncReport, String> {
        let mut guard = self.syncing.lock().await;
        if *guard {
            return Err("sync already in progress".to_string());
        }
        *guard = true;
        {
            let mut st = self.status.write().await;
            st.syncing = true;
            st.started = Some(now_secs());
            st.phase = "starting".to_string();
        }
        let result = self.do_sync(client, sources).await;
        {
            let mut st = self.status.write().await;
            st.syncing = false;
            match &result {
                Ok(r) => {
                    st.phase = "complete".to_string();
                    st.last = Some(r.clone());
                    st.last_sync = Some(now_secs().to_string());
                }
                Err(_) => st.phase = "failed".to_string(),
            }
        }
        *guard = false;
        result
    }

    async fn set_phase(&self, phase: &str) {
        self.status.write().await.phase = phase.to_string();
    }

    async fn do_sync(
        &self,
        client: &reqwest::Client,
        sources: &[Source],
    ) -> Result<SyncReport, String> {
        let mut merged: HashMap<String, LatestPackage> = HashMap::new();
        let mut apt_count = 0usize;
        let mut dnf_count = 0usize;

        let apt_sources: Vec<&Source> = sources.iter().filter(|s| s.kind == "apt").collect();
        let dnf_sources: Vec<&Source> = sources.iter().filter(|s| s.kind == "dnf").collect();
        if apt_sources.is_empty() && dnf_sources.is_empty() {
            return Err("no enabled upstream sources; whitelist at least one in the Sources view".to_string());
        }

        self.set_phase("fetching apt metadata").await;
        for src in &apt_sources {
            if src.suite.is_empty() {
                continue;
            }
            for comp in APT_COMPONENTS {
                let url = format!(
                    "{}/dists/{}/{}/binary-{}/Packages.gz",
                    src.base_url.trim_end_matches('/'),
                    src.suite,
                    comp,
                    APT_ARCH
                );
                tracing::info!("syncing apt: {url}");
                let bytes = fetch(client, &url).await?;
                let parsed = parse_packages_gz(&bytes).map_err(|e| e.to_string())?;
                for para in parsed {
                    let name = para.get("Package").cloned().unwrap_or_default();
                    let version = para.get("Version").cloned().unwrap_or_default();
                    let arch = para.get("Architecture").cloned().unwrap_or_default();
                    let location = para.get("Filename").cloned().unwrap_or_default();
                    if name.is_empty() || version.is_empty() {
                        continue;
                    }
                    insert_latest(
                        &mut merged,
                        name,
                        version,
                        DistroFamily::Debian,
                        format!("{}/{}", src.suite, comp),
                        arch,
                        location,
                    );
                    apt_count += 1;
                }
            }
        }

        self.set_phase("fetching dnf metadata").await;
        for src in &dnf_sources {
            let base = src.base_url.trim_end_matches('/').to_string();
            tracing::info!("syncing dnf: {base}");
            let repomd = fetch(client, &format!("{base}/repodata/repomd.xml")).await?;
            let primary_rel = primary_location(&repomd).ok_or_else(|| {
                format!("no primary metadata found in repomd.xml for {}", src.name)
            })?;
            let primary = fetch(client, &format!("{base}/{primary_rel}")).await?;
            let pkgs = parse_primary_gz(&primary).map_err(|e| e.to_string())?;
            for p in pkgs {
                insert_latest(
                    &mut merged,
                    p.0,
                    p.1,
                    DistroFamily::Rhel,
                    src.name.clone(),
                    p.2,
                    p.3,
                );
                dnf_count += 1;
            }
        }

        self.set_phase("merging").await;
        let data = CatalogData {
            packages: merged,
        };
        let bytes = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;
        let path = self.dir.join("catalog.json");
        let tmp = self.dir.join("catalog.json.tmp");
        tokio::fs::write(&tmp, bytes)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| e.to_string())?;
        *self.data.write().await = data;

        let report = SyncReport {
            packages: self.data.read().await.packages.len(),
            apt: apt_count,
            dnf: dnf_count,
        };
        tracing::info!("catalog sync complete: {report:?}");
        Ok(report)
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("read {url}: {e}"))
}

fn parse_packages_gz(data: &[u8]) -> Result<Vec<HashMap<String, String>>, std::io::Error> {
    let mut text = String::new();
    GzDecoder::new(data).read_to_string(&mut text)?;
    let mut out = Vec::new();
    let mut cur = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            cur.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn primary_location(repomd: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(repomd);
    let mut in_primary = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("<data") && t.contains("type=\"primary\"") {
            in_primary = true;
            continue;
        }
        if in_primary && t.starts_with("<location") {
            let href = t.split("href=\"").nth(1)?;
            let href = href.split('"').next()?.to_string();
            return Some(href);
        }
        if t.starts_with("</data>") {
            in_primary = false;
        }
    }
    None
}

fn parse_primary_gz(data: &[u8]) -> Result<Vec<(String, String, String, String)>, Box<dyn std::error::Error>> {
    let mut gz = GzDecoder::new(data);
    let mut xml = Vec::new();
    gz.read_to_end(&mut xml)?;

    let mut reader = quick_xml::Reader::from_reader(&xml[..]);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut name = String::new();
    let mut ver = String::new();
    let mut rel = String::new();
    let mut arch = String::new();
    let mut location = String::new();
    let mut in_pkg = false;
    let mut cur = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag.as_str() {
                    "package" => {
                        in_pkg = true;
                        name.clear();
                        ver.clear();
                        rel.clear();
                        arch.clear();
                        location.clear();
                    }
                    "version" => {
                        for a in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(a.key.as_ref()).to_string();
                            let v = String::from_utf8_lossy(&a.value).to_string();
                            if k == "ver" {
                                ver = v;
                            } else if k == "rel" {
                                rel = v;
                            }
                        }
                    }
                    _ => {}
                }
                cur = tag;
            }
            Ok(quick_xml::events::Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "version" {
                    for a in e.attributes().flatten() {
                        let k = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let v = String::from_utf8_lossy(&a.value).to_string();
                        if k == "ver" {
                            ver = v;
                        } else if k == "rel" {
                            rel = v;
                        }
                    }
                } else if tag == "location" {
                    for a in e.attributes().flatten() {
                        let k = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let v = String::from_utf8_lossy(&a.value).to_string();
                        if k == "href" {
                            location = v;
                        }
                    }
                }
                cur.clear();
            }
            Ok(quick_xml::events::Event::Text(t)) => {
                if in_pkg && cur == "name" {
                    name = t.unescape().unwrap_or_default().into_owned();
                } else if in_pkg && cur == "arch" {
                    arch = t.unescape().unwrap_or_default().into_owned();
                }
            }
            Ok(quick_xml::events::Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "package" {
                    in_pkg = false;
                    if !name.is_empty() && !ver.is_empty() {
                        let version = if rel.is_empty() {
                            ver.clone()
                        } else {
                            format!("{ver}-{rel}")
                        };
                        out.push((name.clone(), version, arch.clone(), location.clone()));
                    }
                }
                cur.clear();
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

pub fn key_of(family: &str, name: &str) -> String {
    format!("{}/{}", family.to_lowercase(), name.to_lowercase())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn insert_latest(
    map: &mut HashMap<String, LatestPackage>,
    name: String,
    version: String,
    family: DistroFamily,
    repo: String,
    arch: String,
    location: String,
) {
    let family = format!("{family:?}").to_lowercase();
    let key = key_of(&family, &name);
    let entry = LatestPackage {
        name: name.clone(),
        version,
        family: family.clone(),
        repo,
        arch,
        location,
    };
    match map.get(&key) {
        Some(existing) if !version_gt(&entry.version, &existing.version) => {}
        _ => {
            map.insert(key, entry);
        }
    }
}

fn split_epoch(v: &str) -> (i64, &str) {
    if let Some(pos) = v.find(':') {
        if pos > 0 && v[..pos].chars().all(|c| c.is_ascii_digit()) {
            return (v[..pos].parse().unwrap_or(0), &v[pos + 1..]);
        }
    }
    (0, v)
}

pub fn version_gt(a: &str, b: &str) -> bool {
    let (ea, av) = split_epoch(a);
    let (eb, bv) = split_epoch(b);
    if ea != eb {
        return ea > eb;
    }
    let at: Vec<&str> = av.split(['.', '-', '~']).collect();
    let bt: Vec<&str> = bv.split(['.', '-', '~']).collect();
    let n = at.len().max(bt.len());
    for i in 0..n {
        let x = at.get(i).copied().unwrap_or("0");
        let y = bt.get(i).copied().unwrap_or("0");
        let xi: i64 = x
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        let yi: i64 = y
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        if xi != yi {
            return xi > yi;
        }
        let xr = x.trim_start_matches(|c: char| c.is_ascii_digit());
        let yr = y.trim_start_matches(|c: char| c.is_ascii_digit());
        match xr.cmp(yr) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            _ => {}
        }
    }
    false
}
