use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::store::Source;
use airgap_proto::DistroFamily;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// Persisted map of host -> known-good IPv4 edge addresses. Microsoft's CDN
/// round-robins its DNS answer across edges and will happily hand out edges
/// that accept TCP+TLS but never answer HTTP; once an edge delivers bytes we
/// remember it so later fetches try it first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EdgeCache {
    /// host -> Vec<ip> (most recently proven first)
    hosts: HashMap<String, Vec<String>>,
}

fn load_edge_cache(path: &Path) -> EdgeCache {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_edge_cache(path: &Path, cache: &EdgeCache) {
    if let Ok(s) = serde_json::to_string_pretty(cache) {
        let _ = std::fs::write(path, s);
    }
}

fn remember_edge(cache_path: Option<&Path>, host: &str, ip: std::net::IpAddr) {
    let Some(path) = cache_path else { return };
    let mut cache = load_edge_cache(path);
    let list = cache.hosts.entry(host.to_string()).or_default();
    let ip = ip.to_string();
    list.retain(|e| e != &ip);
    list.insert(0, ip);
    save_edge_cache(path, &cache);
}

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
    pub windows: usize,
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
        .timeout(std::time::Duration::from_secs(120))
        // The Microsoft Update Catalog serves a JS-blocked page to clients
        // without a browser User-Agent.
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36");
    for (host, port) in upstream_hosts(sources).into_iter().chain(
        // Windows artifact hosts are not listed in the source config (the
        // catalog source's base_url is the search site) but are used when
        // proxying .msu files - pin them too so they never stall on IPv6.
        EXTRA_PINNED_HOSTS.iter().map(|h| (h.to_string(), 443u16)),
    ) {
        if let Ok(addr) = format!("{host}:{port}").to_socket_addrs() {
            let addrs: Vec<_> = addr.filter(|a| a.is_ipv4()).collect();
            if !addrs.is_empty() {
                builder = builder.resolve_to_addrs(&host, &addrs);
            }
        }
    }
    builder.build().expect("failed to build http client")
}

/// Hosts used to fetch Windows .msu artifacts, pinned to IPv4 alongside the
/// configured sources (they are not themselves configured sources).
const EXTRA_PINNED_HOSTS: &[&str] = &[
    "download.windowsupdate.com",
    "catalog.s.download.windowsupdate.com",
    "download.microsoft.com",
];

/// Hosts from the configured sources, resolved on the scheme-appropriate
/// port (plain http mirrors are contacted on 80, everything else on 443).
fn upstream_hosts(sources: &[Source]) -> Vec<(String, u16)> {
    let mut hosts: Vec<(String, u16)> = Vec::new();
    for s in sources {
        let base = s.base_url.trim_end_matches('/');
        let (scheme, rest) = if let Some(r) = base.strip_prefix("http://") {
            ("http", r)
        } else if let Some(r) = base.strip_prefix("https://") {
            ("https", r)
        } else {
            continue;
        };
        if let Some(host) = rest.split('/').next() {
            if !hosts.iter().any(|(h, _)| h == host) {
                hosts.push((host.to_string(), if scheme == "http" { 80 } else { 443 }));
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
        // Windows (wucatalog) entries store an absolute MSU URL; apt/dnf
        // entries store a relative path joined onto the source base URL.
        if family.eq_ignore_ascii_case("windows") || pkg.location.starts_with("http://")
            || pkg.location.starts_with("https://")
        {
            return Some(pkg.location.clone());
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
        let mut windows_count = 0usize;

        let apt_sources: Vec<&Source> = sources.iter().filter(|s| s.kind == "apt").collect();
        let dnf_sources: Vec<&Source> = sources.iter().filter(|s| s.kind == "dnf").collect();
        let wu_sources: Vec<&Source> = sources.iter().filter(|s| s.kind == "wucatalog").collect();
        if apt_sources.is_empty() && dnf_sources.is_empty() && wu_sources.is_empty() {
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

        self.set_phase("fetching windows update catalog").await;
        for src in &wu_sources {
            let base = src.base_url.trim_end_matches('/').to_string();
            for kb in &src.kbs {
                let kb = kb.trim().to_uppercase();
                if kb.is_empty() || !kb.starts_with("KB") {
                    continue;
                }
                match wu_sync_kb(client, &base, &kb).await {
                    Ok(Some((version, arch, location))) => {
                        insert_latest(
                            &mut merged,
                            kb.clone(),
                            version,
                            DistroFamily::Windows,
                            src.name.clone(),
                            arch,
                            location,
                        );
                        windows_count += 1;
                    }
                    Ok(None) => tracing::warn!("no downloadable artifact found for {kb}"),
                    Err(e) => tracing::warn!("windows catalog sync {kb}: {e}"),
                }
            }
            // Local MSU dropbox: any <store>/windows/*.msu is indexed too.
            // Operators can stage genuine packages here (downloaded from the
            // catalog on an unrestricted machine) - the platform still does
            // the approving, proxying and installing, with no separate WSUS.
            let dropbox = self.dir.join("windows");
            if let Ok(rd) = std::fs::read_dir(&dropbox) {
                let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
                files.sort();
                for path in files {
                    if path.extension().map(|x| x == "msu").unwrap_or(false) {
                        if let Some((kb, version, arch)) = msu_metadata(&path) {
                            insert_latest(
                                &mut merged,
                                kb,
                                version,
                                DistroFamily::Windows,
                                src.name.clone(),
                                arch,
                                format!("file://{}", path.display()),
                            );
                            windows_count += 1;
                        }
                    }
                }
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
            windows: windows_count,
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

/// Resolve every unique IPv4 for an upstream host. The catalog hostname
/// round-robins across CDN edges, some of which accept TCP+TLS but stall on
/// the HTTP request, so we gather the whole address set to try each edge
/// with its own pinned client. Known-good edges from previous fetches are
/// tried first (fresh DNS first, then remembered ones).
fn resolve_ipv4_candidates(host: &str, edge_cache: Option<&Path>) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let mut ips: Vec<std::net::IpAddr> = Vec::new();
    for _ in 0..8 {
        if let Ok(addr) = format!("{host}:443").to_socket_addrs() {
            for a in addr.filter(|a| a.is_ipv4()) {
                if !ips.contains(&a.ip()) {
                    ips.push(a.ip());
                }
            }
        }
        if ips.len() >= 12 {
            break;
        }
    }
    if let Some(path) = edge_cache {
        let cache = load_edge_cache(path);
        if let Some(remembered) = cache.hosts.get(host) {
            for ip in remembered {
                if let Ok(ip) = ip.parse::<std::net::IpAddr>() {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    ips
}

/// Builds a client pinned to one specific upstream edge IP.
pub fn client_for_edge(host: &str, ip: std::net::IpAddr, body_timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(body_timeout)
        .connect_timeout(std::time::Duration::from_secs(5))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        .resolve(host, std::net::SocketAddr::new(ip, 443))
        .build()
        .expect("failed to build http client")
}

/// Fetch `url` resiliently: the catalog hostname round-robins across CDN
/// edges, some of which accept TCP+TLS but stall on the HTTP request (the
/// pinned client would wait out its 120s timeout on a dead edge). Resolve
/// every unique IPv4, then try each with its own client and a short
/// per-attempt timeout so a working edge is reached quickly.
pub async fn fetch_resilient(
    sources: &[Source],
    url: &str,
    per_attempt: std::time::Duration,
    edge_cache_path: Option<&Path>,
) -> Result<Vec<u8>, String> {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
        .to_string();
    if host.is_empty() {
        return fetch(&build_client(sources), url).await;
    }

    let ips = resolve_ipv4_candidates(&host, edge_cache_path);
    tracing::debug!("fetch_resilient {host} -> {} candidates", ips.len());

    let mut last_err: Option<String> = None;
    for ip in ips {
        let client = client_for_edge(&host, ip, std::time::Duration::from_secs(600));
        // Headers must arrive quickly; a dead edge stalls here. The body may
        // be large (hundreds of MB of .msu), so it gets the full timeout.
        let resp = match tokio::time::timeout(per_attempt, client.get(url).send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let msg = format!("GET {url}: {e}");
                tracing::debug!("fetch_resilient {ip}: {msg}");
                last_err = Some(msg);
                continue;
            }
            Err(_) => {
                let msg = format!("GET {url}: header timeout");
                tracing::debug!("fetch_resilient {ip}: {msg}");
                last_err = Some(msg);
                continue;
            }
        };
        if !resp.status().is_success() {
            let msg = format!("GET {url}: HTTP {}", resp.status());
            tracing::debug!("fetch_resilient {ip}: {msg}");
            last_err = Some(msg);
            continue;
        }
        match resp.bytes().await {
            Ok(bytes) => {
                remember_edge(edge_cache_path, &host, ip);
                tracing::debug!("fetch_resilient ok via {ip}");
                return Ok(bytes.to_vec());
            }
            Err(e) => {
                let msg = format!("read {url}: {e}");
                tracing::debug!("fetch_resilient {ip}: {msg}");
                last_err = Some(msg);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| format!("no candidates for {host}")))
}

/// Streaming upstream fetch with per-edge fallthrough and byte-range resume.
///
/// `offset` is the byte offset to resume from (0 = start of file). Each edge
/// is requested with `Range: bytes={offset}-`; the server either answers
/// `206 Partial Content` (range honored) or `200` (whole body, only valid
/// when offset == 0). If an edge dies mid-body, the next edge resumes from
/// the last delivered byte so a huge artifact can complete across edges.
///
/// Returns an `mpsc` receiver that yields body chunks; on total failure an
/// `Err` chunk is sent before the channel closes. `total` is the upstream
/// size when disclosed via Content-Length / Content-Range. When `cache` is
/// set, every chunk is appended to that file before it is forwarded, so a
/// partial download survives a dropped client and resumes next request.
pub async fn stream_resilient(
    sources: &[Source],
    url: &str,
    offset: u64,
    header_budget: std::time::Duration,
    chunk_tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, String>>,
    cache: Option<&std::path::Path>,
    edge_cache_path: Option<&Path>,
) -> Result<Option<u64>, String> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let mut cache_file = match cache {
        Some(path) => Some(
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .map_err(|e| format!("open cache {path:?}: {e}"))?,
        ),
        None => None,
    };

    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
        .to_string();

    async fn forward(
        cache_file: &mut Option<tokio::fs::File>,
        start: &mut u64,
        chunk_tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, String>>,
        chunk: bytes::Bytes,
    ) -> Result<(), ()> {
        if let Some(file) = cache_file {
            file.write_all(&chunk).await.map_err(|_| ())?;
        }
        *start += chunk.len() as u64;
        chunk_tx.send(Ok(chunk)).await.map_err(|_| ())
    }

    let mut start = offset;
    if host.is_empty() {
        // No edge mirror to fall back to: a single direct fetch, streamed
        // straight through. (This previously sat in a `loop` whose body
        // returned unconditionally, so it never actually iterated.)
        let client = build_client(sources);
        let req = if start > 0 {
            client.get(url).header(reqwest::header::RANGE, format!("bytes={start}-"))
        } else {
            client.get(url)
        };
        let resp = req.send().await.map_err(|e| format!("GET {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("GET {url}: HTTP {}", resp.status()));
        }
        let total = content_length(&resp);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("read {url}: {e}"))?;
            if forward(&mut cache_file, &mut start, &chunk_tx, chunk).await.is_err() {
                return Ok(total);
            }
        }
        return Ok(total);
    }

    let ips = resolve_ipv4_candidates(&host, edge_cache_path);
    tracing::debug!("stream_resilient {host} -> {} candidates", ips.len());
    if ips.is_empty() {
        return Err(format!("no candidates for {host}"));
    }
    let clients: Vec<(reqwest::Client, std::net::IpAddr)> = ips
        .into_iter()
        .map(|ip| {
            (
                client_for_edge(&host, ip, std::time::Duration::from_secs(1800)),
                ip,
            )
        })
        .collect();

    let mut last_err: Option<String> = None;
    for (client, ip) in &clients {
        let req = if start > 0 {
            client.get(url).header(reqwest::header::RANGE, format!("bytes={start}-"))
        } else {
            client.get(url)
        };
        let resp = match tokio::time::timeout(header_budget, req.send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                last_err = Some(format!("GET {url}: {e}"));
                continue;
            }
            Err(_) => {
                last_err = Some(format!("GET {url}: header timeout"));
                continue;
            }
        };
        if !resp.status().is_success() {
            last_err = Some(format!("GET {url}: HTTP {}", resp.status()));
            continue;
        }
        // If we asked for a resume range we must get a 206, otherwise the
        // bytes would be a duplicate of what was already delivered.
        if start > 0 && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            last_err = Some(format!("GET {url}: resume ignored (HTTP {})", resp.status()));
            continue;
        }
        let total = content_length(&resp);
        let mut stream = resp.bytes_stream();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(180), stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if forward(&mut cache_file, &mut start, &chunk_tx, chunk).await.is_err() {
                        return Ok(total);
                    }
                }
                Ok(Some(Err(e))) => {
                    last_err = Some(format!("read {url}: {e}"));
                    break;
                }
                Ok(None) => {
                    remember_edge(edge_cache_path, &host, *ip);
                    return Ok(total);
                }
                Err(_) => {
                    last_err = Some(format!("read {url}: stalled mid-body"));
                    break;
                }
            }
        }
        tracing::debug!("stream_resilient edge {start} failed: {:?}", last_err);
    }
    Err(last_err.unwrap_or_else(|| format!("no candidates for {host}")))
}

fn content_length(resp: &reqwest::Response) -> Option<u64> {
    if let Some(cr) = resp.headers().get(reqwest::header::CONTENT_RANGE) {
        if let Ok(s) = cr.to_str() {
            if let Some(total) = s.rsplit('/').next() {
                if let Ok(n) = total.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    resp.content_length()
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

/// A single row of a Microsoft Update Catalog search result.
struct WuRow {
    kb: String,
    title: String,
    date: String,
    guid: String,
    uid_info: String,
    arch: String,
    size: u64,
}

/// Syncs one KB from the Microsoft Update Catalog: searches, picks the best
/// matching row (x64 / server builds preferred), resolves the direct .msu
/// download URL, and returns (version, arch, absolute download URL).
async fn wu_sync_kb(
    client: &reqwest::Client,
    base: &str,
    kb: &str,
) -> Result<Option<(String, String, String)>, String> {
    let rows = wu_search(client, base, kb).await?;
    let mut rows: Vec<WuRow> = rows
        .into_iter()
        .filter(|r| r.kb.eq_ignore_ascii_case(kb))
        .collect();
    rows.sort_by(|a, b| wu_score(b).cmp(&wu_score(a)));
    for row in rows {
        if let Some(url) = wu_download_url(client, base, &row.guid, &row.uid_info, row.size).await {
            tracing::info!(
                "windows catalog: {kb} ({}) -> {}",
                row.title,
                url.split('/').next_back().unwrap_or(&url)
            );
            return Ok(Some((row.date, row.arch, url)));
        }
    }
    Ok(None)
}

/// Ranks catalog rows so the one actually meant for this box wins when a
/// KB search returns several products/architectures.
fn wu_score(r: &WuRow) -> u32 {
    let t = r.title.to_lowercase();
    let mut s = 0u32;
    if r.arch == "x64" {
        s += 50;
    }
    if t.contains("server") {
        s += 30;
    }
    if t.contains("2022") {
        s += 10;
    }
    if t.contains("security") {
        s += 5;
    }
    s
}

/// GETs the catalog search page for `kb` and parses every result row.
async fn wu_search(client: &reqwest::Client, base: &str, kb: &str) -> Result<Vec<WuRow>, String> {
    let url = format!("{base}/Search.aspx?q={kb}");
    let body = fetch(client, &url).await?;
    Ok(parse_wu_rows(&String::from_utf8_lossy(&body)))
}

/// Parses the HTML table of the catalog search results page. Each result row
/// is keyed by `<tr id="<guid>_R<n>">` and its Download button is an input
/// with `id="<guid>"`; title/date/size live in `_C1_R<n>`, `_C4_R<n>`, and the
/// `_originalSize` span.
fn parse_wu_rows(html: &str) -> Vec<WuRow> {
    let re_tr = regex::Regex::new(r#"^\s*id="([0-9a-f-]{36})_R\d+"[^>]*>"#).unwrap();
    let re_kb = regex::Regex::new(r"(?i)\bKB\d+\b").unwrap();
    let re_title =
        regex::Regex::new(r#"id="([0-9a-f-]{36})_C1_R\d+"[^>]*>(?s)(.*?)</td>"#).unwrap();
    let re_date =
        regex::Regex::new(r#"id="([0-9a-f-]{36})_C4_R\d+"[^>]*>\s*([^<]+)\s*</td>"#).unwrap();
    let re_size =
        regex::Regex::new(r#"id="([0-9a-f-]{36})_originalSize">([0-9]+)"#).unwrap();

    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for chunk in html.split("<tr").skip(1) {
        let Some(cap) = re_tr.captures(chunk) else {
            continue;
        };
        let guid = cap[1].to_string();
        if !seen.insert(guid.clone()) {
            continue;
        }
        let title = re_title
            .captures(chunk)
            .map(|c| clean_wu_title(&c[2]))
            .unwrap_or_default();
        let kb = re_kb
            .find(&title)
            .map(|m| m.as_str().to_uppercase())
            .unwrap_or_default();
        let date = re_date
            .captures(chunk)
            .map(|c| normalize_wu_date(c[2].trim()))
            .unwrap_or_default();
        let size = re_size
            .captures(chunk)
            .and_then(|c| c[2].parse().ok())
            .unwrap_or(0);
        let arch = if title.to_lowercase().contains("arm64") {
            "arm64".to_string()
        } else if title.to_lowercase().contains("x86") || title.to_lowercase().contains("32-bit") {
            "x86".to_string()
        } else if title.to_lowercase().contains("x64")
            || title.to_lowercase().contains("64-bit")
            || title.to_lowercase().contains("amd64")
        {
            "x64".to_string()
        } else {
            String::new()
        };
        rows.push(WuRow {
            kb,
            title,
            date,
            guid: guid.clone(),
            uid_info: guid,
            arch,
            size,
        });
    }
    rows
}

/// Strips tags/whitespace from a title cell, keeping the anchor text.
fn clean_wu_title(cell: &str) -> String {
    let re_tag = regex::Regex::new(r"(?s)<[^>]*>").unwrap();
    re_tag.replace_all(cell, " ").to_string().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalizes "6/11/2024" to "2024-06-11".
fn normalize_wu_date(date: &str) -> String {
    let parts: Vec<&str> = date.split('/').collect();
    if parts.len() != 3 {
        return date.to_string();
    }
    let (m, d, y) = (parts[0], parts[1], parts[2]);
    let (m, d) = match (m.parse::<u32>(), d.parse::<u32>()) {
        (Ok(m), Ok(d)) if (1..=12).contains(&m) && (1..=31).contains(&d) => (m, d),
        _ => return date.to_string(),
    };
    format!("{y}-{m:02}-{d:02}")
}

/// Derives (kb, version, arch) from an MSU filename like
/// `windows10.0-kb5039227-x64_<hex>.msu` or `WindowsServer2022-KB5039227.msu`.
/// Version falls back to the file's mtime.
fn msu_metadata(path: &std::path::Path) -> Option<(String, String, String)> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let kb = regex::Regex::new(r"\bkb\d+\b").ok()?.find(&name)?.as_str().to_uppercase();
    let arch = if name.contains("arm64") { "arm64".to_string() } else { "x64".to_string() };
    let version = if let Some(cap) = regex::Regex::new(r"(\d{4}-\d{2}-\d{2})").ok()?.captures(&name) {
        cap.get(1)?.as_str().to_string()
    } else if let Ok(md) = std::fs::metadata(path) {
        if let Ok(modified) = md.modified() {
            let d = std::time::SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(
                modified.duration_since(std::time::SystemTime::UNIX_EPOCH).ok()?.as_secs(),
            ))?;
            let dt: chrono::DateTime<chrono::Utc> = d.into();
            dt.format("%Y-%m-%d").to_string()
        } else {
            "2024-01-01".to_string()
        }
    } else {
        "2024-01-01".to_string()
    };
    Some((kb, version, arch))
}

/// POSTs the catalog's download dialog with an update id and extracts the
/// direct .msu/.cab URL (on download.windowsupdate.com or similar CDN).
async fn wu_download_url(
    client: &reqwest::Client,
    base: &str,
    guid: &str,
    uid_info: &str,
    size: u64,
) -> Option<String> {
    let body = format!(
        r#"updateIDs=[{{"size":{size},"languages":"","uidInfo":"{uid_info}","updateID":"{guid}"}}]"#
    );
    let url = format!("{base}/DownloadDialog.aspx");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .ok()?;
    let text = resp.text().await.ok()?;
    let re = regex::Regex::new(r#"https://[^"'\s]+\.(?:msu|cab)"#).ok()?;
    re.find(&text).map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_catalog_search_rows() {
        let html = r##"
<table id="ctl00_catalogBody_updateResults">
<tr id="a1c1095d-4024-4505-b500-10e48460b99c_R0" style="border-width:0px;">
	<td class="resultsbottomBorder resultspadding resultsIconWidth " id="a1c1095d-4024-4505-b500-10e48460b99c_C0_R0"></td>
	<td class="resultsbottomBorder resultspadding" id="a1c1095d-4024-4505-b500-10e48460b99c_C1_R0">
		<a id='a1c1095d-4024-4505-b500-10e48460b99c_link' href= "javascript:void(0);" onclick='goToDetails("a1c1095d-4024-4505-b500-10e48460b99c");' class="contentTextItemSpacerNoBreakLink">
			2024-06 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5039227)
		</a>
	</td>
	<td class="resultsbottomBorder resultspadding" id="a1c1095d-4024-4505-b500-10e48460b99c_C4_R0">6/11/2024</td>
	<td class="resultsbottomBorder resultspadding resultsSizeWidth" id="a1c1095d-4024-4505-b500-10e48460b99c_C6_R0">
	   <span id="a1c1095d-4024-4505-b500-10e48460b99c_size">207.6 MB</span>
	   <span class="noDisplay" id="a1c1095d-4024-4505-b500-10e48460b99c_originalSize">217703505</span>
	</td>
	<td class="resultsbottomBorder resultsButtonWidth" id="a1c1095d-4024-4505-b500-10e48460b99c_C7_R0">
		<input id="a1c1095d-4024-4505-b500-10e48460b99c" class="flatBlueButtonDownload focus-only" type="button" value='Download' />
	</td>
</tr>
<tr id="11111111-2222-3333-4444-555555555555_R1" style="border-width:0px;">
	<td class="resultsbottomBorder resultspadding resultsIconWidth " id="11111111-2222-3333-4444-555555555555_C0_R1"></td>
	<td class="resultsbottomBorder resultspadding" id="11111111-2222-3333-4444-555555555555_C1_R1">
		<a id='11111111-2222-3333-4444-555555555555_link' href= "javascript:void(0);" onclick='goToDetails("11111111-2222-3333-4444-555555555555");' class="contentTextItemSpacerNoBreakLink">
			2024-06 Cumulative Update for Microsoft server operating system version 21H2 for ARM64-based Systems (KB5039227)
		</a>
	</td>
	<td class="resultsbottomBorder resultspadding" id="11111111-2222-3333-4444-555555555555_C4_R1">6/11/2024</td>
	<td class="resultsbottomBorder resultspadding resultsSizeWidth" id="11111111-2222-3333-4444-555555555555_C6_R1">
	   <span class="noDisplay" id="11111111-2222-3333-4444-555555555555_originalSize">157348048</span>
	</td>
	<td class="resultsbottomBorder resultsButtonWidth" id="11111111-2222-3333-4444-555555555555_C7_R1">
		<input id="11111111-2222-3333-4444-555555555555" class="flatBlueButtonDownload focus-only" type="button" value='Download' />
	</td>
</tr>
</table>
"##;
        let rows = parse_wu_rows(html);
        assert_eq!(rows.len(), 2, "two result rows with download buttons");
        let x64 = rows.iter().find(|r| r.arch == "x64").unwrap();
        assert_eq!(x64.kb, "KB5039227");
        assert_eq!(x64.date, "2024-06-11");
        assert_eq!(x64.guid, "a1c1095d-4024-4505-b500-10e48460b99c");
        assert!(x64.title.contains("x64-based"));
        assert_eq!(x64.size, 217_703_505);
        let arm = rows.iter().find(|r| r.arch == "arm64").unwrap();
        assert_eq!(arm.guid, "11111111-2222-3333-4444-555555555555");
        assert!(wu_score(x64) > wu_score(arm), "x64/server rows rank first");
    }

    #[test]
    fn normalizes_dates() {
        assert_eq!(normalize_wu_date("6/11/2024"), "2024-06-11");
        assert_eq!(normalize_wu_date("12/1/2023"), "2023-12-01");
        assert_eq!(normalize_wu_date(""), "");
    }

    #[test]
    fn extracts_download_url() {
        let html = r#"<html><body><a href="https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/updt/2024/06/windows10.0-kb5039227-x64_b1d1f0a.msu"><input type="button" id="downloadButton" class="tableButton" value="Download" /></a></body></html>"#;
        let re = regex::Regex::new(r#"https://[^"'\s]+\.(?:msu|cab)"#).unwrap();
        let m = re.find(html).unwrap();
        assert!(m.as_str().ends_with(".msu"));
        assert!(m.as_str().contains("kb5039227"));
    }
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
