fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("backup") {
        let store_dir = std::path::PathBuf::from(args.get(2).cloned().unwrap_or_else(|| "data".into()));
        let out = std::path::PathBuf::from(args.get(3).cloned().unwrap_or_else(|| "openupdater-backup.tar.gz".into()));
        airgap_server::backup(&store_dir, &out)?;
        println!("backup written to {}", out.display());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_server=info,axum=info".into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(airgap_server::run())
}
