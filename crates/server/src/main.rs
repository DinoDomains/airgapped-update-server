fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_server=info,axum=info".into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(airgap_server::run())
}
