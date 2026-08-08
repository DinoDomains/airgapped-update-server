use airgap_collector::{run_collector, Cli};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_collector=info".into()),
        )
        .init();

    let cli = Cli::parse();
    run_collector(cli).await
}
