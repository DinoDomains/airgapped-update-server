use airgap_processor::{run_processor, Cli};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airgap_processor=info".into()),
        )
        .init();

    let cli = Cli::parse();
    run_processor(cli).await
}
