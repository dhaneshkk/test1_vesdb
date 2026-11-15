use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use vesdb_core::crypto::{load_public, HybridKey};

#[derive(Parser)]
#[command(
    name = "vesdb-witness",
    version,
    about = "Cosigns vesdb checkpoints that provably extend what it saw before"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the witness HTTP service.
    Run {
        /// Witness key file (from `vesdb keygen`).
        #[arg(long)]
        key_file: PathBuf,
        /// Public key file of a log to witness; its name is the log origin. Repeatable.
        #[arg(long = "log-key", required = true)]
        log_keys: Vec<PathBuf>,
        /// Where the witness keeps its latest-checkpoint state.
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long, default_value = "127.0.0.1:3100")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Run {
            key_file,
            log_keys,
            state_file,
            listen,
        } => {
            let key = HybridKey::load(&key_file)?;
            let logs = log_keys
                .iter()
                .map(|p| load_public(p))
                .collect::<Result<Vec<_>, _>>()?;
            let w = Arc::new(vesdb_witness::Witness::new(key, logs, Some(state_file))?);
            let l = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!("witness {} listening on {listen}", w.key.name());
            axum::serve(l, vesdb_witness::router(w)).await?;
        }
    }
    Ok(())
}
