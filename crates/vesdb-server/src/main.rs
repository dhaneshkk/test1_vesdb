use clap::{Parser, Subcommand};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;
use vesdb_core::crypto::{load_public, HybridKey};
use vesdb_server::{
    router, spawn_checkpointer, try_new_app, ts::spawn_sealer, Scope, ServerConfig, StoreConfig,
    WitnessConfig,
};
use vesdb_store::Store;
use vesdb_ts::TsConfig;

#[derive(Parser)]
#[command(
    name = "vesdb",
    version,
    about = "Verifiable, tamper-evident event store (EventSourcingDB v2-compatible API)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a hybrid Ed25519 + ML-DSA-65 key: writes PATH (secret, 0600) and PATH.pub.
    Keygen {
        /// Key name; for a log this is its origin, e.g. `rig-07.vg360.example/log`.
        #[arg(long)]
        name: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the server.
    Run(Box<Run>),
}

#[derive(clap::Args)]
struct Run {
    #[arg(long, conflicts_with = "data_directory_temporary")]
    data_directory: Option<PathBuf>,
    /// Use a temporary data directory, deleted on shutdown (tests and demos).
    #[arg(long)]
    data_directory_temporary: bool,
    /// Log signing key (from `vesdb keygen`); its name is the log origin.
    #[arg(long)]
    signing_key_file: PathBuf,
    /// Full-access token (EventSourcingDB-compatible), at least 32 characters with a data directory.
    #[arg(long, env = "VESDB_API_TOKEN")]
    api_token: Option<String>,
    /// Scoped token `SECRET=scope,scope` with scopes read, write, audit, redact, admin. Repeatable.
    #[arg(long = "token")]
    tokens: Vec<String>,
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,
    /// Witness `URL=PUBKEYFILE`. Repeatable.
    #[arg(long = "witness")]
    witnesses: Vec<String>,
    /// Cosignatures needed before a checkpoint is published (default: all witnesses).
    #[arg(long)]
    witness_quorum: Option<usize>,
    #[arg(long, default_value_t = 1000)]
    checkpoint_interval_ms: u64,
    #[arg(long, default_value_t = 4096)]
    checkpoint_max_events: u64,
    /// Event type carrying personal data: stored without an unsalted compat hash. Repeatable.
    #[arg(long = "pii-type")]
    pii_types: Vec<String>,
    /// `source` for system events (redactions). Default: https://<origin host>
    #[arg(long)]
    system_source: Option<String>,
    /// Do not claim `EventSourcingDB/1.3 (compatible; ...)` in the Server header (official SDKs then refuse).
    #[arg(long)]
    no_compat_server_header: bool,
    /// Do not add EventSourcingDB-compatible read-time Ed25519 signatures to events.
    #[arg(long)]
    no_compat_signatures: bool,
    /// Disable the time-series engine (`/api/v2/ts/...`).
    #[arg(long)]
    no_time_series: bool,
    /// Time-series sealing window: one chunk, and one log event, per series per window.
    #[arg(long, default_value_t = 60_000)]
    ts_window_ms: u64,
    /// How long after a window ends late points are still waited for before sealing.
    #[arg(long, default_value_t = 5_000)]
    ts_grace_ms: u64,
    #[arg(long, default_value_t = 1_000)]
    ts_seal_interval_ms: u64,
    /// Delete chunk files whose last point is older than this many seconds (each deletion is logged).
    #[arg(long)]
    ts_retention_secs: Option<u64>,
    /// Acknowledge time-series writes without fsync (faster, loses unsealed points on power loss).
    #[arg(long)]
    ts_no_fsync: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { name, out } => {
            let pk = HybridKey::generate_files(&name, &out)?;
            println!(
                "wrote {} and {}.pub (key id {})",
                out.display(),
                out.display(),
                pk.key_id()
            );
        }
        Cmd::Run(r) => run(*r).await?,
    }
    Ok(())
}

async fn run(r: Run) -> Result<(), Box<dyn std::error::Error>> {
    let key = HybridKey::load(&r.signing_key_file)?;
    let compat_key = HybridKey::load(&r.signing_key_file)?;
    let origin = key.name().to_string();
    let _tmp;
    let dir = match (r.data_directory, r.data_directory_temporary) {
        (Some(d), false) => d,
        (None, true) => {
            _tmp = tempfile::tempdir()?;
            _tmp.path().to_path_buf()
        }
        _ => return Err("give --data-directory or --data-directory-temporary".into()),
    };
    let mut tokens: HashMap<String, BTreeSet<Scope>> = HashMap::new();
    if let Some(t) = r.api_token {
        if !r.data_directory_temporary && t.len() < 32 {
            return Err("--api-token must have at least 32 characters".into());
        }
        tokens.insert(t, [Scope::Admin].into_iter().collect());
    }
    for spec in r.tokens {
        let (secret, scopes) = spec
            .split_once('=')
            .ok_or("--token must be SECRET=scope,scope")?;
        if secret.len() < 32 && !r.data_directory_temporary {
            return Err("token secrets must have at least 32 characters".into());
        }
        let set = scopes
            .split(',')
            .map(|s| Scope::parse(s.trim()).ok_or(format!("unknown scope {s}")))
            .collect::<Result<_, _>>()?;
        tokens.insert(secret.to_string(), set);
    }
    if tokens.is_empty() {
        return Err("configure --api-token or at least one --token".into());
    }
    let mut witnesses = Vec::new();
    for w in r.witnesses {
        let (url, keyfile) = w
            .rsplit_once('=')
            .ok_or("--witness must be URL=PUBKEYFILE")?;
        witnesses.push(WitnessConfig {
            url: url.to_string(),
            key: load_public(std::path::Path::new(keyfile))?,
        });
    }
    let quorum = r.witness_quorum.unwrap_or(witnesses.len());
    let host = origin.split('/').next().unwrap_or(&origin).to_string();
    let ts = (!r.no_time_series).then(|| TsConfig {
        window_ns: (r.ts_window_ms as i64).saturating_mul(1_000_000),
        grace_ns: (r.ts_grace_ms as i64).saturating_mul(1_000_000),
        fsync: !r.ts_no_fsync,
        retention_ns: r
            .ts_retention_secs
            .map(|s| (s as i64).saturating_mul(1_000_000_000)),
        ..TsConfig::new(dir.join("ts"))
    });
    let store = Store::open(StoreConfig {
        dir,
        origin: origin.clone(),
        system_source: r.system_source.unwrap_or(format!("https://{host}")),
        pii_types: r.pii_types.into_iter().collect(),
        key,
    })?;
    let app = try_new_app(
        store,
        ServerConfig {
            tokens,
            witnesses,
            quorum,
            checkpoint_interval: Duration::from_millis(r.checkpoint_interval_ms),
            checkpoint_max_events: r.checkpoint_max_events,
            compat_server_header: !r.no_compat_server_header,
            compat_signatures: !r.no_compat_signatures,
            compat_key: Some(compat_key),
            ts,
        },
    )?;
    spawn_checkpointer(app.clone());
    if app.ts.is_some() {
        spawn_sealer(app.clone(), Duration::from_millis(r.ts_seal_interval_ms));
    }
    let l = tokio::net::TcpListener::bind(&r.listen).await?;
    tracing::info!(%origin, listen = %r.listen, "vesdb listening");
    axum::serve(l, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
