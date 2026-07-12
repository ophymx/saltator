//! Saltator: a Matrix homeserver as a self-clustering distributed system.
//! See spec.md. M0: single-node metadata group + internal RPC skeleton.

mod config;

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use config::Config;

#[derive(Parser)]
#[command(name = "saltator", version, about = "Matrix homeserver, natively HA")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a node (bootstraps a new cluster on a fresh data dir with no
    /// seeds configured).
    Start {
        /// Path to the node's TOML config.
        #[arg(short, long)]
        config: std::path::PathBuf,
    },
    /// Print an example configuration file to stdout.
    ExampleConfig,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ExampleConfig => {
            print!("{}", config::EXAMPLE);
            Ok(())
        }
        Command::Start { config } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info,openraft=warn".into()),
                )
                .init();
            let cfg = Config::load(&config)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run(cfg))
        }
    }
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    tracing::info!(
        server_name = %cfg.server_name,
        node_id = cfg.node.id,
        data_dir = %cfg.data_dir.display(),
        "saltator {} starting",
        env!("CARGO_PKG_VERSION"),
    );

    std::fs::create_dir_all(&cfg.data_dir)?;
    let engine = Arc::new(saltator_store::RocksEngine::open(&cfg.data_dir.join("db"))?);

    // Joining via seeds is M4 (placement controller + add-learner flow);
    // M0 supports fresh bootstrap and restart-recovery only.
    if !cfg.cluster.seeds.is_empty() {
        anyhow::bail!("cluster.seeds is not supported yet (M4); run with empty seeds");
    }

    let meta = saltator_cluster::MetadataHandle::start(
        cfg.node.id,
        engine.clone(),
        Some(cfg.node.advertise.clone()),
    )
    .await?;

    let leader = meta.wait_for_leader(Duration::from_secs(10)).await?;
    tracing::info!(leader, "metadata group ready");
    tracing::info!(
        client = %cfg.listeners.client,
        federation = %cfg.listeners.federation,
        "client/federation listeners configured; served from M2/M3",
    );

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
    };

    tracing::info!(listen = %cfg.listeners.internal, "internal RPC listening");
    saltator_cluster::serve_internal(
        meta.clone(),
        cfg.server_name.clone(),
        cfg.listeners.internal,
        shutdown,
    )
    .await?;

    meta.shutdown().await?;
    tracing::info!("saltator stopped");
    Ok(())
}
