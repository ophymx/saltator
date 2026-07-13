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

    let registry = saltator_shard::ShardRegistry::new();
    let meta = saltator_cluster::MetadataHandle::start(
        cfg.node.id,
        engine.clone(),
        Some(cfg.node.advertise.clone()),
        Some(&registry),
    )
    .await?;

    let leader = meta.wait_for_leader(Duration::from_secs(10)).await?;
    tracing::info!(leader, "metadata group ready");

    // Event-signing identity: generated on first boot, recovered from the
    // data dir thereafter.
    let server_name = ruma::OwnedServerName::try_from(cfg.server_name.as_str())
        .map_err(|e| anyhow::anyhow!("server_name is not a valid Matrix server name: {e}"))?;
    let signer = load_or_generate_signer(&cfg.data_dir.join("signing.key"), server_name)?;

    let rooms = saltator_roomserver::RoomServer::start(
        cfg.node.id,
        engine.clone(),
        std::sync::Arc::new(signer),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_roomserver::ROOM_SHARD),
        Some(cfg.node.advertise.clone()),
        Some(&registry),
    )
    .await?;
    rooms
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await?;
    tracing::info!("room shard ready");
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
        registry.clone(),
        cfg.server_name.clone(),
        cfg.listeners.internal,
        shutdown,
    )
    .await?;

    rooms.shutdown().await?;
    meta.shutdown().await?;
    tracing::info!("saltator stopped");
    Ok(())
}

fn load_or_generate_signer(
    path: &std::path::Path,
    server_name: ruma::OwnedServerName,
) -> anyhow::Result<saltator_roomserver::ServerSigner> {
    use saltator_roomserver::ServerSigner;
    // Key versions beyond "0" arrive with key rotation (M2+).
    const KEY_VERSION: &str = "0";

    if path.exists() {
        let der = std::fs::read(path)?;
        return Ok(ServerSigner::from_der(
            server_name,
            &der,
            KEY_VERSION.to_owned(),
        )?);
    }
    let (signer, der) = ServerSigner::generate(server_name, KEY_VERSION.to_owned());
    write_private(path, &der)?;
    tracing::info!(path = %path.display(), "generated new ed25519 signing key");
    Ok(signer)
}

/// Write key material with owner-only permissions.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}
