//! Saltator: a Matrix homeserver as a self-clustering distributed system.
//! See spec.md. M2: single-node with the full client-server surface.

mod config;
mod keys;

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
    /// Mint a new signing-key version and make it active. Run while the
    /// node is stopped.
    RotateSigningKey {
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
            init_tracing();
            let cfg = Config::load(&config)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run(cfg))
        }
        Command::RotateSigningKey { config } => {
            init_tracing();
            let cfg = Config::load(&config)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(rotate(cfg))
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,openraft=warn".into()),
        )
        .init();
}

fn server_name_of(cfg: &Config) -> anyhow::Result<ruma::OwnedServerName> {
    ruma::OwnedServerName::try_from(cfg.server_name.as_str())
        .map_err(|e| anyhow::anyhow!("server_name is not a valid Matrix server name: {e}"))
}

async fn rotate(cfg: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let engine = Arc::new(saltator_store::RocksEngine::open(&cfg.data_dir.join("db"))?);
    let meta = saltator_cluster::MetadataHandle::start(
        cfg.node.id,
        engine,
        Some(cfg.node.advertise.clone()),
        None,
    )
    .await?;
    meta.wait_for_leader(Duration::from_secs(10)).await?;
    let kek = keys::load_kek(&cfg.data_dir.join("master.key"), false)?;
    let version = keys::rotate_signing_key(&meta, &kek, server_name_of(&cfg)?).await?;
    tracing::info!(version, "signing key rotated");
    meta.shutdown().await?;
    Ok(())
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    tracing::info!(
        server_name = %cfg.server_name,
        node_id = cfg.node.id,
        data_dir = %cfg.data_dir.display(),
        "saltator {} starting",
        env!("CARGO_PKG_VERSION"),
    );

    // Minting a KEK is only legitimate when this start will bootstrap a
    // cluster; an existing db with no master.key is a provisioning mistake.
    let fresh_bootstrap = !cfg.data_dir.join("db").exists();
    std::fs::create_dir_all(&cfg.data_dir)?;
    let engine = Arc::new(saltator_store::RocksEngine::open(&cfg.data_dir.join("db"))?);

    // Joining via seeds is M4 (placement controller + add-learner flow);
    // fresh bootstrap and restart-recovery only until then.
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

    // Event-signing identity: versioned, encrypted at rest in the
    // metadata group (spec.md §5.4, §10).
    let server_name = server_name_of(&cfg)?;
    let kek = keys::load_kek(&cfg.data_dir.join("master.key"), fresh_bootstrap)?;
    let signer =
        Arc::new(keys::load_signing_key(&meta, &kek, &cfg.data_dir, server_name.clone()).await?);
    let old_keys = keys::old_verify_keys(&meta, &kek, server_name.clone()).await?;

    let rooms = saltator_roomserver::RoomServer::start(
        cfg.node.id,
        engine.clone(),
        signer.clone(),
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

    let users = saltator_userserver::UserServer::start(
        cfg.node.id,
        engine.clone(),
        server_name.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_userserver::USER_SHARD),
        Some(cfg.node.advertise.clone()),
        Some(&registry),
    )
    .await?;
    users
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await?;
    tracing::info!("user shard ready");

    let projection = saltator_userserver::spawn_membership_projection(users.clone(), rooms.clone());

    // Client-server API.
    let default_room_version = saltator_core::RoomVersion::parse(&cfg.client.default_room_version)
        .map_err(|e| anyhow::anyhow!("client.default_room_version: {e}"))?;
    let media = saltator_media::MediaStore::open(cfg.data_dir.join("media"))?;
    // Signed client for outbound federation, shared by the CS `/join` path
    // and the event sender.
    let fed_client = Arc::new(saltator_federation::FederationClient::new(signer.clone()));
    let cs_state = saltator_cs_api::CsState::new(
        users.clone(),
        rooms.clone(),
        media,
        saltator_cs_api::CsConfig {
            server_name: server_name.clone(),
            default_room_version,
            registration_enabled: cfg.client.registration_enabled,
            max_upload_size: cfg.client.max_upload_size,
            well_known_client: cfg.client.well_known_client.clone(),
        },
    )
    .with_federation(fed_client.clone(), signer.clone());
    let cs_router = saltator_cs_api::router(cs_state);
    let cs_listener = tokio::net::TcpListener::bind(cfg.listeners.client).await?;
    tracing::info!(listen = %cfg.listeners.client, "client-server API listening");

    let fed_state = Arc::new(
        saltator_federation::FedState::new(server_name.clone(), signer.clone(), old_keys)
            .with_rooms(rooms.clone()),
    );
    let fed_router = saltator_federation::router(fed_state);
    let fed_listener = tokio::net::TcpListener::bind(cfg.listeners.federation).await?;
    tracing::info!(listen = %cfg.listeners.federation, "federation API listening");

    // Outbound federation: forward locally originated events to remote
    // servers sharing each room.
    let fed_sender =
        saltator_federation::spawn_sender(rooms.clone(), fed_client, server_name.clone());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut cs_shutdown = shutdown_rx.clone();
    let cs_task = tokio::spawn(async move {
        axum::serve(cs_listener, cs_router)
            .with_graceful_shutdown(async move {
                let _ = cs_shutdown.wait_for(|stop| *stop).await;
            })
            .await
    });
    let mut fed_shutdown = shutdown_rx.clone();
    let fed_task = tokio::spawn(async move {
        axum::serve(fed_listener, fed_router)
            .with_graceful_shutdown(async move {
                let _ = fed_shutdown.wait_for(|stop| *stop).await;
            })
            .await
    });

    let internal_shutdown = {
        let mut rx = shutdown_rx.clone();
        async move {
            let _ = rx.wait_for(|stop| *stop).await;
        }
    };
    tokio::spawn(async move {
        // SIGTERM matters as much as ctrl-c: it's what `docker stop` (and
        // thus Complement teardown) sends, and as PID 1 in a container the
        // default disposition would ignore it.
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    tracing::info!(listen = %cfg.listeners.internal, "internal RPC listening");
    saltator_cluster::serve_internal(
        meta.clone(),
        registry.clone(),
        cfg.server_name.clone(),
        cfg.listeners.internal,
        internal_shutdown,
    )
    .await?;

    cs_task.await??;
    fed_task.await??;
    fed_sender.abort();
    projection.abort();
    rooms.shutdown().await?;
    users.shutdown().await?;
    meta.shutdown().await?;
    tracing::info!("saltator stopped");
    Ok(())
}
