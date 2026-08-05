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
            // rustls needs a process-default crypto provider before any TLS
            // (federation listener / outbound client) is set up.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

    let fresh_bootstrap = !cfg.data_dir.join("db").exists();
    std::fs::create_dir_all(&cfg.data_dir)?;
    let engine = Arc::new(saltator_store::RocksEngine::open(&cfg.data_dir.join("db"))?);

    // A node *founds* a new cluster only on a fresh data dir with no seeds;
    // with seeds it *joins* an existing one. A restart (non-fresh) recovers
    // persisted membership either way. Minting a KEK, and initializing the
    // metadata group single-voter, are legitimate only when founding.
    let founding = fresh_bootstrap && cfg.cluster.seeds.is_empty();

    // Shutdown is signalled early: the internal RPC server must be up before
    // join/reconciliation so a joining node can receive replication.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let registry = saltator_shard::ShardRegistry::new();
    let meta = saltator_cluster::MetadataHandle::start(
        cfg.node.id,
        engine.clone(),
        founding.then(|| cfg.node.advertise.clone()),
        Some(&registry),
    )
    .await?;

    // Serve the internal gRPC surface now (a joiner needs it to receive
    // replication; every node needs it for cross-node Raft traffic).
    let internal_task = {
        let mut rx = shutdown_rx.clone();
        tokio::spawn(saltator_cluster::serve_internal(
            meta.clone(),
            registry.clone(),
            cfg.server_name.clone(),
            cfg.listeners.internal,
            async move {
                let _ = rx.wait_for(|stop| *stop).await;
            },
        ))
    };
    tracing::info!(listen = %cfg.listeners.internal, "internal RPC listening");

    // A joiner asks a seed to admit it to the metadata group before anything
    // else can be read from it.
    if fresh_bootstrap && !cfg.cluster.seeds.is_empty() {
        tracing::info!(seeds = ?cfg.cluster.seeds, "joining existing cluster");
        saltator_cluster::join_cluster(
            &cfg.cluster.seeds,
            cfg.node.id,
            &cfg.node.advertise,
            Duration::from_secs(30),
        )
        .await?;
    }

    let leader = meta.wait_for_leader(Duration::from_secs(30)).await?;
    tracing::info!(leader, "metadata group ready");

    // The founder writes the cluster control plane (topology, roster,
    // placement); joiners read the replicated copy.
    if founding {
        meta.bootstrap_cluster(
            saltator_cluster::ClusterConfig::default(),
            cfg.node.advertise.clone(),
        )
        .await?;
    }

    // Event-signing identity: versioned, encrypted at rest in the
    // metadata group (spec.md §5.4, §10).
    let server_name = server_name_of(&cfg)?;
    let kek = keys::load_kek(&cfg.data_dir.join("master.key"), founding)?;
    let signer =
        Arc::new(keys::load_signing_key(&meta, &kek, &cfg.data_dir, server_name.clone()).await?);
    let old_keys = keys::old_verify_keys(&meta, &kek, server_name.clone()).await?;

    // Room + user shards: the founder bootstraps each single-voter; a joiner
    // starts them uninitialized and the reconciler folds this node in as a
    // voter once the leader has caught it up. The wait therefore tolerates a
    // reconciliation round or two on a joining node.
    let shard_bootstrap = founding.then(|| cfg.node.advertise.clone());
    let rooms = saltator_roomserver::RoomServer::start(
        cfg.node.id,
        engine.clone(),
        signer.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_roomserver::ROOM_SHARD),
        shard_bootstrap.clone(),
        Some(&registry),
    )
    .await?;
    rooms
        .shard_handle()
        .wait_for_leader(Duration::from_secs(60))
        .await?;
    tracing::info!("room shard ready");

    let users = saltator_userserver::UserServer::start(
        cfg.node.id,
        engine.clone(),
        server_name.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_userserver::USER_SHARD),
        shard_bootstrap,
        Some(&registry),
    )
    .await?;
    users
        .shard_handle()
        .wait_for_leader(Duration::from_secs(60))
        .await?;
    tracing::info!("user shard ready");

    // Drive this node's shard groups toward the placement: as a group's
    // leader it admits new replicas; a joiner's freshly-started groups become
    // voters here. Each group is reconciled by exactly its own leader.
    let reconciler = saltator_cluster::spawn_reconciler(
        meta.clone(),
        vec![
            saltator_cluster::LocalGroup::new(
                saltator_roomserver::ROOM_SHARD.group(),
                rooms.shard_handle().clone(),
            ),
            saltator_cluster::LocalGroup::new(
                saltator_userserver::USER_SHARD.group(),
                users.shard_handle().clone(),
            ),
        ],
        Duration::from_secs(2),
    );

    let projection = saltator_userserver::spawn_membership_projection(users.clone(), rooms.clone());

    // Client-server API.
    let default_room_version = saltator_core::RoomVersion::parse(&cfg.client.default_room_version)
        .map_err(|e| anyhow::anyhow!("client.default_room_version: {e}"))?;
    let media = saltator_media::MediaStore::open(cfg.data_dir.join("media"))?;
    let fed_media = media.clone();
    // Optional extra CA for outbound federation (test harnesses / private
    // PKI). System roots are always trusted.
    let outbound_ca =
        match &cfg.federation.ca_cert {
            Some(path) => Some(std::fs::read(path).map_err(|e| {
                anyhow::anyhow!("reading federation.ca_cert {}: {e}", path.display())
            })?),
            None => None,
        };
    // Signed client for outbound federation, shared by the CS `/join` path
    // and the event sender.
    let fed_client = Arc::new(match &outbound_ca {
        Some(ca) => saltator_federation::FederationClient::with_ca(signer.clone(), ca),
        None => saltator_federation::FederationClient::new(signer.clone()),
    });
    // One key cache for the whole process. The CS import paths (remote join,
    // backfill) verify fetched events and so learn the authoring servers'
    // keys; inbound federation auth needs those same keys. Keeping separate
    // caches made every server pay a fresh key fetch — a full cold HTTPS
    // round trip, ~55ms — inside the auth extractor on the first request it
    // received from a server it had just finished talking to.
    let key_cache = Arc::new(match &outbound_ca {
        Some(ca) => saltator_federation::KeyCache::with_ca(ca),
        None => saltator_federation::KeyCache::new(),
    });
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
            rate_limits: if cfg.client.rate_limits_enabled {
                saltator_cs_api::RateLimitConfig::default()
            } else {
                saltator_cs_api::RateLimitConfig::disabled()
            },
            allow_internal_fetch: cfg.client.allow_internal_fetch,
        },
    )
    .with_federation(fed_client.clone(), signer.clone(), key_cache.clone());
    // Typing/presence maps are shared with the federation surface (inbound
    // EDUs update them).
    let cs_typing = cs_state.typing_map();
    let cs_presence = cs_state.presence_map();
    // HTTP push: notify gateways about new events for users with pushers.
    let push_delivery = saltator_cs_api::spawn_push_delivery(cs_state.clone());
    let cs_router = saltator_cs_api::router(cs_state);
    let cs_listener = tokio::net::TcpListener::bind(cfg.listeners.client).await?;
    tracing::info!(listen = %cfg.listeners.client, "client-server API listening");

    let edu_sink = Arc::new(saltator_cs_api::EphemeralEduSink::new(
        cs_typing.clone(),
        cs_presence.clone(),
    ));
    let fed_state = Arc::new(saltator_federation::FedState {
        server_name: server_name.clone(),
        signer: signer.clone(),
        old_keys,
        key_cache,
        rooms: Some(rooms.clone()),
        users: Some(users.clone()),
        client: Some(fed_client.clone()),
        edu_sink: Some(edu_sink),
        media: Some(fed_media),
    });
    let fed_router = saltator_federation::router(fed_state);
    // Federation is served over HTTPS when a cert is configured; otherwise
    // plain HTTP (dev, or behind an external TLS terminator).
    let fed_tls = match (&cfg.federation.tls_cert, &cfg.federation.tls_key) {
        (Some(cert), Some(key)) => Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .map_err(|e| anyhow::anyhow!("loading federation TLS cert/key: {e}"))?,
        ),
        (None, None) => None,
        _ => anyhow::bail!("federation.tls_cert and federation.tls_key must be set together"),
    };
    let fed_addr = cfg.listeners.federation;
    tracing::info!(
        listen = %fed_addr,
        tls = fed_tls.is_some(),
        "federation API listening",
    );

    // Outbound federation: forward locally originated events to remote
    // servers sharing each room.
    let fed_sender =
        saltator_federation::spawn_sender(rooms.clone(), fed_client, server_name.clone());

    let mut cs_shutdown = shutdown_rx.clone();
    let cs_task = tokio::spawn(async move {
        axum::serve(cs_listener, cs_router)
            .with_graceful_shutdown(async move {
                let _ = cs_shutdown.wait_for(|stop| *stop).await;
            })
            .await
    });
    // axum-server drives both the HTTPS and plain-HTTP federation paths;
    // its Handle carries graceful shutdown.
    let fed_handle = axum_server::Handle::new();
    let fed_task = {
        let handle = fed_handle.clone();
        tokio::spawn(async move {
            let svc = fed_router.into_make_service();
            match fed_tls {
                Some(tls) => {
                    axum_server::bind_rustls(fed_addr, tls)
                        .handle(handle)
                        .serve(svc)
                        .await
                }
                None => axum_server::bind(fed_addr).handle(handle).serve(svc).await,
            }
        })
    };
    {
        let mut fed_shutdown = shutdown_rx.clone();
        let handle = fed_handle.clone();
        tokio::spawn(async move {
            let _ = fed_shutdown.wait_for(|stop| *stop).await;
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
    }

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

    // Block until a shutdown signal drives the internal server to return.
    internal_task.await??;
    cs_task.await??;
    fed_task.await??;
    fed_sender.abort();
    push_delivery.abort();
    reconciler.abort();
    projection.abort();
    rooms.shutdown().await?;
    users.shutdown().await?;
    meta.shutdown().await?;
    tracing::info!("saltator stopped");
    Ok(())
}
