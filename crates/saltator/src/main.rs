//! Saltator: a Matrix homeserver as a self-clustering distributed system.
//! See spec.md. M2: single-node with the full client-server surface.

mod config;
mod keys;
mod lifecycle;

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use config::Config;

/// How often shard gauges (leadership, sequence, voter count) are read.
/// Ten seconds is below any sane scrape interval, so a scrape never sees a
/// value older than the sample before last, and the read is a handful of
/// in-memory lookups per shard.
const SHARD_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

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
            let _ = rustls::crypto::ring::default_provider().install_default();
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

/// Open the node's two storage roles (roadmap step 3.5): applied state
/// in `db/` (relaxed-durability applies; replay covers a crash) and the
/// Raft logs of every shard in `raft/` (always fsynced — the durability
/// the protocol actually requires). Every entry point that touches shard
/// storage must open BOTH the same way, or a shard finds its state
/// without its log.
fn open_stores(cfg: &Config) -> anyhow::Result<saltator_store::Stores> {
    let state = Arc::new(saltator_store::RocksEngine::open(&cfg.data_dir.join("db"))?);
    let log = Arc::new(saltator_store::RocksEngine::open_log(
        &cfg.data_dir.join("raft"),
    )?);
    Ok(saltator_store::Stores::split(log, state))
}

fn server_name_of(cfg: &Config) -> anyhow::Result<ruma::OwnedServerName> {
    ruma::OwnedServerName::try_from(cfg.server_name.as_str())
        .map_err(|e| anyhow::anyhow!("server_name is not a valid Matrix server name: {e}"))
}

async fn rotate(cfg: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let stores = open_stores(&cfg)?;
    let meta = saltator_cluster::MetadataHandle::start(
        cfg.node.id,
        stores,
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

    // The recorder goes in before anything that could emit a measurement:
    // the shard runtimes start applying below, and a metric recorded
    // before the recorder exists is simply lost. When no metrics listener
    // is configured there is no recorder at all, and every `metrics!`
    // macro in the tree stays the no-op it is by default.
    let metrics_handle = match cfg.listeners.metrics {
        Some(addr) => {
            if !addr.ip().is_loopback() {
                // Not an error: exporting to a management network is a
                // legitimate deployment. But the exporter has no auth, so
                // whoever wrote this address had better have meant it.
                tracing::warn!(
                    listen = %addr,
                    "metrics listener is not on loopback and is unauthenticated; \
                     anyone who can reach it can read this server's traffic and cluster shape",
                );
            }
            let handle = saltator_metrics::install()?;
            saltator_metrics::set_build_info(env!("CARGO_PKG_VERSION"));
            // Help text is registered here, at startup, so no measurement
            // site pays for it. Each instrumented crate describes its own
            // series; nothing but this line knows they all exist.
            saltator_shard::metrics::describe();
            saltator_federation::metrics::describe();
            saltator_cs_api::appservice_push::describe();
            Some(handle)
        }
        None => None,
    };

    let fresh_bootstrap = !cfg.data_dir.join("db").exists();
    std::fs::create_dir_all(&cfg.data_dir)?;
    let stores = open_stores(&cfg)?;

    // A node *founds* a new cluster only on a fresh data dir with no seeds;
    // with seeds it *joins* an existing one. A restart (non-fresh) recovers
    // persisted membership either way. Minting a KEK, and initializing the
    // metadata group single-voter, are legitimate only when founding.
    let founding = fresh_bootstrap && cfg.cluster.seeds.is_empty();

    // Shutdown is signalled early: the internal RPC server must be up before
    // join/reconciliation so a joining node can receive replication.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Mutual TLS for the internal control plane (security review
    // 2026-08-13, Vuln 4). Peer certs verify against `server_name`, so
    // nodes can dial each other by bare address.
    let internal_tls = match cfg.cluster.tls_files()? {
        Some((cert, key, ca)) => Some(saltator_cluster::InternalTls::from_files(
            cert,
            key,
            ca,
            &cfg.server_name,
        )?),
        None => None,
    };
    config::require_tls_or_loopback(cfg.listeners.internal, internal_tls.is_some())?;

    let registry = saltator_shard::ShardRegistry::new();
    let meta = saltator_cluster::MetadataHandle::start_with_tls(
        cfg.node.id,
        stores.clone(),
        founding.then(|| cfg.node.advertise.clone()),
        Some(&registry),
        internal_tls.clone(),
    )
    .await?;

    // This binary's app schema versions per keyspace: reported over the
    // internal Status RPC (the migration gate) and used by our own
    // supervisors below.
    let schemas = vec![
        (
            saltator_store::Keyspace::Meta as u32,
            saltator_cluster::META_SCHEMA_VERSION,
        ),
        (
            saltator_store::Keyspace::Room as u32,
            saltator_roomserver::SCHEMA_VERSION,
        ),
        (
            saltator_store::Keyspace::User as u32,
            saltator_userserver::SCHEMA_VERSION,
        ),
        (
            saltator_store::Keyspace::FedOut as u32,
            saltator_fedout::SCHEMA_VERSION,
        ),
    ];

    // Serve the internal gRPC surface now (a joiner needs it to receive
    // replication; every node needs it for cross-node Raft traffic).
    let executors = saltator_shard::ExecutorRegistry::new();
    let internal_task = {
        let mut rx = shutdown_rx.clone();
        tokio::spawn(saltator_cluster::serve_internal_with_tls(
            meta.clone(),
            registry.clone(),
            executors.clone(),
            cfg.server_name.clone(),
            schemas.clone(),
            cfg.listeners.internal,
            internal_tls.clone(),
            async move {
                let _ = rx.wait_for(|stop| *stop).await;
            },
        ))
    };
    tracing::info!(
        listen = %cfg.listeners.internal,
        tls = internal_tls.is_some(),
        "internal RPC listening"
    );

    // A joiner asks a seed to admit it to the metadata group before anything
    // else can be read from it.
    if fresh_bootstrap && !cfg.cluster.seeds.is_empty() {
        tracing::info!(seeds = ?cfg.cluster.seeds, "joining existing cluster");
        saltator_cluster::join::join_cluster_with_tls(
            &cfg.cluster.seeds,
            cfg.node.id,
            &cfg.node.advertise,
            Duration::from_secs(30),
            internal_tls.as_ref().map(|t| t.client()).as_ref(),
        )
        .await?;
    }

    let leader = meta.wait_for_leader(Duration::from_secs(30)).await?;
    tracing::info!(leader, "metadata group ready");
    if let Some(cap) = cfg.cluster.rf_cap_unsafe {
        meta.set_rf_cap_unsafe(cap);
    }

    // The founder writes the cluster control plane (topology, roster,
    // placement); joiners read the replicated copy. The room-shard count
    // is chosen HERE, once, forever (docs/design-room-sharding.md):
    // shard split/merge does not exist, so the founding value is the
    // cluster's value for life.
    if founding {
        let defaults = saltator_cluster::ClusterConfig::default();
        meta.bootstrap_cluster(
            saltator_cluster::ClusterConfig {
                room_shards: cfg.cluster.room_shards.unwrap_or(16),
                replication_factor: cfg
                    .cluster
                    .replication_factor
                    .unwrap_or(defaults.replication_factor),
                ..defaults
            },
            cfg.node.advertise.clone(),
        )
        .await?;
    }
    // Everyone — founder, joiner, restart — takes the topology from the
    // durable cluster config, never from their own TOML. The read is from
    // this node's applied state: a joiner is a follower here and cannot
    // serve a linearizable read; it polls until the founding record
    // replicates over.
    let cluster_cfg = {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match meta.cluster_config_local() {
                Ok(Some(c)) => break c,
                Ok(None) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Ok(None) => anyhow::bail!("cluster config never appeared in metadata"),
                Err(e) => return Err(anyhow::anyhow!("reading cluster config: {e}")),
            }
        }
    };
    let room_shards = cluster_cfg.room_shards.max(1);
    if let Some(want) = cfg.cluster.room_shards {
        if want != room_shards {
            tracing::warn!(
                configured = want,
                effective = room_shards,
                "cluster.room_shards differs from the founding value; the durable                  cluster config wins (the count is immutable for the cluster's life)"
            );
        }
    }
    if let Some(want) = cfg.cluster.replication_factor {
        if want != cluster_cfg.replication_factor {
            tracing::warn!(
                configured = want,
                effective = cluster_cfg.replication_factor,
                "cluster.replication_factor differs from the founding value; the durable                  cluster config wins (the factor is immutable for the cluster's life)"
            );
        }
    }
    tracing::info!(
        room_shards,
        replication_factor = cluster_cfg.replication_factor,
        "cluster topology"
    );

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
    let shard_bootstrap_fedout = shard_bootstrap.clone();
    // The placement decides which room groups THIS node hosts (runs the
    // Raft group) vs serves remotely (reads over the Read RPC, writes as
    // intents — docs/design-room-sharding-phase2.md). With
    // `replication_factor` a real cap (phase 3), any cluster larger
    // than RF boots some shards down each arm; `rf_cap_unsafe` forces
    // the remote arm even below RF (debug). Poll: a joiner can race
    // replication.
    let (placement, roster) = {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let placement = meta.placement_local().unwrap_or_default();
            let roster = meta.roster_local().unwrap_or_default();
            let complete = (0..room_shards).all(|idx| {
                let g = saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx).group();
                !placement.replicas(g).is_empty()
            });
            // A joiner must not act on a placement that predates its own
            // admission: it would start ZERO room groups (its rendezvous
            // slots aren't there yet) while the groups' leaders try to
            // fold it in. "Reflects us" is detectable because the USER
            // group floors at every ACTIVE node — a fresh placement
            // always lists an active self there. (A non-active self —
            // rebooting while draining — takes the placement as-is.)
            let fresh = placement
                .replicas(saltator_userserver::USER_SHARD.group())
                .contains(&cfg.node.id)
                || roster
                    .get(&cfg.node.id)
                    .is_some_and(|i| !matches!(i.status, saltator_cluster::NodeStatus::Active));
            if founding || (complete && fresh) {
                break (placement, roster);
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("placement never appeared in metadata");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let addr_of = |nid: u64| {
        roster
            .get(&nid)
            .map(|info: &saltator_cluster::NodeInfo| info.advertise_addr.clone())
    };
    let mut room_shard_servers = Vec::with_capacity(usize::from(room_shards));
    let mut hosted_rooms = 0u16;
    for idx in 0..room_shards {
        let shard = saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx);
        let replicas = placement.replicas(shard.group());
        let hosted = founding || replicas.contains(&cfg.node.id);
        if hosted {
            hosted_rooms += 1;
            // A joiner gaining a group that already has state elsewhere
            // pre-seeds from a replica's checkpoint over the bulk
            // channel (2b part 2) — best-effort; the raft snapshot path
            // covers any failure.
            if !founding {
                let addrs = lifecycle::seed_candidates(replicas, &roster, cfg.node.id);
                lifecycle::pre_seed(
                    &stores,
                    shard,
                    &addrs,
                    internal_tls.as_ref().map(|t| t.client()).as_ref(),
                )
                .await;
            }
            room_shard_servers.push(
                saltator_roomserver::RoomServer::start_shard(
                    shard,
                    cfg.node.id,
                    stores.clone(),
                    signer.clone(),
                    saltator_cluster::network::GrpcRaftNetworkFactory::new(shard)
                        .with_tls(internal_tls.as_ref().map(|t| t.client())),
                    shard_bootstrap.clone(),
                    Some(&registry),
                )
                .await?,
            );
        } else {
            let addrs: Vec<String> = replicas.iter().copied().filter_map(addr_of).collect();
            let remote = saltator_cluster::remote::RemoteShard::new(
                shard.group(),
                addrs,
                internal_tls.as_ref().map(|t| t.client()),
            );
            room_shard_servers.push(saltator_roomserver::RoomServer::remote(
                std::sync::Arc::new(remote),
                signer.clone(),
            ));
        }
    }
    // Leadership waits run concurrently: 16 groups electing serially
    // would stack their timeouts for no reason. Remote groups have
    // nothing to wait for — their replicas boot themselves.
    futures_util::future::try_join_all(
        room_shard_servers
            .iter()
            .filter_map(|r| r.hosted_handle())
            .map(|h| h.wait_for_leader(Duration::from_secs(60))),
    )
    .await?;
    let rooms = saltator_roomserver::RoomShards::new(room_shard_servers);
    tracing::info!(
        count = room_shards,
        hosted = hosted_rooms,
        "room shards ready"
    );

    let users = saltator_userserver::UserServer::start(
        cfg.node.id,
        stores.clone(),
        server_name.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_userserver::USER_SHARD)
            .with_tls(internal_tls.as_ref().map(|t| t.client())),
        shard_bootstrap,
        Some(&registry),
    )
    .await?;
    users
        .shard_handle()
        .wait_for_leader(Duration::from_secs(60))
        .await?;
    tracing::info!("user shard ready");

    let fedout = saltator_fedout::FedOutServer::start(
        cfg.node.id,
        stores.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(saltator_fedout::FED_OUT_SHARD)
            .with_tls(internal_tls.as_ref().map(|t| t.client())),
        shard_bootstrap_fedout,
        Some(&registry),
    )
    .await?;
    fedout
        .shard_handle()
        .wait_for_leader(Duration::from_secs(60))
        .await?;
    tracing::info!("federation-out shard ready");

    // Proposal forwarding: any node serves any write by handing it to the
    // shard's leader over the internal RPC (a load balancer needs no
    // leader awareness).
    let forwarder = saltator_cluster::forward::RpcProposeForwarder::with_tls(
        internal_tls.as_ref().map(|t| t.client()),
    );
    for (_, shard) in rooms.iter() {
        if let Some(h) = shard.hosted_handle() {
            h.set_forwarder(forwarder.clone());
        }
    }
    users.shard_handle().set_forwarder(forwarder.clone());
    fedout.shard_handle().set_forwarder(forwarder.clone());

    // Drive this node's shard groups toward the placement: as a group's
    // leader it admits new replicas; a joiner's freshly-started groups become
    // voters here. Each group is reconciled by exactly its own leader.
    let mut local_groups: Vec<saltator_cluster::LocalGroup> = rooms
        .iter()
        .filter_map(|(idx, shard)| {
            shard.hosted_handle().map(|h| {
                saltator_cluster::LocalGroup::new(
                    saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx).group(),
                    h.clone(),
                )
            })
        })
        .collect();
    local_groups.push(saltator_cluster::LocalGroup::new(
        saltator_userserver::USER_SHARD.group(),
        users.shard_handle().clone(),
    ));
    local_groups.push(saltator_cluster::LocalGroup::new(
        saltator_fedout::FED_OUT_SHARD.group(),
        fedout.shard_handle().clone(),
    ));
    let local_groups = saltator_cluster::LocalGroups::new(local_groups);
    let reconciler = saltator_cluster::spawn_reconciler(
        meta.clone(),
        local_groups.clone(),
        Duration::from_secs(2),
    );

    // The user-outbox drain (step 4 cross-shard move): the fed-out
    // leader copies legacy rows into its own shard and advances the
    // durable marker; exits once the marker covers the tail.
    saltator_federation::spawn_user_outbox_drain(users.clone(), fedout.clone());

    // Schema-migration supervisors: when a shard's stored schema trails
    // this binary's, the leader advances it through the log — but only
    // once every voter's binary confirms support (ClusterGate over the
    // internal Status RPC). Tasks exit once each shard is current. The
    // USER shard's v2 step carries an extra precondition: the fed-out
    // drain marker must cover its outbox tail (the marker-coordinated
    // cross-shard move; docs/design-federation-out.md §drain).
    for h in rooms
        .iter()
        .filter_map(|(_, s)| s.hosted_handle().cloned())
        .chain([fedout.shard_handle().clone()])
    {
        saltator_shard::migrate::spawn_migration_supervisor(
            h.clone(),
            saltator_cluster::ClusterGate::new(
                h.clone(),
                cfg.node.id,
                schemas.clone(),
                internal_tls.as_ref().map(|t| t.client()),
            ),
        );
    }
    saltator_shard::migrate::spawn_migration_supervisor(
        meta.shard_handle().clone(),
        saltator_cluster::ClusterGate::new(
            meta.shard_handle().clone(),
            cfg.node.id,
            schemas.clone(),
            internal_tls.as_ref().map(|t| t.client()),
        ),
    );
    saltator_shard::migrate::spawn_migration_supervisor(
        users.shard_handle().clone(),
        UserMigrationGate {
            cluster: saltator_cluster::ClusterGate::new(
                users.shard_handle().clone(),
                cfg.node.id,
                schemas.clone(),
                internal_tls.as_ref().map(|t| t.client()),
            ),
            users: users.clone(),
            fedout: fedout.clone(),
        },
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
    // Whether outbound federation may reach private/loopback addresses.
    // False in production; the destination is attacker-influenced and
    // resolved before any signature check (security review Vuln 5 / M2).
    let allow_private_ips = cfg.federation.allow_private_ips;
    // Signed client for outbound federation, shared by the CS `/join` path
    // and the event sender.
    let fed_client = Arc::new(saltator_federation::FederationClient::with_policy(
        signer.clone(),
        outbound_ca.as_deref(),
        allow_private_ips,
    ));
    // One key cache for the whole process. The CS import paths (remote join,
    // backfill) verify fetched events and so learn the authoring servers'
    // keys; inbound federation auth needs those same keys. Keeping separate
    // caches made every server pay a fresh key fetch — a full cold HTTPS
    // round trip, ~55ms — inside the auth extractor on the first request it
    // received from a server it had just finished talking to.
    let key_cache = Arc::new(saltator_federation::KeyCache::with_policy(
        outbound_ca.as_deref(),
        allow_private_ips,
    ));
    // Parsed here rather than at the use site so a malformed admin user id
    // fails the daemon at startup instead of silently never matching.
    let admin_users = cfg
        .client
        .admin_users
        .iter()
        .map(|u| {
            ruma::OwnedUserId::try_from(u.as_str())
                .map_err(|e| anyhow::anyhow!("client.admin_users: {u:?} is not a user id: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // Intent executors: every HOSTED room shard serves remote writes
    // (docs/design-room-sharding-phase2.md, 2a part 3), with this
    // stack's federation client powering healing ingests.
    for (idx, shard_server) in rooms.iter() {
        if shard_server.is_hosted() {
            executors.register(
                saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx).group(),
                saltator_federation::room_intent_executor(
                    shard_server.clone(),
                    Some(fed_client.clone()),
                    key_cache.clone(),
                ),
            );
        }
    }
    // Phase 2b: react to placement changes at runtime — start groups the
    // placement moves here, stand down groups it moves away. A no-op
    // while the RF floor keeps every group on every node.
    lifecycle::spawn(lifecycle::LifecycleCtx {
        meta: meta.clone(),
        rooms: rooms.clone(),
        registry: registry.clone(),
        executors: executors.clone(),
        local_groups: local_groups.clone(),
        signer: signer.clone(),
        stores: stores.clone(),
        node_id: cfg.node.id,
        internal_tls: internal_tls.as_ref().map(|t| t.client()),
        fed_client: fed_client.clone(),
        key_cache: key_cache.clone(),
        schemas: schemas.clone(),
    });

    let cs_state = saltator_cs_api::CsState::new(
        users.clone(),
        rooms.clone(),
        media,
        saltator_cs_api::CsConfig {
            server_name: server_name.clone(),
            default_room_version,
            registration_enabled: cfg.client.registration_enabled,
            registration_requires_token: cfg.client.registration_requires_token,
            max_upload_size: cfg.client.max_upload_size,
            well_known_client: cfg.client.well_known_client.clone(),
            rate_limits: if cfg.client.rate_limits_enabled {
                saltator_cs_api::RateLimitConfig::default()
            } else {
                saltator_cs_api::RateLimitConfig::disabled()
            },
            allow_internal_fetch: cfg.client.allow_internal_fetch,
            admin_users,
            server_notices_localpart: cfg.client.server_notices_localpart.clone(),
        },
    )
    .with_federation(fed_client.clone(), signer.clone(), key_cache.clone())
    .with_fedout(fedout.clone())
    .with_cluster(meta.clone());
    // Invalid registrations refuse the boot: a silently dropped bridge
    // is worse than a refused start. The set is shared with the
    // federation surface (query-on-miss for aliases/ghosts).
    let appservices = std::sync::Arc::new(match &cfg.client.appservice_registration_dir {
        Some(dir) => saltator_appservice::load_dir(dir)?,
        None => saltator_appservice::AppServices::default(),
    });
    let cs_state = if appservices.is_empty() {
        cs_state
    } else {
        cs_state.with_appservices(appservices.clone())
    };
    let cs_state = if cfg.client.oidc_providers.is_empty() {
        cs_state
    } else {
        // Refuse to start rather than serve a redirect the IdP will
        // reject: with no public base URL there is no callback to
        // register, and every SSO login would fail at the last hop.
        let base = cfg.client.public_base_url.clone().ok_or_else(|| {
            anyhow::anyhow!("client.oidc_providers requires client.public_base_url")
        })?;
        let providers = cfg
            .client
            .oidc_providers
            .iter()
            .map(|p| {
                if !p.scopes.iter().any(|s| s == "openid") {
                    anyhow::bail!(
                        "client.oidc_providers[{}].scopes must include \"openid\"",
                        p.idp_id
                    );
                }
                Ok(saltator_cs_api::OidcProviderConfig {
                    idp_id: p.idp_id.clone(),
                    name: p.name.clone(),
                    issuer: p.issuer.clone(),
                    client_id: p.client_id.clone(),
                    client_secret: p.client_secret.clone(),
                    scopes: p.scopes.clone(),
                    pkce: p.pkce,
                    allow_existing_users: p.allow_existing_users,
                    enable_registration: p.enable_registration,
                    localpart_claim: p.localpart_claim.clone(),
                    display_name_claim: p.display_name_claim.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for p in &providers {
            tracing::info!(idp = %p.idp_id, issuer = %p.issuer, "OIDC provider configured");
        }
        cs_state.with_oidc(providers, base)
    };
    // Typing/presence maps are shared with the federation surface (inbound
    // EDUs update them).
    let cs_typing = cs_state.typing_map();
    let cs_presence = cs_state.presence_map();
    // HTTP push: notify gateways about new events for users with pushers.
    let push_delivery = saltator_cs_api::spawn_push_delivery(cs_state.clone());
    // Appservice transaction push: interesting events to each registered
    // AS, against durable fed-out cursors, gated on fed-out leadership.
    let as_push = saltator_cs_api::spawn_appservice_push(cs_state.clone());
    // The measurement layer is applied here rather than inside the API
    // crates: it is the same layer on both surfaces, and neither
    // `saltator-cs-api` nor `saltator-federation` has to know it is being
    // measured. Applied to the finished router, so it sees the matched
    // route template rather than the raw path.
    let cs_router = saltator_metrics::instrument_http(saltator_cs_api::router(cs_state), "client");
    let cs_listener = tokio::net::TcpListener::bind(cfg.listeners.client).await?;
    tracing::info!(listen = %cfg.listeners.client, "client-server API listening");

    let edu_sink = Arc::new(saltator_cs_api::EphemeralEduSink::new(
        cs_typing.clone(),
        cs_presence.clone(),
    ));
    let delivery_backoff = Arc::new(saltator_federation::DeliveryBackoff::default());
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
        delivery_backoff: Some(delivery_backoff.clone()),
        appservices: if appservices.is_empty() {
            None
        } else {
            Some(Arc::new(saltator_appservice::AppServiceQuerier::new(
                appservices.clone(),
            )))
        },
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let fed_router =
        saltator_metrics::instrument_http(saltator_federation::router(fed_state), "federation");
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

    // Outbound federation: the unified delivery worker (step 4) owns all
    // outbound — PDUs against durable per-destination cursors, EDUs from
    // the fed-out outbox — gated on fed-out leadership.
    let delivery = saltator_federation::spawn_delivery_worker(
        fedout.clone(),
        rooms.clone(),
        fed_client,
        server_name.clone(),
        delivery_backoff.clone(),
    );

    // Metrics: the exporter's own listener, plus the tick that reads
    // current shard state. Gauges are sampled rather than written on
    // change so no hot path pays for them and none can drift from the
    // handle it describes.
    if let (Some(handle), Some(addr)) = (metrics_handle, cfg.listeners.metrics) {
        saltator_metrics::serve(addr, handle, shutdown_rx.clone()).await?;

        let sample_rooms = rooms.clone();
        let sample_users = users.clone();
        let sample_fedout = fedout.clone();
        let sample_meta = meta.clone();
        let sample_backoff = delivery_backoff.clone();
        let started = std::time::Instant::now();
        // NOTE: every shard group this node runs must appear below — a
        // group left out exports no gauges at all, and nothing errors
        // about the omission.
        saltator_metrics::spawn_sampler(SHARD_SAMPLE_INTERVAL, shutdown_rx.clone(), move || {
            for h in sample_rooms
                .iter()
                .filter_map(|(_, shard)| shard.hosted_handle().cloned())
                .chain([
                    sample_users.shard_handle().clone(),
                    sample_fedout.shard_handle().clone(),
                ])
            {
                // An Err from seq() is a storage failure, not "no
                // sequence": the gauge is left alone (None), but say why,
                // so a frozen saltator_shard_seq has an explanation.
                let seq = h
                    .seq()
                    .inspect_err(|e| {
                        tracing::warn!(shard = %h.shard(), error = %e, "metrics: shard seq read failed");
                    })
                    .ok();
                saltator_shard::metrics::sample_shard_gauges(
                    h.shard(),
                    h.is_leader(),
                    seq,
                    h.voter_ids().len(),
                );
            }
            // The metadata group has no shard app and so no sequence of
            // its own; its leadership is the one every other placement
            // decision depends on, which is why it is sampled at all.
            saltator_shard::metrics::sample_shard_gauges(
                saltator_shard::ShardId::METADATA,
                sample_meta.is_leader(),
                None,
                sample_meta.voter_ids().len(),
            );
            // The backoff count rides the same tick as every other
            // current-state gauge; non-leaders report zero, because only
            // the delivering node's backoff map describes anything.
            saltator_federation::metrics::sample_delivery_gauges(
                &sample_backoff,
                sample_fedout.shard_handle().is_leader(),
            );
            saltator_metrics::set_uptime(started.elapsed());
        });
    }

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
        shutdown_signal().await;
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    // Block until a shutdown signal drives the internal server to return.
    internal_task.await??;
    cs_task.await??;
    fed_task.await??;
    delivery.abort();
    push_delivery.abort();
    if let Some(task) = &as_push {
        task.abort();
    }
    reconciler.abort();
    projection.abort();
    for (_, shard) in rooms.iter() {
        shard.shutdown().await?;
    }
    users.shutdown().await?;
    meta.shutdown().await?;
    tracing::info!("saltator stopped");
    Ok(())
}

/// The user shard's migration gate: the cluster-wide voter check plus
/// the v2 precondition — the fed-out drain marker (read from the LOCAL
/// replica; cross-shard reads are free) must cover the legacy outbox's
/// tail before the drop step may be proposed.
struct UserMigrationGate {
    cluster: saltator_cluster::ClusterGate,
    users: Arc<saltator_userserver::UserServer>,
    fedout: Arc<saltator_fedout::FedOutServer>,
}

impl saltator_shard::migrate::MigrationGate for UserMigrationGate {
    async fn voters_ready(&self, shard: saltator_shard::ShardId, target: u32) -> bool {
        if !self.cluster.voters_ready(shard, target).await {
            return false;
        }
        if target == 2 {
            let tail = self.users.store().edu_outbox_tail().unwrap_or(u64::MAX);
            let marker = self.fedout.store().drain_marker().unwrap_or(0);
            if marker < tail {
                tracing::info!(tail, marker, "user v2 migration waiting on outbox drain");
                return false;
            }
        }
        true
    }
}

/// Resolve when the operating system asks the process to stop.
///
/// SIGTERM matters as much as ctrl-c: it's what `docker stop` (and thus
/// Complement teardown) sends, and as PID 1 in a container the default
/// disposition would ignore it.
#[cfg(unix)]
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

/// Windows has no SIGTERM. The console-control events are the nearest
/// equivalents: ctrl-c and ctrl-break from a terminal, CTRL_CLOSE when the
/// console window goes away, CTRL_SHUTDOWN when the system does.
#[cfg(windows)]
async fn shutdown_signal() {
    use tokio::signal::windows;
    let mut ctrl_break = windows::ctrl_break().expect("installing ctrl-break handler");
    let mut ctrl_close = windows::ctrl_close().expect("installing ctrl-close handler");
    let mut ctrl_shutdown = windows::ctrl_shutdown().expect("installing ctrl-shutdown handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = ctrl_break.recv() => {}
        _ = ctrl_close.recv() => {}
        _ = ctrl_shutdown.recv() => {}
    }
}
