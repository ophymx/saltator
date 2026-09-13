//! Room-shard lifecycle (docs/design-room-sharding-phase2.md, phase 2b):
//! a per-node task on the placement watch that starts a group when the
//! placement moves it onto this node and stands it down — handle swap,
//! deregistration, data removal — when it moves away.
//!
//! Movement itself is the existing machinery: the group leader's
//! reconciler converges membership toward the placement (adding this
//! node as a learner, catching it up via Raft snapshot, promoting it —
//! or demoting a departing replica). This driver supplies the halves
//! that were missing at runtime: starting the local group at all,
//! swapping the router slot between hosted and remote, and cleaning up
//! after a handoff.
//!
//! With the RF floor on (the default), the placement lists every node
//! for every group and this task never acts — the phase-3 policy flip
//! is what makes it routine.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::{LocalGroup, LocalGroups, MetadataHandle, NodeInfo};
use saltator_roomserver::{RoomServer, RoomShards, ServerSigner};
use saltator_shard::{ExecutorRegistry, ReadOp, ReadValue, ShardId, ShardRegistry};
use saltator_store::Keyspace;

/// How long a departing replica waits for the (leader-confirmed) voter
/// set to exclude it before re-checking. Departure is not time-critical;
/// the gate must simply never pass early.
const DEPARTURE_POLL: Duration = Duration::from_secs(5);
/// Idle re-check cadence — the placement watch wakes us sooner.
const IDLE_TICK: Duration = Duration::from_secs(30);

/// Everything a gained group needs wired up, owned by the daemon and
/// borrowed by the driver.
pub struct LifecycleCtx {
    pub meta: MetadataHandle,
    pub rooms: Arc<RoomShards>,
    pub registry: ShardRegistry,
    pub executors: ExecutorRegistry,
    pub local_groups: LocalGroups,
    pub signer: Arc<ServerSigner>,
    pub stores: saltator_store::Stores,
    pub node_id: u64,
    pub internal_tls: Option<saltator_cluster::tls::ClientTlsConfig>,
    pub fed_client: Arc<saltator_federation::FederationClient>,
    pub key_cache: Arc<saltator_federation::KeyCache>,
    pub schemas: Vec<(u32, u32)>,
}

/// Spawn the driver. Runs until aborted.
pub fn spawn(ctx: LifecycleCtx) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watch = ctx.meta.subscribe();
        loop {
            if let Err(e) = reconcile_lifecycle(&ctx).await {
                tracing::warn!(error = %e, "shard lifecycle pass failed");
            }
            // Wake on any metadata change (placement writes included) or
            // the idle tick; lagged is fine — each pass re-reads state.
            tokio::select! {
                _ = watch.recv() => {}
                _ = tokio::time::sleep(IDLE_TICK) => {}
            }
        }
    })
}

async fn reconcile_lifecycle(ctx: &LifecycleCtx) -> anyhow::Result<()> {
    let placement = ctx.meta.placement_local()?;
    let roster = ctx.meta.roster_local()?;
    for idx in 0..ctx.rooms.count() {
        let shard = ShardId::new(Keyspace::Room, idx);
        let replicas = placement.replicas(shard.group());
        if replicas.is_empty() {
            continue; // unplaced: leave alone
        }
        let placed_here = replicas.contains(&ctx.node_id);
        let hosted_here = ctx.rooms.by_index(idx).is_some_and(|s| s.is_hosted());
        if placed_here && !hosted_here {
            gain_group(ctx, shard).await?;
        } else if !placed_here && hosted_here {
            lose_group(ctx, shard, replicas, &roster).await?;
        }
    }
    Ok(())
}

/// Pre-seed a pristine local shard from a current replica's checkpoint
/// (bulk FetchCheckpoint, 2b part 2): the group then boots looking like
/// a node restarted after a snapshot install, and the leader replicates
/// only the log tail — it never builds or ships a snapshot of its own.
/// Best-effort: any failure clears the partial install and falls back
/// to the Raft snapshot path.
pub async fn pre_seed(
    stores: &saltator_store::Stores,
    shard: ShardId,
    replica_addrs: &[String],
    tls: Option<&saltator_cluster::tls::ClientTlsConfig>,
) {
    match saltator_shard::transfer::is_pristine(&*stores.state, shard) {
        Ok(true) => {}
        _ => return, // has history (or unreadable): the Raft path owns it
    }
    if replica_addrs.is_empty() {
        return;
    }
    let snap =
        match saltator_cluster::remote::fetch_checkpoint(shard.group(), replica_addrs, tls).await {
            Ok(s) => s,
            Err(e) => {
                tracing::info!(%shard, error = %e,
                    "pre-seed unavailable; joining via raft snapshot");
                return;
            }
        };
    if snap.last_applied.is_none() {
        return; // empty group: nothing to seed
    }
    let rows = snap.kv.len();
    match saltator_shard::transfer::install(stores, shard, snap) {
        Ok(()) => {
            tracing::info!(%shard, rows, "pre-seeded room shard from checkpoint");
        }
        Err(e) => {
            tracing::warn!(%shard, error = %e, "pre-seed install failed; clearing");
            let _ = saltator_shard::transfer::clear(stores, shard);
        }
    }
}

/// Placement moved a group ONTO this node: start it (uninitialized —
/// the group's leader folds us in as learner → voter), and swap the
/// router slot to the hosted handle once we are a voter, i.e. caught up.
async fn gain_group(ctx: &LifecycleCtx, shard: ShardId) -> anyhow::Result<()> {
    tracing::info!(%shard, "lifecycle: placement gained this group; starting it");
    // Bulk pre-seed before the group starts (best-effort). Candidates
    // are the CURRENT holders — during a move the placement names the
    // destination (us), so the state lives with nodes the placement no
    // longer lists: try the placement's other replicas first, then the
    // rest of the roster (non-holders answer NotFound and are skipped).
    let placement = ctx.meta.placement_local()?;
    let roster = ctx.meta.roster_local()?;
    let addrs = seed_candidates(placement.replicas(shard.group()), &roster, ctx.node_id);
    pre_seed(&ctx.stores, shard, &addrs, ctx.internal_tls.as_ref()).await;
    let server = RoomServer::start_shard(
        shard,
        ctx.node_id,
        ctx.stores.clone(),
        ctx.signer.clone(),
        saltator_cluster::network::GrpcRaftNetworkFactory::new(shard)
            .with_tls(ctx.internal_tls.clone()),
        None, // never bootstrap: the group exists elsewhere
        Some(&ctx.registry),
    )
    .await?;
    let handle = server.shard_handle().clone();
    // Reconciler visibility FIRST: the leader learns to add us from the
    // placement, but add_learner errors until our group is running —
    // which it now is; the voter wait below is what the leader unblocks.
    ctx.local_groups
        .add(LocalGroup::new(shard.group(), handle.clone()));

    // Swap to hosted only once this node is a VOTER: promotion implies
    // the leader considered us caught up, so local reads serve real
    // state, not an empty store.
    let node_id = ctx.node_id;
    let schemas = ctx.schemas.clone();
    let internal_tls = ctx.internal_tls.clone();
    let rooms = ctx.rooms.clone();
    let executors = ctx.executors.clone();
    let fed_client = ctx.fed_client.clone();
    let key_cache = ctx.key_cache.clone();
    tokio::spawn(async move {
        loop {
            if handle.voter_ids().contains(&node_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        saltator_shard::migrate::spawn_migration_supervisor(
            handle.clone(),
            saltator_cluster::ClusterGate::new(handle.clone(), node_id, schemas, internal_tls),
        );
        executors.register(
            shard.group(),
            saltator_federation::room_intent_executor(server.clone(), Some(fed_client), key_cache),
        );
        rooms.replace(shard.index, server);
        tracing::info!(%shard, "lifecycle: group hosted (caught up, promoted)");
    });
    Ok(())
}

/// Checkpoint-source candidates for one group: the placement's other
/// replicas first (the steady-state holders), then every other roster
/// node — during a move, the state lives with nodes the placement no
/// longer lists.
pub fn seed_candidates(
    replicas: &[u64],
    roster: &saltator_cluster::Roster,
    self_node: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |nid: &u64| {
        if *nid == self_node {
            return;
        }
        if let Some(info) = roster.get(nid) {
            if !out.contains(&info.advertise_addr) {
                out.push(info.advertise_addr.clone());
            }
        }
    };
    for nid in replicas {
        push(nid);
    }
    for nid in roster.keys() {
        push(nid);
    }
    out
}

/// Placement moved a group OFF this node: wait for the leader-confirmed
/// voter set to exclude us (the reconciler demotes us), then swap the
/// router slot to a remote handle, stand the local group down, and drop
/// its data.
async fn lose_group(
    ctx: &LifecycleCtx,
    shard: ShardId,
    replicas: &[u64],
    roster: &saltator_cluster::Roster,
) -> anyhow::Result<()> {
    let addr_of = |nid: &u64| roster.get(nid).map(|i: &NodeInfo| i.advertise_addr.clone());
    let addrs: Vec<String> = replicas.iter().filter_map(addr_of).collect();
    if addrs.is_empty() {
        anyhow::bail!("group {shard}: placement names no reachable replica");
    }
    let remote_backend = Arc::new(saltator_cluster::remote::RemoteShard::new(
        shard.group(),
        addrs,
        ctx.internal_tls.clone(),
    ));

    // Departure gate: the REMAINING replicas' leader must report a voter
    // set that excludes us. Our own membership view can read
    // stale-as-voter forever (we may never receive our own removal
    // entry), so the answer has to come from over there.
    let voters = match remote_backend.read(&ReadOp::Voters).await {
        Ok(ReadValue::Voters(v)) => v,
        Ok(other) => anyhow::bail!("voters read returned {other:?}"),
        Err(e) => {
            tracing::debug!(%shard, error = %e, "lifecycle: departure gate unreadable; retrying");
            tokio::time::sleep(DEPARTURE_POLL).await;
            return Ok(());
        }
    };
    if voters.contains(&ctx.node_id) {
        tracing::debug!(%shard, "lifecycle: still a voter; departure deferred");
        return Ok(());
    }

    tracing::info!(%shard, "lifecycle: handed off; standing group down");
    let Some(server) = ctx.rooms.by_index(shard.index) else {
        return Ok(());
    };
    // Order: swap first (new requests go remote), then deregister (no
    // more inbound raft/read routing), then stop, then delete. A request
    // in flight on the old handle finishes against a live engine — the
    // delete races it only across the swap window, which is the
    // accepted 2b-part-1 tradeoff (noted in the design doc).
    ctx.rooms.replace(
        shard.index,
        RoomServer::remote(remote_backend, ctx.signer.clone()),
    );
    ctx.executors.deregister(shard.group());
    ctx.registry.deregister(shard.group());
    ctx.local_groups.remove(shard.group());
    if let Some(handle) = server.hosted_handle() {
        let _ = handle.shutdown().await;
    }
    // Whole-shard range delete on both storage roles: the log store
    // (entries/vote) and the state store (applied tables).
    let (start, end) = saltator_store::shard_bounds(shard.keyspace, shard.index);
    for engine in [&ctx.stores.log, &ctx.stores.state] {
        let mut wb = saltator_store::WriteBatch::new();
        wb.delete_range(start.clone(), end.clone());
        engine.write_batch(wb)?;
    }
    tracing::info!(%shard, "lifecycle: local replica removed");
    Ok(())
}
