//! Two-node shard-group reconciliation (spec.md §4.2): a data shard group,
//! bootstrapped single-voter on node 1, gains node 2 as a voter purely by
//! the reconciler converging its membership to the metadata placement — the
//! same path a real room/user group takes when a node joins. And the way
//! back out: draining node 2 releases the replica by the same mechanism
//! (docs/design-admin-identity.md slice 6).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::network::GrpcRaftNetworkFactory;
use saltator_cluster::{
    join_cluster, reconcile_once, serve_internal, ClusterConfig, LocalGroup, MetadataHandle,
    NodeStatus,
};
use saltator_shard::{ApplyCtx, ShardApp, ShardHandle, ShardId, ShardRegistry, APP_TABLE_MIN};
use saltator_store::{Keyspace, Result as StoreResult, RocksEngine};

/// Minimal state machine: each command is stored verbatim under a fixed key,
/// so a read reflects the last committed command — enough to observe that
/// replication reached a follower.
struct KvApp;

impl ShardApp for KvApp {
    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        ctx.put(APP_TABLE_MIN, b"v", command.to_vec());
        Ok(Vec::new())
    }
}

fn ephemeral_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn spawn_serve(
    meta: MetadataHandle,
    registry: ShardRegistry,
    addr: std::net::SocketAddr,
) -> tokio::sync::oneshot::Sender<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_internal(
        meta,
        registry,
        "example.org".into(),
        vec![],
        addr,
        async {
            let _ = stop_rx.await;
        },
    ));
    stop_tx
}

async fn eventually(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    loop {
        if f() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Start a `Room/0` shard group on `engine` in `registry`, bootstrapping it
/// single-voter iff `bootstrap` is set.
async fn start_room(
    node_id: u64,
    engine: Arc<RocksEngine>,
    registry: &ShardRegistry,
    bootstrap_addr: Option<String>,
) -> ShardHandle {
    let room = ShardId::new(Keyspace::Room, 0);
    ShardHandle::start(
        room,
        node_id,
        engine,
        Arc::new(KvApp),
        GrpcRaftNetworkFactory::new(room),
        bootstrap_addr,
        Some(registry),
    )
    .await
    .unwrap()
}

/// A live two-node cluster: metadata group on both, `Room/0` running on
/// both, node 1 leading and node 2 admitted but not yet a room voter.
struct TwoNodes {
    m1: MetadataHandle,
    m2: MetadataHandle,
    room1: ShardHandle,
    room2: ShardHandle,
    room_group: u64,
    _serve1: tokio::sync::oneshot::Sender<()>,
    _serve2: tokio::sync::oneshot::Sender<()>,
}

impl TwoNodes {
    /// Run the reconciler on node 1 (the room leader) until it reports the
    /// voter set `want`.
    ///
    /// The leader's view is the authority, and it is the only view that
    /// can be asserted on for a *removal*: a node dropped from the group
    /// stops receiving the log, so whether it ever applies the entry that
    /// removed it is a race with its own eviction.
    async fn reconcile_until_voters(&self, want: &BTreeSet<u64>) -> bool {
        let groups = vec![LocalGroup::new(self.room_group, self.room1.clone())];
        for _ in 0..30 {
            reconcile_once(&self.m1, &groups).await;
            if self.room1.voter_ids() == *want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    async fn shutdown(self) {
        self.m1.shutdown().await.unwrap();
        self.m2.shutdown().await.unwrap();
        self.room1.shutdown().await.unwrap();
        self.room2.shutdown().await.unwrap();
    }
}

async fn two_nodes(dir: &std::path::Path) -> TwoNodes {
    let addr1 = ephemeral_addr();
    let addr2 = ephemeral_addr();
    let room_group = ShardId::new(Keyspace::Room, 0).group();

    // --- Node 1: metadata + control plane + a bootstrapped Room/0 ---
    let e1 = Arc::new(RocksEngine::open(&dir.join("n1")).unwrap());
    let reg1 = ShardRegistry::new();
    let m1 = MetadataHandle::start(1, e1.clone(), Some(addr1.to_string()), Some(&reg1))
        .await
        .unwrap();
    m1.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let config = ClusterConfig {
        room_shards: 1,
        user_shards: 0,
        replication_factor: 3,
    };
    m1.bootstrap_cluster(config, addr1.to_string())
        .await
        .unwrap();
    let room1 = start_room(1, e1, &reg1, Some(addr1.to_string())).await;
    room1
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    let serve1 = spawn_serve(m1.clone(), reg1, addr1);

    // --- Node 2: joins metadata, then starts Room/0 uninitialized ---
    let e2 = Arc::new(RocksEngine::open(&dir.join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start(2, e2.clone(), None, Some(&reg2))
        .await
        .unwrap();
    let serve2 = spawn_serve(m2.clone(), reg2.clone(), addr2);
    join_cluster(
        &[addr1.to_string()],
        2,
        &addr2.to_string(),
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    m2.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    // Node 2 now knows (via replicated placement) it should host Room/0, so
    // it starts the group uninitialized, ready to receive the learner add.
    let room2 = start_room(2, e2, &reg2, None).await;

    // Placement should already list both nodes for Room/0.
    assert!(
        eventually(Duration::from_secs(10), || {
            m2.placement_local()
                .map(|p| p.replicas(room_group).contains(&2))
                .unwrap_or(false)
        })
        .await,
        "placement never listed node 2 for the room group"
    );

    TwoNodes {
        m1,
        m2,
        room1,
        room2,
        room_group,
        _serve1: serve1,
        _serve2: serve2,
    }
}

#[tokio::test]
async fn reconciler_admits_a_new_replica_to_a_shard_group() {
    let dir = tempfile::tempdir().unwrap();
    let c = two_nodes(dir.path()).await;

    // --- Reconcile on node 1 (the room leader) until node 2 is a voter ---
    let both: BTreeSet<u64> = [1, 2].into_iter().collect();
    assert!(
        c.reconcile_until_voters(&both).await,
        "reconciler did not make node 2 a voter: {:?}",
        c.room1.voter_ids()
    );
    // And node 2 learns it is one — unlike a removal, an addition always
    // reaches the node it concerns.
    let room2 = c.room2.clone();
    assert!(
        eventually(Duration::from_secs(10), || room2.voter_ids() == both).await,
        "node 2 never saw itself join the group: {:?}",
        c.room2.voter_ids()
    );

    // A write on the room leader now replicates to node 2's applied state.
    c.room1
        .propose(b"hello-from-node-1".to_vec())
        .await
        .unwrap();
    let room2 = c.room2.clone();
    assert!(
        eventually(Duration::from_secs(10), || {
            room2
                .read_ctx()
                .get(APP_TABLE_MIN, b"v")
                .ok()
                .flatten()
                .as_deref()
                == Some(b"hello-from-node-1".as_slice())
        })
        .await,
        "room write did not replicate to node 2"
    );

    c.shutdown().await;
}

/// The way out, end to end (docs/design-admin-identity.md slice 6): drain
/// takes node 2 out of the placement, the ordinary reconciler releases the
/// replica it was holding, and only then may the node be removed from the
/// metadata group.
#[tokio::test]
async fn draining_releases_a_replica_and_then_the_node_can_be_removed() {
    let dir = tempfile::tempdir().unwrap();
    let c = two_nodes(dir.path()).await;
    let both: BTreeSet<u64> = [1, 2].into_iter().collect();
    let alone: BTreeSet<u64> = [1].into_iter().collect();
    assert!(c.reconcile_until_voters(&both).await, "setup: node 2 voter");

    // Removal before draining is refused — an active node still holds
    // replicas, and cutting it out of the metadata group is what would
    // strand them.
    let err = c.m1.remove_node(2).await.unwrap_err();
    assert!(err.to_string().contains("drained"), "{err}");

    // Drain: node 2 leaves the placement but stays in the roster, which is
    // how it keeps hearing that it should stand down.
    let roster = c.m1.drain_node(2).await.unwrap();
    assert_eq!(roster[&2].status, NodeStatus::Draining);
    assert_eq!(roster.len(), 2, "draining is not removal");
    assert!(
        !c.m1
            .placement()
            .await
            .unwrap()
            .replicas(c.room_group)
            .contains(&2),
        "a draining node must not be a placement target"
    );

    // The ordinary reconciler — no drain-specific code path — demotes it.
    assert!(
        c.reconcile_until_voters(&alone).await,
        "reconciler did not release node 2: {:?}",
        c.room1.voter_ids()
    );

    // Now removal is allowed, and takes it out of the metadata group too.
    let roster = c.m1.remove_node(2).await.unwrap();
    assert_eq!(roster.keys().copied().collect::<Vec<_>>(), [1]);
    assert!(
        eventually(Duration::from_secs(10), || c.m1.voter_ids() == alone).await,
        "node 2 is still a metadata voter: {:?}",
        c.m1.voter_ids()
    );

    // The cluster still works with what is left.
    c.room1.propose(b"after-drain".to_vec()).await.unwrap();

    c.shutdown().await;
}
