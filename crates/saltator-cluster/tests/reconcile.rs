//! Two-node shard-group reconciliation (spec.md §4.2): a data shard group,
//! bootstrapped single-voter on node 1, gains node 2 as a voter purely by
//! the reconciler converging its membership to the metadata placement — the
//! same path a real room/user group takes when a node joins.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::network::GrpcRaftNetworkFactory;
use saltator_cluster::{
    join_cluster, reconcile_once, serve_internal, ClusterConfig, LocalGroup, MetadataHandle,
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

#[tokio::test]
async fn reconciler_admits_a_new_replica_to_a_shard_group() {
    let dir = tempfile::tempdir().unwrap();
    let addr1 = ephemeral_addr();
    let addr2 = ephemeral_addr();
    let room_group = ShardId::new(Keyspace::Room, 0).group();

    // --- Node 1: metadata + control plane + a bootstrapped Room/0 ---
    let e1 = Arc::new(RocksEngine::open(&dir.path().join("n1")).unwrap());
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
    let _s1 = spawn_serve(m1.clone(), reg1, addr1);

    // --- Node 2: joins metadata, then starts Room/0 uninitialized ---
    let e2 = Arc::new(RocksEngine::open(&dir.path().join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start(2, e2.clone(), None, Some(&reg2))
        .await
        .unwrap();
    let _s2 = spawn_serve(m2.clone(), reg2.clone(), addr2);
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

    // --- Reconcile on node 1 (the room leader) until node 2 is a voter ---
    let groups = vec![LocalGroup::new(room_group, room1.clone())];
    let both: std::collections::BTreeSet<u64> = [1, 2].into_iter().collect();
    let mut ok = false;
    for _ in 0..30 {
        reconcile_once(&m1, &groups).await;
        if room1.voter_ids() == both && room2.voter_ids() == both {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        ok,
        "reconciler did not make node 2 a voter: {:?}",
        room2.voter_ids()
    );

    // A write on the room leader now replicates to node 2's applied state.
    room1.propose(b"hello-from-node-1".to_vec()).await.unwrap();
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

    m1.shutdown().await.unwrap();
    m2.shutdown().await.unwrap();
    room1.shutdown().await.unwrap();
    room2.shutdown().await.unwrap();
}
