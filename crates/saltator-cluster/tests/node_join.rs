//! Two-node metadata-group join (spec.md §4.4): a second node, started
//! uninitialized, joins node 1's metadata group via the Join control RPC.
//! This is the first exercise of the full multi-node Raft path — vote,
//! append-entries, membership change, and log replication over real gRPC.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::types::MetaCommand;
use saltator_cluster::{join_cluster, serve_internal, ClusterConfig, MetadataHandle};
use saltator_shard::ShardRegistry;
use saltator_store::RocksEngine;

/// Bind-and-release to pick a free port. Racy in principle; fine for tests.
fn ephemeral_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Spawn the internal RPC server for `meta` on `addr`, returning a stop
/// handle.
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

/// Poll `f` until it returns true or the deadline passes.
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

#[tokio::test]
async fn second_node_joins_metadata_group() {
    let dir = tempfile::tempdir().unwrap();
    let addr1 = ephemeral_addr();
    let addr2 = ephemeral_addr();

    // Node 1 bootstraps a single-voter metadata group and serves RPC.
    let e1 = Arc::new(RocksEngine::open(&dir.path().join("n1")).unwrap());
    let reg1 = ShardRegistry::new();
    let m1 = MetadataHandle::start(1, e1, Some(addr1.to_string()), Some(&reg1))
        .await
        .unwrap();
    m1.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let _s1 = spawn_serve(m1.clone(), reg1, addr1);

    // Node 2 starts uninitialized (no bootstrap addr → awaiting join) and
    // serves RPC so the leader can replicate to it.
    let e2 = Arc::new(RocksEngine::open(&dir.path().join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start(2, e2, None, Some(&reg2))
        .await
        .unwrap();
    let _s2 = spawn_serve(m2.clone(), reg2, addr2);

    // Join node 2 through node 1 as its seed.
    join_cluster(
        &[addr1.to_string()],
        2,
        &addr2.to_string(),
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    // Node 2 now sees node 1 as leader and both nodes are voters.
    let leader = m2.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    assert_eq!(leader, 1, "node 2 should follow node 1");
    let both: std::collections::BTreeSet<u64> = [1, 2].into_iter().collect();
    assert_eq!(m1.voter_ids(), both, "leader's voter set");
    assert!(
        eventually(Duration::from_secs(10), || m2.voter_ids() == both).await,
        "node 2 never observed the two-voter membership: {:?}",
        m2.voter_ids()
    );

    // A write on the leader replicates to node 2's applied state, proving
    // real log replication over the gRPC transport.
    m1.write(MetaCommand::Set {
        key: "shared".into(),
        value: b"replicated".to_vec(),
    })
    .await
    .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || {
            m2.read_local("shared").ok().flatten().as_deref() == Some(b"replicated".as_slice())
        })
        .await,
        "write did not replicate to node 2"
    );

    m1.shutdown().await.unwrap();
    m2.shutdown().await.unwrap();
}

#[tokio::test]
async fn placement_recomputes_and_replicates_on_join() {
    let dir = tempfile::tempdir().unwrap();
    let addr1 = ephemeral_addr();
    let addr2 = ephemeral_addr();

    // Node 1 bootstraps the cluster control plane (config + roster +
    // placement) with a two-way replication factor.
    let e1 = Arc::new(RocksEngine::open(&dir.path().join("n1")).unwrap());
    let reg1 = ShardRegistry::new();
    let m1 = MetadataHandle::start(1, e1, Some(addr1.to_string()), Some(&reg1))
        .await
        .unwrap();
    m1.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let config = ClusterConfig {
        room_shards: 4,
        user_shards: 2,
        replication_factor: 2,
    };
    m1.bootstrap_cluster(config.clone(), addr1.to_string())
        .await
        .unwrap();
    let _s1 = spawn_serve(m1.clone(), reg1, addr1);

    // Before any peer, every group is placed on node 1 alone.
    let placement = m1.placement().await.unwrap();
    for g in config.data_groups() {
        assert_eq!(placement.replicas(g), &[1], "group {g} pre-join");
    }

    // Node 2 joins.
    let e2 = Arc::new(RocksEngine::open(&dir.path().join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start(2, e2, None, Some(&reg2))
        .await
        .unwrap();
    let _s2 = spawn_serve(m2.clone(), reg2, addr2);
    join_cluster(
        &[addr1.to_string()],
        2,
        &addr2.to_string(),
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    // The leader's placement now spreads every group across both nodes
    // (RF=2, two nodes), and node 2 is in the roster.
    let placement = m1.placement().await.unwrap();
    let both: std::collections::BTreeSet<u64> = [1, 2].into_iter().collect();
    for g in config.data_groups() {
        let replicas: std::collections::BTreeSet<u64> =
            placement.replicas(g).iter().copied().collect();
        assert_eq!(replicas, both, "group {g} should be on both nodes");
    }
    assert!(
        m1.roster().await.unwrap().contains_key(&2),
        "node 2 in roster"
    );

    // And the recomputed placement replicates to node 2's applied state —
    // how a joining node learns which groups it must host.
    assert!(
        eventually(Duration::from_secs(10), || {
            let p = m2.placement_local().unwrap_or_default();
            config
                .data_groups()
                .iter()
                .all(|g| p.replicas(*g).contains(&2))
        })
        .await,
        "placement did not replicate to node 2"
    );

    m1.shutdown().await.unwrap();
    m2.shutdown().await.unwrap();
}
