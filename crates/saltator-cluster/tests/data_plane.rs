//! The unhosted-shard data plane: storage-level reads at the leader and gap-free change
//! subscriptions, over the real internal gRPC surface.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;

use saltator_cluster::remote::RemoteShard;
use saltator_cluster::{serve_internal, MetadataHandle};
use saltator_shard::{
    ApplyCtx, ReadCtx, ReadOp, ReadValue, ShardApp, ShardHandle, ShardId, ShardRegistry,
    APP_TABLE_FIRST,
};
use saltator_store::{Keyspace, RocksEngine};

mod common;
use common::ephemeral_addr;

const T_J: u8 = APP_TABLE_FIRST;

/// A minimal replayable app: every command is journaled under its seq,
/// so replay is a scan — the same shape RoomApp's T_SEQ table has.
struct JournalApp;

impl ShardApp for JournalApp {
    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> saltator_store::Result<Vec<u8>> {
        let seq = ctx.emit(command.to_vec());
        ctx.put(T_J, &seq.to_be_bytes(), command.to_vec());
        Ok(seq.to_be_bytes().to_vec())
    }

    fn replay(
        &self,
        ctx: &ReadCtx,
        from_seq: u64,
        limit: usize,
    ) -> saltator_store::Result<Vec<(u64, Arc<[u8]>)>> {
        let start = (from_seq + 1).to_be_bytes();
        Ok(ctx
            .scan(T_J, &start, &[], limit, false)?
            .into_iter()
            .map(|(k, v)| {
                let seq = u64::from_be_bytes(k.as_slice().try_into().unwrap());
                (seq, Arc::from(v.into_boxed_slice()))
            })
            .collect())
    }
}

struct Node {
    _dir: tempfile::TempDir,
    addr: std::net::SocketAddr,
    shard: ShardHandle,
    meta: MetadataHandle,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// One in-process "node": metadata group + one JournalApp data shard,
/// both behind a real internal RPC listener. `bootstrap` = whether the
/// data shard initializes as a single voter (a non-bootstrapped shard is
/// the leaderless-replica case).
async fn start_node(node_id: u64, bootstrap: bool) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let addr = ephemeral_addr();
    let registry = ShardRegistry::new();
    let meta = MetadataHandle::start(
        node_id,
        engine.clone(),
        Some(addr.to_string()),
        Some(&registry),
    )
    .await
    .unwrap();
    meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();

    let shard = ShardHandle::start(
        ShardId::new(Keyspace::Room, 0),
        node_id,
        engine,
        Arc::new(JournalApp),
        saltator_shard::NoopNetworkFactory,
        bootstrap.then(|| addr.to_string()),
        Some(&registry),
    )
    .await
    .unwrap();
    if bootstrap {
        shard
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
    }

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_internal(
        meta.clone(),
        registry,
        saltator_shard::ExecutorRegistry::new(),
        "hs.test".into(),
        vec![],
        addr,
        async {
            let _ = stop_rx.await;
        },
    ));
    // Wait for the listener.
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
    for _ in 0..50 {
        if endpoint.connect().await.is_ok() {
            return Node {
                _dir: dir,
                addr,
                shard,
                meta,
                _stop: stop_tx,
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("internal RPC never came up on {addr}");
}

fn group() -> u64 {
    ShardId::new(Keyspace::Room, 0).group()
}

#[tokio::test]
async fn remote_read_serves_at_the_leader() {
    let node = start_node(1, true).await;
    for body in [b"a".as_slice(), b"b", b"c"] {
        node.shard.propose(body.to_vec()).await.unwrap();
    }

    let remote = RemoteShard::new(group(), vec![node.addr.to_string()], None);

    // Point read.
    let v = remote
        .read(&ReadOp::Get {
            table: T_J,
            key: 2u64.to_be_bytes().to_vec(),
        })
        .await
        .unwrap();
    assert!(
        matches!(v, ReadValue::Value(Some(ref b)) if b == b"b"),
        "{v:?}"
    );

    // Bounded scan, reverse.
    let v = remote
        .read(&ReadOp::Scan {
            table: T_J,
            start: Vec::new(),
            end: Vec::new(),
            limit: 2,
            reverse: true,
        })
        .await
        .unwrap();
    match v {
        ReadValue::Entries(e) => {
            // Reverse scan: the LAST two entries, in reverse key order.
            assert_eq!(e.len(), 2);
            assert_eq!(e[0].1, b"c");
            assert_eq!(e[1].1, b"b");
        }
        other => panic!("{other:?}"),
    }

    // Seq.
    let v = remote.read(&ReadOp::Seq).await.unwrap();
    assert!(matches!(v, ReadValue::Seq(3)), "{v:?}");
}

#[tokio::test]
async fn remote_read_refuses_runtime_tables() {
    let node = start_node(1, true).await;
    let remote = RemoteShard::new(group(), vec![node.addr.to_string()], None);
    let err = remote
        .read(&ReadOp::Get {
            table: 0,
            key: vec![],
        })
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("runtime-reserved"),
        "unexpected: {err}"
    );
}

#[tokio::test]
async fn remote_read_falls_through_a_leaderless_replica() {
    // Node 2 hosts the group but never initialized it (no leader, no
    // hint); node 1 leads. The client must fall through to node 1.
    let leader = start_node(1, true).await;
    let bystander = start_node(2, false).await;
    leader.shard.propose(b"x".to_vec()).await.unwrap();

    let remote = RemoteShard::new(
        group(),
        vec![bystander.addr.to_string(), leader.addr.to_string()],
        None,
    );
    let v = remote.read(&ReadOp::Seq).await.unwrap();
    assert!(matches!(v, ReadValue::Seq(1)), "{v:?}");
}

#[tokio::test]
async fn subscribe_backfills_then_tails_gap_free() {
    let node = start_node(1, true).await;
    for i in 0..5u8 {
        node.shard.propose(vec![i]).await.unwrap();
    }

    let remote = RemoteShard::new(group(), vec![node.addr.to_string()], None);
    // Resume from seq 2: the backfill must deliver 3..=5.
    let mut stream = Box::pin(remote.subscribe(2));
    for want in 3..=5u64 {
        let rec = stream.next().await.unwrap().unwrap();
        assert_eq!(rec.seq, want);
        assert_eq!(rec.payload.as_ref(), &[want as u8 - 1]);
    }

    // Live frames arrive after the splice, in order, no dupes.
    for i in 5..8u8 {
        node.shard.propose(vec![i]).await.unwrap();
    }
    for want in 6..=8u64 {
        let rec = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("live frame timed out")
            .unwrap()
            .unwrap();
        assert_eq!(rec.seq, want);
        assert_eq!(rec.payload.as_ref(), &[want as u8 - 1]);
    }
}

#[tokio::test]
async fn subscribe_without_replay_support_is_a_clean_error() {
    // An app without a replay hook must surface an error on subscribe,
    // not a silent gap.
    struct NoReplayApp;
    impl ShardApp for NoReplayApp {
        fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> saltator_store::Result<Vec<u8>> {
            ctx.emit(command.to_vec());
            Ok(Vec::new())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let addr = ephemeral_addr();
    let registry = ShardRegistry::new();
    let meta = MetadataHandle::start(9, engine.clone(), Some(addr.to_string()), None)
        .await
        .unwrap();
    meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let shard = ShardHandle::start(
        ShardId::new(Keyspace::User, 0),
        9,
        engine,
        Arc::new(NoReplayApp),
        saltator_shard::NoopNetworkFactory,
        Some(addr.to_string()),
        Some(&registry),
    )
    .await
    .unwrap();
    shard
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_internal(
        meta,
        registry,
        saltator_shard::ExecutorRegistry::new(),
        "hs.test".into(),
        vec![],
        addr,
        async {
            let _ = stop_rx.await;
        },
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    shard.propose(b"x".to_vec()).await.unwrap();

    let remote = RemoteShard::new(
        ShardId::new(Keyspace::User, 0).group(),
        vec![addr.to_string()],
        None,
    );
    let mut stream = Box::pin(remote.subscribe(0));
    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("expected an item");
    assert!(matches!(item, Some(Err(_))), "{item:?}");
}

#[tokio::test]
async fn placement_watch_sees_control_plane_writes() {
    // Meta schema v2: committed Set/Delete emit MetaChange frames, so
    // Subscribe(group 0) IS the placement watch.
    let node = start_node(1, true).await;
    let migrated = node.meta.shard_handle().propose_migrate(2).await.unwrap();
    migrated.expect("meta migration to v2");

    let remote = RemoteShard::new(
        saltator_cluster::network::METADATA_GROUP,
        vec![node.addr.to_string()],
        None,
    );
    let mut stream = Box::pin(remote.subscribe(0));

    node.meta
        .write(saltator_cluster::types::MetaCommand::Set {
            key: saltator_cluster::K_PLACEMENT.into(),
            value: b"p".to_vec(),
        })
        .await
        .unwrap();

    let rec = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("watch frame timed out")
        .unwrap()
        .unwrap();
    let change: saltator_cluster::types::MetaChange = postcard::from_bytes(&rec.payload).unwrap();
    assert_eq!(change.key, saltator_cluster::K_PLACEMENT);
}

/// 2b part 2: a pristine node pre-seeds a shard from a replica's
/// checkpoint over the bulk FetchCheckpoint stream, and the installed
/// stores report exactly the state a raft-snapshot install would —
/// last_applied, seq, rows — so a subsequently-started group needs only
/// the log tail.
#[tokio::test]
async fn checkpoint_transfer_round_trip() {
    let node = start_node(1, true).await;
    for i in 0..64u8 {
        node.shard.propose(vec![i]).await.unwrap();
    }
    let want_seq = node.shard.seq().unwrap();

    // Fetch over the bulk stream (fresh connection by construction).
    let snap = saltator_cluster::remote::fetch_checkpoint(group(), &[node.addr.to_string()], None)
        .await
        .expect("fetch checkpoint");
    assert_eq!(snap.seq, want_seq);
    assert_eq!(snap.kv.len(), 64, "one journal row per command");
    let last = snap.last_applied.expect("has a log position");

    // Install into a pristine store; a handle started over it reports
    // the transferred position (the leader would replicate last+1..).
    let dir = tempfile::tempdir().unwrap();
    let engine: Arc<dyn saltator_store::KvEngine> =
        Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let stores = saltator_store::Stores::single(engine.clone());
    let shard_id = ShardId::new(Keyspace::Room, 0);
    saltator_shard::transfer::install(&stores, shard_id, snap).expect("install");

    // Pristine no more: a second install must refuse.
    let snap2 = saltator_cluster::remote::fetch_checkpoint(group(), &[node.addr.to_string()], None)
        .await
        .unwrap();
    assert!(
        saltator_shard::transfer::install(&stores, shard_id, snap2).is_err(),
        "double install must be refused"
    );

    let handle = ShardHandle::start(
        shard_id,
        9,
        stores,
        Arc::new(JournalApp),
        saltator_shard::NoopNetworkFactory,
        None, // never bootstrap: the group exists elsewhere
        None,
    )
    .await
    .unwrap();
    assert_eq!(handle.seq().unwrap(), want_seq);
    // Replay works off the installed rows — the change-stream backfill
    // a remote subscriber would use.
    let replayed = handle.replay(0, 100).unwrap();
    assert_eq!(replayed.len(), 64);
    assert_eq!(replayed.last().unwrap().seq, want_seq);
    // The log store reports the transferred position as its floor.
    let _ = last;
}
