//! Exercises the generic shard runtime with a toy KV app: bootstrap,
//! propose/read, per-shard sequence numbers, change streams, restart
//! recovery, batched-apply overlay reads, and snapshot roundtrip.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use saltator_shard::storage::ShardStateMachine;
use saltator_shard::{ApplyCtx, NoopNetworkFactory, ShardApp, ShardHandle, ShardId, APP_TABLE_MIN};
use saltator_store::{Keyspace, KvEngine, Result as StoreResult, RocksEngine};

const T_KV: u8 = APP_TABLE_MIN;
const SHARD: ShardId = ShardId::new(Keyspace::User, 3);

#[derive(Debug, Serialize, Deserialize)]
enum KvCmd {
    /// Set a key; emit a change record iff `emit`.
    Set {
        key: String,
        value: Vec<u8>,
        emit: bool,
    },
    Delete {
        key: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct KvResp {
    previous: Option<Vec<u8>>,
    seq: Option<u64>,
}

struct KvApp;

impl ShardApp for KvApp {
    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        let cmd: KvCmd = postcard::from_bytes(command).expect("test commands decode");
        let resp = match cmd {
            KvCmd::Set { key, value, emit } => {
                let previous = ctx.get(T_KV, key.as_bytes())?;
                ctx.put(T_KV, key.as_bytes(), value.clone());
                let seq = emit.then(|| ctx.emit(value));
                KvResp { previous, seq }
            }
            KvCmd::Delete { key } => {
                let previous = ctx.get(T_KV, key.as_bytes())?;
                ctx.delete(T_KV, key.as_bytes());
                KvResp {
                    previous,
                    seq: None,
                }
            }
        };
        Ok(postcard::to_stdvec(&resp).expect("test responses encode"))
    }
}

async fn start(engine: Arc<dyn KvEngine>) -> ShardHandle {
    let handle = ShardHandle::start(
        SHARD,
        1,
        engine,
        Arc::new(KvApp),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    handle
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    handle
}

async fn set(handle: &ShardHandle, key: &str, value: &[u8], emit: bool) -> KvResp {
    let cmd = postcard::to_stdvec(&KvCmd::Set {
        key: key.into(),
        value: value.into(),
        emit,
    })
    .unwrap();
    postcard::from_bytes(&handle.propose(cmd).await.unwrap()).unwrap()
}

#[tokio::test]
async fn propose_read_seq_and_change_stream() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let handle = start(engine).await;

    let mut changes = handle.subscribe();
    assert_eq!(handle.seq().unwrap(), 0);

    // First write: no previous, emits seq 1.
    let r1 = set(&handle, "a", b"one", true).await;
    assert_eq!(r1.previous, None);
    assert_eq!(r1.seq, Some(1));

    // Overwrite without emitting: previous visible, seq unchanged.
    let r2 = set(&handle, "a", b"two", false).await;
    assert_eq!(r2.previous.as_deref(), Some(b"one".as_slice()));
    assert_eq!(r2.seq, None);
    assert_eq!(handle.seq().unwrap(), 1);

    // Emitting write bumps seq again.
    let r3 = set(&handle, "b", b"three", true).await;
    assert_eq!(r3.seq, Some(2));
    assert_eq!(handle.seq().unwrap(), 2);

    // Applied state is readable outside apply.
    handle.ensure_linearizable().await.unwrap();
    let read = handle.read_ctx();
    assert_eq!(
        read.get(T_KV, b"a").unwrap().as_deref(),
        Some(b"two".as_slice())
    );
    let all = read.range(T_KV, b"", b"").unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].0, b"a");

    // The change stream saw exactly the emitting writes, in seq order.
    let c1 = changes.recv().await.unwrap();
    assert_eq!((c1.seq, &c1.payload[..]), (1, b"one".as_slice()));
    let c2 = changes.recv().await.unwrap();
    assert_eq!((c2.seq, &c2.payload[..]), (2, b"three".as_slice()));

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_recovers_state_and_seq() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");

    {
        let engine = Arc::new(RocksEngine::open(&db).unwrap());
        let handle = start(engine).await;
        set(&handle, "k", b"v", true).await;
        assert_eq!(handle.seq().unwrap(), 1);
        handle.shutdown().await.unwrap();
    }

    let engine = Arc::new(RocksEngine::open(&db).unwrap());
    // No bootstrap address: recovery must come from disk.
    let handle = ShardHandle::start(
        SHARD,
        1,
        engine,
        Arc::new(KvApp),
        NoopNetworkFactory,
        None,
        None,
    )
    .await
    .unwrap();
    handle
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();

    assert_eq!(handle.seq().unwrap(), 1);
    assert_eq!(
        handle.read_ctx().get(T_KV, b"k").unwrap().as_deref(),
        Some(b"v".as_slice())
    );
    // And the group still accepts writes.
    let r = set(&handle, "k", b"v2", true).await;
    assert_eq!(r.previous.as_deref(), Some(b"v".as_slice()));
    assert_eq!(r.seq, Some(2));

    handle.shutdown().await.unwrap();
}

// -- direct state-machine tests (batching and snapshots are hard to force
//    through a live single-node raft) --

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};

fn entry(index: u64, cmd: &KvCmd) -> Entry<saltator_shard::TypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(postcard::to_stdvec(cmd).unwrap()),
    }
}

fn sm(engine: Arc<dyn KvEngine>) -> ShardStateMachine<KvApp> {
    let (tx, _) = broadcast::channel(16);
    ShardStateMachine::new(SHARD, engine, Arc::new(KvApp), tx)
}

#[tokio::test]
async fn batched_apply_sees_earlier_writes_and_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let engine: Arc<dyn KvEngine> = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let mut machine = sm(engine);

    // Two commands touching the same key in ONE apply batch: the second
    // must observe the first through the staged overlay.
    let responses = machine
        .apply([
            entry(
                1,
                &KvCmd::Set {
                    key: "x".into(),
                    value: b"first".to_vec(),
                    emit: true,
                },
            ),
            entry(
                2,
                &KvCmd::Set {
                    key: "x".into(),
                    value: b"second".to_vec(),
                    emit: true,
                },
            ),
        ])
        .await
        .unwrap();

    let r2: KvResp = postcard::from_bytes(&responses[1]).unwrap();
    assert_eq!(r2.previous.as_deref(), Some(b"first".as_slice()));
    assert_eq!(r2.seq, Some(2));
    assert_eq!(machine.seq().unwrap(), 2);
}

#[tokio::test]
async fn snapshot_roundtrip_restores_app_state_and_seq() {
    let src_dir = tempfile::tempdir().unwrap();
    let src: Arc<dyn KvEngine> = Arc::new(RocksEngine::open(&src_dir.path().join("db")).unwrap());
    let mut source = sm(src);
    source
        .apply([
            entry(
                1,
                &KvCmd::Set {
                    key: "a".into(),
                    value: b"1".to_vec(),
                    emit: true,
                },
            ),
            entry(
                2,
                &KvCmd::Set {
                    key: "b".into(),
                    value: b"2".to_vec(),
                    emit: true,
                },
            ),
        ])
        .await
        .unwrap();
    let snapshot = source.build_snapshot().await.unwrap();

    let dst_dir = tempfile::tempdir().unwrap();
    let dst: Arc<dyn KvEngine> = Arc::new(RocksEngine::open(&dst_dir.path().join("db")).unwrap());
    let mut target = sm(dst.clone());
    // Pre-existing app state must be wiped by the install.
    target
        .apply([entry(
            1,
            &KvCmd::Set {
                key: "stale".into(),
                value: b"x".to_vec(),
                emit: true,
            },
        )])
        .await
        .unwrap();

    target
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();

    assert_eq!(target.seq().unwrap(), 2);
    let (last_applied, _) = target.applied_state().await.unwrap();
    assert_eq!(last_applied.map(|l| l.index), Some(2));

    // Snapshot state replaced the pre-existing app state wholesale.
    let app_key = |k: &[u8]| saltator_store::key(SHARD.keyspace, SHARD.index, T_KV, k);
    assert_eq!(
        dst.get(&app_key(b"a")).unwrap().as_deref(),
        Some(b"1".as_slice())
    );
    assert_eq!(
        dst.get(&app_key(b"b")).unwrap().as_deref(),
        Some(b"2".as_slice())
    );
    assert_eq!(dst.get(&app_key(b"stale")).unwrap(), None);
}
