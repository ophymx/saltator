//! Serving an unhosted room shard: node B holds NO replica of the room
//! shard — its
//! `RoomServer::remote` handle writes via intents at node A's leader,
//! reads through the Read RPC, and tails the change stream over
//! Subscribe. The crate-level proof that a node can serve rooms it does
//! not host.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use saltator_cluster::remote::RemoteShard;
use saltator_cluster::{serve_internal, MetadataHandle};
use saltator_core::RoomVersion;
use saltator_federation::KeyCache;
use saltator_roomserver::{Outcome, RoomServer, SeqEntry, ServerSigner};
use saltator_shard::{NoopNetworkFactory, ShardRegistry};
use saltator_store::RocksEngine;

mod common;
use common::ephemeral_addr;

#[tokio::test]
async fn unhosted_shard_serves_reads_writes_and_changes() {
    let dir = tempfile::tempdir().unwrap();
    let server_name = ruma::OwnedServerName::try_from("hs.test").unwrap();
    let (signer, _) = ServerSigner::generate(server_name.clone(), "0".to_owned());
    let signer = Arc::new(signer);

    // --- Node A: hosts the room shard, serves the internal RPC ---
    let engine = Arc::new(RocksEngine::open(&dir.path().join("a")).unwrap());
    let addr = ephemeral_addr();
    let registry = ShardRegistry::new();
    let meta = MetadataHandle::start(1, engine.clone(), Some(addr.to_string()), Some(&registry))
        .await
        .unwrap();
    meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let hosted = RoomServer::start(
        1,
        engine,
        signer.clone(),
        NoopNetworkFactory,
        Some(addr.to_string()),
        Some(&registry),
    )
    .await
    .unwrap();
    hosted
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    let executors = saltator_shard::ExecutorRegistry::new();
    executors.register(
        hosted.shard_handle().shard().group(),
        saltator_federation::room_intent_executor(hosted.clone(), None, Arc::new(KeyCache::new())),
    );
    tokio::spawn(serve_internal(
        meta,
        registry,
        executors,
        "hs.test".into(),
        vec![],
        addr,
        std::future::pending::<()>(),
    ));
    // Wait for the listener.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // --- Node B: a remote handle only — no Raft group, no local state ---
    let group = hosted.shard_handle().shard().group();
    let backend = Arc::new(RemoteShard::new(group, vec![addr.to_string()], None));
    let remote = RoomServer::remote(backend, signer.clone());
    assert!(!remote.is_hosted());

    // A change stream anchored before any writes.
    let mut changes = remote.changes(0);

    // Write path: create + message via intents at A's leader.
    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    let (room_id, outcome) = remote
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .expect("remote create_room");
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    let room_ref = ruma::RoomId::parse(room_id.as_str()).unwrap();
    // The creator joins (create_room only lays the create event).
    let joined = remote
        .send_state(
            &room_ref,
            &alice,
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        )
        .await
        .expect("remote join state");
    assert!(matches!(joined, Outcome::Accepted { .. }), "{joined:?}");
    let sent = remote
        .send_message(
            &room_ref,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "over the wire"}),
        )
        .await
        .expect("remote send_message");
    let Outcome::Accepted { event_id, seq } = sent else {
        panic!("message not accepted: {sent:?}");
    };

    // Read path: the remote store serves what A applied.
    let stored = remote
        .store()
        .event(event_id.as_str())
        .await
        .expect("remote event read")
        .expect("event present");
    assert_eq!(stored.seq, seq);
    let timeline = remote.store().timeline(0, 100).await.unwrap();
    assert!(
        timeline.iter().any(|(_, e)| matches!(
            e,
            SeqEntry::Event { event_id: id, .. } if id == event_id.as_str()
        )),
        "timeline missing the message"
    );
    // ... and both handles agree on the seq.
    assert_eq!(
        remote.current_seq().await.unwrap(),
        hosted.shard_handle().seq().unwrap()
    );

    // Change stream: every record from seq 1 arrives, in order, over the
    // Subscribe RPC (backfill for the records that predate the stream's
    // first poll, live for the rest).
    let mut last = 0;
    while last < seq {
        let rec = tokio::time::timeout(Duration::from_secs(5), changes.recv())
            .await
            .expect("change record timed out")
            .expect("stream ended early");
        assert_eq!(rec.seq, last + 1, "gap in the remote change stream");
        last = rec.seq;
    }

    // Typed error round trip: an unknown-room intent surfaces as the
    // typed RoomError variant, not a string blob.
    let bogus = ruma::RoomId::parse("!nosuchroom:hs.test").unwrap();
    let err = remote
        .send_message(&bogus, &alice, "m.room.message", json!({"body": "x"}))
        .await
        .unwrap_err();
    assert!(
        matches!(err, saltator_roomserver::RoomError::UnknownRoom(_)),
        "expected UnknownRoom, got {err:?}"
    );

    hosted.shutdown().await.unwrap();
}
