//! The media-blob bulk RPCs end to end over a real listener:
//! push a
//! blob to a peer, ask whether it has one, stream it back.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::{serve_internal_with_tls, MetadataHandle};
use saltator_media::MediaStore;
use saltator_shard::ShardRegistry;
use saltator_store::RocksEngine;

mod common;
use common::ephemeral_addr;

struct Node {
    addr: std::net::SocketAddr,
    media: MediaStore,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// A node that serves media, and nothing else of interest.
async fn start_node(node_id: u64, serves_media: bool) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let addr = ephemeral_addr();
    let registry = ShardRegistry::new();
    let meta = MetadataHandle::start(node_id, engine, Some(addr.to_string()), Some(&registry))
        .await
        .unwrap();
    meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();

    let media = MediaStore::open(dir.path().join("media")).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_internal_with_tls(
        meta,
        registry,
        saltator_shard::ExecutorRegistry::new(),
        "hs.test".into(),
        vec![],
        addr,
        None,
        serves_media.then(|| media.clone()),
        async {
            let _ = stop_rx.await;
        },
    ));
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
    for _ in 0..50 {
        if endpoint.connect().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Node {
        addr,
        media,
        _dir: dir,
        _stop: stop_tx,
    }
}

/// The replication round trip: push bytes to a peer, confirm it has
/// them, stream them back byte-identical.
#[tokio::test]
async fn blob_round_trips_over_the_bulk_rpcs() {
    let node = start_node(1, true).await;
    let addr = node.addr.to_string();
    // Multi-chunk: larger than the 1 MiB frame, so the reassembly on
    // both sides is actually exercised rather than a single frame.
    let bytes: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let blob_id = "a-test-blob-id";

    assert!(
        !saltator_cluster::remote::has_blob(blob_id, &addr, None)
            .await
            .unwrap(),
        "peer claims a blob it was never given"
    );

    saltator_cluster::remote::store_blob(blob_id, &bytes, &addr, None)
        .await
        .unwrap();
    assert!(saltator_cluster::remote::has_blob(blob_id, &addr, None)
        .await
        .unwrap());
    // It really landed on that node's disk, not just in its answer.
    assert_eq!(
        node.media.read_local(blob_id).await.unwrap().unwrap().len(),
        bytes.len()
    );

    let fetched = saltator_cluster::remote::fetch_blob(blob_id, &[addr], None)
        .await
        .unwrap()
        .expect("blob should be served");
    assert_eq!(fetched, bytes, "blob did not survive the round trip");
}

/// A zero-byte blob is a legal blob, and must not read back as "absent"
/// — the reason FetchBlob answers NOT_FOUND rather than an empty stream.
#[tokio::test]
async fn empty_blob_is_distinguishable_from_a_missing_one() {
    let node = start_node(1, true).await;
    let addr = node.addr.to_string();

    saltator_cluster::remote::store_blob("empty-blob", b"", &addr, None)
        .await
        .unwrap();
    assert_eq!(
        saltator_cluster::remote::fetch_blob("empty-blob", std::slice::from_ref(&addr), None)
            .await
            .unwrap(),
        Some(Vec::new()),
        "an empty blob must read back as present-and-empty"
    );
    assert_eq!(
        saltator_cluster::remote::fetch_blob("no-such-blob", &[addr], None)
            .await
            .unwrap(),
        None,
        "a missing blob must read back as absent"
    );
}

/// "Nobody has it" and "nobody would answer" are different outcomes: the
/// first is a client 404, the second is an error the caller must not
/// serve as a 404. Getting this backwards would let a network blip
/// convince a client that its media had been deleted.
#[tokio::test]
async fn unreachable_peers_are_an_error_not_a_miss() {
    let reachable = start_node(1, true).await;
    let dead = ephemeral_addr().to_string();

    // Every candidate unreachable: an error.
    assert!(
        saltator_cluster::remote::fetch_blob("some-blob", std::slice::from_ref(&dead), None)
            .await
            .is_err(),
        "an unreachable replica set must not read as a missing blob"
    );
    // One reachable peer that answers "not here": a miss.
    assert_eq!(
        saltator_cluster::remote::fetch_blob(
            "some-blob",
            &[dead, reachable.addr.to_string()],
            None
        )
        .await
        .unwrap(),
        None
    );
    // No candidates at all (a single-node cluster) is a miss, not an error.
    assert_eq!(
        saltator_cluster::remote::fetch_blob("some-blob", &[], None)
            .await
            .unwrap(),
        None
    );
}

/// A node that serves no media must say so, rather than answering "not
/// here" — a peer has to be able to tell the two apart before it decides
/// the blob is gone.
#[tokio::test]
async fn a_node_without_media_answers_unimplemented() {
    let node = start_node(1, false).await;
    let addr = node.addr.to_string();
    assert!(saltator_cluster::remote::has_blob("any-blob", &addr, None)
        .await
        .is_err());
    assert!(
        saltator_cluster::remote::fetch_blob("any-blob", &[addr], None)
            .await
            .is_err(),
        "UNIMPLEMENTED must not collapse into a miss"
    );
}
