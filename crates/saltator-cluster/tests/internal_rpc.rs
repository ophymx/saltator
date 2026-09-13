//! Exercises the internal gRPC surface end to end (spec.md §8): the
//! ControlService status endpoint, the envelope version/group checks, and a
//! full openraft round-trip through the client side in `network.rs` — the
//! paths single-node Raft never touches on its own.

use std::sync::Arc;
use std::time::Duration;

use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::VoteRequest;
use openraft::{BasicNode, Vote};

use saltator_cluster::network::{GrpcRaftNetworkFactory, METADATA_GROUP};
use saltator_cluster::proto::control_service_client::ControlServiceClient;
use saltator_cluster::proto::raft_service_client::RaftServiceClient;
use saltator_cluster::proto::{RaftPayload, StatusRequest};
use saltator_cluster::types::{MetaCommand, CODEC_VERSION};
use saltator_cluster::{serve_internal, MetadataHandle};
use saltator_shard::{ShardId, ShardRegistry};
use saltator_store::RocksEngine;

/// Bind-and-release to pick a free port. Racy in principle; fine for tests.
fn ephemeral_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

async fn connect(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap();
    for _ in 0..50 {
        if let Ok(channel) = endpoint.connect().await {
            return channel;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("internal RPC server did not come up on {addr}");
}

#[tokio::test]
async fn internal_rpc_surface() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());

    let addr = ephemeral_addr();
    let registry = ShardRegistry::new();
    let meta = MetadataHandle::start(1, engine, Some(addr.to_string()), Some(&registry))
        .await
        .unwrap();
    meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_internal(
        meta.clone(),
        registry,
        saltator_shard::ExecutorRegistry::new(),
        "example.org".into(),
        vec![],
        addr,
        async {
            let _ = stop_rx.await;
        },
    ));

    let channel = connect(addr).await;

    // --- ControlService.Status reflects the live group ---
    let mut control = ControlServiceClient::new(channel.clone());
    let status = control.status(StatusRequest {}).await.unwrap().into_inner();
    assert_eq!(status.node_id, 1);
    assert_eq!(status.server_name, "example.org");
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    assert!(status.initialized);
    assert_eq!(status.leader, Some(1));

    // ... and tracks applies.
    let applied_before = status.last_applied;
    meta.write(MetaCommand::Set {
        key: "rpc-test".into(),
        value: b"v".to_vec(),
    })
    .await
    .unwrap();
    let status = control.status(StatusRequest {}).await.unwrap().into_inner();
    assert!(status.last_applied > applied_before);

    // --- envelope checks reject bad codec versions and unknown groups ---
    let mut raft = RaftServiceClient::new(channel.clone());
    let err = raft
        .vote(RaftPayload {
            group: METADATA_GROUP,
            codec_version: CODEC_VERSION + 1,
            payload: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let err = raft
        .vote(RaftPayload {
            group: 42,
            codec_version: CODEC_VERSION,
            payload: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // --- full openraft round-trip through the network.rs client ---
    // A vote for a stale term must come back not-granted; getting a typed
    // response at all proves the postcard-in-proto encoding survives
    // client → server → client.
    let mut conn = GrpcRaftNetworkFactory::new(ShardId::METADATA)
        .new_client(1, &BasicNode::new(addr.to_string()))
        .await;
    let resp = conn
        .vote(
            VoteRequest {
                vote: Vote::new(0, 1),
                last_log_id: None,
            },
            RPCOption::new(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(!resp.vote_granted);

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    meta.shutdown().await.unwrap();
}
