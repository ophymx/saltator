//! Out-queue ownership (spec.md §4.2): when a room shard is replicated
//! across two nodes, both apply every event, but only the *leader* delivers
//! it to remote servers. This proves the sender does not double-send from a
//! follower — the multi-node federation-out correctness property.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_cluster::network::GrpcRaftNetworkFactory;
use saltator_cluster::{serve_internal, MetadataHandle};
use saltator_federation::{spawn_sender, FederationClient};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner, ROOM_SHARD};
use saltator_shard::ShardRegistry;
use saltator_store::RocksEngine;

use saltator_core::RoomVersion;

fn ephemeral_addr() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A stand-in remote homeserver that just counts inbound transactions.
async fn mock_remote(count: Arc<AtomicUsize>) -> String {
    let app = axum::Router::new().route(
        "/_matrix/federation/v1/send/{txn}",
        axum::routing::put(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({ "pdus": {} }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn spawn_serve(meta: MetadataHandle, registry: ShardRegistry, addr: std::net::SocketAddr) {
    tokio::spawn(serve_internal(
        meta,
        registry,
        "us.test".into(),
        addr,
        std::future::pending::<()>(),
    ));
}

async fn start_room(
    node_id: u64,
    engine: Arc<RocksEngine>,
    signer: Arc<ServerSigner>,
    registry: &ShardRegistry,
    bootstrap_addr: Option<String>,
) -> Arc<RoomServer> {
    RoomServer::start(
        node_id,
        engine,
        signer,
        GrpcRaftNetworkFactory::new(ROOM_SHARD),
        bootstrap_addr,
        Some(registry),
    )
    .await
    .unwrap()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_shard_leader_delivers_outbound() {
    let dir = tempfile::tempdir().unwrap();
    let us: OwnedServerName = "us.test".try_into().unwrap();
    let addr1 = ephemeral_addr();
    let addr2 = ephemeral_addr();

    let (s1, _) = ServerSigner::generate(us.clone(), "0".to_owned());
    let (s2, _) = ServerSigner::generate(us.clone(), "0".to_owned());
    let s1 = Arc::new(s1);
    let s2 = Arc::new(s2);

    // --- Node 1: metadata + a bootstrapped Room/0 (leader) ---
    let e1 = Arc::new(RocksEngine::open(&dir.path().join("n1")).unwrap());
    let reg1 = ShardRegistry::new();
    let m1 = MetadataHandle::start(1, e1.clone(), Some(addr1.to_string()), Some(&reg1))
        .await
        .unwrap();
    m1.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let rooms1 = start_room(1, e1, s1.clone(), &reg1, Some(addr1.to_string())).await;
    rooms1
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    spawn_serve(m1.clone(), reg1, addr1);

    // --- Node 2: metadata + an uninitialized Room/0 (follower) ---
    let e2 = Arc::new(RocksEngine::open(&dir.path().join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start(2, e2.clone(), Some(addr2.to_string()), Some(&reg2))
        .await
        .unwrap();
    m2.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    let rooms2 = start_room(2, e2, s2.clone(), &reg2, None).await;
    spawn_serve(m2.clone(), reg2, addr2);

    // Fold node 2 into the room shard as a voter (what the reconciler does
    // in the real binary).
    rooms1
        .shard_handle()
        .add_learner(2, addr2.to_string())
        .await
        .unwrap();
    rooms1
        .shard_handle()
        .set_voters([1, 2].into_iter().collect())
        .await
        .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || rooms2
            .shard_handle()
            .voter_ids()
            == [1, 2].into_iter().collect())
        .await,
        "node 2 never joined the room shard"
    );
    assert!(
        rooms1.shard_handle().is_leader(),
        "node 1 should lead the room"
    );

    // --- A public room with a remote member ---
    let alice = ruma::OwnedUserId::try_from("@alice:us.test").unwrap();
    let (room_id, _) = rooms1
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        rooms1
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    // A remote user joins so the room has an outbound destination.
    let remote: OwnedServerName = "remote.test".try_into().unwrap();
    let (rsigner, _) = ServerSigner::generate(remote.clone(), "0".to_owned());
    let bob = ruma::UserId::parse("@bob:remote.test").unwrap();
    let (version, template) = rooms1.make_join_template(&room_id, &bob).unwrap();
    let mut join = template;
    rsigner.hash_and_sign_event(&mut join, version).unwrap();
    if let Some(keys) = rsigner.public_key_map().get("remote.test") {
        rooms1.trust_keys("remote.test", keys.clone());
    }
    rooms1.send_join(join).await.unwrap();
    assert_eq!(
        rooms1
            .remote_servers_in_room(room_id.as_str(), "us.test")
            .unwrap(),
        vec!["remote.test".to_owned()],
        "room should have a remote destination"
    );

    // --- Both nodes run a sender aimed at the same mock remote ---
    let count = Arc::new(AtomicUsize::new(0));
    let base = mock_remote(count.clone()).await;
    let c1 = Arc::new(FederationClient::with_base_url(s1.clone(), base.clone()));
    let c2 = Arc::new(FederationClient::with_base_url(s2.clone(), base));
    let send1 = spawn_sender(rooms1.clone(), c1, us.clone());
    let send2 = spawn_sender(rooms2.clone(), c2, us.clone());

    // Give both senders a moment to reach the current tip (they start there,
    // so the pre-existing setup events are not re-sent).
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A locally-originated message must be delivered — exactly once.
    let sent = rooms1
        .send_message(
            &room_id,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "hi remote"}),
        )
        .await
        .unwrap();
    assert!(matches!(sent, Outcome::Accepted { .. }));

    assert!(
        eventually(Duration::from_secs(10), || count.load(Ordering::SeqCst)
            >= 1)
        .await,
        "the leader never delivered the message"
    );
    // Hold long enough that a follower delivery (if it happened) would land.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "message delivered more than once — a follower also sent"
    );

    send1.abort();
    send2.abort();
}
