//! Exercises the mock federation peer ([`support::MockPeer`]): our server
//! joins a peer-hosted room, ingests a message the peer pushes, and rejects
//! a PDU the peer deliberately malforms. This is the local capability that
//! stands in for Complement's synthetic-peer tests (Groups 6b/8/…).

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_federation::{router, FedState, KeyCache, OldVerifyKey};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

use saltator_testsupport::{strip_signatures, MockPeer};

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn start_rooms(
    server: &str,
    signer: Arc<ServerSigner>,
    dir: &std::path::Path,
) -> Arc<RoomServer> {
    let engine = Arc::new(RocksEngine::open(&dir.join(server)).unwrap());
    let rooms = RoomServer::start(
        1,
        engine,
        signer,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    rooms
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    rooms
}

/// Single-node fed-out shard + the unified delivery worker (step 4's
/// replacement for the old spawn_sender in these tests).
async fn start_delivery(
    rooms: Arc<saltator_roomserver::RoomShards>,
    client: Arc<saltator_federation::FederationClient>,
    hs: OwnedServerName,
    dir: &std::path::Path,
) -> (
    Arc<saltator_fedout::FedOutServer>,
    tokio::task::JoinHandle<()>,
) {
    let engine: Arc<dyn saltator_store::KvEngine> =
        Arc::new(saltator_store::RocksEngine::open(&dir.join("fedout")).unwrap());
    let fedout = saltator_fedout::FedOutServer::start(
        1,
        engine,
        saltator_shard::NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    fedout
        .wait_for_leader(std::time::Duration::from_secs(10))
        .await
        .unwrap();
    let worker = saltator_federation::spawn_delivery_worker(
        fedout.clone(),
        rooms,
        client,
        hs,
        Arc::new(saltator_federation::DeliveryBackoff::default()),
    );
    (fedout, worker)
}

/// Two room shards deliver to one destination: their per-shard seq
/// streams overlap, so the transaction ids must not — the receiver
/// replay-caches on (origin, txn_id), and a reused id gets the cached
/// response back: the second shard's chunk is acked but never ingested,
/// and the cursor advance means it is never retried. (Caught by the
/// Complement multi-shard flip: TestFederationRoomsInvite lost a
/// rescind and a join to exactly this collision.)
#[tokio::test]
async fn sharded_delivery_txn_ids_do_not_collide() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;

    // One peer-hosted room per shard of a 2-shard router.
    let mut room_ids: [Option<String>; 2] = [None, None];
    while room_ids.iter().any(Option::is_none) {
        let id = peer.make_room(RoomVersion::V11, "charlie");
        let idx = saltator_roomserver::shard_of(&id, 2) as usize;
        room_ids[idx].get_or_insert(id);
    }

    let mut shards = Vec::new();
    for idx in 0..2u16 {
        let engine = Arc::new(RocksEngine::open(&dir.path().join(format!("room{idx}"))).unwrap());
        let s = RoomServer::start_shard(
            saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx),
            1,
            engine,
            hs_signer.clone(),
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        s.shard_handle()
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        shards.push(s);
    }
    let router = saltator_roomserver::RoomShards::new(shards.clone());

    let (_fedout, sender) = start_delivery(
        router.clone(),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        dir.path(),
    )
    .await;

    // Symmetric histories — join + import + one message per shard — so
    // the two seq streams line up: the collision-prone shape.
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    for room_id in room_ids.iter().flatten() {
        let shard = router.for_room(room_id);
        let resp = join_remote_room(&client, &hs_signer, "peer.test", room_id, "@alice:hs.test")
            .await
            .expect("join");
        shard
            .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
            .await
            .expect("import");
        let room = ruma::RoomId::parse(room_id.as_str()).unwrap();
        shard
            .send_message(
                &room,
                &alice,
                "m.room.message",
                json!({"msgtype": "m.text", "body": "hello"}),
            )
            .await
            .expect("send");
    }

    // Both shards' messages must reach the peer (delivery is async)...
    let mut got = 0;
    for _ in 0..100 {
        got =
            peer.received()
                .iter()
                .filter(|txn| {
                    txn.origin == "hs.test"
                        && txn.pdus.iter().any(|p| {
                            p.get("type").and_then(|t| t.as_str()) == Some("m.room.message")
                        })
                })
                .count();
        if got >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let received = peer.received();
    assert!(
        got >= 2,
        "expected both shards' messages delivered; got {received:?}"
    );

    // ...and no two transactions may share an id.
    let mut ids = std::collections::HashSet::new();
    for txn in received.iter().filter(|t| t.origin == "hs.test") {
        assert!(
            ids.insert(txn.txn_id.clone()),
            "txn id {:?} reused — a real receiver's replay cache would swallow the later chunk",
            txn.txn_id
        );
    }

    sender.abort();
    for s in shards {
        s.shutdown().await.unwrap();
    }
}

/// The peer hosts a public room; our server drives the make_join/send_join
/// handshake against it and imports the returned state — proving the peer
/// builds a room + join response our pipeline accepts.
#[tokio::test]
async fn our_server_joins_peer_hosted_room() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join handshake against the mock peer");

    assert_eq!(resp.room_version, RoomVersion::V11);
    // The resident omits `event` (like Synapse), so we fall back to the join
    // we submitted — signed by us.
    let sigs = resp.event.get("signatures").unwrap().as_object().unwrap();
    assert!(sigs.contains_key("hs.test"), "our signature missing");
    assert!(
        resp.state
            .iter()
            .any(|e| matches!(e.get("type"), Some(ruma::CanonicalJsonValue::String(t)) if t == "m.room.create")),
        "state missing create event"
    );

    let outcome = our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import the peer's room");
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");

    // Our server now hosts a copy with the peer as a remote member.
    let peers = our_rooms
        .remote_servers_in_room(&room_id, "hs.test")
        .await
        .unwrap();
    assert_eq!(peers, vec!["peer.test".to_owned()]);

    our_rooms.shutdown().await.unwrap();
}

/// After the join, the peer pushes a genuinely-signed message over `/send`;
/// our server fetches the peer's keys and ingests it.
#[tokio::test]
async fn peer_pushed_message_is_ingested() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    // Our server joins + imports the room.
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // Our federation surface: authenticates callers against the peer's keys
    // (fetched from the peer's key server) and routes PDUs to our rooms.
    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // The peer authors a message (prev = alice's join, which we hold).
    let charlie = "@charlie:peer.test";
    let msg_id = peer.with_room(&room_id, |room| {
        room.message(
            charlie,
            json!({"msgtype": "m.text", "body": "hi from the peer"}),
        )
    });
    let msg = peer.with_room(&room_id, |room| room.raw(&msg_id));

    let out = peer.send_transaction(&our_base, "hs.test", vec![msg]).await;
    assert_eq!(
        &out["pdus"][&msg_id],
        &json!({}),
        "peer message should verify and ingest: {out}"
    );
    assert!(
        our_rooms.store().event(&msg_id).await.unwrap().is_some(),
        "message not persisted"
    );

    our_rooms.shutdown().await.unwrap();
}

/// The federation `timestamp_to_event` endpoint answers a member server's
/// query with the closest event, and refuses the query for an unknown
/// room (the requester-in-room gate).
#[tokio::test]
async fn timestamp_to_event_serves_member_servers() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    // Our server joins + imports the room (charlie@peer.test is a member,
    // so peer.test passes the requester-in-room check).
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // Backwards from far in the future → the newest timeline event (our
    // alice's join, the only post-import timeline entry). Forwards from 0
    // would equally find the oldest.
    let (status, body) = peer
        .signed_get(
            &our_base,
            "hs.test",
            &format!(
                "/_matrix/federation/v1/timestamp_to_event/{}?ts=99999999999999&dir=b",
                room_id.replace('!', "%21")
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["event_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with('$'),
        "{body}"
    );
    assert!(body["origin_server_ts"].is_u64(), "{body}");

    // A room we host nothing of → the requester is not "in the room" → 403.
    let (status, body) = peer
        .signed_get(
            &our_base,
            "hs.test",
            "/_matrix/federation/v1/timestamp_to_event/%21unknown:peer.test?ts=1&dir=f",
        )
        .await;
    assert_eq!(status, 403, "{body}");

    our_rooms.shutdown().await.unwrap();
}

/// `/state` and `/state_ids` serve a member server the resolved state
/// *before* the named event: a query at charlie's join must show the room
/// pre-join (no charlie member entry among the pdus), and the `_ids`
/// variant must agree with the full variant.
#[tokio::test]
async fn state_at_event_serves_pre_event_snapshot() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    let alice_join_id = saltator_core::event::event_id(&resp.event, RoomVersion::V11)
        .unwrap()
        .to_string();
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // State before alice's own join: her member event must NOT be present.
    let path = format!(
        "/_matrix/federation/v1/state/{}?event_id={}",
        room_id.replace('!', "%21"),
        alice_join_id.replace('$', "%24"),
    );
    let (status, body) = peer.signed_get(&our_base, "hs.test", &path).await;
    assert_eq!(status, 200, "{body}");
    let pdus = body["pdus"].as_array().expect("pdus array");
    assert!(
        pdus.iter().any(|p| p["type"] == "m.room.create"),
        "state missing create"
    );
    assert!(
        !pdus
            .iter()
            .any(|p| p["type"] == "m.room.member" && p["state_key"] == "@alice:hs.test"),
        "state at alice's join must precede the join itself"
    );
    assert!(
        !body["auth_chain"].as_array().unwrap().is_empty(),
        "auth chain empty"
    );

    // The ids variant agrees with the full variant.
    let ids_path = format!(
        "/_matrix/federation/v1/state_ids/{}?event_id={}",
        room_id.replace('!', "%21"),
        alice_join_id.replace('$', "%24"),
    );
    let (status, ids_body) = peer.signed_get(&our_base, "hs.test", &ids_path).await;
    assert_eq!(status, 200, "{ids_body}");
    // Raw v3+ PDUs carry no event_id field, so compare cardinality and
    // shape: one id per pdu, all id-shaped.
    let id_list = ids_body["pdu_ids"].as_array().unwrap();
    assert_eq!(id_list.len(), pdus.len(), "{ids_body}");
    assert!(
        id_list
            .iter()
            .all(|v| v.as_str().unwrap_or_default().starts_with('$')),
        "{ids_body}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// The key notary serves another server's signed key publication under
/// our co-signature: the returned object keeps the peer's own signature
/// and gains ours, so a requester can pin trust on the notary. Our own
/// server name resolves locally without a fetch.
#[tokio::test]
async fn key_notary_co_signs_peer_keys() {
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: None,
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;
    let http = reqwest::Client::new();

    // Single-server GET (unauthenticated, like /key/v2/server).
    let body: serde_json::Value = http
        .get(format!("{our_base}/_matrix/key/v2/query/peer.test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = body["server_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "{body}");
    assert_eq!(keys[0]["server_name"], "peer.test", "{body}");
    let sigs = keys[0]["signatures"].as_object().unwrap();
    assert!(sigs.contains_key("peer.test"), "origin signature kept");
    assert!(sigs.contains_key("hs.test"), "notary co-signature added");

    // Batch POST: the peer plus ourselves; an unknown server is omitted.
    let body: serde_json::Value = http
        .post(format!("{our_base}/_matrix/key/v2/query"))
        .json(&json!({"server_keys": {
            "peer.test": {},
            "hs.test": {},
            "unreachable.test": {},
        }}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = body["server_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|k| k["server_name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{body}");
    assert!(
        names.contains(&"peer.test") && names.contains(&"hs.test"),
        "{body}"
    );
}

/// A PDU citing a prev event we never received is recovered by fetching
/// that event by ID (`GET /event/{id}`) from the origin — the path taken
/// when `/get_missing_events` cannot help. This is the shape of an invite
/// arriving mid-`/invite` handshake: the origin has not stored the invite
/// yet, so it cannot walk back from it, but serves its prev events by ID
/// (the peer here has no `/get_missing_events` route at all).
#[tokio::test]
async fn pdu_with_undelivered_prev_is_recovered_via_event_fetch() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    // Our server joins + imports the room.
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = Arc::new(FederationClient::with_base_url(
        hs_signer.clone(),
        peer.base_url.clone(),
    ));
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: Some(client),
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // The peer authors two chained messages but delivers only the second:
    // its prev is unknown to us, so ingest must recover `first` from the
    // peer before `second` can be accepted.
    let charlie = "@charlie:peer.test";
    let first_id = peer.with_room(&room_id, |room| {
        room.message(charlie, json!({"msgtype": "m.text", "body": "one"}))
    });
    let second_id = peer.with_room(&room_id, |room| {
        room.event_with_prev(
            charlie,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "two"}),
            vec![first_id.clone()],
        )
    });
    let second = peer.with_room(&room_id, |room| room.raw(&second_id));

    let out = peer
        .send_transaction(&our_base, "hs.test", vec![second])
        .await;
    assert_eq!(
        &out["pdus"][&second_id],
        &json!({}),
        "PDU with undelivered prev should ingest after /event recovery: {out}"
    );
    assert!(
        our_rooms.store().event(&first_id).await.unwrap().is_some(),
        "missing prev not recovered from the origin"
    );
    assert!(
        our_rooms.store().event(&second_id).await.unwrap().is_some(),
        "delivered PDU not persisted"
    );

    our_rooms.shutdown().await.unwrap();
}

/// An event whose `auth_events` cite a *rejected* event is itself rejected,
/// while a normal sentinel alongside it is accepted (the core rule behind
/// Complement's TestInboundFederationRejectsEventsWithRejectedAuthEvents).
#[tokio::test]
async fn event_citing_rejected_auth_event_is_rejected() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // Gather the state event IDs to hand-build auth chains.
    let (tip, create, pl, charlie_m) = peer.with_room(&room_id, |r| {
        (
            r.tip(),
            r.state_event_id("m.room.create", "").unwrap(),
            r.state_event_id("m.room.power_levels", "").unwrap(),
            r.state_event_id("m.room.member", "@charlie:peer.test")
                .unwrap(),
        )
    });

    // R: a power-levels event from @mallory, who is NOT a member — our server
    // rejects it on auth (the sender is not joined / lacks power).
    let (r_id, r_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@mallory:peer.test",
            "m.room.power_levels",
            Some(""),
            json!({"users": {}}),
            tip.clone(),
            vec![create.clone(), pl.clone()],
        )
    });
    // X: a well-formed message from charlie, but citing the rejected R in the
    // (type-permitted) power-levels slot of its auth_events — must be rejected
    // as a consequence of R being rejected.
    let (x_id, x_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@charlie:peer.test",
            "m.room.message",
            None,
            json!({"body": "X cites rejected R"}),
            tip.clone(),
            vec![create.clone(), r_id.clone(), charlie_m.clone()],
        )
    });
    // S: a genuine sentinel (cites the real power levels) that must be accepted.
    let (s_id, s_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@charlie:peer.test",
            "m.room.message",
            None,
            json!({"body": "sentinel"}),
            tip.clone(),
            vec![create, pl, charlie_m],
        )
    });

    let out = peer
        .send_transaction(&our_base, "hs.test", vec![r_raw, x_raw, s_raw])
        .await;

    async fn rejected(rooms: &RoomServer, id: &str) -> Option<bool> {
        rooms
            .store()
            .event(id)
            .await
            .unwrap()
            .map(|e| e.rejected.is_some())
    }
    assert_eq!(
        rejected(&our_rooms, &r_id).await,
        Some(true),
        "R must be rejected: {out}"
    );
    assert_eq!(
        rejected(&our_rooms, &x_id).await,
        Some(true),
        "X cites rejected R and must be rejected: {out}"
    );
    assert_eq!(
        rejected(&our_rooms, &s_id).await,
        Some(false),
        "sentinel S must be accepted: {out}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// After joining the peer's room, a message our local user sends is
/// delivered outbound to the peer (which shares the room) — the outbound
/// half of Complement's TestOutboundFederationSend.
#[tokio::test]
async fn outbound_send_reaches_remote_members() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;

    // Start the outbound sender *before* the join, as a real server would
    // (it runs continuously). This puts the imported join within the
    // sender's window, so the co-signer-skip is actually exercised.
    let (_fedout, sender) = start_delivery(
        saltator_roomserver::RoomShards::single(our_rooms.clone()),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        dir.path(),
    )
    .await;

    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // Our local user (joined via the handshake) sends a message.
    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    let room = ruma::RoomId::parse(&room_id).unwrap();
    let sent = our_rooms
        .send_message(
            &room,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "Hello world!"}),
        )
        .await
        .expect("send");
    let msg_id = match sent {
        Outcome::Accepted { event_id, .. } => event_id.to_string(),
        other => panic!("message not accepted: {other:?}"),
    };

    // The peer should receive it in a transaction (delivery is async).
    let mut delivered = false;
    for _ in 0..50 {
        if peer.received().iter().any(|txn| {
            txn.origin == "hs.test"
                && txn.pdus.iter().any(|p| {
                    p.get("type").and_then(|t| t.as_str()) == Some("m.room.message")
                        && p.get("content")
                            .and_then(|c| c.get("body"))
                            .and_then(|b| b.as_str())
                            == Some("Hello world!")
                })
        }) {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered,
        "peer never received the outbound message {msg_id}; got {:?}",
        peer.received()
    );

    // Our co-signed join must NOT be echoed back to the resident (it already
    // co-signed and distributed it): the peer should see no m.room.member
    // from us in any received transaction.
    let echoed_membership = peer.received().iter().any(|txn| {
        txn.pdus.iter().any(|p| {
            p.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                && p.get("sender").and_then(|s| s.as_str()) == Some("@alice:hs.test")
        })
    });
    assert!(
        !echoed_membership,
        "our join membership was echoed back to the resident: {:?}",
        peer.received()
    );

    sender.abort();
    our_rooms.shutdown().await.unwrap();
}

/// After importing a room hosted on a server whose name carries a *port*
/// (`peer.test:1099`), our local user can still send into it — a regression
/// guard for the ported-server-name send bug (Complement's servers are all
/// `host.docker.internal:PORT`).
#[tokio::test]
async fn local_send_in_imported_ported_room() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test:1099").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(
        &client,
        &hs_signer,
        "peer.test:1099",
        &room_id,
        "@alice:hs.test",
    )
    .await
    .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    let room = ruma::RoomId::parse(&room_id).unwrap();
    let sent = our_rooms
        .send_message(
            &room,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "hi"}),
        )
        .await;
    assert!(
        matches!(sent, Ok(Outcome::Accepted { .. })),
        "send into a ported-server imported room should be accepted: {sent:?}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// The peer crafts a PDU with its signature stripped; our server must reject
/// it on `/send` and not persist it (the Group 6b/8 capability).
#[tokio::test]
async fn peer_malformed_pdu_is_rejected() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // Author a valid message, then strip its signatures before delivery.
    let charlie = "@charlie:peer.test";
    let msg_id = peer.with_room(&room_id, |room| {
        room.message(charlie, json!({"msgtype": "m.text", "body": "unsigned"}))
    });
    let forged = strip_signatures(peer.with_room(&room_id, |room| room.raw(&msg_id)));

    let out = peer
        .send_transaction(&our_base, "hs.test", vec![forged])
        .await;
    assert_ne!(
        &out["pdus"][&msg_id],
        &json!({}),
        "an unsigned PDU must not report success: {out}"
    );
    assert!(
        our_rooms.store().event(&msg_id).await.unwrap().is_none(),
        "an unsigned PDU must not be persisted"
    );

    our_rooms.shutdown().await.unwrap();
}

/// Drive a `send_join` against our server from `@<localpart>:<server>`, the
/// way a remote homeserver would: trust the joiner's keys, fetch a join
/// template, sign it as that server, and apply it. Returns the joiner's user
/// id. Bypasses HTTP (we call `send_join` directly) but exercises the real
/// resident-side apply path — including the `relay` flag the fan-out depends
/// on.
async fn peer_joins_our_room(
    rooms: &Arc<RoomServer>,
    room: &ruma::RoomId,
    server: &str,
    localpart: &str,
) -> String {
    let (signer, _) = ServerSigner::generate(server.try_into().unwrap(), "1".to_owned());
    let keys = signer
        .public_key_map()
        .get(server)
        .cloned()
        .expect("joiner keys");
    rooms.trust_keys(server, keys).await;
    let user = ruma::OwnedUserId::try_from(format!("@{localpart}:{server}")).unwrap();
    let (version, mut template) = rooms
        .make_join_template(
            &saltator_roomserver::RoomShards::single(rooms.clone()),
            room,
            &user,
        )
        .await
        .unwrap();
    signer.hash_and_sign_event(&mut template, version).unwrap();
    rooms.send_join(template).await.expect("send_join applies");
    user.to_string()
}

/// As the *resident* of a room, when a third server joins via `send_join` we
/// must relay its membership to the room's other member servers (spec
/// "Joining Rooms": "The resident server must also send the event to other
/// servers participating in the room"), and must NOT echo it back to the
/// joining server itself. This is the fan-out that unblocks Complement's
/// TestACLs / TestACLsForEDUs.
#[tokio::test]
async fn resident_fans_out_send_join_membership_to_other_members() {
    use saltator_federation::FederationClient;

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    // Our server hosts a public room (alice is the resident creator).
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
    let (room_id, _) = our_rooms
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
        our_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }
    let room = ruma::RoomId::parse(&room_id).unwrap();

    // Capture our outbound federation at a single mock endpoint. The sender's
    // client ignores the destination name and posts everything here, so this
    // stands in for every remote member server.
    let peer = MockPeer::start("capture.test").await;
    let (_fedout, sender) = start_delivery(
        saltator_roomserver::RoomShards::single(our_rooms.clone()),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        dir.path(),
    )
    .await;

    // b.test joins first: at that point only alice (local) is a member, so
    // there is no other server to fan bob's join out to.
    let bob = peer_joins_our_room(&our_rooms, &room, "b.test", "bob").await;
    // c.test joins via us: now b.test is a member, so charlie's join must be
    // relayed to b.test — but not back to c.test.
    let charlie = peer_joins_our_room(&our_rooms, &room, "c.test", "charlie").await;

    // charlie's join membership should reach the capture endpoint.
    let is_join_member = |p: &serde_json::Value, who: &str| {
        p.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
            && p.get("state_key").and_then(|s| s.as_str()) == Some(who)
            && p.get("content")
                .and_then(|c| c.get("membership"))
                .and_then(|m| m.as_str())
                == Some("join")
    };
    let count_join_deliveries = |who: String| {
        move |peer: &MockPeer| {
            peer.received()
                .iter()
                .filter(|txn| {
                    txn.origin == "hs.test" && txn.pdus.iter().any(|p| is_join_member(p, &who))
                })
                .count()
        }
    };
    let charlie_deliveries = count_join_deliveries(charlie.clone());
    let bob_deliveries = count_join_deliveries(bob.clone());

    let mut delivered = 0;
    for _ in 0..50 {
        delivered = charlie_deliveries(&peer);
        if delivered > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered >= 1,
        "resident never relayed charlie's join to the other member server; got {:?}",
        peer.received()
    );
    // Exactly once: relayed to b.test only, never echoed back to c.test (its
    // own origin is excluded from the destination set).
    assert_eq!(
        charlie_deliveries(&peer),
        1,
        "charlie's join must be relayed to b.test only, not echoed to c.test: {:?}",
        peer.received()
    );
    // bob's join had no other member server to reach, so it is never fanned
    // out (and certainly not echoed back to b.test).
    assert_eq!(
        bob_deliveries(&peer),
        0,
        "bob's join should not have been fanned out: {:?}",
        peer.received()
    );

    sender.abort();
    our_rooms.shutdown().await.unwrap();
}

/// Banning a *remote* user delivers the ban to that user's server even though
/// the ban removes them from the room's current membership: as of the ban that
/// server is still a recipient, and otherwise would never learn its user is
/// gone (the delivery half of Complement's TestUnbanViaInvite — alice@hs1 must
/// see her ban in a room hosted elsewhere).
#[tokio::test]
async fn ban_of_remote_user_reaches_their_server() {
    use saltator_federation::FederationClient;

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    // Our server hosts a public room; alice is the creator (power 100).
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
    let (room_id, _) = our_rooms
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
        our_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }
    let room = ruma::RoomId::parse(&room_id).unwrap();

    // Capture our outbound at a single mock endpoint (destination name ignored).
    let peer = MockPeer::start("capture.test").await;
    let (_fedout, sender) = start_delivery(
        saltator_roomserver::RoomShards::single(our_rooms.clone()),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        dir.path(),
    )
    .await;

    // bob (on b.test) joins, then alice bans him — bob's server is now the only
    // *remote* server and the ban removes it from current membership.
    let bob = peer_joins_our_room(&our_rooms, &room, "b.test", "bob").await;
    our_rooms
        .send_state(
            &room,
            &alice,
            "m.room.member",
            &bob,
            json!({"membership": "ban"}),
        )
        .await
        .expect("alice bans bob");

    // The ban must be delivered to bob's server despite it no longer being a
    // joined member.
    let mut delivered = false;
    for _ in 0..50 {
        if peer.received().iter().any(|txn| {
            txn.origin == "hs.test"
                && txn.pdus.iter().any(|p| {
                    p.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                        && p.get("state_key").and_then(|s| s.as_str()) == Some(bob.as_str())
                        && p.get("content")
                            .and_then(|c| c.get("membership"))
                            .and_then(|m| m.as_str())
                            == Some("ban")
                })
        }) {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered,
        "ban of a remote user was not delivered to their server: {:?}",
        peer.received()
    );

    sender.abort();
    our_rooms.shutdown().await.unwrap();
}

/// A PDU whose origin is denied by the room's m.room.server_acl is dropped
/// on inbound /send, while the same origin is unaffected in a room that
/// allows it (Complement TestACLs).
#[tokio::test]
async fn inbound_pdu_from_acl_denied_server_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);
    // A ported name, as Complement/deployments use — the ACL entry and the
    // sending origin must match on the full `host:port`.
    let peer = MockPeer::start("peer.test:9001").await;

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();

    // A room whose ACL denies the peer (by its full host:port), and one that allows it.
    let mk_room = |acl_deny: &'static str| {
        let rooms = our_rooms.clone();
        let alice = alice.clone();
        async move {
            let (room, _) = rooms
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
                (
                    "m.room.server_acl",
                    "",
                    json!({"allow": ["*"], "deny": [acl_deny]}),
                ),
            ] {
                rooms
                    .send_state(&room, &alice, ty, sk, content)
                    .await
                    .unwrap();
            }
            room.to_string()
        }
    };
    let denied_room = mk_room("peer.test:9001").await;
    let open_room = mk_room("other.test").await;

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let our_base = spawn(router(our_fed)).await;

    // A signed message PDU for `room` from a user on the peer.
    let make_pdu = |room: &str| {
        let mut raw = match ruma::CanonicalJsonValue::try_from(json!({
            "room_id": room,
            "sender": "@mallory:peer.test:9001",
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "hi"},
            "auth_events": [],
            "prev_events": [],
            "depth": 5,
            "origin_server_ts": 1_700_000_000_000u64,
        }))
        .unwrap()
        {
            ruma::CanonicalJsonValue::Object(o) => o,
            _ => unreachable!(),
        };
        peer.signer
            .hash_and_sign_event(&mut raw, RoomVersion::V11)
            .unwrap();
        raw
    };

    // Denied room: the PDU is ACL-rejected and not persisted.
    let denied_pdu = make_pdu(&denied_room);
    let denied_id = saltator_core::event::event_id(&denied_pdu, RoomVersion::V11)
        .unwrap()
        .to_string();
    let out = peer
        .send_transaction(&our_base, "hs.test", vec![denied_pdu])
        .await;
    assert!(
        out["pdus"][&denied_id]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("server ACL"),
        "denied PDU should be ACL-rejected: {out}"
    );
    assert!(our_rooms.store().event(&denied_id).await.unwrap().is_none());

    // Allowed room: the same origin is NOT ACL-rejected (it fails ingest for
    // a different reason — missing events — proving the ACL let it through).
    let open_pdu = make_pdu(&open_room);
    let open_id = saltator_core::event::event_id(&open_pdu, RoomVersion::V11)
        .unwrap()
        .to_string();
    let out = peer
        .send_transaction(&our_base, "hs.test", vec![open_pdu])
        .await;
    assert!(
        !out["pdus"][&open_id]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("server ACL"),
        "allowed server must not be ACL-rejected: {out}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// The restart-from-tip delivery-loss gap, closed: events committed
/// while the delivery worker is down are delivered after "restart" (a
/// fresh worker resuming from the durable cursors) — exactly once, with
/// no re-delivery of what was already acked. This is step 4's headline
/// exit assertion in-process; the 3-node kill -9 variant is tracked in
/// the design doc.
#[tokio::test]
async fn delivery_resumes_from_durable_cursor_after_restart() {
    use saltator_federation::FederationClient;

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    // Our server hosts a room with a remote member on the peer.
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
    let (room_id, _) = our_rooms
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
        our_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }
    let peer = MockPeer::start("peer.test").await;
    let room = ruma::RoomId::parse(&room_id).unwrap();
    let _bob = peer_joins_our_room(&our_rooms, &room, "peer.test", "bob").await;

    let (fedout, worker) = start_delivery(
        saltator_roomserver::RoomShards::single(our_rooms.clone()),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        dir.path(),
    )
    .await;

    // msg1 delivers under the first worker; wait for its arrival.
    let count_bodies = |peer: &MockPeer, needle: &str| {
        peer.received()
            .iter()
            .flat_map(|t| t.pdus.iter())
            .filter(|p| p["content"]["body"] == *needle)
            .count()
    };
    our_rooms
        .send_message(&room, &alice, "m.room.message", json!({"body": "msg1"}))
        .await
        .unwrap();
    for _ in 0..200 {
        if count_bodies(&peer, "msg1") >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(count_bodies(&peer, "msg1"), 1, "msg1 never delivered");
    // Let the cursor-advance proposal land before the kill.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The worker dies; two more messages commit while nothing delivers.
    worker.abort();
    for body in ["msg2", "msg3"] {
        our_rooms
            .send_message(&room, &alice, "m.room.message", json!({"body": body}))
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        count_bodies(&peer, "msg2"),
        0,
        "no worker should be running"
    );

    // "Restart": a fresh worker on the same durable state.
    let worker2 = saltator_federation::spawn_delivery_worker(
        fedout.clone(),
        saltator_roomserver::RoomShards::single(our_rooms.clone()),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
        Arc::new(saltator_federation::DeliveryBackoff::default()),
    );
    for _ in 0..300 {
        if count_bodies(&peer, "msg3") >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(count_bodies(&peer, "msg2"), 1, "msg2 lost across restart");
    assert_eq!(count_bodies(&peer, "msg3"), 1, "msg3 lost across restart");
    // And the already-acked span did not re-deliver.
    assert_eq!(count_bodies(&peer, "msg1"), 1, "msg1 re-delivered");

    worker2.abort();
    our_rooms.shutdown().await.unwrap();
}

/// `/event`, `/backfill` and `/event_auth` serve room members only
/// (Synapse parity): a server with no user in the room gets a 403, not
/// the room's history. The member keeps full service through the same
/// code path.
#[tokio::test]
async fn room_data_endpoints_refuse_strangers() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let stranger = MockPeer::start("stranger.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    // Our server joins + imports the room — peer.test is a member on our
    // copy (charlie lives there); stranger.test never appears in it.
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = Arc::new(FederationClient::with_base_url(
        hs_signer.clone(),
        peer.base_url.clone(),
    ));
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // Two routers over the SAME room store, differing only in whose keys
    // the KeyCache can fetch — so each caller authenticates as itself.
    let fed_for = |base: String| {
        Arc::new(FedState {
            server_name: hs.clone(),
            signer: hs_signer.clone(),
            old_keys: Vec::<OldVerifyKey>::new(),
            key_cache: Arc::new(KeyCache::with_base_url(base)),
            rooms: Some(saltator_roomserver::RoomShards::single(our_rooms.clone())),
            users: None,
            client: None,
            edu_sink: None,
            media: None,
            delivery_backoff: None,
            appservices: None,
            txn_replay: saltator_federation::TxnReplayCache::default(),
        })
    };
    let member_base = spawn(router(fed_for(peer.base_url.clone()))).await;
    let stranger_base = spawn(router(fed_for(stranger.base_url.clone()))).await;

    // Any stored event of the room will do as the probe target.
    let event_id = our_rooms
        .store()
        .timeline(0, 64)
        .await
        .unwrap()
        .into_iter()
        .find_map(|(_, e)| match e {
            saltator_roomserver::SeqEntry::Event {
                room_id: r,
                event_id,
            } if r == room_id => Some(event_id),
            _ => None,
        })
        .expect("imported room has events");

    let enc = |s: &str| {
        s.replace('$', "%24")
            .replace('!', "%21")
            .replace(':', "%3A")
    };
    let paths = [
        format!("/_matrix/federation/v1/event/{}", enc(&event_id)),
        format!(
            "/_matrix/federation/v1/backfill/{}?v={}",
            enc(&room_id),
            enc(&event_id)
        ),
        format!(
            "/_matrix/federation/v1/event_auth/{}/{}",
            enc(&room_id),
            enc(&event_id)
        ),
    ];
    for path in &paths {
        let (status, body) = peer.signed_get(&member_base, "hs.test", path).await;
        assert_eq!(status, 200, "member should be served {path}: {body}");

        let (status, body) = stranger.signed_get(&stranger_base, "hs.test", path).await;
        assert_eq!(status, 403, "stranger must be refused {path}: {body}");
        assert_eq!(body["errcode"], "M_FORBIDDEN", "{path}: {body}");
    }
}
