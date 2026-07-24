//! End-to-end `PUT /_matrix/federation/v1/send/{txnId}`: a signed
//! transaction carrying real PDUs is authenticated, routed through the
//! room pipeline, and answered with per-PDU results.

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_federation::{router, sign_request, FedState, KeyCache, OldVerifyKey};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

const SERVER: &str = "hs.test";

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn send_transaction_routes_pdus_and_reports_results() {
    let dir = tempfile::tempdir().unwrap();
    let name: OwnedServerName = SERVER.try_into().unwrap();
    let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
    let signer = Arc::new(signer);
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let rooms = RoomServer::start(
        1,
        engine,
        signer.clone(),
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
    // `RoomServer::start` already returns Arc<RoomServer>.

    // A real, already-persisted PDU: the create event of a fresh room.
    let alice = ruma::OwnedUserId::try_from(format!("@alice:{SERVER}")).unwrap();
    let (room_id, outcome) = rooms
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    let create_id = match outcome {
        Outcome::Accepted { event_id, .. } => event_id,
        other => panic!("create not accepted: {other:?}"),
    };
    let create_pdu: serde_json::Value = serde_json::from_slice(
        &rooms
            .store()
            .event(create_id.as_str())
            .unwrap()
            .unwrap()
            .raw,
    )
    .unwrap();

    // A stand-alone key server for SERVER, so the receiver's key cache can
    // resolve the (self-)origin without a chicken-and-egg on its own addr.
    let key_base = spawn(router(Arc::new(FedState::new(
        name.clone(),
        signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;

    // The receiver: authenticates against key_base, routes PDUs to `rooms`.
    let state = Arc::new(FedState {
        server_name: name.clone(),
        signer: signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::with_base_url(key_base),
        rooms: Some(rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let base = spawn(router(state)).await;

    // Transaction: the real create PDU (already present → Duplicate →
    // success), a malformed PDU (→ error, unkeyable, dropped), and a
    // well-formed message in the known room whose prev/auth events are
    // absent (→ error, keyed by its computable event id).
    let bad_pdu = json!({
        "type": "m.room.message",
        "room_id": room_id,
        "sender": format!("@alice:{SERVER}"),
        "content": {"msgtype": "m.text", "body": "hi"},
        "depth": 100,
        "prev_events": ["$missing_parent"],
        "auth_events": ["$missing_parent"],
        "origin_server_ts": 1000,
    });
    let body = json!({
        "origin": SERVER,
        "origin_server_ts": 1000,
        "pdus": [create_pdu, "not-an-object", bad_pdu],
    });

    let path = "/_matrix/federation/v1/send/txn1";
    let content = ruma::CanonicalJsonValue::try_from(body.clone()).unwrap();
    let auth = sign_request(&signer, "PUT", path, SERVER, Some(&content)).unwrap();
    let resp = reqwest::Client::new()
        .put(format!("{base}{path}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let out: serde_json::Value = resp.json().await.unwrap();

    let pdus = out["pdus"].as_object().expect("pdus object");
    // The real create event is already present → success (empty object).
    let create_result = &pdus[create_id.as_str()];
    assert!(
        create_result.as_object().unwrap().is_empty(),
        "create PDU should succeed, got {create_result}"
    );
    // At least one PDU is reported with an error (the unknown-room one).
    let has_error = pdus
        .values()
        .any(|v| v.get("error").and_then(|e| e.as_str()).is_some());
    assert!(has_error, "expected an error entry, got {out}");
}

#[tokio::test]
async fn send_fills_dag_gap_via_get_missing_events() {
    use saltator_federation::FederationClient;

    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // A hosts a room; collect its events in DAG order.
    let a_engine = Arc::new(RocksEngine::open(&dir.path().join("a")).unwrap());
    let rooms_a = RoomServer::start(
        1,
        a_engine,
        a_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    rooms_a
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, oc) = rooms_a
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    let mut ids = vec![match oc {
        Outcome::Accepted { event_id, .. } => event_id.to_string(),
        o => panic!("{o:?}"),
    }];
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership":"join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users":{alice.as_str():100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule":"public"})),
    ] {
        let o = rooms_a
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
        ids.push(match o {
            Outcome::Accepted { event_id, .. } => event_id.to_string(),
            o => panic!("{o:?}"),
        });
    }
    // Two messages: msg1 then msg2 (msg2.prev = [msg1]).
    for body in ["msg1", "msg2"] {
        let o = rooms_a
            .send_message(
                &room_id,
                &alice,
                "m.room.message",
                json!({"msgtype":"m.text","body":body}),
            )
            .await
            .unwrap();
        ids.push(match o {
            Outcome::Accepted { event_id, .. } => event_id.to_string(),
            o => panic!("{o:?}"),
        });
    }
    let raw_of = |id: &str| -> serde_json::Value {
        serde_json::from_slice(&rooms_a.store().event(id).unwrap().unwrap().raw).unwrap()
    };
    // ids: [create, member, power_levels, join_rules, msg1, msg2]
    let msg2 = raw_of(&ids[5]);

    // Standalone B key server so A can verify B's get_missing_events request.
    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;
    // A's federation endpoint: serves keys + get_missing_events, authenticates B.
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::with_base_url(b_key_base),
        rooms: Some(rooms_a.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;

    // B has the room only up to join_rules (missing msg1). Replay e0..e3.
    let b_engine = Arc::new(RocksEngine::open(&dir.path().join("b")).unwrap());
    let rooms_b = RoomServer::start(
        1,
        b_engine,
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    rooms_b
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    if let Some(set) = a_signer.public_key_map().get("a.test") {
        rooms_b.trust_keys("a.test", set.clone());
    }
    for id in ids.iter().take(4) {
        let obj = match ruma::CanonicalJsonValue::try_from(raw_of(id)).unwrap() {
            ruma::CanonicalJsonValue::Object(o) => o,
            _ => panic!(),
        };
        rooms_b.ingest_pdu(obj).await.unwrap();
    }
    assert_eq!(
        rooms_b.room_extremities(room_id.as_str()).unwrap(),
        vec![ids[3].clone()],
        "B at join_rules"
    );

    // B's federation endpoint: authenticates A, gap-fills from A.
    let b_state = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::with_base_url(a_base.clone()),
        rooms: Some(rooms_b.clone()),
        users: None,
        client: Some(Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            a_base.clone(),
        ))),
        edu_sink: None,
        media: None,
    });
    let b_base = spawn(router(b_state)).await;

    // A sends msg2 (prev = [msg1], which B lacks) to B via /send.
    let txn = json!({ "origin": "a.test", "origin_server_ts": 1000, "pdus": [msg2] });
    let path = "/_matrix/federation/v1/send/gaptxn";
    let content = ruma::CanonicalJsonValue::try_from(txn.clone()).unwrap();
    let auth = sign_request(&a_signer, "PUT", path, "b.test", Some(&content)).unwrap();
    let resp = reqwest::Client::new()
        .put(format!("{b_base}{path}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&txn)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let out: serde_json::Value = resp.json().await.unwrap();

    // msg2 accepted (empty result object = success), after the gap filled.
    let result = &out["pdus"][&ids[5]];
    assert!(
        result.as_object().map(|o| o.is_empty()).unwrap_or(false),
        "msg2 should succeed after gap fill: {out}"
    );
    // B now has msg1 and msg2.
    assert!(
        rooms_b.store().event(&ids[4]).unwrap().is_some(),
        "B backfilled msg1"
    );
    assert!(
        rooms_b.store().event(&ids[5]).unwrap().is_some(),
        "B has msg2"
    );
}
