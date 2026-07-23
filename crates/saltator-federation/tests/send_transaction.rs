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
