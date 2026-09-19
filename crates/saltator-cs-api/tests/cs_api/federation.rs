//! Federation as a client sees it: remote join by room id and by alias
//! (with backfill and unverifiable-state pruning), invites and bans in
//! both directions, EDUs arriving in `/sync` (receipts, typing,
//! presence, to-device), federated key query and claim, sync gaps, the
//! SSRF guard, rate limiting, and an imported room's `send_join`
//! state reaching `/sync`.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use saltator_cs_api::{CsConfig, CsState};
use saltator_federation::{FedState, FederationClient, KeyCache, OldVerifyKey};
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::{spawn_membership_projection, UserServer};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use crate::harness::*;

#[tokio::test]
async fn client_joins_a_remote_room_via_federation() {
    let dir = tempfile::tempdir().unwrap();

    // Node A hosts a public v11 room.
    let (a_rooms, a_signer) = start_fed_rooms("a.test", dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = a_rooms
        .create_room(
            &alice,
            saltator_core::RoomVersion::V11,
            serde_json::Map::new(),
        )
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
        a_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    // Node B: full CS stack + its own room/user servers + federation.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    // B's key server, so A can verify B's signed requests and join event.
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    // A's federation surface, authenticating B against B's key server.
    let a_base = spawn_fed(
        "a.test",
        a_signer.clone(),
        Some(a_rooms.clone()),
        Some(b_key_base),
    )
    .await;

    // B's CS state, with an outbound client aimed at A.
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base)),
    );
    let router = saltator_cs_api::router(state);

    // Register bob on B and join the remote room by ID.
    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut b = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    b = b.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        b = b.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(b.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    // Register (UIA dummy).
    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    // POST /join/{roomId} — the remote-join path.
    let room_enc: String = room_id
        .as_str()
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join failed: {body}");
    assert_eq!(body["room_id"], room_id.as_str());

    // Bob's /sync now shows the room joined.
    let (status, sync) = http_req("GET", "/_matrix/client/v3/sync".into(), Some(bob), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sync["rooms"]["join"].get(room_id.as_str()).is_some(),
        "joined room missing from sync: {sync}"
    );

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
    a_rooms.shutdown().await.unwrap();
}

/// A federated ban of a local user must surface in that user's `/sync` in the
/// `leave` section — and must never leak into `join`. This guards a cross-shard
/// consistency bug behind Complement's TestUnbanViaInvite: the membership index
/// (user shard) is a projection of the room shard and trails it, so a sync that
/// reads a stale "join" membership while the room-shard timeline already holds
/// the ban would classify the room as joined (ban in its timeline) and only
/// later move it to an empty `leave`, so the transition is never observed in
/// `leave`. hs2 hosts, alice@hs1 remote-joins, bob bans her.
#[tokio::test]
async fn federated_ban_of_local_user_surfaces_in_sync() {
    let dir = tempfile::tempdir().unwrap();
    let pct = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };

    // --- hs2 hosts a public room; bob is the creator (power 100). ---
    let (hs2_rooms, hs2_signer) = start_fed_rooms("hs2", dir.path()).await;
    let bob = ruma::OwnedUserId::try_from("@bob:hs2").unwrap();
    let (room_id, _) = hs2_rooms
        .create_room(
            &bob,
            saltator_core::RoomVersion::V11,
            serde_json::Map::new(),
        )
        .await
        .unwrap();
    for (ty, sk, content) in [
        ("m.room.member", bob.as_str(), json!({"membership": "join"})),
        (
            "m.room.power_levels",
            "",
            json!({"users": {bob.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        hs2_rooms
            .send_state(&room_id, &bob, ty, sk, content)
            .await
            .unwrap();
    }

    // --- hs1: rooms + users + membership projection (alice's home server). ---
    let hs1_dir = dir.path().join("hs1full");
    std::fs::create_dir_all(&hs1_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&hs1_dir.join("db")).unwrap());
    let hs1_name = ruma::OwnedServerName::try_from("hs1").unwrap();
    let (hs1_signer, _) =
        saltator_roomserver::ServerSigner::generate(hs1_name.clone(), "1".to_owned());
    let hs1_signer = Arc::new(hs1_signer);
    let hs1_rooms = RoomServer::start(
        1,
        engine.clone(),
        hs1_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let hs1_users = UserServer::start(
        1,
        engine,
        hs1_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [hs1_rooms.shard_handle(), hs1_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let proj = spawn_membership_projection(
        hs1_users.clone(),
        saltator_roomserver::RoomShards::single(hs1_rooms.clone()),
    );

    // Separate key servers break the mutual auth dependency.
    let hs1_key_base = spawn_fed("hs1", hs1_signer.clone(), None, None).await;
    let hs2_key_base = spawn_fed("hs2", hs2_signer.clone(), None, None).await;
    let hs2_fed_base = spawn_fed(
        "hs2",
        hs2_signer.clone(),
        Some(hs2_rooms.clone()),
        Some(hs1_key_base),
    )
    .await;
    let hs1_fed_base = spawn_fed(
        "hs1",
        hs1_signer.clone(),
        Some(hs1_rooms.clone()),
        Some(hs2_key_base),
    )
    .await;

    // --- hs1's CS stack (alice), federating to hs2. ---
    let media = MediaStore::open(hs1_dir.join("media")).unwrap();
    let cs = CsState::new(
        hs1_users.clone(),
        saltator_roomserver::RoomShards::single(hs1_rooms.clone()),
        media,
        CsConfig {
            server_name: hs1_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            hs1_signer.clone(),
            hs2_fed_base.clone(),
        )),
        hs1_signer.clone(),
        Arc::new(KeyCache::with_base_url(hs2_fed_base.clone())),
    );
    let hs1_router = saltator_cs_api::router(cs);

    // alice registers and joins the remote room via hs2, then syncs to obtain
    // a baseline token from *before* the ban.
    let alice_tok = reg(&hs1_router, "alice").await;
    let (status, body) = oneshot(
        &hs1_router,
        "POST",
        &format!(
            "/_matrix/client/v3/rooms/{}/join?server_name=hs2",
            pct(room_id.as_str())
        ),
        Some(&alice_tok),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remote join failed: {body}");
    let (_s, sync0) = oneshot(
        &hs1_router,
        "GET",
        "/_matrix/client/v3/sync",
        Some(&alice_tok),
        None,
    )
    .await;
    assert!(
        sync0["rooms"]["join"].get(room_id.as_str()).is_some(),
        "alice not joined after remote join: {sync0}"
    );
    let since = sync0["next_batch"].as_str().unwrap().to_owned();

    // hs2's real outbound delivery worker, aimed at hs1.
    let (_hs2_fedout, hs2_sender) = start_fedout_delivery(
        dir.path(),
        hs2_rooms.clone(),
        Arc::new(FederationClient::with_base_url(
            hs2_signer.clone(),
            hs1_fed_base.clone(),
        )),
        "hs2",
    )
    .await;

    // bob bans alice; the sender delivers the ban to hs1.
    let alice_uid = "@alice:hs1";
    let out = hs2_rooms
        .send_state(
            &room_id,
            &bob,
            "m.room.member",
            alice_uid,
            json!({"membership": "ban"}),
        )
        .await
        .unwrap();
    assert!(
        matches!(out, saltator_roomserver::Outcome::Accepted { .. }),
        "ban not accepted on the host: {out:?}"
    );

    // Incremental syncs from the pre-ban token: the ban must appear in `leave`
    // and must NEVER appear in `join` (the projection-lag classification bug).
    let has_ban = |section: &Value| {
        section["events"].as_array().is_some_and(|es| {
            es.iter().any(|e| {
                e["type"] == "m.room.member"
                    && e["state_key"] == alice_uid
                    && e["content"]["membership"] == "ban"
            })
        })
    };
    let mut seen_in_leave = false;
    for _ in 0..100 {
        let (_s, sync) = oneshot(
            &hs1_router,
            "GET",
            &format!("/_matrix/client/v3/sync?since={since}"),
            Some(&alice_tok),
            None,
        )
        .await;
        let join = &sync["rooms"]["join"][room_id.as_str()];
        assert!(
            !has_ban(&join["timeline"]) && !has_ban(&join["state"]),
            "ban leaked into the JOIN section (sync read a stale membership): {sync}"
        );
        let leave = &sync["rooms"]["leave"][room_id.as_str()];
        if has_ban(&leave["timeline"]) || has_ban(&leave["state"]) {
            seen_in_leave = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen_in_leave,
        "alice never saw her federated ban in the /sync leave section"
    );

    hs2_sender.abort();
    proj.abort();
    hs1_rooms.shutdown().await.unwrap();
    hs1_users.shutdown().await.unwrap();
    hs2_rooms.shutdown().await.unwrap();
}

/// Joining by a *remote* alias: B resolves `#flibble:a.test` through A's
/// federation `/query/directory`, then joins the room it names — the
/// join-by-alias half of Complement's TestOutboundFederationSend.
#[tokio::test]
async fn client_joins_a_remote_room_by_remote_alias() {
    let dir = tempfile::tempdir().unwrap();

    // Node A: rooms + a user server (so it can serve the directory), hosting
    // a public v11 room reachable via the alias #flibble:a.test.
    let (a_rooms, a_signer) = start_fed_rooms("a.test", dir.path()).await;
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let a_users_engine = Arc::new(RocksEngine::open(&dir.path().join("a_users")).unwrap());
    let a_users = UserServer::start(
        1,
        a_users_engine,
        a_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    a_users
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();

    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = a_rooms
        .create_room(
            &alice,
            saltator_core::RoomVersion::V11,
            serde_json::Map::new(),
        )
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
        a_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }
    let room_alias = "#flibble:a.test";
    a_users
        .create_alias(room_alias, room_id.as_str(), &alice)
        .await
        .unwrap();

    // Node B: full CS stack + its own room/user servers + federation.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    // B's key server, so A can verify B's signed requests and join event.
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    // A's federation surface: rooms + users (for /query/directory),
    // authenticating B against B's key server.
    let a_state = FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(a_rooms.clone())),
        users: Some(a_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    };
    let a_app = saltator_federation::router(Arc::new(a_state));
    let a_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(a_listener, a_app).await.unwrap();
    });
    let a_base = format!("http://{a_addr}");

    // B's CS state, with an outbound client + key cache aimed at A.
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base)),
    );
    let router = saltator_cs_api::router(state);

    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut b = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    b = b.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        b = b.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(b.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    // Register bob on B.
    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    // POST /join/{roomIdOrAlias} with the REMOTE alias.
    let alias_enc: String = room_alias
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/join/{alias_enc}"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remote-alias join failed: {body}");
    assert_eq!(body["room_id"], room_id.as_str());

    // Bob's /sync now shows the room joined.
    let (status, sync) = http_req("GET", "/_matrix/client/v3/sync".into(), Some(bob), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sync["rooms"]["join"].get(room_id.as_str()).is_some(),
        "joined room missing from sync: {sync}"
    );

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
}

/// A send_join response carrying an unverifiable *non-critical* state event
/// (an unsigned room name) must not block the join: the bad event is dropped
/// and the join succeeds. Only the join's own auth chain must verify
/// (Complement TestJoinFederatedRoomWithUnverifiableEvents).
#[tokio::test]
async fn remote_join_drops_unverifiable_noncritical_state() {
    use saltator_testsupport::MockPeer;

    let dir = tempfile::tempdir().unwrap();

    // A mock resident hosting a room whose current state includes an
    // unsigned m.room.name (not part of a joiner's auth chain).
    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(saltator_core::RoomVersion::V11, "charlie");
    peer.with_room(&room_id, |room| {
        room.unverifiable_state_event(
            "@charlie:peer.test",
            "m.room.name",
            "",
            json!({"name": "This event has no signature"}),
        )
    });

    // Node B: full CS stack + federation aimed at the peer.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            peer.base_url.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
    );
    let router = saltator_cs_api::router(state);

    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut b = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    b = b.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        b = b.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(b.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    // Register bob on B.
    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    // Join by room ID: the unsigned room name in the resident's state must
    // be dropped, not block the join.
    let room_enc: String = room_id
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "join with an unverifiable non-critical event should succeed: {body}"
    );
    assert_eq!(body["room_id"], room_id);

    // Bob's /sync shows the room joined.
    let (status, sync) = http_req("GET", "/_matrix/client/v3/sync".into(), Some(bob), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sync["rooms"]["join"].get(&room_id).is_some(),
        "joined room missing from sync: {sync}"
    );

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// After joining a room hosted on a *ported* server name
/// (`host.docker.internal:PORT`), a client can send a message into it through
/// the CS API — regression for the ported-room-id send bug behind
/// Complement's TestOutboundFederationSend.
#[tokio::test]
async fn send_message_in_remote_ported_room() {
    use saltator_testsupport::MockPeer;

    let dir = tempfile::tempdir().unwrap();
    let peer = MockPeer::start("peer.test:1099").await;
    let room_id = peer.make_room(saltator_core::RoomVersion::V11, "charlie");

    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            peer.base_url.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
    );
    let router = saltator_cs_api::router(state);

    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut rb = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    rb = rb.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        rb = rb.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(rb.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    let room_enc = enc(&room_id);
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join failed: {body}");

    // The regression: sending into the ported-server room via the CS API.
    let (status, body) = http_req(
        "PUT",
        format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/txn1"),
        Some(bob),
        Some(json!({"msgtype": "m.text", "body": "hello"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "send into ported-server room should succeed: {body}"
    );
    assert!(body["event_id"].is_string(), "no event_id: {body}");

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// Remote join, then paginate the room's WHOLE history backwards: the
/// messages sent before our join live on the resident and arrive via
/// federated `GET /backfill`, continuing seamlessly past the local
/// timeline floor until `end` disappears at the room's beginning
/// (Complement TestMessagesOverFederation).
#[tokio::test]
async fn remote_join_backfills_full_history() {
    let dir = tempfile::tempdir().unwrap();

    // Node A hosts a public v11 room with pre-join history.
    let (a_rooms, a_signer) = start_fed_rooms("a.test", dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = a_rooms
        .create_room(
            &alice,
            saltator_core::RoomVersion::V11,
            serde_json::Map::new(),
        )
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
        a_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }
    let total = 20;
    for i in 1..=total {
        a_rooms
            .send_message(
                &room_id,
                &alice,
                "m.room.message",
                json!({"msgtype": "m.text", "body": format!("history {i}")}),
            )
            .await
            .unwrap();
    }

    // Node B: full CS stack + federation aimed at A.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    let a_base = spawn_fed(
        "a.test",
        a_signer.clone(),
        Some(a_rooms.clone()),
        Some(b_key_base),
    )
    .await;

    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base)),
    );
    let router = saltator_cs_api::router(state);

    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut b = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    b = b.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        b = b.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(b.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    let room_enc: String = room_id
        .as_str()
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join failed: {body}");

    // Paginate backwards until `end` disappears, collecting everything.
    let mut bodies: Vec<String> = Vec::new();
    let mut saw_create = false;
    let mut from: Option<String> = None;
    for page in 0.. {
        assert!(page < 12, "pagination did not terminate");
        let path = match &from {
            Some(f) => {
                format!("/_matrix/client/v3/rooms/{room_enc}/messages?dir=b&limit=10&from={f}")
            }
            None => format!("/_matrix/client/v3/rooms/{room_enc}/messages?dir=b&limit=10"),
        };
        let (status, got) = http_req("GET", path, Some(bob.clone()), None).await;
        assert_eq!(status, StatusCode::OK, "{got}");
        for ev in got["chunk"].as_array().unwrap() {
            if ev["type"] == "m.room.create" {
                saw_create = true;
            }
            if let Some(b) = ev["content"]["body"].as_str() {
                bodies.push(b.to_owned());
            }
        }
        match got["end"].as_str() {
            Some(end) => from = Some(end.to_owned()),
            None => break,
        }
    }
    let expected: Vec<String> = (1..=total).rev().map(|i| format!("history {i}")).collect();
    assert_eq!(
        bodies, expected,
        "backfilled history incomplete or out of order"
    );
    assert!(saw_create, "pagination never reached the room's beginning");

    // Re-join: bob leaves, misses 20 messages (no local user → nothing
    // federates to us), rejoins. The rejoin must go back through the
    // resident (our fork is stale) and the missed span must become
    // paginatable via the refreshed backfill frontier.
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/leave"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leave failed: {body}");
    for i in 1..=total {
        a_rooms
            .send_message(
                &room_id,
                &alice,
                "m.room.message",
                json!({"msgtype": "m.text", "body": format!("missed {i}")}),
            )
            .await
            .unwrap();
    }
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rejoin failed: {body}");

    let mut bodies: Vec<String> = Vec::new();
    let mut from: Option<String> = None;
    for page in 0.. {
        assert!(page < 16, "rejoin pagination did not terminate");
        let path = match &from {
            Some(f) => {
                format!("/_matrix/client/v3/rooms/{room_enc}/messages?dir=b&limit=10&from={f}")
            }
            None => format!("/_matrix/client/v3/rooms/{room_enc}/messages?dir=b&limit=10"),
        };
        let (status, got) = http_req("GET", path, Some(bob.clone()), None).await;
        assert_eq!(status, StatusCode::OK, "{got}");
        for ev in got["chunk"].as_array().unwrap() {
            if let Some(b) = ev["content"]["body"].as_str() {
                bodies.push(b.to_owned());
            }
        }
        match got["end"].as_str() {
            Some(end) => from = Some(end.to_owned()),
            None => break,
        }
    }
    // The missed messages appear in reverse-chronological relative order
    // (their absolute position rides the MSC3871 gappy-timeline hole).
    let missed: Vec<&String> = bodies.iter().filter(|b| b.starts_with("missed ")).collect();
    let expected_missed: Vec<String> = (1..=total).rev().map(|i| format!("missed {i}")).collect();
    assert_eq!(
        missed,
        expected_missed.iter().collect::<Vec<_>>(),
        "missed span not backfilled in order: {bodies:?}"
    );
    for i in 1..=total {
        assert!(
            bodies.contains(&format!("history {i}")),
            "pre-join history lost after rejoin"
        );
    }

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
    a_rooms.shutdown().await.unwrap();
}

/// An unfillable DAG gap (the origin truncates /get_missing_events) is
/// anchored on fetched state; the recovered tail joins the timeline past
/// a gap marker, and the incremental sync spanning it serves ONLY the
/// post-gap events with `limited: true` (Complement TestSyncTimelineGap).
#[tokio::test]
async fn sync_gap_sets_limited_and_truncates_window() {
    let dir = tempfile::tempdir().unwrap();

    // Node A hosts the room.
    let (a_rooms, a_signer) = start_fed_rooms("a.test", dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = a_rooms
        .create_room(
            &alice,
            saltator_core::RoomVersion::V11,
            serde_json::Map::new(),
        )
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
        a_rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    // Node B: full CS stack; bob joins remotely (same shape as the
    // backfill test).
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    let a_base = spawn_fed(
        "a.test",
        a_signer.clone(),
        Some(a_rooms.clone()),
        Some(b_key_base),
    )
    .await;

    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base.clone())),
    );
    let router = saltator_cs_api::router(state);

    let http_req =
        |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
            let router = router.clone();
            async move {
                let mut b = Request::builder().method(method).uri(path);
                if let Some(t) = token {
                    b = b.header("Authorization", format!("Bearer {t}"));
                }
                let body = match body {
                    Some(v) => {
                        b = b.header("Content-Type", "application/json");
                        Body::from(serde_json::to_vec(&v).unwrap())
                    }
                    None => Body::empty(),
                };
                let resp = router.oneshot(b.body(body).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let val: Value = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
                };
                (status, val)
            }
        };

    let (_s, ch) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username": "bob", "password": "bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http_req(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({
            "username": "bob", "password": "bob-pw-1234",
            "auth": {"type": "m.login.dummy", "session": session},
        })),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    let room_enc: String = room_id
        .as_str()
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let (status, body) = http_req(
        "POST",
        format!("/_matrix/client/v3/rooms/{room_enc}/join"),
        Some(bob.clone()),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "join failed: {body}");

    // Bob's sync position before any of the new traffic.
    let (_, sync0) = http_req(
        "GET",
        "/_matrix/client/v3/sync".into(),
        Some(bob.clone()),
        None,
    )
    .await;
    let since = sync0["next_batch"].as_str().unwrap().to_owned();

    // On A: one message that will federate normally, then 12 that won't,
    // then the one that triggers the gap fill.
    let send = |body: String| {
        let a_rooms = a_rooms.clone();
        let room_id = room_id.clone();
        let alice = alice.clone();
        async move {
            match a_rooms
                .send_message(
                    &room_id,
                    &alice,
                    "m.room.message",
                    json!({"msgtype": "m.text", "body": body}),
                )
                .await
                .unwrap()
            {
                saltator_roomserver::Outcome::Accepted { event_id, .. } => event_id.to_string(),
                o => panic!("{o:?}"),
            }
        }
    };
    let pre_id = send("before the gap".to_owned()).await;
    let mut gap_ids = Vec::new();
    for i in 1..=12 {
        gap_ids.push(send(format!("gap {i}")).await);
    }
    let last_id = send("End".to_owned()).await;

    async fn raw_of(rooms: &saltator_roomserver::RoomServer, id: &str) -> Value {
        serde_json::from_slice(&rooms.store().event(id).await.unwrap().unwrap().raw).unwrap()
    }

    // The mock origin: /get_missing_events returns only the newest two
    // gap events (a truncated response, like Synapse's default limit
    // against a 50-event gap), /state returns A's current state.
    let a_meta = a_rooms
        .store()
        .meta(room_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let state_map: std::collections::BTreeMap<(String, String), String> = a_rooms
        .store()
        .resolve_group(room_id.as_str(), a_meta.current_group)
        .await
        .unwrap();
    let mut state_pdus: Vec<Value> = Vec::new();
    for id in state_map.values() {
        state_pdus.push(raw_of(&a_rooms, id).await);
    }
    let mut tail: Vec<Value> = Vec::new();
    for id in &gap_ids[10..] {
        tail.push(raw_of(&a_rooms, id).await);
    }
    let missing_resp = json!({ "events": tail });
    let state_resp = json!({ "pdus": state_pdus, "auth_chain": [] });
    let mock = axum::Router::new()
        .route(
            "/_matrix/federation/v1/get_missing_events/{room_id}",
            axum::routing::post(move || {
                let r = missing_resp.clone();
                async move { axum::Json(r) }
            }),
        )
        .route(
            "/_matrix/federation/v1/state/{room_id}",
            axum::routing::get(move || {
                let r = state_resp.clone();
                async move { axum::Json(r) }
            }),
        );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_base = format!("http://{}", mock_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(mock_listener, mock).await.unwrap();
    });

    // B's inbound federation surface: authenticates A via a_base, but its
    // outbound gap-fill client talks to the truncating mock.
    let b_fed = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_base.clone())),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: None,
        client: Some(Arc::new(FederationClient::with_base_url(
            b_signer.clone(),
            mock_base,
        ))),
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_router = saltator_federation::router(b_fed);
    let b_fed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_fed_base = format!("http://{}", b_fed_listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(b_fed_listener, b_fed_router).await.unwrap();
    });

    let a_client = FederationClient::with_base_url(a_signer.clone(), b_fed_base.clone());
    let deliver = |path: &'static str, pdu: Value, expect_id: String| {
        let a_client = &a_client;
        async move {
            let txn = json!({ "origin": "a.test", "origin_server_ts": 1000, "pdus": [pdu] });
            let out = a_client.put("b.test", path, &txn).await.unwrap();
            assert!(
                out["pdus"][&expect_id]
                    .as_object()
                    .map(|o| o.is_empty())
                    .unwrap_or(false),
                "PDU {expect_id} not accepted: {out}"
            );
        }
    };
    // The pre-gap message federates normally (its prev is bob's join,
    // which B holds).
    deliver(
        "/_matrix/federation/v1/send/txnpre",
        raw_of(&a_rooms, &pre_id).await,
        pre_id.clone(),
    )
    .await;
    // "End" arrives with 12 missing ancestors; the origin only coughs up
    // the last two, so B must anchor them on fetched state.
    deliver(
        "/_matrix/federation/v1/send/txngap",
        raw_of(&a_rooms, &last_id).await,
        last_id.clone(),
    )
    .await;

    // The recovered tail is on B's timeline; the unfetchable span joined
    // the backfill frontier behind a gap marker.
    let b_meta = b_rooms
        .store()
        .meta(room_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b_meta.gap_markers.len(), 1, "expected one gap marker");
    assert!(
        b_rooms
            .history_frontier(room_id.as_str())
            .await
            .unwrap()
            .contains(&gap_ids[9]),
        "gap 10 should be on the backfill frontier"
    );

    // Incremental sync spanning the gap: only the post-gap events, with
    // the limited flag — the pre-gap message must not ride along.
    let (status, got) = http_req(
        "GET",
        format!("/_matrix/client/v3/sync?since={since}"),
        Some(bob.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let timeline = &got["rooms"]["join"][room_id.as_str()]["timeline"];
    assert_eq!(
        timeline["limited"], true,
        "gap window must be limited: {timeline}"
    );
    let bodies: Vec<&str> = timeline["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["content"]["body"].as_str())
        .collect();
    assert_eq!(
        bodies,
        vec!["gap 11", "gap 12", "End"],
        "window should hold exactly the post-gap events: {timeline}"
    );

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
    a_rooms.shutdown().await.unwrap();
}

// --- Inbound federated invite --------------------------------------------

#[tokio::test]
async fn inbound_federated_invite_appears_in_sync() {
    let dir = tempfile::tempdir().unwrap();

    // Node A: just a signing identity + key server (the inviter's server).
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    // Node B: full CS stack + user/room shards, plus a federation surface
    // that authenticates A and can record invites into B's user shard.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );

    // B's CS router (for registration + /sync).
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    );
    let cs_router = saltator_cs_api::router(cs_state);

    // B's federation surface: authenticates A, records invites into b_users.
    let b_fed = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Register bob on B.
    let http = |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
        let router = cs_router.clone();
        async move {
            let mut b = axum::http::Request::builder().method(method).uri(path);
            if let Some(t) = token {
                b = b.header("Authorization", format!("Bearer {t}"));
            }
            let body = match body {
                Some(v) => {
                    b = b.header("Content-Type", "application/json");
                    axum::body::Body::from(serde_json::to_vec(&v).unwrap())
                }
                None => axum::body::Body::empty(),
            };
            let resp = tower::ServiceExt::oneshot(router, b.body(body).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let val: Value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap_or(Value::Null)
            };
            (status, val)
        }
    };
    let (_s, ch) = http(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username":"bob","password":"bob-pw-1234"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http("POST", "/_matrix/client/v3/register".into(), None, Some(json!({"username":"bob","password":"bob-pw-1234","auth":{"type":"m.login.dummy","session":session}}))).await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    // A builds and signs an m.room.member invite for @bob:b.test.
    let room_id = "!invroom:a.test";
    let mut invite = match ruma::CanonicalJsonValue::try_from(json!({
        "type": "m.room.member",
        "room_id": room_id,
        "sender": "@alice:a.test",
        "state_key": "@bob:b.test",
        "content": {"membership": "invite"},
        "origin_server_ts": 1000,
        "depth": 5,
        "prev_events": [],
        "auth_events": [],
    }))
    .unwrap()
    {
        ruma::CanonicalJsonValue::Object(o) => o,
        _ => panic!(),
    };
    a_signer
        .hash_and_sign_event(&mut invite, saltator_core::RoomVersion::V11)
        .unwrap();
    let create_stripped = json!({"type":"m.room.create","state_key":"","sender":"@alice:a.test","content":{"room_version":"11"}});
    let invite_body = json!({
        "room_version": "11",
        "event": ruma::CanonicalJsonValue::Object(invite),
        "invite_room_state": [create_stripped],
    });

    // A PUTs the invite to B's /invite endpoint (signed request).
    let client = FederationClient::with_base_url(a_signer.clone(), b_fed_base);
    let event_id_enc: String = "$placeholder"
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let path = format!("/_matrix/federation/v2/invite/%21invroom:a.test/{event_id_enc}");
    let resp = client
        .put("b.test", &path, &invite_body)
        .await
        .expect("invite accepted");
    let sigs = resp["event"]["signatures"]
        .as_object()
        .expect("signed event");
    assert!(sigs.contains_key("a.test"), "origin signature missing");
    assert!(sigs.contains_key("b.test"), "our co-signature missing");

    // bob's /sync now shows the invite.
    let (status, sync) = http("GET", "/_matrix/client/v3/sync".into(), Some(bob), None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let inv = sync["rooms"]["invite"].get(room_id);
    assert!(inv.is_some(), "invite room missing from sync: {sync}");
    let has_create = inv.unwrap()["invite_state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "m.room.create");
    assert!(has_create, "invite_state missing create: {inv:?}");

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// A blocked room's inbound `/invite` is refused on the PATH room, and an
/// event whose `room_id` names a different, unblocked room cannot smuggle a
/// pending invite into the blocked room (security review 2026-08-13,
/// Vuln 2). The block check once read the event body while the handler
/// recorded the invite under the path room.
#[tokio::test]
async fn inbound_invite_into_a_blocked_room_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }

    // Block a room this server does not host — exactly the case the block
    // exists for.
    let admin = ruma::OwnedUserId::try_from("@root:b.test").unwrap();
    b_users
        .set_room_blocked("!blocked:a.test", true, &admin)
        .await
        .unwrap();

    let b_fed = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    };
    let client = FederationClient::with_base_url(a_signer.clone(), b_fed_base);

    // A signed invite for @bob:b.test whose event names `event_room`, PUT to
    // the /invite path for `path_room`.
    let signed_invite = |event_room: &str| {
        let a_signer = a_signer.clone();
        let event_room = event_room.to_owned();
        async move {
            let mut invite = match ruma::CanonicalJsonValue::try_from(json!({
                "type": "m.room.member",
                "room_id": event_room,
                "sender": "@alice:a.test",
                "state_key": "@bob:b.test",
                "content": {"membership": "invite"},
                "origin_server_ts": 1000,
                "depth": 5,
                "prev_events": [],
                "auth_events": [],
            }))
            .unwrap()
            {
                ruma::CanonicalJsonValue::Object(o) => o,
                _ => panic!(),
            };
            a_signer
                .hash_and_sign_event(&mut invite, saltator_core::RoomVersion::V11)
                .unwrap();
            json!({
                "room_version": "11",
                "event": ruma::CanonicalJsonValue::Object(invite),
                "invite_room_state": [json!({"type":"m.room.create","state_key":"","sender":"@alice:a.test","content":{"room_version":"11"}})],
            })
        }
    };
    // Path is percent-encoded `!blocked:a.test`.
    let path = "/_matrix/federation/v2/invite/%21blocked:a.test/$evt";

    // 1. Event names the blocked room too: refused by the block.
    let err = client
        .put("b.test", path, &signed_invite("!blocked:a.test").await)
        .await
        .expect_err("blocked room invite must be refused");
    assert!(format!("{err:?}").contains("403"), "{err:?}");

    // 2. Event names a *different*, unblocked room while the path is the
    //    blocked one: the mismatch is refused (400), so the attacker cannot
    //    launder a pending invite into the blocked room.
    let err = client
        .put("b.test", path, &signed_invite("!elsewhere:a.test").await)
        .await
        .expect_err("mismatched room_id must be refused");
    assert!(format!("{err:?}").contains("400"), "{err:?}");

    // And bob has no pending invite for the blocked room.
    assert!(b_users
        .store()
        .invite_state("@bob:b.test", "!blocked:a.test")
        .unwrap()
        .is_none());

    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

#[tokio::test]
async fn outbound_federated_invite_round_trip() {
    let dir = tempfile::tempdir().unwrap();

    // Node B: full stack; its fed endpoint records invites. Key server for
    // A is B's own fed router (serves keys); B authenticates A via A's keys.
    let (b_rooms, b_users, b_signer, b_router, b_proj) = cs_stack("b.test", dir.path(), None).await;

    // A's signing identity + key server so B can verify A's requests and
    // the invite event signature.
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    // B's federation endpoint: authenticates A, records invites into b_users.
    let b_fed = Arc::new(FedState {
        server_name: ruma::OwnedServerName::try_from("b.test").unwrap(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Node A: full stack, CS federation client aimed at B's fed endpoint,
    // reusing the a_signer we already made for the key server.
    let a_engine = Arc::new(RocksEngine::open(&dir.path().join("a.test")).unwrap());
    let a_rooms = RoomServer::start(
        1,
        a_engine.clone(),
        a_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let a_users = UserServer::start(
        1,
        a_engine,
        a_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [a_rooms.shard_handle(), a_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let a_proj = spawn_membership_projection(
        a_users.clone(),
        saltator_roomserver::RoomShards::single(a_rooms.clone()),
    );
    let a_media = MediaStore::open(dir.path().join("a-media")).unwrap();
    let a_cs = CsState::new(
        a_users.clone(),
        saltator_roomserver::RoomShards::single(a_rooms.clone()),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base.clone(),
        )),
        a_signer.clone(),
        Arc::new(KeyCache::with_base_url(b_fed_base)),
    );
    let a_router = saltator_cs_api::router(a_cs);

    // bob registers on B.
    let bob = reg(&b_router, "bob").await;

    // alice registers on A and creates a room that invites @bob:b.test at
    // creation. bob is remote, so the invite must be co-signed via /invite
    // (spec "Inviting to a room"), carrying the room's stripped state — a local
    // member write would never reach him.
    let alice = reg(&a_router, "alice").await;
    let (status, room) = oneshot(
        &a_router,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&alice),
        Some(json!({
            "preset": "private_chat",
            "name": "Invites room",
            "invite": ["@bob:b.test"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // bob on B sees the invite, with the room's metadata in invite_state.
    let (status, sync) = oneshot(
        &b_router,
        "GET",
        "/_matrix/client/v3/sync",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let inv = sync["rooms"]["invite"].get(&room_id);
    assert!(inv.is_some(), "invite missing from bob's sync: {sync}");
    let events = inv.unwrap()["invite_state"]["events"]
        .as_array()
        .expect("invite_state events");
    assert!(
        events.iter().any(|e| e["type"] == "m.room.create"),
        "invite_state missing m.room.create: {sync}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "m.room.name" && e["content"]["name"] == "Invites room"),
        "invite_state missing room name: {sync}"
    );

    a_proj.abort();
    b_proj.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// A joined room's `/sync` always carries an `ephemeral` object with an
/// `events` array, even when there is no ephemeral activity. ruma omits an
/// empty ephemeral, but clients and Complement (TestACLsForEDUs asserts
/// `ephemeral.events` has size 0 in an EDU-free room) expect the empty array
/// to be present rather than the whole field missing. Guards the respond()
/// post-processing that re-adds it.
#[tokio::test]
async fn joined_room_sync_always_has_ephemeral_events() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // A fresh (initial) sync — the path where the empty ephemeral was omitted.
    let body = env
        .sync_until(&alice, |b| b["rooms"]["join"].get(&room_id).is_some())
        .await;
    let ephemeral = &body["rooms"]["join"][&room_id]["ephemeral"];
    assert!(
        ephemeral["events"].is_array(),
        "joined room sync must carry an ephemeral.events array even when empty: {body}"
    );
    assert_eq!(
        ephemeral["events"].as_array().unwrap().len(),
        0,
        "a room with no ephemeral activity should have an empty events array: {body}"
    );

    env.shutdown().await;
}

/// An inbound `m.receipt` EDU from a remote server surfaces that user's
/// read receipt in a local member's `/sync` (federated read receipts).
#[tokio::test]
async fn receipt_edu_over_federation_surfaces_in_sync() {
    let dir = tempfile::tempdir().unwrap();
    let (b_rooms, b_users, b_signer, b_router, b_proj) = cs_stack("b.test", dir.path(), None).await;

    // Remote server A + its key server so B can authenticate A's /send.
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name, "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    // B's federation surface (rooms + users), trusting A's keys.
    let b_fed = Arc::new(FedState {
        server_name: ruma::OwnedServerName::try_from("b.test").unwrap(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Bob (on B) hosts a room and sends a message.
    let bob = reg(&b_router, "bob").await;
    let (_s, room) = oneshot(
        &b_router,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&bob),
        Some(json!({"preset": "public_chat"})),
    )
    .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (_s, sent) = oneshot(
        &b_router,
        "PUT",
        &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/rm1"),
        Some(&bob),
        Some(json!({"msgtype": "m.text", "body": "hi"})),
    )
    .await;
    let event_id = sent["event_id"].as_str().unwrap().to_owned();

    // A signs an m.receipt EDU: @alice:a.test read bob's message.
    let a_client = FederationClient::with_base_url(a_signer.clone(), b_fed_base);
    let txn = json!({
        "origin": "a.test",
        "origin_server_ts": 1000,
        "edus": [{
            "edu_type": "m.receipt",
            "content": { room_id.clone(): { "m.read": { "@alice:a.test": {
                "data": {"ts": 1234},
                "event_ids": [event_id.clone()],
            }}}},
        }],
    });
    a_client
        .put("b.test", "/_matrix/federation/v1/send/rcpt1", &txn)
        .await
        .unwrap();

    // Bob's sync shows alice's read receipt on his event.
    let mut seen = false;
    for _ in 0..100 {
        let (_s, sync) = oneshot(
            &b_router,
            "GET",
            "/_matrix/client/v3/sync",
            Some(&bob),
            None,
        )
        .await;
        let ephemeral = &sync["rooms"]["join"][&room_id]["ephemeral"]["events"];
        if ephemeral.as_array().is_some_and(|evs| {
            evs.iter().any(|e| {
                e["type"] == "m.receipt"
                    && !e["content"][&event_id]["m.read"]["@alice:a.test"].is_null()
            })
        }) {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen,
        "alice's federated read receipt never appeared in bob's sync"
    );

    b_proj.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// Alice on A `/sendToDevice`s to @bob:b.test; the message rides an
/// `m.direct_to_device` EDU to B and lands in bob's `/sync`.
#[tokio::test]
async fn to_device_over_federation_round_trip() {
    let dir = tempfile::tempdir().unwrap();

    // Node B: full stack; its fed endpoint queues to-device messages into
    // b_users. A's key server lets B authenticate A's requests.
    let (b_rooms, b_users, b_signer, b_router, b_proj) = cs_stack("b.test", dir.path(), None).await;
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    let b_fed = Arc::new(FedState {
        server_name: ruma::OwnedServerName::try_from("b.test").unwrap(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Node A: full stack, CS federation client aimed at B's fed endpoint.
    let a_engine = Arc::new(RocksEngine::open(&dir.path().join("a.test")).unwrap());
    let a_rooms = RoomServer::start(
        1,
        a_engine.clone(),
        a_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let a_users = UserServer::start(
        1,
        a_engine,
        a_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [a_rooms.shard_handle(), a_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let a_media = MediaStore::open(dir.path().join("a-media")).unwrap();
    let a_cs = CsState::new(
        a_users.clone(),
        saltator_roomserver::RoomShards::single(a_rooms.clone()),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base.clone(),
        )),
        a_signer.clone(),
        Arc::new(KeyCache::with_base_url(b_fed_base.clone())),
    );
    // Remote to-device goes through the fed-out outbox (step 4); run the
    // shard + delivery worker like the daemon does.
    let (a_fedout, a_edu_sender) = start_fedout_delivery(
        dir.path(),
        a_rooms.clone(),
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base,
        )),
        "a.test",
    )
    .await;
    let a_cs = a_cs.with_fedout(a_fedout.clone());
    let a_router = saltator_cs_api::router(a_cs);

    let bob = reg(&b_router, "bob").await;
    let alice = reg(&a_router, "alice").await;

    // Alice addresses all of bob's devices on the remote server.
    let (status, body) = oneshot(
        &a_router,
        "PUT",
        "/_matrix/client/v3/sendToDevice/m.room.encrypted/fed-td-1",
        Some(&alice),
        Some(json!({
            "messages": {"@bob:b.test": {"*": {"ciphertext": "remote"}}}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The EDU is delivered in the background; poll bob's sync for it.
    let mut delivered = Value::Null;
    for _ in 0..100 {
        let (status, sync) = oneshot(
            &b_router,
            "GET",
            "/_matrix/client/v3/sync",
            Some(&bob),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{sync}");
        if sync["to_device"]["events"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        {
            delivered = sync;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let events = delivered["to_device"]["events"]
        .as_array()
        .expect("to-device message never arrived over federation");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "m.room.encrypted");
    assert_eq!(events[0]["sender"], "@alice:a.test");
    assert_eq!(events[0]["content"]["ciphertext"], "remote");

    // Decision-3 uniqueness rider: redeliver the identical EDU (same
    // message_id, fresh outbox row = fresh txn id — an at-least-once
    // sender's duplicate after a cursor rewind). B's durable message_id
    // dedupe must drop it: bob must never see the message twice.
    let dup_edu = serde_json::json!({
        "edu_type": "m.direct_to_device",
        "content": {
            "sender": "@alice:a.test",
            "type": "m.room.encrypted",
            // Must match the server's minting (user-scoped, spec:
            // unique per origin server) for this to BE a duplicate.
            "message_id": "@alice:a.test/fed-td-1",
            "messages": {"@bob:b.test": {"*": {"ciphertext": "remote"}}},
        },
    });
    a_fedout
        .enqueue_edus(vec![saltator_fedout::OutboundEdu {
            destination: "b.test".into(),
            json: serde_json::to_vec(&dup_edu).unwrap(),
        }])
        .await
        .unwrap();
    // Wait until the worker has delivered + acked the duplicate (outbox
    // drains), then count copies in a fresh full sync: the original is
    // still in the inbox (never acked — earlier polls carried no since
    // token), so exactly-once means exactly ONE copy total; a failed
    // dedupe would show two.
    for _ in 0..200 {
        if a_fedout.store().edu_outbox("b.test", 1).unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        a_fedout.store().edu_outbox("b.test", 1).unwrap().is_empty(),
        "duplicate EDU never delivered"
    );
    let (_, sync) = oneshot(
        &b_router,
        "GET",
        "/_matrix/client/v3/sync",
        Some(&bob),
        None,
    )
    .await;
    let dup_count = sync["to_device"]["events"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e["content"]["ciphertext"] == "remote")
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        dup_count, 1,
        "client-visible copies != 1 after redelivery: {sync}"
    );

    b_proj.abort();
    a_edu_sender.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// Federated E2EE keys: alice on A queries and claims @bob:b.test's keys
/// through her own server (proxied over federation), and an inbound
/// m.device_list_update EDU logs a device-list change for its user.
#[tokio::test]
async fn federated_key_query_claim_and_device_list_update() {
    let dir = tempfile::tempdir().unwrap();

    let (b_rooms, b_users, b_signer, b_router, b_proj) = cs_stack("b.test", dir.path(), None).await;
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    let b_fed = Arc::new(FedState {
        server_name: ruma::OwnedServerName::try_from("b.test").unwrap(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Node A: full stack, CS federation client aimed at B's fed endpoint.
    let a_engine = Arc::new(RocksEngine::open(&dir.path().join("a.test")).unwrap());
    let a_rooms = RoomServer::start(
        1,
        a_engine.clone(),
        a_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let a_users = UserServer::start(
        1,
        a_engine,
        a_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [a_rooms.shard_handle(), a_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let a_media = MediaStore::open(dir.path().join("a-media")).unwrap();
    let a_cs = CsState::new(
        a_users.clone(),
        saltator_roomserver::RoomShards::single(a_rooms.clone()),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base.clone(),
        )),
        a_signer.clone(),
        Arc::new(KeyCache::with_base_url(b_fed_base.clone())),
    );
    let a_router = saltator_cs_api::router(a_cs);

    let bob = reg(&b_router, "bob").await;
    let alice = reg(&a_router, "alice").await;
    let (_, whoami) = oneshot(
        &b_router,
        "GET",
        "/_matrix/client/v3/account/whoami",
        Some(&bob),
        None,
    )
    .await;
    let bob_dev = whoami["device_id"].as_str().unwrap().to_owned();

    // Bob publishes identity keys + two OTKs on his own server.
    let (status, body) = oneshot(
        &b_router,
        "POST",
        "/_matrix/client/v3/keys/upload",
        Some(&bob),
        Some(json!({
            "device_keys": {"user_id": "@bob:b.test", "device_id": bob_dev,
                             "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                             "keys": {"curve25519:BOB": "bobkey"}, "signatures": {}},
            "one_time_keys": {
                "signed_curve25519:AAAAAQ": {"key": "aaa"},
                "signed_curve25519:AAAAAg": {"key": "bbb"},
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Alice queries bob's keys through HER server: proxied over federation.
    let (status, resp) = oneshot(
        &a_router,
        "POST",
        "/_matrix/client/v3/keys/query",
        Some(&alice),
        Some(json!({"device_keys": {"@bob:b.test": []}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        resp["device_keys"]["@bob:b.test"][&bob_dev]["keys"]["curve25519:BOB"], "bobkey",
        "federated key query: {resp}"
    );

    // Claims forward too, and never hand out the same OTK twice.
    let claim = |token: String| {
        let a_router = a_router.clone();
        let bob_dev = bob_dev.clone();
        async move {
            let (status, resp) = oneshot(
                &a_router,
                "POST",
                "/_matrix/client/v3/keys/claim",
                Some(&token),
                Some(json!({"one_time_keys": {"@bob:b.test": {&bob_dev: "signed_curve25519"}}})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp["one_time_keys"]["@bob:b.test"][&bob_dev]
                .as_object()
                .map(|m| m.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        }
    };
    let first = claim(alice.clone()).await;
    let second = claim(alice.clone()).await;
    assert_eq!(first.len(), 1, "first federated claim");
    assert_eq!(second.len(), 1, "second federated claim");
    assert_ne!(first[0], second[0], "an OTK crossed federation twice");
    let third = claim(alice.clone()).await;
    assert!(
        third.is_empty(),
        "exhausted OTKs still handed out: {third:?}"
    );

    // An inbound m.device_list_update EDU logs a change for its user.
    let edu_client = FederationClient::with_base_url(a_signer.clone(), b_fed_base);
    let txn = json!({
        "origin": "a.test", "origin_server_ts": 1000, "pdus": [],
        "edus": [{"edu_type": "m.device_list_update",
                   "content": {"user_id": "@zed:a.test", "device_id": "ZED", "stream_id": 1}}],
    });
    edu_client
        .put("b.test", "/_matrix/federation/v1/send/dltxn", &txn)
        .await
        .expect("EDU transaction accepted");
    assert!(
        b_users
            .store()
            .key_changes(0, u64::MAX)
            .unwrap()
            .iter()
            .any(|e| e.user_id == "@zed:a.test" && e.membership.is_none()),
        "device-list EDU not logged"
    );

    b_proj.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

// --- Inbound EDUs (typing/presence over federation) ----------------------

#[tokio::test]
async fn inbound_typing_and_presence_edus_reach_sync() {
    let dir = tempfile::tempdir().unwrap();

    // Node A: signer + key server (the sending server).
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_key_base = spawn_fed("a.test", a_signer.clone(), None, None).await;

    // Node B: full CS stack.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_rooms = RoomServer::start(
        1,
        engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        engine,
        b_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [b_rooms.shard_handle(), b_users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    );
    let cs_router = saltator_cs_api::router(cs_state.clone());

    // B's federation endpoint with an EDU sink into the shared maps.
    let sink = Arc::new(saltator_cs_api::EphemeralEduSink::new(
        cs_state.typing_map(),
        cs_state.presence_map(),
    ));
    let b_fed = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(saltator_roomserver::RoomShards::single(b_rooms.clone())),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: Some(sink),
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let b_fed_base = {
        let app = saltator_federation::router(b_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Register bob on B and create a room he's in (so typing has a room).
    let http = |method: &'static str, path: String, token: Option<String>, body: Option<Value>| {
        let router = cs_router.clone();
        async move {
            let mut b = axum::http::Request::builder().method(method).uri(path);
            if let Some(t) = token {
                b = b.header("Authorization", format!("Bearer {t}"));
            }
            let body = match body {
                Some(v) => {
                    b = b.header("Content-Type", "application/json");
                    axum::body::Body::from(serde_json::to_vec(&v).unwrap())
                }
                None => axum::body::Body::empty(),
            };
            let resp = tower::ServiceExt::oneshot(router, b.body(body).unwrap())
                .await
                .unwrap();
            let st = resp.status();
            let by = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                st,
                if by.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&by).unwrap_or(Value::Null)
                },
            )
        }
    };
    let (_s, ch) = http(
        "POST",
        "/_matrix/client/v3/register".into(),
        None,
        Some(json!({"username":"bob","password":"pw-12345678"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, reg) = http("POST","/_matrix/client/v3/register".into(),None,Some(json!({"username":"bob","password":"pw-12345678","auth":{"type":"m.login.dummy","session":session}}))).await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();
    let (_s, room) = http(
        "POST",
        "/_matrix/client/v3/createRoom".into(),
        Some(bob.clone()),
        Some(json!({"preset":"public_chat"})),
    )
    .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // A sends a transaction with typing + presence EDUs for @alice:a.test.
    let txn = json!({
        "origin": "a.test", "origin_server_ts": 1000, "pdus": [],
        "edus": [
            {"edu_type":"m.typing","content":{"room_id":room_id,"user_id":"@alice:a.test","typing":true}},
            {"edu_type":"m.presence","content":{"push":[{"user_id":"@alice:a.test","presence":"online","status_msg":"hi"}]}},
        ],
    });
    let client = FederationClient::with_base_url(a_signer.clone(), b_fed_base);
    client
        .put("b.test", "/_matrix/federation/v1/send/edutxn", &txn)
        .await
        .expect("EDU transaction accepted");

    // bob's /sync shows alice typing in the room, and alice's presence.
    let (status, sync) = http(
        "GET",
        "/_matrix/client/v3/sync".into(),
        Some(bob.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let typing = &sync["rooms"]["join"][&room_id]["ephemeral"]["events"];
    let has_typing = typing
        .as_array()
        .map(|a| {
            a.iter().any(|e| {
                e["type"] == "m.typing"
                    && e["content"]["user_ids"]
                        .as_array()
                        .map(|u| u.iter().any(|x| x == "@alice:a.test"))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    assert!(has_typing, "alice should be typing in bob's sync: {typing}");
    // Presence for a non-room-mate isn't shown in /sync (visibility filter),
    // but the inbound EDU updated the map — check it directly.
    let (status, ps) = http(
        "GET",
        "/_matrix/client/v3/presence/@alice:a.test/status".into(),
        Some(bob),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ps["presence"], "online", "alice presence from EDU: {ps}");
    assert_eq!(ps["status_msg"], "hi");

    projection.abort();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

/// SSRF guard: with internal fetches disabled (production default), both
/// preview_url and pusher registration refuse targets that point at
/// internal/loopback addresses or non-http schemes.
#[tokio::test]
async fn ssrf_guard_blocks_internal_targets() {
    let env = start_env_cfg(saltator_cs_api::RateLimitConfig::disabled(), false).await;
    let tok = env.register("alice", "pw").await;

    // preview_url against internal literals / bad schemes is forbidden.
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/admin",
        "http://[::1]:8080/x",
        "file:///etc/passwd",
    ] {
        let enc = url
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('[', "%5B")
            .replace(']', "%5D");
        let (status, body) = env
            .req(
                "GET",
                &format!("/_matrix/client/v1/media/preview_url?url={enc}"),
                Some(&tok),
                None,
            )
            .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
            "preview_url {url} should be refused, got {status}: {body}"
        );
    }

    // A pusher aimed at an internal gateway is refused at registration.
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&tok),
            Some(json!({
                "app_id": "t", "pushkey": "k", "kind": "http",
                "app_display_name": "t", "device_display_name": "t", "lang": "en",
                "data": { "url": "http://169.254.169.254/_matrix/push/v1/notify" },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    env.shutdown().await;
}

/// Rate limiting (spec "Rate limiting"): drained buckets return 429
/// M_LIMIT_EXCEEDED with retry_after_ms and a Retry-After header;
/// budgets are per class and per key.
#[tokio::test]
async fn rate_limits_return_429_with_retry() {
    let mut cfg = saltator_cs_api::RateLimitConfig::disabled();
    cfg.enabled = true;
    // Tiny message/login budgets that won't refill within the test; a
    // roomy registration budget so setup doesn't trip it.
    cfg.message_rate = 0.001;
    cfg.message_burst = 2;
    cfg.login_rate = 0.001;
    cfg.login_burst = 2;
    cfg.registration_rate = 1000.0;
    cfg.registration_burst = 100;
    let env = start_env_with(cfg).await;
    let alice = env.register("alice", "alice-pw").await;
    env.register("bob", "bob-pw").await;

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_enc = body["room_id"]
        .as_str()
        .unwrap()
        .replace('!', "%21")
        .replace(':', "%3A");

    // Two sends fit the burst; the third drains the bucket.
    for txn in ["rl1", "rl2"] {
        let (status, body) = env
            .req(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/{txn}"),
                Some(&alice),
                Some(json!({"msgtype": "m.text", "body": txn})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // Raw request so the Retry-After header is observable.
    let resp = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/rl3"
                ))
                .header("Authorization", format!("Bearer {alice}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"msgtype":"m.text","body":"rl3"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_header: u64 = resp.headers()["Retry-After"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_header >= 1);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
    assert!(body["retry_after_ms"].as_u64().unwrap() >= 1, "{body}");
    // Replaying a limited txn id is NOT rate limited (idempotency wins),
    // and other users keep their own budget untouched.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/rl1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "rl1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Login is keyed by the targeted account: alice's budget drains,
    // bob's stays intact.
    let login = |user: &'static str, pw: &'static str| {
        env.req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": user},
                "password": pw,
            })),
        )
    };
    for _ in 0..2 {
        let (status, _) = login("alice", "wrong").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, body) = login("alice", "alice-pw").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED");
    let (status, _) = login("bob", "bob-pw").await;
    assert_eq!(status, StatusCode::OK);

    env.shutdown().await;
}

/// Spaces summary (`GET /rooms/{roomId}/hierarchy`, MSC2946): a space tree is
/// walked depth-first, non-space children are not expanded, `children_state`
/// reflects the `m.space.child` links, and `suggested_only` / `max_depth` /
/// `limit`+`from` shape the result. Mirrors Complement's TestClientSpacesSummary.
#[tokio::test]
async fn spaces_hierarchy_walks_the_tree() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let bob = env.register("bob", "pw").await;

    let enc = |id: &str| {
        id.replace('!', "%21")
            .replace(':', "%3A")
            .replace('$', "%24")
    };

    let create = |tok: String, body: Value| {
        let env = &env;
        async move {
            let (s, r) = env
                .req(
                    "POST",
                    "/_matrix/client/v3/createRoom",
                    Some(&tok),
                    Some(body),
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{r}");
            r["room_id"].as_str().unwrap().to_owned()
        }
    };
    let space = |name: &str| json!({"preset": "public_chat", "name": name, "creation_content": {"type": "m.space"}});
    let world_readable_room = |name: &str| {
        json!({"preset": "public_chat", "name": name, "initial_state": [{
            "type": "m.room.history_visibility", "state_key": "",
            "content": {"history_visibility": "world_readable"}
        }]})
    };

    let root = create(alice.clone(), space("Root")).await;
    let r1 = create(
        alice.clone(),
        json!({"preset": "public_chat", "name": "R1"}),
    )
    .await;
    let ss1 = create(alice.clone(), space("Sub-Space 1")).await;
    let r2 = create(
        alice.clone(),
        json!({"preset": "public_chat", "name": "R2"}),
    )
    .await;
    let ss2 = create(alice.clone(), space("SS2")).await;
    let r3 = create(
        alice.clone(),
        json!({"preset": "public_chat", "name": "R3"}),
    )
    .await;
    // bob owns r4 (world-readable, alice not joined) and r5.
    let r4 = create(bob.clone(), world_readable_room("R4")).await;
    let r5 = create(bob.clone(), json!({"preset": "public_chat", "name": "R5"})).await;
    // Borrow as `&str` (Copy) so the query closures below don't move it.
    let alice: &str = &alice;

    // Child links. A small gap keeps origin_server_ts strictly increasing so
    // sibling order is deterministic (the real test round-trips through /sync).
    let link = |parent: String, child: String, extra: Value| {
        let env = &env;
        let enc = &enc;
        async move {
            tokio::time::sleep(Duration::from_millis(3)).await;
            let mut content = json!({"via": [SERVER]});
            if let Some(obj) = extra.as_object() {
                for (k, v) in obj {
                    content[k] = v.clone();
                }
            }
            let (s, r) = env
                .req(
                    "PUT",
                    &format!(
                        "/_matrix/client/v3/rooms/{}/state/m.space.child/{}",
                        enc(&parent),
                        enc(&child)
                    ),
                    Some(alice),
                    Some(content),
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{r}");
        }
    };

    link(root.clone(), r1.clone(), json!({"suggested": true})).await;
    link(root.clone(), ss1.clone(), json!({})).await;
    link(root.clone(), r2.clone(), json!({"suggested": true})).await;
    // r2 is not a space, so this child is never expanded (R5 must not appear).
    link(r2.clone(), r5.clone(), json!({})).await;
    link(ss1.clone(), ss2.clone(), json!({})).await;
    link(ss2.clone(), r3.clone(), json!({})).await;
    link(ss2.clone(), r4.clone(), json!({})).await;

    let hierarchy = |query: &str| {
        let env = &env;
        let enc = &enc;
        let root = &root;
        let query = query.to_owned();
        async move {
            let (s, r) = env
                .req(
                    "GET",
                    &format!("/_matrix/client/v1/rooms/{}/hierarchy{}", enc(root), query),
                    Some(alice),
                    None,
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{r}");
            r
        }
    };
    let room_ids = |r: &Value| -> Vec<String> {
        r["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|room| room["room_id"].as_str().unwrap().to_owned())
            .collect()
    };
    let children_of = |r: &Value, id: &str| -> Vec<String> {
        let room = r["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|room| room["room_id"] == id)
            .unwrap();
        room["children_state"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["state_key"].as_str().unwrap().to_owned())
            .collect()
    };

    // Whole graph: every room reachable through spaces, R5 excluded.
    let all = hierarchy("").await;
    let mut got = room_ids(&all);
    got.sort();
    let mut want = vec![
        root.clone(),
        r1.clone(),
        r2.clone(),
        r3.clone(),
        r4.clone(),
        ss1.clone(),
        ss2.clone(),
    ];
    want.sort();
    assert_eq!(got, want, "whole graph: {all}");
    assert!(
        !room_ids(&all).contains(&r5),
        "R5 under a non-space must not appear"
    );
    // ss1 is a space.
    let ss1_room = all["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|room| room["room_id"] == ss1.as_str())
        .unwrap();
    assert_eq!(ss1_room["room_type"], "m.space", "{ss1_room}");
    // Links in send order.
    assert_eq!(
        children_of(&all, &root),
        vec![r1.clone(), ss1.clone(), r2.clone()]
    );
    assert_eq!(children_of(&all, &ss2), vec![r3.clone(), r4.clone()]);

    // max_depth=1: root's direct children only (no ss2 under ss1).
    let d1 = hierarchy("?max_depth=1").await;
    let mut got = room_ids(&d1);
    got.sort();
    let mut want = vec![root.clone(), r1.clone(), r2.clone(), ss1.clone()];
    want.sort();
    assert_eq!(got, want, "max_depth=1: {d1}");

    // suggested_only: only suggested links are followed, and shown.
    let sug = hierarchy("?suggested_only=true").await;
    let mut got = room_ids(&sug);
    got.sort();
    let mut want = vec![root.clone(), r1.clone(), r2.clone()];
    want.sort();
    assert_eq!(got, want, "suggested_only: {sug}");
    assert_eq!(children_of(&sug, &root), vec![r1.clone(), r2.clone()]);

    // Pagination: DFS pre-order split across two pages.
    let page1 = hierarchy("?limit=4").await;
    assert_eq!(
        room_ids(&page1),
        vec![root.clone(), r1.clone(), ss1.clone(), ss2.clone()],
        "page1: {page1}"
    );
    let next = page1["next_batch"].as_str().expect("next_batch");
    let page2 = hierarchy(&format!("?from={next}")).await;
    assert_eq!(
        room_ids(&page2),
        vec![r3.clone(), r4.clone(), r2.clone()],
        "page2: {page2}"
    );
    assert!(page2.get("next_batch").is_none(), "no more pages: {page2}");

    // Redacting a link (empty content) drops it from the tree.
    let (s, r) = env
        .req(
            "PUT",
            &format!(
                "/_matrix/client/v3/rooms/{}/state/m.space.child/{}",
                enc(&root),
                enc(&ss1)
            ),
            Some(alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let redacted = hierarchy("").await;
    let mut got = room_ids(&redacted);
    got.sort();
    let mut want = vec![root.clone(), r1.clone(), r2.clone()];
    want.sort();
    assert_eq!(got, want, "after redacting root->ss1: {redacted}");
    assert_eq!(children_of(&redacted, &root), vec![r1.clone(), r2.clone()]);

    env.shutdown().await;
}

/// A federated join served over /sync: `import_room` keeps the
/// resident's state dump off-timeline — only our co-signed join rides
/// the timeline — so the state section must be recovered from the join's
/// state group. The E2EE interop smoke caught this missing: a client
/// joining an encrypted remote room never saw `m.room.encryption` and
/// treated the room as plaintext.
#[tokio::test]
async fn imported_room_sync_includes_send_join_state() {
    let env = start_env().await;
    let bob_token = env.register("bob", "pw").await;

    let room_id = "!remote:elsewhere.test";
    let ev = |ty: &str, sk: &str, sender: &str, content: Value, depth: u64| {
        serde_json::from_value::<ruma::CanonicalJsonObject>(json!({
            "type": ty,
            "state_key": sk,
            "sender": sender,
            "room_id": room_id,
            "content": content,
            "origin_server_ts": 1_700_000_000_000u64,
            "depth": depth,
            "prev_events": [],
            "auth_events": [],
        }))
        .unwrap()
    };
    let create = ev(
        "m.room.create",
        "",
        "@eve:elsewhere.test",
        json!({"room_version": "11", "creator": "@eve:elsewhere.test"}),
        1,
    );
    let eve_join = ev(
        "m.room.member",
        "@eve:elsewhere.test",
        "@eve:elsewhere.test",
        json!({"membership": "join"}),
        2,
    );
    let encryption = ev(
        "m.room.encryption",
        "",
        "@eve:elsewhere.test",
        json!({"algorithm": "m.megolm.v1.aes-sha2"}),
        3,
    );
    let bob_join = ev(
        "m.room.member",
        "@bob:hs.test",
        "@bob:hs.test",
        json!({"membership": "join"}),
        4,
    );

    let outcome = env
        .rooms
        .import_room(
            saltator_core::RoomVersion::V11,
            bob_join,
            vec![create.clone(), eve_join, encryption],
            vec![create],
        )
        .await
        .unwrap();
    let seq = match outcome {
        saltator_roomserver::Outcome::Accepted { seq, .. } => seq,
        other => panic!("import not accepted: {other:?}"),
    };
    // The membership projection lifts bob's join off the room timeline.
    saltator_userserver::wait_for_projection(&env.users, 0, seq, Duration::from_secs(10))
        .await
        .unwrap();

    let body = env
        .sync_until(&bob_token, |b| !b["rooms"]["join"][room_id].is_null())
        .await;
    let room = &body["rooms"]["join"][room_id];
    let state = room["state"]["events"].as_array().unwrap();
    assert!(
        state.iter().any(|e| e["type"] == "m.room.encryption"),
        "sync state must carry the imported m.room.encryption: {room}"
    );
    assert!(
        state.iter().any(|e| e["type"] == "m.room.create"),
        "sync state must carry the imported m.room.create: {room}"
    );
    // Bob's own join is timeline, not state.
    assert!(room["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "m.room.member" && e["state_key"] == "@bob:hs.test"));

    env.shutdown().await;
}
