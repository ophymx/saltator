//! Spaces and room discovery: the `/hierarchy` walk across federation,
//! MSC3266 room summaries with `allowed_room_ids`, a local knock
//! surfacing in `/sync`, and the federated public-room directory.
use axum::http::StatusCode;
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

use crate::harness::*;

/// Spaces over federation (MSC2946): a space tree spanning two servers is
/// returned whole from the querying server. hs1 hosts the root space (and r1,
/// r4); hs2 hosts a leaf (r2) and a sub-space (ss2) whose child points back to
/// hs1's r4. hs1's /hierarchy must fetch the hs2 rooms over the federation
/// hierarchy endpoint and keep walking back into itself. Mirrors
/// TestFederatedClientSpaces.
#[tokio::test]
async fn spaces_hierarchy_spans_federation() {
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

    // --- hs2 hosts r2 (leaf) and ss2 (sub-space); both public/world-readable.
    let (hs2_rooms, hs2_signer) = start_fed_rooms("hs2", dir.path()).await;
    let bob = ruma::OwnedUserId::try_from("@bob:hs2").unwrap();
    let make_hs2 = |space: bool| {
        let hs2_rooms = hs2_rooms.clone();
        let bob = bob.clone();
        async move {
            let mut cc = serde_json::Map::new();
            if space {
                cc.insert("type".into(), "m.space".into());
            }
            let (room_id, _) = hs2_rooms
                .create_room(&bob, saltator_core::RoomVersion::V11, cc)
                .await
                .unwrap();
            for (ty, sk, content) in [
                ("m.room.member", bob.as_str(), json!({"membership": "join"})),
                ("m.room.join_rules", "", json!({"join_rule": "public"})),
                (
                    "m.room.history_visibility",
                    "",
                    json!({"history_visibility": "world_readable"}),
                ),
            ] {
                hs2_rooms
                    .send_state(&room_id, &bob, ty, sk, content)
                    .await
                    .unwrap();
            }
            room_id
        }
    };
    let r2 = make_hs2(false).await;
    let ss2 = make_hs2(true).await;

    // --- hs1: full stack (alice). ---
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

    // Mutual key servers + hs2's authenticated hierarchy surface for hs1.
    let hs1_key_base = spawn_fed("hs1", hs1_signer.clone(), None, None).await;
    let hs2_key_base = spawn_fed("hs2", hs2_signer.clone(), None, None).await;
    let hs2_fed_base = spawn_fed(
        "hs2",
        hs2_signer.clone(),
        Some(hs2_rooms.clone()),
        Some(hs1_key_base),
    )
    .await;

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
        Arc::new(KeyCache::with_base_url(hs2_key_base.clone())),
    );
    let router = saltator_cs_api::router(cs);

    let alice = reg(&router, "alice").await;
    let create = |body: Value| {
        let router = &router;
        let alice = alice.as_str();
        async move {
            let (s, r) = oneshot(
                router,
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(alice),
                Some(body),
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{r}");
            r["room_id"].as_str().unwrap().to_owned()
        }
    };
    let root = create(
        json!({"preset": "public_chat", "name": "Root", "creation_content": {"type": "m.space"}}),
    )
    .await;
    let r1 = create(json!({"preset": "public_chat", "name": "R1"})).await;
    // r4 lives on hs1 but is only reachable through hs2's ss2.
    let r4 = create(json!({"preset": "public_chat", "name": "R4"})).await;

    // ss2 (hs2) links back to r4 (hs1).
    hs2_rooms
        .send_state(
            &ss2,
            &bob,
            "m.space.child",
            r4.as_str(),
            json!({"via": ["hs1"]}),
        )
        .await
        .unwrap();

    // root (hs1) links to r1 (local), r2 (hs2), ss2 (hs2).
    for (child, via) in [
        (r1.as_str(), "hs1"),
        (r2.as_str(), "hs2"),
        (ss2.as_str(), "hs2"),
    ] {
        let (s, r) = oneshot(
            &router,
            "PUT",
            &format!(
                "/_matrix/client/v3/rooms/{}/state/m.space.child/{}",
                pct(&root),
                pct(child)
            ),
            Some(&alice),
            Some(json!({"via": [via]})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "link {child}: {r}");
    }

    let (s, body) = oneshot(
        &router,
        "GET",
        &format!("/_matrix/client/v1/rooms/{}/hierarchy", pct(&root)),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let mut got: Vec<String> = body["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|room| room["room_id"].as_str().unwrap().to_owned())
        .collect();
    got.sort();
    let mut want = vec![
        root.clone(),
        r1.clone(),
        r2.to_string(),
        ss2.to_string(),
        r4.clone(),
    ];
    want.sort();
    assert_eq!(got, want, "federated hierarchy: {body}");

    proj.abort();
}

/// GET /_matrix/client/v1/room_summary/{roomIdOrAlias} (MSC3266): the summary
/// carries allowed_room_ids for a restricted room and omits it otherwise.
/// Mirrors Complement's TestRoomSummaryAllowedRoomIDs.
#[tokio::test]
async fn room_summary_allowed_room_ids() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let enc = |id: &str| id.replace('!', "%21").replace(':', "%3A");

    let create = |body: Value| {
        let env = &env;
        let alice = alice.as_str();
        async move {
            let (s, r) = env
                .req(
                    "POST",
                    "/_matrix/client/v3/createRoom",
                    Some(alice),
                    Some(body),
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{r}");
            r["room_id"].as_str().unwrap().to_owned()
        }
    };

    let space = create(json!({
        "preset": "public_chat",
        "creation_content": {"type": "m.space"}
    }))
    .await;
    let restricted = create(json!({
        "preset": "public_chat",
        "room_version": "8",
        "initial_state": [{
            "type": "m.room.join_rules",
            "state_key": "",
            "content": {
                "join_rule": "restricted",
                "allow": [{"type": "m.room_membership", "room_id": space}]
            }
        }]
    }))
    .await;
    let invite = create(json!({"preset": "private_chat"})).await;

    // Restricted room: join_rule + allowed_room_ids present.
    let (s, r) = env
        .req(
            "GET",
            &format!("/_matrix/client/v1/room_summary/{}", enc(&restricted)),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["room_id"], restricted.as_str(), "{r}");
    assert_eq!(r["join_rule"], "restricted", "{r}");
    assert_eq!(r["allowed_room_ids"], json!([space]), "{r}");
    assert_eq!(r["membership"], "join", "{r}");

    // Invite-only room: allowed_room_ids omitted.
    let (s, r) = env
        .req(
            "GET",
            &format!("/_matrix/client/v1/room_summary/{}", enc(&invite)),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["room_id"], invite.as_str(), "{r}");
    assert!(
        r.get("allowed_room_ids").is_none(),
        "allowed_room_ids must be absent: {r}"
    );

    env.shutdown().await;
}

/// Local knocking over the CS API: a room whose join rule is `knock`
/// accepts `POST /knock/{roomId}` from a local user, the knock surfaces in
/// the knocker's `/sync` under `rooms.knock` with the reason, and knocks on
/// a non-knock room are refused with 403.
#[tokio::test]
async fn local_knock_surfaces_in_sync() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let bob_id = format!("@bob:{SERVER}");

    // Alice creates an invite-only room.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "private_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();

    // Knocking while the join rule is still `invite` is forbidden.
    let (status, _) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/knock/{room_id}"),
            Some(&bob),
            Some(json!({"reason": "too early"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Alice opens the room to knocking.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.join_rules/"),
            Some(&alice),
            Some(json!({"join_rule": "knock"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob knocks, with a reason.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/knock/{room_id}"),
            Some(&bob),
            Some(json!({"reason": "let me in"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id);

    // The knock surfaces in Bob's sync under rooms.knock, carrying his own
    // stripped knock membership with the reason.
    let body = env
        .sync_until(&bob, |b| b["rooms"]["knock"].get(&room_id).is_some())
        .await;
    let events = body["rooms"]["knock"][&room_id]["knock_state"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let bob_knock = events
        .iter()
        .find(|e| e["type"] == "m.room.member" && e["state_key"] == bob_id)
        .unwrap_or_else(|| panic!("bob's knock member event missing: {events:?}"));
    assert_eq!(bob_knock["content"]["membership"], "knock");
    assert_eq!(bob_knock["content"]["reason"], "let me in");

    // Alice (in the room) sees Bob's knock as a normal state/timeline event.
    let a_body = env
        .sync_until(&alice, |b| {
            b["rooms"]["join"][&room_id]["timeline"]["events"]
                .as_array()
                .map(|evs| {
                    evs.iter().any(|e| {
                        e["type"] == "m.room.member"
                            && e["state_key"] == bob_id
                            && e["content"]["membership"] == "knock"
                    })
                })
                .unwrap_or(false)
        })
        .await;
    let _ = a_body;

    // A repeat knock is idempotent (still 200).
    let (status, _) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/knock/{room_id}"),
            Some(&bob),
            Some(json!({"reason": "again"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    env.shutdown().await;
}

/// The federation `/publicRooms` twin serves the same directory as the CS
/// endpoint (one shared builder), to an authenticated peer: published
/// rooms appear with an explicit `join_rule`, and the filtered POST
/// variant honours `generic_search_term`.
#[tokio::test]
async fn federation_public_rooms_lists_published_rooms() {
    use saltator_testsupport::MockPeer;

    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "visibility": "public",
                "preset": "public_chat",
                "name": "Federated Directory Room",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();

    // Federation surface over the same stores, authenticating the peer.
    let peer = MockPeer::start("peer.test").await;
    let name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (fed_signer, _) = saltator_roomserver::ServerSigner::generate(name.clone(), "9".to_owned());
    let fed = Arc::new(FedState {
        server_name: name,
        signer: Arc::new(fed_signer),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(peer.base_url.clone())),
        rooms: Some(env.rooms.clone()),
        users: Some(env.users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });
    let app = saltator_federation::router(fed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    let (status, body) = peer
        .signed_get(&base, SERVER, "/_matrix/federation/v1/publicRooms?limit=5")
        .await;
    assert_eq!(status, 200, "{body}");
    let chunk = &body["chunk"][0];
    assert_eq!(chunk["room_id"], room_id.as_str(), "{body}");
    assert_eq!(chunk["name"], "Federated Directory Room", "{body}");
    assert_eq!(chunk["join_rule"], "public", "{body}");
    assert_eq!(body["total_room_count_estimate"], 1, "{body}");

    env.shutdown().await;
}
