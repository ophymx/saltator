//! The M2 exit criterion, at the crate level: two users register, chat,
//! and observe each other through the real HTTP surface (router-level
//! requests; the binary-level test covers real sockets).
use axum::http::StatusCode;
use serde_json::json;
// --- Remote join (the M3 exit criterion, crate level) --------------------

use crate::harness::*;

// ---------------------------------------------------------------------------
// Multi-shard rooms (docs/design-room-sharding.md phase 1)
// ---------------------------------------------------------------------------

/// Create rooms until two land on different shards, then run the core
/// loop against both: send, sync (vector token), incremental sync,
/// /messages pagination — the same behavior a count-1 cluster has, with
/// rooms living in different Raft groups.
#[tokio::test]
async fn multi_shard_rooms_sync_and_paginate() {
    let env = start_env_sharded(4).await;
    let alice = env.register("alice", "pw-12345678").await;

    // Rooms on at least two distinct shards.
    let mut by_shard: std::collections::BTreeMap<u16, String> = Default::default();
    for _ in 0..16 {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(&alice),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room_id = body["room_id"].as_str().unwrap().to_owned();
        by_shard
            .entry(env.rooms.index_of(&room_id))
            .or_insert(room_id);
        if by_shard.len() >= 2 {
            break;
        }
    }
    assert!(by_shard.len() >= 2, "16 rooms all hashed to one shard?");
    let rooms: Vec<String> = by_shard.into_values().collect();

    // Initial sync: both rooms joined; multi-shard token shape (the `r`
    // vector form — never the legacy single-seq form).
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["next_batch"].as_str().unwrap().to_owned();
    assert!(
        token.contains('r'),
        "multi-shard cluster must mint vector tokens: {token}"
    );
    for room in &rooms {
        assert!(
            body["rooms"]["join"].get(room).is_some(),
            "{room} missing from initial sync"
        );
    }

    // A message in each room; the incremental sync sees both.
    let mut event_ids = Vec::new();
    for (i, room) in rooms.iter().enumerate() {
        let enc = room.replace('!', "%21").replace(':', "%3A");
        let (status, body) = env
            .req(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{enc}/send/m.room.message/t{i}"),
                Some(&alice),
                Some(json!({"msgtype": "m.text", "body": format!("hello {i}")})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        event_ids.push(body["event_id"].as_str().unwrap().to_owned());
    }
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={token}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (room, event_id) in rooms.iter().zip(&event_ids) {
        let timeline = &body["rooms"]["join"][room]["timeline"]["events"];
        assert!(
            timeline
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == event_id.as_str())),
            "{room}: incremental sync missing its event: {body}"
        );
    }
    let token2 = body["next_batch"].as_str().unwrap().to_owned();

    // /messages accepts the vector sync token as `from`, per room —
    // each room reads its own shard's component.
    for (room, event_id) in rooms.iter().zip(&event_ids) {
        let enc = room.replace('!', "%21").replace(':', "%3A");
        let (status, body) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/rooms/{enc}/messages?dir=b&from={token2}"),
                Some(&alice),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["chunk"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == event_id.as_str())),
            "{room}: /messages missing its event: {body}"
        );
    }

    // A legacy single-seq token is refused on a multi-shard cluster.
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/sync?since=s1_2_0_0",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Membership spans shards: invites, joins and leaves in rooms on
/// different shards all converge through the per-shard projections into
/// one coherent /sync.
#[tokio::test]
async fn multi_shard_membership_projections() {
    let env = start_env_sharded(4).await;
    let alice = env.register("alice", "pw-12345678").await;
    let bob = env.register("bob", "pw-12345678").await;

    let mut by_shard: std::collections::BTreeMap<u16, String> = Default::default();
    for _ in 0..16 {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(&alice),
                Some(json!({"invite": ["@bob:hs.test"], "preset": "public_chat"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room_id = body["room_id"].as_str().unwrap().to_owned();
        by_shard
            .entry(env.rooms.index_of(&room_id))
            .or_insert(room_id);
        if by_shard.len() >= 2 {
            break;
        }
    }
    assert!(by_shard.len() >= 2);
    let rooms: Vec<String> = by_shard.into_values().collect();

    // Bob sees both invites, joins both, then leaves the first.
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for room in &rooms {
        assert!(
            body["rooms"]["invite"].get(room).is_some(),
            "{room} invite missing: {body}"
        );
    }
    for room in &rooms {
        let enc = room.replace('!', "%21").replace(':', "%3A");
        let (status, body) = env
            .req(
                "POST",
                &format!("/_matrix/client/v3/rooms/{enc}/join"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let enc = rooms[0].replace('!', "%21").replace(':', "%3A");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{enc}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["rooms"]["join"].get(&rooms[1]).is_some(),
        "second room joined: {body}"
    );
    assert!(
        body["rooms"]["join"].get(&rooms[0]).is_none(),
        "left room must not be joined: {body}"
    );
}

/// A restricted room's allow condition names a room on a DIFFERENT
/// shard: the authoriser must route the allow-room membership read by
/// that room's own id. Reading it from the join room's shard reports
/// the allow room unknown, and the server refuses to vouch for a room
/// it does hold (the whole TestRestrictedRooms* family failed this way
/// when CI flipped to 4 shards).
#[tokio::test]
async fn restricted_join_allow_room_on_other_shard() {
    let env = start_env_sharded(4).await;
    let alice = env.register("alice", "pw-12345678").await;
    let bob = env.register("bob", "pw-12345678").await;

    // The allow room: public, joinable by bob.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let allow_room = body["room_id"].as_str().unwrap().to_owned();

    // A restricted room on a DIFFERENT shard than the allow room.
    let mut restricted = None;
    for _ in 0..32 {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(&alice),
                Some(json!({
                    "preset": "public_chat",
                    "initial_state": [{
                        "type": "m.room.join_rules",
                        "state_key": "",
                        "content": {
                            "join_rule": "restricted",
                            "allow": [{
                                "type": "m.room_membership",
                                "room_id": allow_room,
                            }],
                        },
                    }],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = body["room_id"].as_str().unwrap().to_owned();
        if env.rooms.index_of(&id) != env.rooms.index_of(&allow_room) {
            restricted = Some(id);
            break;
        }
    }
    let restricted = restricted.expect("32 rooms all hashed to the allow room's shard?");
    let enc_restricted = restricted.replace('!', "%21").replace(':', "%3A");
    let enc_allow = allow_room.replace('!', "%21").replace(':', "%3A");

    // Not in the allow room yet: the join is refused.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{enc_restricted}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Joined to the allow room: the cross-shard membership read must
    // authorise the join.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{enc_allow}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{enc_restricted}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "join via cross-shard allow room: {body}"
    );

    // Left both again: the refusal is a clean FailsConditions (403),
    // not a can't-see-the-room CannotValidate.
    for enc in [&enc_restricted, &enc_allow] {
        let (status, body) = env
            .req(
                "POST",
                &format!("/_matrix/client/v3/rooms/{enc}/leave"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{enc_restricted}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
}
