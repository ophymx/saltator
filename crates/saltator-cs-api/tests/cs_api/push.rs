//! Despite the file name, this module holds no push tests. It covers
//! password change and deactivation (an account concern) and
//! `send_join` state reaching `/sync` for an imported room (a
//! federation concern). Both belong in those modules; the HTTP pusher
//! itself is tested in `client`, and push rules in `rooms`.
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

use crate::harness::*;

/// Account lifecycle: password change behind a UIA password stage (other
/// sessions die by default, optionally survive), then deactivation
/// (permanent — all sessions dead, logins refused).
#[tokio::test]
async fn password_change_and_deactivation() {
    let env = start_env().await;
    let alice = env.register("alice", "first-pw").await;

    let login = |password: &'static str| {
        let env = &env;
        async move {
            env.req(
                "POST",
                "/_matrix/client/v3/login",
                None,
                Some(json!({
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
                    "password": password,
                })),
            )
            .await
        }
    };
    let uia = |password: &str| {
        json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
            "password": password,
        })
    };
    let (status, other) = login("first-pw").await;
    assert_eq!(status, StatusCode::OK, "{other}");
    let other_session = other["access_token"].as_str().unwrap().to_owned();

    // No auth → UIA challenge with a password flow and no errcode.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "second-pw"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");
    assert!(body.get("errcode").is_none(), "bare challenge: {body}");

    // Wrong password → 401 M_FORBIDDEN, still carrying the flows.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "second-pw", "auth": uia("wrong")})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
    assert!(body.get("flows").is_some(), "{body}");

    // Correct password: this session survives, the other dies, the old
    // password is refused and the new one works.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "second-pw", "auth": uia("first-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&other_session),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = login("first-pw").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = login("second-pw").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let kept = body["access_token"].as_str().unwrap().to_owned();

    // logout_devices: false keeps the other sessions alive.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({
                "new_password": "third-pw", "logout_devices": false,
                "auth": uia("second-pw"),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&kept),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Deactivation: challenge first, then permanent shutdown.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/deactivate",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/deactivate",
            Some(&alice),
            Some(json!({"auth": uia("third-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id_server_unbind_result"], "success");
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = login("third-pw").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

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
