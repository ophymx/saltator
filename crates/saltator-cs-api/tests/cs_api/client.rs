//! The core client-server loop against the real HTTP router: two users
//! register, chat, and observe each other. Plus the surfaces that ride
//! on `/sync` — account data, to-device and OTK counts, device-list
//! changes, presence, relations and threads, the user directory,
//! transaction-id scoping, and HTTP pusher delivery.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use crate::harness::*;

#[tokio::test]
async fn two_users_chat_end_to_end() {
    let env = start_env().await;

    // Discovery.
    let (status, body) = env.req("GET", "/_matrix/client/versions", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "v1.19"));
    let (status, body) = env
        .req("GET", "/.well-known/matrix/client", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["m.homeserver"]["base_url"], "https://hs.test");

    // Registration + whoami.
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], format!("@alice:{SERVER}"));
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some("garbage"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Profile.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/profile/@alice:{SERVER}/displayname"),
            Some(&alice),
            Some(json!({"displayname": "Alice"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/profile/@alice:{SERVER}"),
            None,
            None,
        )
        .await;
    assert_eq!(body["displayname"], "Alice");

    // Alice creates a room and invites Bob.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "name": "two users chat",
                "topic": "two users chat",
                "preset": "private_chat",
                "invite": [format!("@bob:{SERVER}")],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();

    // Bob sees the invite (via the membership projection) with stripped
    // state, then joins.
    let body = env
        .sync_until(&bob, |b| b["rooms"]["invite"].get(&room_id).is_some())
        .await;
    let invite_state = &body["rooms"]["invite"][&room_id]["invite_state"]["events"];
    assert!(invite_state
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "m.room.name"));
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Alice sends a message; the txnId is idempotent.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hi bob"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event_id = body["event_id"].as_str().unwrap().to_owned();
    let (_, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hi bob"})),
        )
        .await;
    assert_eq!(body["event_id"], event_id.as_str());

    // Bob sees the room and the message on initial sync.
    let body = env
        .sync_until(&bob, |b| {
            b["rooms"]["join"][&room_id]["timeline"]["events"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == event_id.as_str()))
        })
        .await;
    let joined = &body["rooms"]["join"][&room_id];
    // State section holds what the (limit-10) timeline scrolled past.
    assert!(joined["state"]["events"].as_array().is_some());
    let next_batch = body["next_batch"].as_str().unwrap().to_owned();

    // Bob replies; alice long-polls incrementally and gets it.
    let alice_sync = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await
        .1["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let router = env.router.clone();
    let alice_token = alice.clone();
    let poll = tokio::spawn(async move {
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/_matrix/client/v3/sync?since={alice_sync}&timeout=15000"
            ))
            .header("Authorization", format!("Bearer {alice_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn2"),
            Some(&bob),
            Some(json!({"msgtype": "m.text", "body": "hi alice"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let reply_id = body["event_id"].as_str().unwrap().to_owned();
    let polled = tokio::time::timeout(Duration::from_secs(10), poll)
        .await
        .expect("long-poll must wake on the new event")
        .unwrap();
    let events = polled["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(events.iter().any(|e| e["event_id"] == reply_id.as_str()));

    // Receipts: bob acks alice's message; alice sees it in ephemeral.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let body = env
        .sync_until(&alice, |b| {
            b["rooms"]["join"][&room_id]["ephemeral"]["events"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["type"] == "m.receipt"))
        })
        .await;
    let receipts = &body["rooms"]["join"][&room_id]["ephemeral"]["events"];
    let receipt = receipts
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.receipt")
        .unwrap();
    assert!(receipt["content"][&event_id]["m.read"][format!("@bob:{SERVER}")]["ts"].is_u64());

    // Typing: bob types; alice's incremental sync carries it.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/typing/@bob:{SERVER}"),
            Some(&bob),
            Some(json!({"typing": true, "timeout": 30000})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let body = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={next_batch}"),
            Some(&bob),
            None,
        )
        .await
        .1;
    let ephemeral = &body["rooms"]["join"][&room_id]["ephemeral"]["events"];
    assert!(ephemeral
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "m.typing"
            && e["content"]["user_ids"]
                .as_array()
                .unwrap()
                .contains(&json!(format!("@bob:{SERVER}")))));

    // Pagination.
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=3"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chunk = body["chunk"].as_array().unwrap();
    assert_eq!(chunk.len(), 3);
    // Newest first; the reply is the newest message.
    assert_eq!(chunk[0]["event_id"], reply_id.as_str());

    // Redaction: alice redacts her message.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/txn3"),
            Some(&alice),
            Some(json!({"reason": "oops"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/event/{event_id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["content"].as_object().unwrap().is_empty());
    assert!(body["unsigned"]["redacted_because"].is_object());

    // Membership queries.
    let (_, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/joined_members"),
            Some(&alice),
            None,
        )
        .await;
    let joined = body["joined"].as_object().unwrap();
    assert_eq!(joined.len(), 2);
    assert_eq!(joined[&format!("@alice:{SERVER}")]["display_name"], "Alice");

    // Media upload/download roundtrip.
    let upload = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload?filename=hello.txt")
        .header("Authorization", format!("Bearer {alice}"))
        .header("Content-Type", "text/plain")
        .body(Body::from("hello media"))
        .unwrap();
    let resp = env.router.clone().oneshot(upload).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let mxc = body["content_uri"].as_str().unwrap().to_owned();
    let media_id = mxc.rsplit('/').next().unwrap();
    let download = Request::builder()
        .method("GET")
        .uri(format!(
            "/_matrix/client/v1/media/download/{SERVER}/{media_id}"
        ))
        .header("Authorization", format!("Bearer {bob}"))
        .body(Body::empty())
        .unwrap();
    let resp = env.router.clone().oneshot(download).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    // Media responses are hardened against being rendered as an active
    // document on the homeserver origin.
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("sandbox"));
    // text/plain is inline-safe.
    assert!(resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("inline"));
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"hello media");

    // An uploaded HTML document must come back as an attachment (never
    // inline) so it can't run script on the media origin.
    let up_html = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload?filename=x.html")
        .header("Authorization", format!("Bearer {alice}"))
        .header("Content-Type", "text/html")
        .body(Body::from("<script>alert(1)</script>"))
        .unwrap();
    let resp = env.router.clone().oneshot(up_html).await.unwrap();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let html_id = body["content_uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let dl_html = Request::builder()
        .method("GET")
        .uri(format!(
            "/_matrix/client/v1/media/download/{SERVER}/{html_id}"
        ))
        .header("Authorization", format!("Bearer {bob}"))
        .body(Body::empty())
        .unwrap();
    let resp = env.router.clone().oneshot(dl_html).await.unwrap();
    assert!(resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("attachment"));
    // Unauthenticated media is refused.
    let download = Request::builder()
        .method("GET")
        .uri(format!(
            "/_matrix/client/v1/media/download/{SERVER}/{media_id}"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = env.router.clone().oneshot(download).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Directory: alias create/resolve.
    let alias = format!("#general:{SERVER}");
    let alias_enc = alias.replace('#', "%23");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/directory/room/{alias_enc}"),
            Some(&alice),
            Some(json!({"room_id": room_id})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/directory/room/{alias_enc}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(body["room_id"], room_id.as_str());

    // Kick/leave flow: alice kicks bob; bob's sync moves the room to
    // `leave`.
    let bob_since = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await
        .1["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/kick"),
            Some(&alice),
            Some(json!({"user_id": format!("@bob:{SERVER}"), "reason": "bye"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for _ in 0..100 {
        let (_, body) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/sync?since={bob_since}"),
                Some(&bob),
                None,
            )
            .await;
        if body["rooms"]["leave"].get(&room_id).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Logout invalidates the session.
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v3/logout",
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    env.shutdown().await;
}

#[tokio::test]
async fn account_data_filters_and_devices() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let uid = format!("@alice:{SERVER}");

    // Account data roundtrip; appears in sync.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/user/{uid}/account_data/m.direct"),
            Some(&alice),
            Some(json!({"@bob:hs.test": ["!x:hs.test"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/user/{uid}/account_data/m.direct"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(body["@bob:hs.test"][0], "!x:hs.test");
    let body = env
        .sync_until(&alice, |b| {
            b["account_data"]["events"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["type"] == "m.direct"))
        })
        .await;
    drop(body);

    // Filter upload + use by ID.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/user/{uid}/filter"),
            Some(&alice),
            Some(json!({"room": {"timeline": {"limit": 5}, "state": {"lazy_load_members": true}}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let filter_id = body["filter_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={filter_id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Devices + UIA-guarded deletion.
    let (_, body) = env
        .req("GET", "/_matrix/client/v3/devices", Some(&alice), None)
        .await;
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    let device_id = devices[0]["device_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");
    let (status, body) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            Some(&alice),
            Some(json!({"auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "pw",
            }})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Push rules exist.
    let alice2 = {
        // The first session died with its device; log in again.
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/login",
                None,
                Some(json!({
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": "alice"},
                    "password": "pw",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    };
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice2), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["global"]["underride"].as_array().is_some());

    // Refresh-token flow.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "pw",
                "refresh_token": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["expires_in_ms"].is_u64());
    let refresh = body["refresh_token"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/refresh",
            None,
            Some(json!({"refresh_token": refresh})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());

    env.shutdown().await;
}

/// The E2EE transport surface: `/sendToDevice` queues into the recipient
/// device's inbox, `/sync` delivers it (with one-time-key counts) and a
/// later since token drains it.
#[tokio::test]
async fn to_device_messages_and_otk_counts_via_sync() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (_, whoami) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    let alice_dev = whoami["device_id"].as_str().unwrap().to_owned();

    // Alice publishes one-time keys; her sync reports the counts.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({
                "one_time_keys": {
                    "signed_curve25519:AAAAAQ": {"key": "aaa"},
                    "signed_curve25519:AAAAAg": {"key": "bbb"},
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync0}");
    assert_eq!(sync0["device_one_time_keys_count"]["signed_curve25519"], 2);
    let before = sync0["next_batch"].as_str().unwrap().to_owned();

    // Bob addresses Alice's device; retransmitting the same transaction
    // must not queue a second copy.
    for _ in 0..2 {
        let (status, body) = env
            .req(
                "PUT",
                "/_matrix/client/v3/sendToDevice/m.room.encrypted/td-txn-1",
                Some(&bob),
                Some(json!({
                    "messages": {"@alice:hs.test": {&alice_dev: {"ciphertext": "xyz"}}}
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // The proposal committed before the PUT returned, so an incremental
    // sync sees the message immediately.
    let (status, delivered) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={before}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{delivered}");
    let events = delivered["to_device"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "retransmission queued a duplicate");
    assert_eq!(events[0]["type"], "m.room.encrypted");
    assert_eq!(events[0]["sender"], "@bob:hs.test");
    assert_eq!(events[0]["content"]["ciphertext"], "xyz");
    let after = delivered["next_batch"].as_str().unwrap().to_owned();

    // Syncing past the message acknowledges it, and the inbox is drained
    // for good: even rewinding to the pre-message token finds nothing.
    for since in [&after, &before] {
        let (status, resp) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/sync?since={since}&timeout=0"),
                Some(&alice),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert!(
            resp["to_device"]["events"]
                .as_array()
                .is_none_or(|a| a.is_empty()),
            "inbox not drained at since={since}: {resp}"
        );
    }

    // Wildcard addressing reaches every device of the user.
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.key.verification.request/td-txn-2",
            Some(&bob),
            Some(json!({
                "messages": {"@alice:hs.test": {"*": {"body": "verify"}}}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={after}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    let events = resp["to_device"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "m.key.verification.request");

    env.shutdown().await;
}

/// Device-list change tracking: publishing or deleting a device's keys
/// surfaces the user in room-mates' `device_lists.changed` and in
/// `/keys/changes` — the signal clients use to re-query keys.
#[tokio::test]
async fn device_list_changes_reach_sync_and_keys_changes() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let carol = env.register("carol", "carol-pw").await;

    // Alice and bob share a room; carol is unrelated.
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat", "invite": [format!("@bob:{SERVER}")]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Wait until both membership projections have settled.
    let bob_joined = |s: &Value| s["rooms"]["join"].get(&room_id).is_some();
    env.sync_until(&bob, bob_joined).await;
    let t1 = env.sync_until(&alice, bob_joined).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    // Bob publishes identity keys (carol too — but alice shares no room
    // with her, so carol must stay invisible).
    for (localpart, token) in [("bob", &bob), ("carol", &carol)] {
        let (_, whoami) = env
            .req(
                "GET",
                "/_matrix/client/v3/account/whoami",
                Some(token),
                None,
            )
            .await;
        let device_id = whoami["device_id"].as_str().unwrap().to_owned();
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/upload",
                Some(token),
                Some(json!({"device_keys": {
                    "user_id": format!("@{localpart}:{SERVER}"), "device_id": device_id,
                    "algorithms": [], "keys": {}, "signatures": {},
                }})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={t1}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let changed = resp["device_lists"]["changed"].as_array().unwrap();
    assert!(
        changed.iter().any(|u| u == &format!("@bob:{SERVER}")),
        "bob missing from device_lists.changed: {resp}"
    );
    assert!(
        !changed.iter().any(|u| u == &format!("@carol:{SERVER}")),
        "carol leaked into device_lists.changed: {resp}"
    );
    let t2 = resp["next_batch"].as_str().unwrap().to_owned();

    // The same window through /keys/changes.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/keys/changes?from={t1}&to={t2}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let changed = resp["changed"].as_array().unwrap();
    assert!(changed.iter().any(|u| u == &format!("@bob:{SERVER}")));
    assert!(!changed.iter().any(|u| u == &format!("@carol:{SERVER}")));

    // Logout deletes bob's device: his keys vanish from /keys/query and
    // alice is told to re-query.
    let (status, body) = env
        .req("POST", "/_matrix/client/v3/logout", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={t2}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        resp["device_lists"]["changed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u == &format!("@bob:{SERVER}")),
        "bob's logout not surfaced: {resp}"
    );
    let t3 = resp["next_batch"].as_str().unwrap().to_owned();
    let (status, resp) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&alice),
            Some(json!({"device_keys": {format!("@bob:{SERVER}"): []}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    // Requested users always appear; bob's dict is empty post-logout.
    assert!(
        resp["device_keys"][&format!("@bob:{SERVER}")]
            .as_object()
            .is_some_and(|m| m.is_empty()),
        "bob's deleted device keys still served: {resp}"
    );

    // Membership-driven changes. Carol joining the shared room makes her
    // newly tracked (`changed`)...
    let dl = |resp: &Value, section: &str, user: &str| -> bool {
        resp["device_lists"][section]
            .as_array()
            .is_some_and(|a| a.iter().any(|u| u == &format!("@{user}:{SERVER}")))
    };
    let sync_since = |since: String, token: String| {
        let env = &env;
        async move {
            let (status, resp) = env
                .req(
                    "GET",
                    &format!("/_matrix/client/v3/sync?since={since}&timeout=0"),
                    Some(&token),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp
        }
    };
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp = sync_since(t3, alice.clone()).await;
    assert!(dl(&resp, "changed", "carol"), "carol's join: {resp}");
    let t4 = resp["next_batch"].as_str().unwrap().to_owned();

    // ...and her leave lands her in `left` (no other shared room).
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp = sync_since(t4, alice.clone()).await;
    assert!(dl(&resp, "left", "carol"), "carol's leave: {resp}");
    let t5 = resp["next_batch"].as_str().unwrap().to_owned();

    // Alice joining a room starts tracking its existing members...
    let (status, room2) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&carol),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room2}");
    let room2_id = room2["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room2_id}/join"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp = sync_since(t5, alice.clone()).await;
    assert!(dl(&resp, "changed", "carol"), "alice's join: {resp}");
    let t6 = resp["next_batch"].as_str().unwrap().to_owned();

    // ...and leaving it stops tracking them.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room2_id}/leave"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp = sync_since(t6, alice.clone()).await;
    assert!(dl(&resp, "left", "carol"), "alice's leave: {resp}");

    env.shutdown().await;
}

/// Presence of newly-visible users rides the incremental sync: existing
/// members see the joiner's presence, and the joiner sees the members'.
#[tokio::test]
async fn presence_surfaces_on_join() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/presence/@bob:{SERVER}/status"),
            Some(&bob),
            Some(json!({"presence": "online"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (_, a_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let a_token = a_sync["next_batch"].as_str().unwrap().to_owned();
    let (_, b_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let b_token = b_sync["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let has_presence = |resp: &Value, user: &str| {
        resp["presence"]["events"]
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e["sender"] == format!("@{user}:{SERVER}")))
    };
    // Existing member sees the joiner's presence...
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={a_token}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        has_presence(&resp, "bob"),
        "joiner presence missing: {resp}"
    );
    // ...along with the room summary counts (TestRoomSummary shape).
    let summary = &resp["rooms"]["join"][&room_id]["summary"];
    assert_eq!(summary["m.joined_member_count"], 2, "{resp}");
    assert_eq!(summary["m.invited_member_count"], 0, "{resp}");
    // ...and the joiner sees the existing members'.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={b_token}&timeout=0"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        has_presence(&resp, "alice"),
        "members' presence missing: {resp}"
    );

    env.shutdown().await;
}

/// Upgrading a room (or joining/creating its replacement) carries each
/// local user's room-scoped push rules over to the new room.
#[tokio::test]
async fn push_rules_carry_over_room_upgrade() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let create = |token: String, body: serde_json::Value| {
        let env = &env;
        async move {
            let (status, room) = env
                .req(
                    "POST",
                    "/_matrix/client/v3/createRoom",
                    Some(&token),
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{room}");
            room["room_id"].as_str().unwrap().to_owned()
        }
    };
    let set_room_rule = |token: String, room: String| {
        let env = &env;
        async move {
            let (status, body) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/pushrules/global/room/{room}"),
                    Some(&token),
                    Some(json!({"actions": ["dont_notify"]})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
    };
    let room_rules = |token: String| {
        let env = &env;
        async move {
            let (status, rules) = env
                .req("GET", "/_matrix/client/v3/pushrules/", Some(&token), None)
                .await;
            assert_eq!(status, StatusCode::OK, "{rules}");
            rules["global"]["room"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["rule_id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };

    // /upgrade path: both the upgrader and a later joiner carry over.
    let old = create(alice.clone(), json!({"preset": "public_chat"})).await;
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{old}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    set_room_rule(alice.clone(), old.clone()).await;
    set_room_rule(bob.clone(), old.clone()).await;

    let (status, upgraded) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{old}/upgrade"),
            Some(&alice),
            Some(json!({"new_version": "11"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{upgraded}");
    let new_room = upgraded["replacement_room"].as_str().unwrap().to_owned();

    let alice_rules = room_rules(alice.clone()).await;
    assert!(
        alice_rules.contains(&old) && alice_rules.contains(&new_room),
        "upgrader rules not carried: {alice_rules:?}"
    );
    // Bob's copy happens at his join of the replacement.
    assert!(!room_rules(bob.clone()).await.contains(&new_room));
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{new_room}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bob_rules = room_rules(bob.clone()).await;
    assert!(
        bob_rules.contains(&old) && bob_rules.contains(&new_room),
        "joiner rules not carried: {bob_rules:?}"
    );

    // Manual upgrade path: createRoom with creation_content.predecessor.
    let manual = create(
        alice.clone(),
        json!({
            "preset": "public_chat",
            "creation_content": {"predecessor": {"room_id": new_room}},
        }),
    )
    .await;
    let alice_rules = room_rules(alice.clone()).await;
    assert!(
        alice_rules.contains(&manual),
        "manual-upgrade creator rules not carried: {alice_rules:?}"
    );

    env.shutdown().await;
}

/// /relations filters by target, rel_type, and event type, paginates in
/// both directions accepting sync tokens, and /threads orders roots by
/// latest activity with the m.thread aggregation attached.
#[tokio::test]
async fn relations_and_threads_endpoints() {
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

    let send = |txn: String, ty: &'static str, content: serde_json::Value| {
        let env = &env;
        let alice = alice.clone();
        let room_id = room_id.clone();
        async move {
            let (status, resp) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room_id}/send/{ty}/{txn}"),
                    Some(&alice),
                    Some(content),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp["event_id"].as_str().unwrap().to_owned()
        }
    };
    let thread_reply = |root: String, body: String| {
        json!({
            "msgtype": "m.text", "body": body,
            "m.relates_to": {"event_id": root, "rel_type": "m.thread"},
        })
    };

    let root = send(
        "t1".into(),
        "m.room.message",
        json!({"msgtype": "m.text", "body": "root"}),
    )
    .await;
    let (_, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let after_root = sync["next_batch"].as_str().unwrap().to_owned();
    let reply = send(
        "t2".into(),
        "m.room.message",
        thread_reply(root.clone(), "reply".into()),
    )
    .await;
    let dummy = send(
        "t3".into(),
        "m.dummy",
        json!({"m.relates_to": {"event_id": root, "rel_type": "m.thread"}}),
    )
    .await;
    let edit = send(
        "t4".into(),
        "m.room.message",
        json!({
            "msgtype": "m.text", "body": "* edited",
            "m.new_content": {"msgtype": "m.text", "body": "edited"},
            "m.relates_to": {"event_id": root, "rel_type": "m.replace"},
        }),
    )
    .await;

    let get = |url: String| {
        let env = &env;
        let alice = alice.clone();
        async move {
            let (status, resp) = env.req("GET", &url, Some(&alice), None).await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp
        }
    };
    let ids = |resp: &Value| -> Vec<String> {
        resp["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["event_id"].as_str().unwrap().to_owned())
            .collect()
    };

    // All relations; by rel_type; by rel_type + event type.
    let all = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}"
    ))
    .await;
    assert_eq!(ids(&all), vec![edit.clone(), dummy.clone(), reply.clone()]);
    let threads_only = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}/m.thread"
    ))
    .await;
    assert_eq!(ids(&threads_only), vec![dummy.clone(), reply.clone()]);
    let msgs = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}/m.thread/m.room.message"
    ))
    .await;
    assert_eq!(ids(&msgs), vec![reply.clone()]);

    // Backward pagination with limit, then the next page via next_batch.
    let page1 = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}?limit=2"
    ))
    .await;
    assert_eq!(ids(&page1), vec![edit.clone(), dummy.clone()]);
    let next = page1["next_batch"].as_str().expect("next_batch").to_owned();
    let page2 = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}?limit=2&from={next}"
    ))
    .await;
    assert_eq!(ids(&page2), vec![reply.clone()]);
    assert!(page2.get("next_batch").is_none(), "{page2}");

    // Forward pagination from a sync token.
    let fwd = get(format!(
        "/_matrix/client/v1/rooms/{room_id}/relations/{root}?dir=f&from={after_root}&limit=2"
    ))
    .await;
    assert_eq!(ids(&fwd), vec![reply.clone(), dummy.clone()]);

    // /threads: two threads, ordered by latest activity, with aggregation.
    let root2 = send(
        "t5".into(),
        "m.room.message",
        json!({"msgtype": "m.text", "body": "root2"}),
    )
    .await;
    let reply2 = send(
        "t6".into(),
        "m.room.message",
        thread_reply(root2.clone(), "r2".into()),
    )
    .await;
    let threads = get(format!("/_matrix/client/v1/rooms/{room_id}/threads")).await;
    let listed: Vec<(String, String)> = threads["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["event_id"].as_str().unwrap().to_owned(),
                e["unsigned"]["m.relations"]["m.thread"]["latest_event"]["event_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![(root2.clone(), reply2), (root.clone(), dummy.clone())],
        "{threads}"
    );
    // New reply to thread 1 reorders it to the front and moves latest_event.
    let reply3 = send(
        "t7".into(),
        "m.room.message",
        thread_reply(root.clone(), "r3".into()),
    )
    .await;
    let threads = get(format!("/_matrix/client/v1/rooms/{room_id}/threads")).await;
    let first = &threads["chunk"].as_array().unwrap()[0];
    assert_eq!(first["event_id"], root.as_str());
    assert_eq!(
        first["unsigned"]["m.relations"]["m.thread"]["latest_event"]["event_id"],
        reply3.as_str()
    );
    assert_eq!(first["unsigned"]["m.relations"]["m.thread"]["count"], 3);
    assert_eq!(
        first["unsigned"]["m.relations"]["m.thread"]["current_user_participated"],
        true
    );

    env.shutdown().await;
}

/// /user_directory/search matches global profile names and mxids for
/// users visible to the caller (shared room or public directory), and
/// never leaks room-specific member displaynames.
#[tokio::test]
async fn user_directory_search_scopes_visibility() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let eve = env.register("eve", "eve-pw").await;
    let alice_id = format!("@alice:{SERVER}");

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(&alice),
            Some(json!({"displayname": "Alice Cooper"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Alice is discoverable through a publicly-listed room.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"visibility": "public"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Bob's private room, where alice reveals a room-specific name.
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&bob),
            Some(json!({"visibility": "private", "invite": [alice_id.clone()], "preset": "private_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let private_room = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{private_room}/join"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{private_room}/state/m.room.member/{alice_id}"),
            Some(&alice),
            Some(json!({"membership": "join", "displayname": "Freddy"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let search = |token: String, term: &'static str| {
        let env = &env;
        async move {
            let (status, resp) = env
                .req(
                    "POST",
                    "/_matrix/client/v3/user_directory/search",
                    Some(&token),
                    Some(json!({"search_term": term})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp["results"].as_array().unwrap().clone()
        }
    };

    // Eve finds alice by public name and mxid — and only alice.
    for term in ["Alice Cooper", "alice"] {
        let results = search(eve.clone(), term).await;
        assert_eq!(results.len(), 1, "term {term}: {results:?}");
        assert_eq!(results[0]["user_id"], alice_id.as_str());
        assert_eq!(results[0]["display_name"], "Alice Cooper");
    }
    // The room-specific name is invisible to eve AND unindexed for bob.
    assert!(search(eve.clone(), "Freddy").await.is_empty());
    assert!(search(bob.clone(), "Freddy").await.is_empty());
    // Bob sees alice through the shared room, by name and mxid.
    for term in ["Alice Cooper", "alice"] {
        let results = search(bob.clone(), term).await;
        assert_eq!(results.len(), 1, "term {term}: {results:?}");
        assert_eq!(results[0]["user_id"], alice_id.as_str());
    }
    // Bob is invisible to eve: no shared room, no public listing.
    assert!(search(eve.clone(), "bob").await.is_empty());

    env.shutdown().await;
}

/// Transaction IDs are scoped to device + endpoint path, and the local
/// echo (`unsigned.transaction_id`) is stamped on /event and sync — but
/// only for the device that sent the event.
#[tokio::test]
async fn txn_ids_scope_to_device_and_path() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    let mut room_ids = Vec::new();
    for _ in 0..2 {
        let (status, room) = env
            .req("POST", "/_matrix/client/v3/createRoom", Some(&alice), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{room}");
        room_ids.push(room["room_id"].as_str().unwrap().to_owned());
    }
    let (r1, r2) = (&room_ids[0], &room_ids[1]);

    let send = |room: String, token: String, body: &'static str| {
        let env = &env;
        async move {
            let (status, resp) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/abc"),
                    Some(&token),
                    Some(json!({"msgtype": "m.text", "body": body})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            resp["event_id"].as_str().unwrap().to_owned()
        }
    };

    // Idempotent per room+type even when the content changes...
    let e1 = send(r1.clone(), alice.clone(), "first").await;
    let e2 = send(r1.clone(), alice.clone(), "second").await;
    assert_eq!(e1, e2, "same txn in same room must dedupe");
    // ...but a different room is a different endpoint path.
    let e3 = send(r2.clone(), alice.clone(), "first").await;
    assert_ne!(e1, e3, "same txn in another room must NOT dedupe");

    // Local echo on /event for the sending device.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{r1}/event/{e1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["unsigned"]["transaction_id"], "abc", "{got}");

    // Local echo in the sync timeline for the sending device.
    let (_, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let echo = sync["rooms"]["join"][r1]["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event_id"] == e1.as_str())
        .expect("event in timeline")["unsigned"]["transaction_id"]
        .clone();
    assert_eq!(echo, "abc", "{sync}");

    // The same user on a NEW device sees no transaction_id...
    let (status, login) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "alice-pw",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let alice2 = login["access_token"].as_str().unwrap().to_owned();
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{r1}/event/{e1}"),
            Some(&alice2),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        got["unsigned"].get("transaction_id").is_none(),
        "txn id must not leak to other devices: {got}"
    );

    // ...but a second session sharing the ORIGINAL device ID sees it.
    let (_, whoami) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    let device = whoami["device_id"].as_str().unwrap().to_owned();
    let (status, login) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "alice-pw",
                "device_id": device,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let alice_same_device = login["access_token"].as_str().unwrap().to_owned();
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{r1}/event/{e1}"),
            Some(&alice_same_device),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["unsigned"]["transaction_id"], "abc",
        "same device id shares the txn echo: {got}"
    );

    env.shutdown().await;
}

/// /messages must keep the `end` token when a `contains_url` filter shrinks
/// the chunk below the raw scan: a short *filtered* chunk is not proof the
/// timeline start was reached, so dropping `end` would strand the client
/// before earlier matching events (regression for TestRoomImageRoundtrip).
#[tokio::test]
async fn messages_end_survives_url_filter() {
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

    // A plain text message, then one carrying a `url` (the only filter match).
    for (txn, content) in [
        ("m1", json!({"msgtype": "m.text", "body": "hello"})),
        (
            "m2",
            json!({"msgtype": "m.file", "body": "f.png", "url": "mxc://hs.test/abc"}),
        ),
    ] {
        let (status, body) = env
            .req(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
                Some(&alice),
                Some(content),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // {"contains_url": true}, percent-encoded.
    let filter = "%7B%22contains_url%22%3Atrue%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&filter={filter}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let chunk = got["chunk"].as_array().unwrap();
    assert_eq!(chunk.len(), 1, "only the url event matches: {got}");
    assert_eq!(chunk[0]["content"]["url"], "mxc://hs.test/abc");
    // The token must be present even though the filtered chunk is short.
    assert!(
        got["end"].is_string(),
        "end must survive a filtered short chunk: {got}"
    );
}

/// v12 create-event semantics (MSC4289/4291): trusted_private_chat
/// invitees join `additional_creators`, client-supplied creators merge in,
/// a client can't send `m.room.create`, and an upgrade preserves
/// `additional_creators` while omitting `predecessor.event_id`.
#[tokio::test]
async fn v12_create_event_semantics() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let bob = format!("@bob:{SERVER}");
    let charlie = format!("@charlie:{SERVER}");
    env.register("bob", "pw").await;
    env.register("charlie", "pw").await;

    // trusted_private_chat (v12) + invite bob + creation_content charlie:
    // the create event's additional_creators holds BOTH.
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "room_version": "12",
                "preset": "trusted_private_chat",
                "is_direct": true,
                "invite": [bob],
                "creation_content": {"additional_creators": [charlie]},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    let (status, create) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{enc}/state/m.room.create/"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{create}");
    let creators: Vec<&str> = create["additional_creators"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        creators.contains(&bob.as_str()),
        "invitee missing: {create}"
    );
    assert!(
        creators.contains(&charlie.as_str()),
        "client creator missing: {create}"
    );

    // A client cannot send m.room.create — 400, not the pipeline's 403.
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{enc}/state/m.room.create/"),
            Some(&alice),
            Some(json!({"room_version": "12", "entropy": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Upgrade: additional_creators preserved, predecessor has no event_id.
    let (status, up) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{enc}/upgrade"),
            Some(&alice),
            Some(json!({"new_version": "12"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{up}");
    let new_enc = up["replacement_room"]
        .as_str()
        .unwrap()
        .replace('!', "%21")
        .replace(':', "%3A");
    let (status, new_create) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{new_enc}/state/m.room.create/"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{new_create}");
    assert!(
        new_create["additional_creators"].is_array(),
        "additional_creators lost on upgrade: {new_create}"
    );
    assert!(
        new_create["predecessor"]["event_id"].is_null(),
        "v12 predecessor must omit event_id: {new_create}"
    );
    assert_eq!(new_create["predecessor"]["room_id"], room_id.as_str());

    env.shutdown().await;
}

/// HTTP push delivery: a message lands, bob's pusher gateway receives a
/// notification with the event, tweaks, and counts; a gateway rejection
/// then drops the pusher (spec "Push Gateway API").
#[tokio::test]
async fn http_pusher_delivers_and_drops_rejected() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    // Mock push gateway: captures notifications, rejects on demand.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let reject: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let gateway = axum::Router::new().route(
        "/_matrix/push/v1/notify",
        axum::routing::post({
            let reject = reject.clone();
            move |axum::Json(body): axum::Json<Value>| {
                let rejected = reject.lock().unwrap().clone();
                tx.send(body).unwrap();
                async move { axum::Json(json!({ "rejected": rejected })) }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!(
        "http://{}/_matrix/push/v1/notify",
        listener.local_addr().unwrap()
    );
    let gateway_task = tokio::spawn(async move { axum::serve(listener, gateway).await });

    // http pushers must carry a spec-shaped gateway URL.
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&bob),
            Some(json!({
                "app_id": "test.app", "pushkey": "pk1", "kind": "http",
                "app_display_name": "t", "device_display_name": "t", "lang": "en",
                "data": { "url": "https://bad.example/notify" },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&bob),
            Some(json!({
                "app_id": "test.app", "pushkey": "pk1", "kind": "http",
                "app_display_name": "t", "device_display_name": "t", "lang": "en",
                "data": { "url": gateway_url },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let delivery = saltator_cs_api::spawn_push_delivery(env.state.clone());

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat", "name": "push room"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();
    let room_enc = room_id.replace('!', "%21").replace(':', "%3A");
    let (status, _) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_enc}/join"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/push1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hello bob"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The gateway hears about alice's message (join/member events don't
    // notify under default rules).
    let deadline = tokio::time::Duration::from_secs(10);
    let pushed = tokio::time::timeout(deadline, rx.recv())
        .await
        .expect("no push arrived")
        .unwrap();
    let n = &pushed["notification"];
    assert_eq!(n["room_id"], room_id.as_str(), "{pushed}");
    assert_eq!(n["type"], "m.room.message");
    assert_eq!(n["sender"], "@alice:hs.test");
    assert_eq!(n["content"]["body"], "hello bob");
    assert_eq!(n["room_name"], "push room");
    assert_eq!(n["devices"][0]["app_id"], "test.app");
    assert_eq!(n["devices"][0]["pushkey"], "pk1");
    assert!(n["counts"]["unread"].as_u64().unwrap() >= 1, "{pushed}");
    assert!(n["event_id"].as_str().unwrap().starts_with('$'));

    // Gateway starts rejecting pk1: the pusher must be dropped.
    reject.lock().unwrap().push("pk1".to_owned());
    let (status, _) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/push2"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hello again"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::timeout(deadline, rx.recv())
        .await
        .expect("no second push")
        .unwrap();
    for _ in 0..100 {
        let (_, body) = env
            .req("GET", "/_matrix/client/v3/pushers", Some(&bob), None)
            .await;
        if body["pushers"].as_array().is_some_and(|p| p.is_empty()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (_, body) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&bob), None)
        .await;
    assert_eq!(body["pushers"], json!([]), "rejected pusher not dropped");

    delivery.abort();
    gateway_task.abort();
    env.shutdown().await;
}
