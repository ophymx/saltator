//! Push: the default rule set riding the initial sync, rule and pusher
//! mutations, HTTP pusher delivery (including dropping a pusher the
//! gateway rejects), and rules surviving a room upgrade.
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::harness::*;

/// Push rules and pushers: defaults ride the initial sync, mutations
/// land as `m.push_rules` account data in the next window (waking
/// long-polls), reads are stable, and pushers die with the session that
/// created them.
#[tokio::test]
async fn push_rules_and_pushers() {
    let env = start_env().await;
    let alice = env.register("alice", "first-pw").await;

    // Server-default rules ride the initial sync.
    let (status, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync0}");
    let pr = sync0["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.push_rules")
        .expect("push rules in initial sync")
        .clone();
    assert!(pr["content"]["global"]["underride"].is_array(), "{pr}");
    let t1 = sync0["next_batch"].as_str().unwrap().to_owned();

    // Single-rule GET: 404 for unknown rules and kinds (clients probe
    // optional rules and take any other status as existence), 200 with the
    // rule body for known ones.
    for path in [
        "/_matrix/client/v3/pushrules/global/postcontent/.io.element.msc4306.rule.subscribed_thread",
        "/_matrix/client/v3/pushrules/global/override/.m.rule.does_not_exist",
    ] {
        let (status, body) = env.req("GET", path, Some(&alice), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
    let (status, rule) = env
        .req(
            "GET",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.master",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rule}");
    assert_eq!(rule["rule_id"], ".m.rule.master", "{rule}");
    let (status, attr) = env
        .req(
            "GET",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{attr}");
    assert_eq!(attr["enabled"], false, "{attr}");

    // Adding a rule shows in GET /pushrules/ and in the next sync window.
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com",
            Some(&alice),
            Some(json!({"actions": ["notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, rules) = env
        .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{rules}");
    assert_eq!(rules["global"]["room"][0]["rule_id"], "!foo:example.com");
    let synced_rules = |resp: &Value| {
        resp["account_data"]["events"]
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e["type"] == "m.push_rules"))
    };
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={t1}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(synced_rules(&resp), "rule add missed the window: {resp}");
    let t2 = resp["next_batch"].as_str().unwrap().to_owned();

    // Disabling and setting actions both surface in the next window, and
    // repeated reads are stable (the SYN-390 cache-health shape).
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com/enabled",
            Some(&alice),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com/actions",
            Some(&alice),
            Some(json!({"actions": ["dont_notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for _ in 0..2 {
        let (status, rules) = env
            .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{rules}");
        assert_eq!(rules["global"]["room"][0]["enabled"], false);
        assert_eq!(rules["global"]["room"][0]["actions"][0], "dont_notify");
    }
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
        synced_rules(&resp),
        "attr changes missed the window: {resp}"
    );

    // A sender rule (the cache-health test's exact shape).
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/pushrules/global/sender/@alice:{SERVER}"),
            Some(&alice),
            Some(json!({"actions": ["dont_notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, rules) = env
        .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
        .await;
    assert_eq!(rules["global"]["sender"][0]["actions"][0], "dont_notify");

    // Pushers: one made by another session dies on password change...
    let (status, other) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
                "password": "first-pw",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{other}");
    let other_session = other["access_token"].as_str().unwrap().to_owned();
    let pusher = json!({
        "data": {"url": "https://dummy.url/_matrix/push/v1/notify"},
        "kind": "http", "app_id": "complement", "pushkey": "a_push_key",
        "app_display_name": "c", "device_display_name": "d", "lang": "en",
    });
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&other_session),
            Some(pusher.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let count = |resp: &Value| resp["pushers"].as_array().map(Vec::len).unwrap_or(0);
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 1, "{resp}");
    let uia = |password: &str| {
        json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
            "password": password,
        })
    };
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "second-pw", "auth": uia("first-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 0, "other session's pusher survived: {resp}");

    // ...while one made by the surviving session stays.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&alice),
            Some(pusher.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "third-pw", "auth": uia("second-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 1, "own pusher deleted: {resp}");

    // kind: null deletes.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&alice),
            Some(json!({"app_id": "complement", "pushkey": "a_push_key", "kind": null})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 0, "{resp}");

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
