//! The M2 exit criterion, at the crate level: two users register, chat,
//! and observe each other through the real HTTP surface (router-level
//! requests; the binary-level test covers real sockets).
use axum::http::StatusCode;
use serde_json::json;
use std::time::Duration;
// --- Remote join (the M3 exit criterion, crate level) --------------------

use crate::harness::*;

/// Namespace ownership cuts both ways: the AS cannot register outside
/// its namespaces, and ordinary users cannot register inside an
/// exclusive one. Both are the spec's `M_EXCLUSIVE`.
#[tokio::test]
async fn appservice_namespace_exclusivity_on_register() {
    let env = start_env_admin(&[], vec![test_registration("as-tok", "bridge", "@tg_.*")]).await;

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({"type": "m.login.application_service", "username": "not_ours"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE");

    // The sender's own localpart is always registrable — that is how a
    // bridge gets a real account row for AS login later.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({"type": "m.login.application_service", "username": "bridge"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An ordinary registration inside the exclusive namespace is refused
    // before UIA even starts.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "tg_stolen", "password": "pw-12345678"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE");

    // And /register/available says why the name is unavailable.
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/register/available?username=tg_stolen",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE");
}

/// `m.login.application_service`: the as_token is the credential; the
/// minted session is a real device usable without the AS token.
#[tokio::test]
async fn appservice_login_mints_real_session() {
    let env = start_env_admin(&[], vec![test_registration("as-tok", "bridge", "@tg_.*")]).await;
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({
                "type": "m.login.application_service",
                "username": "tg_alice",
                "inhibit_login": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("access_token").is_none(), "{body}");

    // Without the as_token the login type is refused.
    let login_body = json!({
        "type": "m.login.application_service",
        "identifier": {"type": "m.id.user", "user": "tg_alice"},
    });
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(login_body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            Some("as-tok"),
            Some(login_body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ghost_token = body["access_token"].as_str().unwrap().to_owned();
    let device_id = body["device_id"].as_str().unwrap().to_owned();

    let (status, body) = env.req("GET", WHOAMI, Some(&ghost_token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@tg_alice:hs.test");

    // That real device is masqueradable via ?device_id=.
    let (status, body) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@tg_alice:hs.test&device_id={device_id}"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], device_id);

    // Outside the namespace: M_EXCLUSIVE, not a password error.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            Some("as-tok"),
            Some(json!({
                "type": "m.login.application_service",
                "identifier": {"type": "m.id.user", "user": "someone_else"},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE");
}

/// End-to-end outbound push: interesting events arrive as transactions
/// with the `hs_token`, uninteresting rooms never do, a 500 is retried
/// with the identical transaction id and events, and delivery resumes
/// from the durable cursor.
#[tokio::test]
async fn appservice_push_delivers_and_retries() {
    let stub = start_stub_as().await;
    let env = start_appservice_env(&stub.url).await;
    let worker = saltator_cs_api::spawn_appservice_push(env.state.clone())
        .expect("push worker should spawn: url + fedout are present");

    // Ghost + room, all through the AS.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({"type": "m.login.application_service", "username": "tg_alice"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some("as-tok"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();
    let room_enc = room_id.replace(':', "%3A").replace('!', "%21");

    // Ghost joins (invited by the sender, accepted by masquerade), then
    // speaks.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_enc}/invite"),
            Some("as-tok"),
            Some(json!({"user_id": "@tg_alice:hs.test"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_enc}/join?user_id=@tg_alice:hs.test"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/tx1?user_id=@tg_alice:hs.test"),
            Some("as-tok"),
            Some(json!({"msgtype": "m.text", "body": "bridged hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hello_event = body["event_id"].as_str().unwrap().to_owned();

    // Noise the AS must NOT see: an unrelated user's room.
    let carol = env.register("carol", "pw-12345678").await;
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&carol),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let carol_room = body["room_id"].as_str().unwrap().to_owned();

    // Wait for the hello to arrive.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let hello_txn = loop {
        let txns = stub.transactions.lock().await;
        let hit = txns.iter().find(|(_, body, _)| {
            body["events"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == hello_event.as_str()))
        });
        if let Some((txn_id, body, bearer)) = hit {
            break (txn_id.clone(), body.clone(), bearer.clone());
        }
        drop(txns);
        assert!(
            std::time::Instant::now() < deadline,
            "transaction never arrived"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(hello_txn.2.as_deref(), Some("hs-as-tok"), "hs_token auth");
    let ev = hello_txn.1["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event_id"] == hello_event.as_str())
        .unwrap();
    assert_eq!(ev["type"], "m.room.message");
    assert_eq!(ev["sender"], "@tg_alice:hs.test");
    assert_eq!(ev["room_id"], room_id);
    assert_eq!(ev["content"]["body"], "bridged hello");

    // A 500 is retried: same transaction id, same events.
    stub.fail_next.store(1, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/tx2?user_id=@tg_alice:hs.test"),
            Some("as-tok"),
            Some(json!({"msgtype": "m.text", "body": "second"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second_event = body["event_id"].as_str().unwrap().to_owned();

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let txns = stub.transactions.lock().await;
        let attempts: Vec<_> = txns
            .iter()
            .filter(|(_, body, _)| {
                body["events"]
                    .as_array()
                    .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == second_event.as_str()))
            })
            .collect();
        if attempts.len() >= 2 {
            assert_eq!(
                attempts[0].0, attempts[1].0,
                "retry must reuse the transaction id"
            );
            assert_eq!(
                attempts[0].1, attempts[1].1,
                "retry must carry the identical event set"
            );
            break;
        }
        drop(txns);
        assert!(std::time::Instant::now() < deadline, "retry never arrived");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The uninteresting room never left the building.
    let txns = stub.transactions.lock().await;
    assert!(
        txns.iter().all(|(_, body, _)| {
            body["events"]
                .as_array()
                .is_none_or(|evs| evs.iter().all(|e| e["room_id"] != carol_room.as_str()))
        }),
        "carol's room must not be pushed"
    );
    drop(txns);
    worker.abort();
}

/// The two query-on-miss paths: an unknown alias/user in the AS's
/// namespaces makes the homeserver ask the AS, which provisions the
/// entity through the ordinary CS API before answering.
#[tokio::test]
async fn appservice_query_on_miss_provisions() {
    let stub = start_stub_as().await;
    let env = start_appservice_env(&stub.url).await;

    // A room for the stub to hang the queried alias on.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some("as-tok"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();
    *stub.hs.lock().await = Some((env.router.clone(), room_id.clone()));

    // Alias: unknown locally, inside the namespace → resolved via the AS.
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/directory/room/%23tg_portal%3Ahs.test",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id);

    // Outside the namespace: a plain 404, no AS involved.
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/directory/room/%23other%3Ahs.test",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // User: profile of an unregistered ghost → the AS registers it
    // during the blocking query and the profile answers.
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/profile/@tg_ghost%3Ahs.test",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@tg_ghost:hs.test"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "ghost exists after the query");
}

/// The ping round trip, and its two refusals: a mismatched appservice id
/// and a non-appservice token.
#[tokio::test]
async fn appservice_ping_round_trip() {
    let stub = start_stub_as().await;
    let env = start_appservice_env(&stub.url).await;

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v1/appservice/bridge/ping",
            Some("as-tok"),
            Some(json!({"transaction_id": "meow"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["duration_ms"].is_u64(), "{body}");
    assert_eq!(
        stub.pings.lock().await.as_slice(),
        &[Some("meow".to_owned())]
    );

    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v1/appservice/other/ping",
            Some("as-tok"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let user_token = env.register("dora", "pw-12345678").await;
    let (status, _) = env
        .req(
            "POST",
            "/_matrix/client/v1/appservice/bridge/ping",
            Some(&user_token),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// AS device management (v1.17): `PUT /devices/{id}` creates a device
/// for an appservice, and device deletion skips UIA.
#[tokio::test]
async fn appservice_device_management() {
    let env = start_env_admin(&[], vec![test_registration("as-tok", "bridge", "@tg_.*")]).await;
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({"type": "m.login.application_service", "username": "tg_alice"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Create a ghost device out of thin air (no /login involved).
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/devices/GHOSTDEV?user_id=@tg_alice:hs.test",
            Some("as-tok"),
            Some(json!({"display_name": "bridge device"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/devices/GHOSTDEV?user_id=@tg_alice:hs.test&device_id=GHOSTDEV",
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "bridge device");

    // Deletion without UIA (spec v1.17 MUST NOT ask).
    let (status, body) = env
        .req(
            "DELETE",
            "/_matrix/client/v3/devices/GHOSTDEV?user_id=@tg_alice:hs.test",
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A normal user still gets the UIA challenge on device deletion.
    let token = env.register("erin", "pw-12345678").await;
    let (_, body) = env.req("GET", WHOAMI, Some(&token), None).await;
    let device = body["device_id"].as_str().unwrap().to_owned();
    let (status, _) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "UIA challenge expected");
}

/// `?ts` timestamp massaging applies to `PUT /state` (the spec routes
/// kick-style operations through /state for exactly this reason).
#[tokio::test]
async fn appservice_ts_massaging_on_state_events() {
    let env = start_env_admin(&[], vec![test_registration("as-tok", "bridge", "@tg_.*")]).await;
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some("as-tok"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();
    let room_enc = room_id.replace(':', "%3A").replace('!', "%21");

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/state/m.room.topic?ts=12345"),
            Some("as-tok"),
            Some(json!({"topic": "bridged"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event_id = body["event_id"].as_str().unwrap().to_owned();
    let event_enc = event_id.replace(':', "%3A").replace('$', "%24");

    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_enc}/event/{event_enc}"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["origin_server_ts"], 12345, "{body}");
}

#[tokio::test]
async fn admin_user_detail_reports_devices_and_404s_for_strangers() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let token = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;

    let (status, body) = env
        .req(
            "GET",
            "/_saltator/admin/v1/users/@alice:hs.test",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");
    assert_eq!(body["displayname"], "alice");
    assert_eq!(body["has_password"], true);
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    // The hash is never exposed, only whether one exists.
    assert!(body.get("password_hash").is_none());

    let (status, body) = env
        .req(
            "GET",
            "/_saltator/admin/v1/users/@nobody:hs.test",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

/// The full appservice identity-assertion flow: ghost registration via
/// `m.login.application_service` (no UIA), then `?user_id=` masquerading
/// — which requires the ghost to exist and to sit inside the AS's user
/// namespaces.
#[tokio::test]
async fn appservice_registers_ghost_and_masquerades() {
    let env = start_env_admin(&[], vec![test_registration("as-tok", "bridge", "@tg_.*")]).await;

    // No user_id param: the AS is its own sender.
    let (status, body) = env.req("GET", WHOAMI, Some("as-tok"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@bridge:hs.test");

    // Masquerading as an unregistered ghost is refused (Synapse parity:
    // the AS must /register it first).
    let (status, body) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@tg_alice:hs.test"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Ghost registration: no UIA challenge, passwordless, one round trip.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            Some("as-tok"),
            Some(json!({"type": "m.login.application_service", "username": "tg_alice"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@tg_alice:hs.test");

    // Now the masquerade resolves.
    let (status, body) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@tg_alice:hs.test"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@tg_alice:hs.test");

    // Outside the namespace: refused even though the account exists.
    env.register("carol", "pw-12345678").await;
    let (status, body) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@carol:hs.test"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A masqueraded device must exist: unknown ids are the spec's 400
    // M_UNKNOWN_DEVICE, not a silent synthetic device.
    let (status, body) = env
        .req(
            "GET",
            &format!("{WHOAMI}?user_id=@tg_alice:hs.test&device_id=NOPE"),
            Some("as-tok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_DEVICE");
}
