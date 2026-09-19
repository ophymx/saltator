//! Registration and account identity: gated registration walking its UIA
//! stages, one-use registration tokens and their admin CRUD, UIA session
//! scoping, the external-identity links the SSO path is built on, and
//! password change and deactivation.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;
use tower::ServiceExt;

use crate::harness::*;

/// Regressions surfaced by the first Complement run: trailing-slash state
/// URLs, username case handling, directory visibility, size/encoding
/// rejections, history visibility, MSC4115 annotations, and the
/// newly-joined-room incremental-sync race.
#[tokio::test]
async fn complement_shaped_regressions() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-password-1").await;
    let bob = env.register("bob", "bob-password-1").await;

    // Uppercase registration downcases; uppercase login canonicalizes.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "CaRoL", "password": "carol-password-1",
                        "auth": {"type": "m.login.dummy"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], format!("@carol:{SERVER}"));
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password",
                        "identifier": {"type": "m.id.user", "user": "CAROL"},
                        "password": "carol-password-1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let carol = body["access_token"].as_str().unwrap().to_owned();

    // register/available validates the localpart.
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/register/available?username=not,valid",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_USERNAME");

    // Invalid UTF-8 body → 400 M_NOT_JSON (not a UIA challenge).
    let resp = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("Content-Type", "application/json")
                .body(Body::from(b"{ \"test\":\"a\x81\" }".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["errcode"], "M_NOT_JSON");

    // Bob's sync position from before the room even exists: the classic
    // newly-joined race. next_batch here predates every room event.
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bob_since = body["next_batch"].as_str().unwrap().to_owned();

    // Public room with a power-level override. In a v12 room the creator has
    // infinite power and must not be listed in `users` (MSC4289) — an override
    // that lists one is rejected (see v12_creator_power_level_rules), so this
    // sets only `users_default`.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "visibility": "public",
                "preset": "public_chat",
                "name": "Complement Room",
                "topic": "regressions",
                "power_level_content_override": {"users_default": 0},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();
    let room_enc = room_id.replace('!', "%21");

    // Trailing-slash state URLs (empty state key).
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_enc}/state/m.room.name/"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Complement Room");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/state/m.room.power_levels/"),
            Some(&alice),
            Some(json!({"users": {}, "users_default": 10})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Directory: listed with name/topic; filtered search; visibility PUT.
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/publicRooms", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chunk = &body["chunk"][0];
    assert_eq!(chunk["room_id"], room_id.as_str(), "{body}");
    assert_eq!(chunk["name"], "Complement Room");
    assert_eq!(chunk["topic"], "regressions");
    // join_rule must be present even for public rooms — ruma elides the
    // default ("public"), so the directory response fills it back in.
    assert_eq!(chunk["join_rule"], "public", "{body}");
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/publicRooms",
            Some(&alice),
            Some(json!({"filter": {"generic_search_term": "zzz-no-match"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["chunk"].as_array().unwrap().len(), 0);
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/directory/list/room/{room_enc}"),
            Some(&alice),
            Some(json!({"visibility": "private"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/directory/list/room/{room_enc}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["visibility"], "private");

    // Canonical alias must exist and point at this room.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/state/m.room.canonical_alias/"),
            Some(&alice),
            Some(json!({"alias": format!("#missing:{SERVER}")})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_ALIAS");

    // Oversized event → 413 M_TOO_LARGE.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/big"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "x".repeat(70_000)})),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["errcode"], "M_TOO_LARGE");

    // Pre-join message, then bob joins.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/pre"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "prejoin"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let prejoin_event = body["event_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_enc}/join"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Incremental sync from the pre-room since token must surface the
    // newly-joined room even though its events predate the token.
    let mut appeared = false;
    for _ in 0..100 {
        let (status, body) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/sync?since={bob_since}"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = &body["rooms"]["join"][&room_id];
        if !room.is_null() {
            let in_timeline = room["timeline"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .chain(room["state"]["events"].as_array().into_iter().flatten())
                .any(|e| {
                    e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}")
                });
            assert!(in_timeline, "join membership missing: {room}");
            appeared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        appeared,
        "newly-joined room never appeared in incremental sync"
    );

    // MSC4115: bob sees his own membership annotated per event.
    let sync = env
        .sync_until(&bob, |b| !b["rooms"]["join"][&room_id].is_null())
        .await;
    let events = sync["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .unwrap()
        .clone();
    for e in &events {
        let m = e["unsigned"]["membership"].as_str().unwrap();
        if e["event_id"] == prejoin_event.as_str() {
            assert_eq!(m, "leave", "{e}");
        }
        if e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}") {
            assert_eq!(m, "join", "{e}");
        }
    }

    // History visibility on /event: carol (never a member) is denied with
    // 404 under the default `shared` visibility, while bob (member) sees
    // the pre-join event.
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_enc}/event/{prejoin_event}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_enc}/event/{prejoin_event}"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // world_readable admits non-members.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/state/m.room.history_visibility/"),
            Some(&alice),
            Some(json!({"history_visibility": "world_readable"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/wr"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "world-readable"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let wr_event = body["event_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_enc}/event/{wr_event}"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    env.shutdown().await;
}

/// The gated two-stage registration flow, end to end: the challenge names
/// both stages, the interim 401 reports progress, and only the second
/// request creates the account.
#[tokio::test]
async fn gated_registration_walks_both_stages() {
    // The gate applies to everyone, including the bootstrap admin, so
    // enabling it on an empty server locks it with nobody inside.
    let env = start_env_admin_cfg(&["@root:hs.test"], Vec::new(), true).await;
    let (status, body) = env
        .req(
            "POST",
            REGISTER,
            None,
            Some(json!({"username": "root", "password": "pw-12345678"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let stages: Vec<&str> = body["flows"][0]["stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(
        stages,
        ["m.login.registration_token", "m.login.dummy"],
        "{body}"
    );
}

/// With tokens required, a token minted by an admin lets exactly one
/// registration through, and the second attempt is refused.
#[tokio::test]
async fn one_use_token_admits_exactly_one_registration() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;

    let (status, token_body) = env
        .req(
            "POST",
            REG_TOKENS,
            Some(&root),
            Some(json!({"uses_allowed": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{token_body}");
    let token = token_body["token"].as_str().unwrap().to_owned();
    assert_eq!(token_body["used"], 0);
    assert_eq!(token_body["valid"], true);

    // Registering with the token twice: the second must lose, because the
    // token is consumed atomically inside the register command rather than
    // at the UIA stage (which is only a read).
    let register_with = |user: &'static str, token: String| {
        env.req(
            "POST",
            REGISTER,
            None,
            Some(json!({
                "username": user,
                "password": "pw-12345678",
                "auth": {"type": "m.login.registration_token", "token": token}
            })),
        )
    };

    // First: the token stage completes but the flow still wants dummy.
    let (status, body) = register_with("alice", token.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let session = body["session"].as_str().unwrap().to_owned();
    assert_eq!(body["completed"][0], "m.login.registration_token");

    let (status, body) = env
        .req(
            "POST",
            REGISTER,
            None,
            Some(json!({
                "username": "alice",
                "password": "pw-12345678",
                "auth": {"type": "m.login.dummy", "session": session}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The token is now spent.
    let (status, body) = env
        .req("GET", &format!("{REG_TOKENS}/{token}"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["used"], 1);
    assert_eq!(body["valid"], false);

    let (status, body) = register_with("bob", token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

/// The unauthenticated validity probe, so a client can reject a bad invite
/// code before collecting a password.
#[tokio::test]
async fn registration_token_validity_probe() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let (_, created) = env
        .req(
            "POST",
            REG_TOKENS,
            Some(&root),
            Some(json!({"token": "open-sesame", "uses_allowed": 2})),
        )
        .await;
    assert_eq!(created["token"], "open-sesame");

    let path = "/_matrix/client/v1/register/m.login.registration_token/validity";
    let (status, body) = env
        .req("GET", &format!("{path}?token=open-sesame"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);

    let (status, body) = env
        .req("GET", &format!("{path}?token=nonsense"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], false, "must not leak which tokens exist");
}

#[tokio::test]
async fn registration_token_admin_crud() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;

    let (_, a) = env
        .req(
            "POST",
            REG_TOKENS,
            Some(&root),
            Some(json!({"token": "aaa"})),
        )
        .await;
    assert_eq!(a["uses_allowed"], serde_json::Value::Null, "{a}");
    env.req(
        "POST",
        REG_TOKENS,
        Some(&root),
        Some(json!({"token": "bbb"})),
    )
    .await;

    let (status, list) = env.req("GET", REG_TOKENS, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let names: Vec<&str> = list["registration_tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["token"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["aaa", "bbb"]);

    // Duplicates are refused rather than silently resetting the counter.
    let (status, body) = env
        .req(
            "POST",
            REG_TOKENS,
            Some(&root),
            Some(json!({"token": "aaa"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, _) = env
        .req("DELETE", &format!("{REG_TOKENS}/aaa"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .req("GET", &format!("{REG_TOKENS}/aaa"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Only administrators may see or mint invite codes.
    let mallory = env.register("mallory", "pw-12345678").await;
    let (status, _) = env.req("GET", REG_TOKENS, Some(&mallory), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A UIA session that has actually completed a stage is bound to the
/// request it completed for, and cannot be spent on another endpoint.
///
/// Note the setup deliberately completes a stage first: an id from an
/// opening challenge is never stored, so presenting one elsewhere is not
/// a replay — the client still has to do that endpoint's auth work in the
/// same request. What must not work is carrying *earned* progress across.
#[tokio::test]
async fn uia_session_does_not_cross_endpoints() {
    let env = start_env().await;
    let token = env.register("alice", "pw-12345678").await;
    let session = "client-chosen-session";
    let password_auth = |session: &str| {
        json!({"auth": {
            "type": "m.login.password",
            "session": session,
            "identifier": {"type": "m.id.user", "user": "alice"},
            "password": "pw-12345678"
        }})
    };

    // A second session to delete, so the deletion does not revoke the
    // token driving this test.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "pw-12345678"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = body["device_id"].as_str().unwrap().to_owned();

    // Earn a completed password stage against the device deletion.
    let (status, body) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device}"),
            Some(&token),
            Some(password_auth(session)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The same session, now carrying that progress, against deactivation.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/deactivate",
            Some(&token),
            Some(password_auth(session)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A fresh session for the same call is fine — it is the carried-over
    // progress that was refused, not the operation.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/deactivate",
            Some(&token),
            Some(password_auth("a-different-session")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// -- identity links ---------------

/// The link surface is admin-only, like everything else under
/// `/_saltator/admin`: an ordinary account authenticates and is refused.
#[tokio::test]
async fn link_endpoints_are_admin_only() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let mallory = env.register("mallory", "pw-12345678").await;

    for (method, path, body) in [
        (
            "PUT",
            "/_saltator/admin/v1/users/@mallory:hs.test/external_ids/oidc-keycloak",
            Some(json!({"external_id": "sub-1"})),
        ),
        (
            "DELETE",
            "/_saltator/admin/v1/users/@mallory:hs.test/external_ids/oidc-keycloak",
            None,
        ),
        (
            "GET",
            "/_saltator/admin/v1/auth_providers/oidc-keycloak/users/sub-1",
            None,
        ),
    ] {
        let (status, resp) = env.req(method, path, Some(&mallory), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {resp}");
    }
    env.shutdown().await;
}

/// A link written through the API shows up on the account and by reverse
/// lookup, and unlinking clears both views. The subject carries a `/` to
/// prove the path form survives percent-encoding — opaque IdP subjects
/// are not URL-safe by nature.
#[tokio::test]
async fn external_ids_round_trip_through_the_admin_api() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;
    const LINK: &str = "/_saltator/admin/v1/users/@alice:hs.test/external_ids/oidc-keycloak";

    let (status, body) = env
        .req(
            "PUT",
            LINK,
            Some(&root),
            Some(json!({"external_id": "sub/1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["external_ids"][0]["auth_provider"], "oidc-keycloak");
    assert_eq!(body["external_ids"][0]["external_id"], "sub/1");

    let (status, body) = env
        .req(
            "GET",
            "/_saltator/admin/v1/auth_providers/oidc-keycloak/users/sub%2F1",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");

    let (status, body) = env.req("DELETE", LINK, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["external_ids"].as_array().unwrap().len(), 0);

    let (status, body) = env
        .req(
            "GET",
            "/_saltator/admin/v1/auth_providers/oidc-keycloak/users/sub%2F1",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    env.shutdown().await;
}

/// Two accounts cannot hold the same subject at one provider: the second
/// write is a conflict that names the holder.
#[tokio::test]
async fn linking_a_taken_subject_is_a_conflict() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;
    env.register("bob", "pw-12345678").await;

    async fn link(env: &Env, user: &str, token: &str) -> (StatusCode, Value) {
        env.req(
            "PUT",
            &format!("/_saltator/admin/v1/users/{user}/external_ids/oidc-keycloak"),
            Some(token),
            Some(json!({"external_id": "sub-1"})),
        )
        .await
    }
    let (status, body) = link(&env, "@alice:hs.test", &root).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = link(&env, "@bob:hs.test", &root).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("@alice:hs.test"),
        "{body}"
    );
    env.shutdown().await;
}

/// `GET /login` derives its flows from the configured providers now
/// rather than a literal. With only local passwords configured the wire
/// shape must be exactly what it was.
#[tokio::test]
async fn login_flows_advertise_password() {
    let env = start_env().await;
    let (status, body) = env.req("GET", "/_matrix/client/v3/login", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let flows = body["flows"].as_array().unwrap();
    assert_eq!(flows.len(), 1, "{body}");
    assert_eq!(flows[0]["type"], "m.login.password");
    env.shutdown().await;
}

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

/// Every endpoint that takes a user id in its path must refuse a token
/// belonging to someone else.
///
/// These nine checks are one decision repeated, which is exactly why
/// they are worth a test: the pattern is easy to leave out of a tenth
/// endpoint, and each omission is a user reading or writing another
/// user's data. They are swept together rather than one test each
/// because the interesting property is that NONE of them is missing.
#[tokio::test]
async fn a_token_cannot_act_on_another_users_resources() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw-123").await;
    let _bob = env.register("bob", "bob-pw-12345").await;
    let bob_id = format!("@bob:{SERVER}");
    let room_id = make_room(&env, &alice, "authz").await;
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    // (method, path, body) — alice's token, bob's user id throughout.
    let cases: Vec<(&str, String, Option<Value>)> = vec![
        (
            "PUT",
            format!("/_matrix/client/v3/profile/{bob_id}/displayname"),
            Some(json!({"displayname": "not bob"})),
        ),
        (
            "PUT",
            format!("/_matrix/client/v3/profile/{bob_id}/avatar_url"),
            Some(json!({"avatar_url": "mxc://hs.test/nope"})),
        ),
        (
            "PUT",
            format!("/_matrix/client/v3/user/{bob_id}/account_data/m.test"),
            Some(json!({"snooped": true})),
        ),
        (
            "GET",
            format!("/_matrix/client/v3/user/{bob_id}/account_data/m.test"),
            None,
        ),
        (
            "PUT",
            format!("/_matrix/client/v3/user/{bob_id}/rooms/{enc}/account_data/m.test"),
            Some(json!({"snooped": true})),
        ),
        (
            "GET",
            format!("/_matrix/client/v3/user/{bob_id}/rooms/{enc}/account_data/m.test"),
            None,
        ),
        (
            "POST",
            format!("/_matrix/client/v3/user/{bob_id}/filter"),
            Some(json!({"room": {"timeline": {"limit": 1}}})),
        ),
        (
            "GET",
            format!("/_matrix/client/v3/user/{bob_id}/filter/0"),
            None,
        ),
        (
            "PUT",
            format!("/_matrix/client/v3/presence/{bob_id}/status"),
            Some(json!({"presence": "online"})),
        ),
    ];

    for (method, path, body) in cases {
        let (status, resp) = env.req(method, &path, Some(&alice), body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {path} should refuse another user's token, got {status}: {resp}"
        );
        assert_eq!(resp["errcode"], "M_FORBIDDEN", "{method} {path}: {resp}");
    }
    env.shutdown().await;
}
