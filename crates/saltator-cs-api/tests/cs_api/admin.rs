//! The admin API (`/_saltator/admin/v1`): who may reach it at all, user
//! lifecycle (lock, deactivate, erase, password reset, admin flag), room
//! shutdown and blocking, server notices, health probes, cluster node
//! listing and drain guards, and the embedded console's serving rules.
use axum::http::StatusCode;
use saltator_federation::{FedState, KeyCache, OldVerifyKey};
use serde_json::json;
use std::sync::Arc;

use crate::harness::*;

/// The admin surface is not part of the Matrix API and must not answer an
/// anonymous caller.
#[tokio::test]
async fn admin_api_requires_a_token() {
    let env = start_env().await;
    let (status, body) = env.req("GET", ADMIN_USERS, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");
}

/// An ordinary account authenticates fine and is still refused: the
/// account exists, so this proves the privilege check runs rather than
/// the token check failing.
#[tokio::test]
async fn admin_api_refuses_a_non_admin() {
    let env = start_env().await;
    let token = env.register("mallory", "pw-12345678").await;
    let (status, body) = env.req("GET", ADMIN_USERS, Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

/// The config allowlist is the bootstrap: it grants admin to an account
/// whose stored `admin` flag is false, because nothing can set that flag
/// on a fresh server.
#[tokio::test]
async fn config_named_admin_may_list_users() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let token = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;

    let (status, body) = env.req("GET", ADMIN_USERS, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["user_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["@alice:hs.test", "@root:hs.test"]);
    // Bootstrap admin-ness comes from config, so the stored flag is still
    // false — the two sources are unioned, not conflated.
    let root = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["user_id"] == "@root:hs.test")
        .unwrap();
    assert_eq!(root["admin"], false);
    assert_eq!(root["state"], "active");
}

/// An appservice token authenticates as its sender user but has no account
/// row at all, so it can never be an administrator — even when that user
/// id is named in the admin allowlist.
#[tokio::test]
async fn appservice_token_is_never_admin() {
    let env = start_env_admin(
        &["@bridge:hs.test"],
        vec![test_registration("as-secret-token", "bridge", "")],
    )
    .await;
    let (status, body) = env
        .req("GET", ADMIN_USERS, Some("as-secret-token"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// Paging through the admin list is driven by `next_from`, which is the
/// next page's first key.
#[tokio::test]
async fn admin_user_list_pages() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let token = env.register("root", "pw-12345678").await;
    for lp in ["alice", "bob"] {
        env.register(lp, "pw-12345678").await;
    }

    let (status, first) = env
        .req("GET", &format!("{ADMIN_USERS}?limit=2"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["users"].as_array().unwrap().len(), 2);
    let next = first["next_from"].as_str().unwrap().to_owned();
    assert_eq!(next, "@root:hs.test");

    let (status, last) = env
        .req(
            "GET",
            &format!("{ADMIN_USERS}?limit=2&from={next}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{last}");
    assert_eq!(last["users"][0]["user_id"], "@root:hs.test");
    assert!(last.get("next_from").is_none(), "{last}");
}

/// A deactivated account's token stops working, and the admin view says
/// why — the state is the operator-visible reason, not a missing row.
#[tokio::test]
async fn deactivated_account_is_visible_and_cannot_authenticate() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let admin_token = env.register("root", "pw-12345678").await;
    let victim_token = env.register("alice", "pw-12345678").await;

    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
    env.users.deactivate(&alice).await.unwrap();

    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&victim_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = env
        .req(
            "GET",
            "/_saltator/admin/v1/users/@alice:hs.test",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "deactivated");
}

/// The admin surface refuses a token passed the deprecated query way, even
/// though the same token works on the Matrix API. Keeps administrator
/// credentials out of URLs, where `Referer` and access logs would spread
/// them once a console is served from this origin.
#[tokio::test]
async fn admin_api_refuses_query_param_tokens() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let token = env.register("root", "pw-12345678").await;

    let (status, body) = env
        .req(
            "GET",
            &format!("{ADMIN_USERS}?access_token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");

    // The same token in the header is accepted, so this is about the
    // transport and not the credential.
    let (status, _) = env.req("GET", ADMIN_USERS, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    // The Matrix API keeps the fallback for old clients.
    let (status, _) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/account/whoami?access_token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

// -- admin lifecycle --------------

/// The headline property of `Locked`: an existing token stops working
/// immediately and works again after unlock, with no re-login. Only
/// provable through the real authentication path, which is why this lives
/// at the router rather than the service.
#[tokio::test]
async fn lock_revokes_live_tokens_and_unlock_restores_them() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    let whoami = "/_matrix/client/v3/account/whoami";

    let (status, _) = env.req("GET", whoami, Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/lock",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "locked");

    let (status, body) = env.req("GET", whoami, Some(&alice), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/unlock",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "active");

    // Same token, no re-login: the lock never destroyed the session.
    let (status, _) = env.req("GET", whoami, Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
}

/// A locked account cannot log in afresh either — the refusal is in the
/// account check, not only in token validation.
#[tokio::test]
async fn locked_account_cannot_log_in() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;
    env.req(
        "POST",
        "/_saltator/admin/v1/users/@alice:hs.test/lock",
        Some(&root),
        None,
    )
    .await;

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
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// An admin password reset kills the old sessions and the old password.
#[tokio::test]
async fn admin_password_reset_replaces_credential_and_sessions() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;

    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/reset_password",
            Some(&root),
            Some(json!({"new_password": "fresh-password-1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap().len(), 0);

    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old session survived");

    let login = |password: &'static str| {
        env.req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": password
            })),
        )
    };
    assert_eq!(login("pw-12345678").await.0, StatusCode::FORBIDDEN);
    assert_eq!(login("fresh-password-1").await.0, StatusCode::OK);
}

/// The stored admin flag is a real grant, not only a config mirror: a
/// promoted account reaches the admin API, and demotion closes it again.
#[tokio::test]
async fn granting_the_admin_flag_opens_the_api() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;

    let (status, _) = env.req("GET", ADMIN_USERS, Some(&alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = env
        .req(
            "PUT",
            "/_saltator/admin/v1/users/@alice:hs.test/admin",
            Some(&root),
            Some(json!({"admin": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["admin"], true);

    let (status, _) = env.req("GET", ADMIN_USERS, Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);

    env.req(
        "PUT",
        "/_saltator/admin/v1/users/@alice:hs.test/admin",
        Some(&root),
        Some(json!({"admin": false})),
    )
    .await;
    let (status, _) = env.req("GET", ADMIN_USERS, Some(&alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The self-lockout guard, over HTTP: an administrator cannot remove their
/// own access, because nothing in this API could give it back.
#[tokio::test]
async fn admin_cannot_lock_out_themselves() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;

    for (method, path, body) in [
        ("POST", "/_saltator/admin/v1/users/@root:hs.test/lock", None),
        (
            "POST",
            "/_saltator/admin/v1/users/@root:hs.test/deactivate",
            None,
        ),
        (
            "PUT",
            "/_saltator/admin/v1/users/@root:hs.test/admin",
            Some(json!({"admin": false})),
        ),
    ] {
        let (status, resp) = env.req(method, path, Some(&root), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {resp}");
        assert_eq!(resp["errcode"], "M_INVALID_PARAM");
    }

    let (status, _) = env.req("GET", ADMIN_USERS, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "admin locked themselves out anyway");
}

/// A malformed user id in the path is a 400, not a 404 that reads as
/// "no such account".
#[tokio::test]
async fn malformed_target_user_id_is_a_bad_request() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/not-a-user-id/lock",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
}

/// Deactivate with `erase` clears the profile, and the erasure shows in
/// the admin view.
#[tokio::test]
async fn admin_deactivate_with_erase() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    env.register("alice", "pw-12345678").await;

    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/deactivate",
            Some(&root),
            Some(json!({"erase": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "deactivated");
    assert_eq!(body["erased"], true);
    assert!(body["displayname"].is_null(), "{body}");
}

/// The room surface is admin-only, like the rest of `/_saltator/admin`.
#[tokio::test]
async fn room_admin_endpoints_are_admin_only() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let mallory = env.register("mallory", "pw-12345678").await;
    let room = make_room(&env, &mallory, "Mallory's room").await;

    for (method, path, body) in [
        ("GET", ADMIN_ROOMS.to_owned(), None),
        ("GET", format!("{ADMIN_ROOMS}/{room}"), None),
        ("DELETE", format!("{ADMIN_ROOMS}/{room}"), None),
        (
            "PUT",
            format!("{ADMIN_ROOMS}/{room}/block"),
            Some(json!({"blocked": true})),
        ),
        ("GET", "/_saltator/admin/v1/blocked_rooms".to_owned(), None),
    ] {
        let (status, resp) = env.req(method, &path, Some(&mallory), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {resp}");
    }
    env.shutdown().await;
}

/// A hosted room lists with its name and member counts; the detail adds
/// the creator and the local members.
#[tokio::test]
async fn admin_room_list_and_detail() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    let room = make_room(&env, &alice, "Ops").await;

    let (status, body) = env.req("GET", ADMIN_ROOMS, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rooms = body["rooms"].as_array().unwrap();
    assert_eq!(rooms.len(), 1, "{body}");
    assert_eq!(rooms[0]["room_id"], room.as_str());
    assert_eq!(rooms[0]["name"], "Ops");
    assert_eq!(rooms[0]["joined_members"], 1);
    assert_eq!(rooms[0]["local_joined_members"], 1);
    assert_eq!(rooms[0]["join_rule"], "public");
    assert!(rooms[0].get("blocked").is_none(), "open room: {body}");

    let (status, body) = env
        .req("GET", &format!("{ADMIN_ROOMS}/{room}"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["local_members"][0], "@alice:hs.test");
    assert_eq!(body["local_members_truncated"], false);

    let (status, body) = env
        .req(
            "GET",
            &format!("{ADMIN_ROOMS}/!nope:hs.test"),
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    env.shutdown().await;
}

/// Shutdown makes every local member leave and closes the room: the
/// rejoin is refused, and the room is still readable afterwards, because
/// this is a shutdown and not a purge.
#[tokio::test]
async fn shutdown_evicts_members_and_blocks_rejoin() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    let bob = env.register("bob", "pw-12345678").await;
    let room = make_room(&env, &alice, "Spam").await;
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{room}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = env
        .req(
            "DELETE",
            &format!("{ADMIN_ROOMS}/{room}"),
            Some(&root),
            Some(json!({"reason": "abuse"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut kicked: Vec<&str> = body["kicked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap())
        .collect();
    kicked.sort();
    assert_eq!(kicked, ["@alice:hs.test", "@bob:hs.test"], "{body}");
    assert_eq!(body["failed"].as_array().unwrap().len(), 0, "{body}");
    assert_eq!(body["blocked"], true);

    // Closed to both of them, and to anyone else.
    for token in [&alice, &bob] {
        let (status, body) = env
            .req(
                "POST",
                &format!("/_matrix/client/v3/join/{room}"),
                Some(token),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["errcode"], "M_FORBIDDEN");
    }
    // A knock is a request to join, so it is refused by the same block.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/knock/{room}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The room itself survives: emptied and blocked, not deleted.
    let (status, body) = env
        .req("GET", &format!("{ADMIN_ROOMS}/{room}"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["local_joined_members"], 0, "{body}");
    assert_eq!(body["blocked"]["by"], "@root:hs.test");
    assert!(body["local_members"].as_array().unwrap().is_empty());
    env.shutdown().await;
}

/// A block can name a room this server has never heard of — the only way
/// to keep local users out of somewhere else — and unblocking lifts it.
#[tokio::test]
async fn a_room_we_do_not_host_can_be_blocked() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    const REMOTE: &str = "!abuse:remote.test";
    const BLOCKED: &str = "/_saltator/admin/v1/blocked_rooms";

    let (status, body) = env
        .req(
            "PUT",
            &format!("{ADMIN_ROOMS}/{REMOTE}/block"),
            Some(&root),
            Some(json!({"blocked": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = env.req("GET", BLOCKED, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["blocked_rooms"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{body}");
    assert_eq!(rows[0]["room_id"], REMOTE);
    assert_eq!(rows[0]["hosted"], false, "we do not host it: {body}");

    // It is invisible to the room list, which only knows hosted rooms —
    // which is exactly why the blocked list is its own endpoint.
    let (_, body) = env.req("GET", ADMIN_ROOMS, Some(&root), None).await;
    assert_eq!(body["rooms"].as_array().unwrap().len(), 0, "{body}");

    // Shutdown is not available for a room we do not host.
    let (status, body) = env
        .req(
            "DELETE",
            &format!("{ADMIN_ROOMS}/{REMOTE}"),
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = env
        .req(
            "PUT",
            &format!("{ADMIN_ROOMS}/{REMOTE}/block"),
            Some(&root),
            Some(json!({"blocked": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("blocked").is_none(), "{body}");
    let (_, body) = env.req("GET", BLOCKED, Some(&root), None).await;
    assert_eq!(body["blocked_rooms"].as_array().unwrap().len(), 0, "{body}");
    env.shutdown().await;
}

/// The block is enforced on the resident side too. A block that only
/// stopped our own clients would leave the room reachable through us by
/// every other server on the federation.
#[tokio::test]
async fn federated_join_into_a_blocked_room_is_refused() {
    use saltator_testsupport::MockPeer;

    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    let room = make_room(&env, &alice, "Spam").await;

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
    let make_join = format!("/_matrix/federation/v1/make_join/{room}/@remote:peer.test");

    // Open: the resident hands out a template.
    let (status, body) = peer.signed_get(&base, SERVER, &make_join).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = env
        .req(
            "PUT",
            &format!("{ADMIN_ROOMS}/{room}/block"),
            Some(&root),
            Some(json!({"blocked": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = peer.signed_get(&base, SERVER, &make_join).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
    env.shutdown().await;
}

/// The first notice builds the room and invites the user; the second
/// reuses it. A second room per notice would be the obvious bug.
#[tokio::test]
async fn server_notices_create_a_room_once_and_reuse_it() {
    let env = start_env_notices(&["@root:hs.test"], "notices").await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    const NOTICE: &str = "/_saltator/admin/v1/users/@alice:hs.test/notice";

    let (status, first) = env
        .req("POST", NOTICE, Some(&root), Some(notice("disk is full")))
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let room_id = first["room_id"].as_str().unwrap().to_owned();

    let (status, second) = env
        .req("POST", NOTICE, Some(&root), Some(notice("still full")))
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["room_id"], room_id.as_str(), "one room per user");
    assert_ne!(second["event_id"], first["event_id"]);

    // Alice sees an invite to it, from the server's own account.
    let (status, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    let invite = &sync["rooms"]["invite"][room_id.as_str()];
    assert!(!invite.is_null(), "no invite in sync: {sync}");
    let name = invite["invite_state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.room.name")
        .map(|e| e["content"]["name"].clone());
    assert_eq!(name, Some(json!("Server Notices")), "{invite}");

    // The sending account exists and is passwordless — there is no
    // credential, so nobody can log in as the server.
    let (status, detail) = env
        .req(
            "GET",
            "/_saltator/admin/v1/users/@notices:hs.test",
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(detail["has_password"], false);
    env.shutdown().await;
}

/// The notices room is a notice board, not an inbox: the recipient can
/// read it and cannot post in it.
#[tokio::test]
async fn a_user_cannot_post_in_their_notices_room() {
    let env = start_env_notices(&["@root:hs.test"], "notices").await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;

    let (_, sent) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/notice",
            Some(&root),
            Some(notice("read only")),
        )
        .await;
    let room_id = sent["room_id"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{room_id}"),
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "please stop"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    env.shutdown().await;
}

/// Leaving is always allowed, so the next notice has to put the user back
/// — otherwise it would land in a room they are not in.
#[tokio::test]
async fn leaving_a_notices_room_does_not_stop_the_next_notice() {
    let env = start_env_notices(&["@root:hs.test"], "notices").await;
    let root = env.register("root", "pw-12345678").await;
    let alice = env.register("alice", "pw-12345678").await;
    const NOTICE: &str = "/_saltator/admin/v1/users/@alice:hs.test/notice";

    let (_, sent) = env
        .req("POST", NOTICE, Some(&root), Some(notice("first")))
        .await;
    let room_id = sent["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = env
        .req("POST", NOTICE, Some(&root), Some(notice("second")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id.as_str(), "same room, re-invited");

    let (_, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert!(
        !sync["rooms"]["invite"][room_id.as_str()].is_null(),
        "expected a fresh invite: {sync}"
    );
    env.shutdown().await;
}

/// Unconfigured is a 400 that says so, not a mystery. And the reserved
/// localpart cannot be registered by a user: it is the server's voice.
#[tokio::test]
async fn notices_need_configuring_and_reserve_their_localpart() {
    let off = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = off.register("root", "pw-12345678").await;
    off.register("alice", "pw-12345678").await;
    let (status, body) = off
        .req(
            "POST",
            "/_saltator/admin/v1/users/@alice:hs.test/notice",
            Some(&root),
            Some(notice("nobody home")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("server_notices_localpart"),
        "{body}"
    );
    // With notices off nothing reserves the name, so it is registrable.
    assert!(!off.register("notices", "pw-12345678").await.is_empty());
    off.shutdown().await;

    let on = start_env_notices(&["@root:hs.test"], "notices").await;
    let (status, body) = on
        .req(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(json!({
                "username": "notices",
                "password": "pw-12345678",
                "auth": {"type": "m.login.dummy"}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_USER_IN_USE");

    let (status, body) = on
        .req(
            "GET",
            "/_matrix/client/v3/register/available?username=notices",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_USER_IN_USE");
    on.shutdown().await;
}

/// The reservation canonicalises: registration lowercases the localpart and
/// accepts the `@user:server` form, so neither a case variant nor the full
/// id may slip past and seize the server's own voice (security review
/// 2026-08-13, Vuln 1). Every form must map to the one reserved account.
#[tokio::test]
async fn reserved_notices_localpart_cannot_be_taken_by_a_case_or_full_form() {
    let env = start_env_notices(&["@root:hs.test"], "notices").await;
    for username in ["Notices", "NOTICES", "@notices:hs.test", "@Notices:hs.test"] {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(json!({
                    "username": username,
                    "password": "pw-12345678",
                    "auth": {"type": "m.login.dummy"}
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{username}: {body}");
        assert_eq!(body["errcode"], "M_USER_IN_USE", "{username}: {body}");

        let (status, body) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/register/available?username={username}"),
                None,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "avail {username}: {body}");
        assert_eq!(body["errcode"], "M_USER_IN_USE", "avail {username}: {body}");
    }
    env.shutdown().await;
}

/// A notice to an account that does not exist is a 404, not a room
/// created for nobody.
#[tokio::test]
async fn a_notice_needs_a_real_recipient() {
    let env = start_env_notices(&["@root:hs.test"], "notices").await;
    let root = env.register("root", "pw-12345678").await;
    let (status, body) = env
        .req(
            "POST",
            "/_saltator/admin/v1/users/@nobody:hs.test/notice",
            Some(&root),
            Some(notice("hello?")),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    env.shutdown().await;
}

// -- health probes --------------------------------------------------------

/// Both probes answer without a token: whatever fronts this node — a load
/// balancer, an orchestrator — has no credentials to offer.
#[tokio::test]
async fn health_probes_need_no_auth() {
    let env = start_env().await;
    for path in ["/_saltator/health/live", "/_saltator/health/ready"] {
        let (status, body) = env.req("GET", path, None, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    env.shutdown().await;
}

/// A healthy node is live and ready, with a control plane or without one.
#[tokio::test]
async fn a_healthy_node_is_live_and_ready() {
    for env in [start_env().await, start_env_cluster(&[]).await] {
        let (status, body) = env.req("GET", "/_saltator/health/live", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "ok");

        let (status, body) = env.req("GET", "/_saltator/health/ready", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "ready");
        env.shutdown().await;
    }
}

/// The probes say nothing about the cluster's shape. They are the one
/// unauthenticated surface that could enumerate it, so the body carries a
/// status and a reason and no node ids, addresses or counts.
#[tokio::test]
async fn health_bodies_do_not_leak_topology() {
    let env = start_env_cluster(&[]).await;
    let (_, body) = env.req("GET", "/_saltator/health/ready", None, None).await;
    let rendered = body.to_string();
    for leak in ["127.0.0.1", "node_id", "leader", "advertise"] {
        assert!(!rendered.contains(leak), "readiness leaked {leak}: {body}");
    }
    env.shutdown().await;
}

/// Admin-only, like the rest of the surface — and the check runs before
/// anything looks at whether a control plane exists.
#[tokio::test]
async fn cluster_endpoints_are_admin_only() {
    let env = start_env_cluster(&["@root:hs.test"]).await;
    let mallory = env.register("mallory", "pw-12345678").await;
    for (method, path) in [
        ("GET", CLUSTER_NODES.to_owned()),
        ("POST", format!("{CLUSTER_NODES}/1/drain")),
        ("POST", format!("{CLUSTER_NODES}/1/undrain")),
        ("DELETE", format!("{CLUSTER_NODES}/1")),
    ] {
        let (status, body) = env.req(method, &path, Some(&mallory), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {body}");
    }
    env.shutdown().await;
}

/// A server with no control plane says so rather than 500ing or
/// pretending the cluster is empty.
#[tokio::test]
async fn cluster_endpoints_report_a_missing_control_plane() {
    let env = start_env_admin(&["@root:hs.test"], Vec::new()).await;
    let root = env.register("root", "pw-12345678").await;
    let (status, body) = env.req("GET", CLUSTER_NODES, Some(&root), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("control plane"),
        "{body}"
    );
    env.shutdown().await;
}

/// The roster read, and the two refusals that keep an operator from
/// dismantling the cluster they are standing on.
#[tokio::test]
async fn cluster_node_list_and_drain_guards() {
    let env = start_env_cluster(&["@root:hs.test"]).await;
    let root = env.register("root", "pw-12345678").await;

    let (status, body) = env.req("GET", CLUSTER_NODES, Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["view_from"], 1);
    assert_eq!(body["leader"], 1);
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1, "{body}");
    assert_eq!(nodes[0]["node_id"], 1);
    assert_eq!(nodes[0]["status"], "active");
    assert_eq!(nodes[0]["metadata_voter"], true);
    // The founder hosts every group; the labels are readable, not raw
    // group numbers.
    let groups: Vec<&str> = nodes[0]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    assert_eq!(groups, ["Room/0", "User/0", "FedOut/0"], "{body}");

    // Draining the only node would leave the cluster nowhere to put data.
    let (status, body) = env
        .req(
            "POST",
            &format!("{CLUSTER_NODES}/1/drain"),
            Some(&root),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("last active"),
        "{body}"
    );

    // Removing the node answering the request is refused too.
    let (status, body) = env
        .req("DELETE", &format!("{CLUSTER_NODES}/1"), Some(&root), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // And a node that was never in the roster is a 404, not a silent no-op.
    for (method, path) in [
        ("POST", format!("{CLUSTER_NODES}/99/drain")),
        ("POST", format!("{CLUSTER_NODES}/99/undrain")),
        ("DELETE", format!("{CLUSTER_NODES}/99")),
    ] {
        let (status, body) = env.req(method, &path, Some(&root), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body}");
    }
    env.shutdown().await;
}

// -- admin console ----------------------
//
// Feature-gated: the console is default-off, so these run in the same CI
// job that builds with `--features admin-ui`.

#[cfg(feature = "admin-ui")]
mod admin_ui {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const UI: &str = "/_saltator/admin/ui";

    /// A raw request that keeps the response headers, which `Env::req`
    /// discards.
    async fn head(env: &Env, path: &str, origin: Option<&str>) -> (StatusCode, http::HeaderMap) {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(origin) = origin {
            builder = builder.header("Origin", origin);
        }
        let resp = env
            .router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        (resp.status(), resp.headers().clone())
    }

    /// The shell is served at the mount point and for client-side routes —
    /// including one carrying a user id, whose dots must not be mistaken
    /// for a file extension.
    #[tokio::test]
    async fn the_console_serves_its_shell_for_client_routes() {
        let env = start_env().await;
        for path in [
            UI,
            &format!("{UI}/"),
            &format!("{UI}/users"),
            &format!("{UI}/users/@alice:hs.test"),
        ] {
            let (status, headers) = head(&env, path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                headers["content-type"], "text/html; charset=utf-8",
                "{path}"
            );
        }
        // A missing bundle file is a bundle bug, not a route.
        let (status, _) = head(&env, &format!("{UI}/assets/nope.js"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        env.shutdown().await;
    }

    /// The console mounts after the CORS layer, and that placement is the
    /// whole opt-out: the permissive header exists for Matrix clients and
    /// must not land on an admin console.
    #[tokio::test]
    async fn the_console_is_not_readable_cross_origin() {
        let env = start_env().await;
        let (_, matrix) = head(&env, "/_matrix/client/versions", Some("https://evil.test")).await;
        assert_eq!(
            matrix
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap()),
            Some("*"),
            "the Matrix surface keeps its permissive CORS"
        );

        let (_, console) = head(&env, UI, Some("https://evil.test")).await;
        assert!(
            console.get("access-control-allow-origin").is_none(),
            "console answered with CORS headers: {console:?}"
        );
        env.shutdown().await;
    }

    /// This is the only HTML this server emits, so the policy that makes
    /// that safe is asserted at the router, not just in the embed crate.
    #[tokio::test]
    async fn the_console_carries_its_security_headers() {
        let env = start_env().await;
        let (_, headers) = head(&env, UI, None).await;
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        env.shutdown().await;
    }
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
