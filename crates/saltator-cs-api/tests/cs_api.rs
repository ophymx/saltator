//! The M2 exit criterion, at the crate level: two users register, chat,
//! and observe each other through the real HTTP surface (router-level
//! requests; the binary-level test covers real sockets).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use saltator_cs_api::{CsConfig, CsState};
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::{spawn_membership_projection, UserServer};

const SERVER: &str = "hs.test";

struct Env {
    _dir: tempfile::TempDir,
    router: axum::Router,
    rooms: Arc<RoomServer>,
    users: Arc<UserServer>,
    projection: tokio::task::JoinHandle<()>,
}

async fn start_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server_name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (signer, _der) =
        saltator_roomserver::ServerSigner::generate(server_name.clone(), "0".to_owned());
    let rooms = RoomServer::start(
        1,
        engine.clone(),
        Arc::new(signer),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let users = UserServer::start(
        1,
        engine,
        server_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [rooms.shard_handle(), users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(users.clone(), rooms.clone());
    let media = MediaStore::open(dir.path().join("media")).unwrap();
    let state = CsState::new(
        users.clone(),
        rooms.clone(),
        media,
        CsConfig {
            server_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: Some("https://hs.test".into()),
        },
    );
    Env {
        _dir: dir,
        router: saltator_cs_api::router(state),
        rooms,
        users,
        projection,
    }
}

impl Env {
    async fn req(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        let body = match body {
            Some(v) => {
                builder = builder.header("Content-Type", "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let resp = self
            .router
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn register(&self, localpart: &str, password: &str) -> String {
        // First request: UIA challenge.
        let (status, body) = self
            .req(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(json!({"username": localpart, "password": password})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["flows"][0]["stages"][0], "m.login.dummy");
        let session = body["session"].as_str().unwrap();

        let (status, body) = self
            .req(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(json!({
                    "username": localpart,
                    "password": password,
                    "auth": {"type": "m.login.dummy", "session": session},
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["user_id"].as_str().unwrap(),
            format!("@{localpart}:{SERVER}")
        );
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// Poll /sync until `pred` matches (fresh initial sync each time).
    async fn sync_until(&self, token: &str, pred: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..100 {
            let (status, body) = self
                .req("GET", "/_matrix/client/v3/sync", Some(token), None)
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            if pred(&body) {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("sync_until: condition never matched");
    }

    async fn shutdown(self) {
        self.projection.abort();
        self.rooms.shutdown().await.unwrap();
        self.users.shutdown().await.unwrap();
    }
}

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
                "name": "M2 exit",
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
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"hello media");
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

/// /messages with a lazy_load_members filter returns the member events of
/// the chunk's senders in `state` — exactly one per distinct sender.
#[tokio::test]
async fn messages_lazy_loads_member_state() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let charlie = env.register("charlie", "charlie-pw").await;

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
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&charlie),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let before = sync["next_batch"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/ll1"),
            Some(&charlie),
            Some(json!({"msgtype": "m.text", "body": "test"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sync) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={before}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    let after = sync["next_batch"].as_str().unwrap().to_owned();

    // {"lazy_load_members": true}, percent-encoded.
    let filter = "%7B%22lazy_load_members%22%3Atrue%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={before}&to={after}&filter={filter}"
            ),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let state = got["state"]
        .as_array()
        .unwrap_or_else(|| panic!("state array present: {got}"));
    assert_eq!(state.len(), 1, "one member event expected: {got}");
    assert_eq!(state[0]["type"], "m.room.member");
    assert_eq!(state[0]["state_key"], format!("@charlie:{SERVER}"));
    assert_eq!(state[0]["content"]["membership"], "join");

    env.shutdown().await;
}

/// Sync filters shape the response: timeline/state `types` narrow events,
/// `limit: 0` empties the timeline and moves pre-leave state (including
/// the leave itself) into `state.events`, and `timeline.limited` is always
/// present in the serialized JSON even when false.
#[tokio::test]
async fn sync_filters_shape_timeline_and_leave_state() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

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
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, bob_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let bob_since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "before"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/a.madeup.test.state/"),
            Some(&alice),
            Some(json!({"my_key": "before"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Life moves on without bob.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f2"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "after"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/a.madeup.test.state/"),
            Some(&alice),
            Some(json!({"my_key": "after"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let make_filter = |user: String, token: String, def: serde_json::Value| {
        let env = &env;
        async move {
            let (status, body) = env
                .req(
                    "POST",
                    &format!("/_matrix/client/v3/user/@{user}:{SERVER}/filter"),
                    Some(&token),
                    Some(def),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["filter_id"].as_str().unwrap().to_owned()
        }
    };

    // Types-filtered leave section (the ArchivedRoomsHistory shape).
    let typed = make_filter(
        "bob".into(),
        bob.clone(),
        json!({"room": {
            "timeline": {"types": ["m.room.message", "a.madeup.test.state"]},
            "state": {"types": ["a.madeup.test.state"]},
            "include_leave": true,
        }}),
    )
    .await;
    for since in [None, Some(&bob_since)] {
        let url = match since {
            None => format!("/_matrix/client/v3/sync?filter={typed}"),
            Some(s) => format!("/_matrix/client/v3/sync?filter={typed}&since={s}&timeout=0"),
        };
        let (status, resp) = env.req("GET", &url, Some(&bob), None).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let left = &resp["rooms"]["leave"][&room_id];
        let timeline: Vec<(&str, &str)> = left["timeline"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["type"].as_str().unwrap(),
                    e["content"]["body"]
                        .as_str()
                        .or(e["content"]["my_key"].as_str())
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(
            timeline,
            vec![
                ("m.room.message", "before"),
                ("a.madeup.test.state", "before")
            ],
            "since={since:?}: {left}"
        );
        assert!(
            left["state"]["events"]
                .as_array()
                .unwrap_or(&vec![])
                .is_empty(),
            "state should be empty: {left}"
        );
    }

    // limit 0: empty timeline, pre-leave state (incl. the leave) in state.
    let empty_tl = make_filter(
        "bob".into(),
        bob.clone(),
        json!({"room": {"timeline": {"limit": 0}, "include_leave": true}}),
    )
    .await;
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={empty_tl}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let left = &resp["rooms"]["leave"][&room_id];
    assert!(
        left["timeline"]["events"]
            .as_array()
            .unwrap_or(&vec![])
            .is_empty(),
        "timeline should be empty: {left}"
    );
    let state_events = left["state"]["events"].as_array().unwrap();
    let bob_membership = state_events
        .iter()
        .find(|e| e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}"))
        .expect("bob's leave in state");
    assert_eq!(bob_membership["content"]["membership"], "leave");
    let madeup = state_events
        .iter()
        .find(|e| e["type"] == "a.madeup.test.state")
        .expect("madeup state present");
    assert_eq!(
        madeup["content"]["my_key"], "before",
        "post-leave state leaked: {left}"
    );

    // Joined rooms: types narrow the timeline and `limited` always
    // serializes (checkJoinFieldsExist requires the key even when false).
    let msgs_only = make_filter(
        "alice".into(),
        alice.clone(),
        json!({"room": {"timeline": {"limit": 10, "types": ["m.room.message"]}}}),
    )
    .await;
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={msgs_only}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let timeline = &resp["rooms"]["join"][&room_id]["timeline"];
    assert!(
        timeline["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["type"] == "m.room.message"),
        "non-message events in typed timeline: {timeline}"
    );
    assert!(
        timeline.as_object().unwrap().contains_key("limited"),
        "limited key missing: {timeline}"
    );
    // Unfiltered sync also serializes `limited` (false) explicitly.
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let timeline = &resp["rooms"]["join"][&room_id]["timeline"];
    assert!(
        timeline.as_object().unwrap().contains_key("limited"),
        "limited key missing on unfiltered sync: {timeline}"
    );

    env.shutdown().await;
}

/// Departed members read the room frozen at their leave — state, members,
/// and history cap there; include_leave surfaces old leaves on initial
/// sync; /members?at= resolves a historical snapshot.
#[tokio::test]
async fn departed_room_reads_frozen_at_leave() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let carol = env.register("carol", "carol-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat", "name": "N1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // Snapshot token before bob joins, for /members?at=.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let pre_bob = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (txn, msg) in [("d1", "M1"), ("d2", "M2")] {
        let (status, body) = env
            .req(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
                Some(&alice),
                Some(json!({"msgtype": "m.text", "body": msg})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, bob_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let bob_since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    // Life moves on without bob.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.name/"),
            Some(&alice),
            Some(json!({"name": "N2"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/d3"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "M3"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // State: bob sees the world as he left it; alice sees the present.
    let name_url = format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.name/");
    let (status, got) = env.req("GET", &name_url, Some(&bob), None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "N1", "departed view leaked new state: {got}");
    let (_, got) = env.req("GET", &name_url, Some(&alice), None).await;
    assert_eq!(got["name"], "N2");

    // Members: alice + bob's leave; carol (post-leave) invisible to bob.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let members: Vec<(&str, &str)> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["state_key"].as_str().unwrap(),
                e["content"]["membership"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(members.contains(&(&format!("@alice:{SERVER}") as &str, "join")));
    assert!(members.contains(&(&format!("@bob:{SERVER}") as &str, "leave")));
    assert!(
        !members.iter().any(|(u, _)| u.contains("carol")),
        "post-leave joiner visible to departed member: {got}"
    );

    // History: backward reads end at bob's leave; forward reads are empty.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=3&from={bob_since}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let bodies: Vec<String> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["content"]["body"].as_str().map(str::to_owned))
        .collect();
    assert!(bodies.contains(&"M1".to_owned()) && bodies.contains(&"M2".to_owned()));
    assert!(!bodies.contains(&"M3".to_owned()), "{got}");
    assert!(
        got["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}")),
        "own leave event missing from departed history: {got}"
    );
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={bob_since}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        got["chunk"].as_array().unwrap().is_empty(),
        "forward pagination crossed the leave: {got}"
    );

    // ?at=: members as of the pre-bob snapshot — only alice.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members?at={pre_bob}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let at_members: Vec<&str> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["state_key"].as_str().unwrap())
        .collect();
    assert_eq!(at_members, vec![format!("@alice:{SERVER}")], "{got}");

    // include_leave: bob's initial sync surfaces the room in `leave`,
    // with a timeline that never crosses his departure.
    let filter = "%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let left = &got["rooms"]["leave"][&room_id];
    assert!(
        !left.is_null(),
        "left room missing with include_leave: {got}"
    );
    let leave_bodies: Vec<&str> = left["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["content"]["body"].as_str())
        .collect();
    assert!(
        !leave_bodies.contains(&"M3"),
        "leave timeline crossed departure: {got}"
    );

    env.shutdown().await;
}

/// Forgetting a room revokes the departed-member residual access: history
/// reads 403 (even with malformed queries), fresh include_leave syncs drop
/// the room, but the leave still rides incremental syncs so other devices
/// learn of it. Rejoining clears the flag.
#[tokio::test]
async fn forget_revokes_departed_access() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

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

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Token from before the leave, for the incremental-sync assertion.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let pre_leave = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/forget"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // History reads 403 — including a /messages with no dir param at all:
    // access is judged before query validation.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{got}");
    assert_eq!(got["errcode"], "M_FORBIDDEN", "{got}");
    for path in ["state", "members"] {
        let (status, got) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room_id}/{path}"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "forgotten /{path}: {got}");
    }

    // Fresh include_leave sync: the forgotten room is gone.
    let filter = "%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        got["rooms"]["leave"][&room_id].is_null(),
        "forgotten room in initial include_leave sync: {got}"
    );

    // Incremental sync spanning the leave still reports it (other devices
    // must be able to observe the departure).
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={pre_leave}&filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        !got["rooms"]["leave"][&room_id].is_null(),
        "leave hidden from incremental sync after forget: {got}"
    );

    // Rejoining clears the flag: reads work again.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rejoin did not restore reads: {got}"
    );

    env.shutdown().await;
}

/// /members?at= with a sync prev_batch token resolves to the room position
/// the sync was minted at — not the timeline-window start the token also
/// anchors for /messages pagination.
#[tokio::test]
async fn members_at_prev_batch_snapshots_mint_position() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

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
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/p1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Hello world!"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Initial sync covers the room's whole history; its prev_batch must
    // still snapshot members as of sync time.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let prev_batch = sync0["rooms"]["join"][&room_id]["timeline"]["prev_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members?at={prev_batch}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let at_members: Vec<&str> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["state_key"].as_str().unwrap())
        .collect();
    assert_eq!(
        at_members,
        vec![format!("@alice:{SERVER}")],
        "prev_batch ?at= should see alice but not the later joiner: {got}"
    );

    env.shutdown().await;
}

/// Key-upload validation, query shape rules, and MSC4225 claim ordering.
#[tokio::test]
async fn key_upload_validation_and_claim_ordering() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let (_, whoami) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    let dev = whoami["device_id"].as_str().unwrap().to_owned();

    // Incomplete identity keys are rejected...
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"device_keys": {"user_id": format!("@alice:{SERVER}"), "device_id": dev}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_JSON");
    // ...as are someone else's.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"device_keys": {
                "user_id": format!("@mallory:{SERVER}"), "device_id": dev,
                "algorithms": [], "keys": {}, "signatures": {},
            }})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Malformed query shape (object instead of device list) is rejected.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&alice),
            Some(json!({"device_keys": {format!("@alice:{SERVER}"): {"device_id": dev}}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Claims come back in upload order (MSC4225), not key-ID order: key
    // "…:1" is uploaded before "…:0" in a separate request.
    for key_id in ["signed_curve25519:1", "signed_curve25519:0"] {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/upload",
                Some(&alice),
                Some(json!({"one_time_keys": {key_id: {"key": key_id}}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let claim = json!({"one_time_keys": {format!("@alice:{SERVER}"): {&dev: "signed_curve25519"}}});
    let mut claimed = Vec::new();
    for _ in 0..2 {
        let (status, resp) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/claim",
                Some(&alice),
                Some(claim.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let keys = resp["one_time_keys"][&format!("@alice:{SERVER}")][&dev]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        claimed.extend(keys);
    }
    assert_eq!(
        claimed,
        vec!["signed_curve25519:1", "signed_curve25519:0"],
        "claims not in upload order"
    );

    env.shutdown().await;
}

/// Kicking a non-present user is forbidden; identical state and repeated
/// joins are idempotent (no duplicate events).
#[tokio::test]
async fn kick_guards_and_idempotent_writes() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (_, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // Kick of a never-present user: 403.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/kick"),
            Some(&alice),
            Some(json!({"user_id": format!("@bob:{SERVER}"), "reason": "testing"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bob joins twice: the member event ID must not change.
    for _ in 0..2 {
        let (status, body) = env
            .req(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room_id}/join"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let member_url = format!(
        "/_matrix/client/v3/rooms/{room_id}/state/m.room.member/@bob:{SERVER}?format=event"
    );
    let (_, first) = env.req("GET", &member_url, Some(&bob), None).await;
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, second) = env.req("GET", &member_url, Some(&bob), None).await;
    assert_eq!(
        first["event_id"], second["event_id"],
        "re-join minted a new member event"
    );

    // Kick of a left user: 403.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/kick"),
            Some(&alice),
            Some(json!({"user_id": format!("@bob:{SERVER}"), "reason": "testing"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Identical state twice returns the same event ID.
    let put_state = |content: Value| {
        let env = &env;
        let alice = &alice;
        let room_id = &room_id;
        async move {
            let (status, body) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room_id}/state/a.test.state/key"),
                    Some(alice),
                    Some(content),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["event_id"].as_str().unwrap().to_owned()
        }
    };
    let e1 = put_state(json!({"v": 1})).await;
    let e2 = put_state(json!({"v": 1})).await;
    assert_eq!(e1, e2, "identical state minted a new event");
    let e3 = put_state(json!({"v": 2})).await;
    assert_ne!(e1, e3, "changed state did not mint a new event");

    env.shutdown().await;
}

/// `/messages` accepts sync tokens as pagination bounds (clients feed
/// next_batch straight in) and answers 403, not 404, for unknown rooms.
#[tokio::test]
async fn messages_accept_sync_tokens_and_hide_unknown_rooms() {
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
    let (status, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let token = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/m1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "after the token"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Forward from the sync token: exactly the new message.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={token}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let chunk = resp["chunk"].as_array().unwrap();
    assert!(
        chunk
            .iter()
            .any(|e| e["content"]["body"] == "after the token"),
        "message missing from sync-token window: {resp}"
    );

    // Unknown room: forbidden, not an existence oracle.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/!nope:{SERVER}/messages?dir=b"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");

    env.shutdown().await;
}

/// E2EE key backup: version lifecycle, the replace rules (verified wins,
/// then lower first_message_index, then lower forwarded_count), stale
/// version refusal, and per-granularity reads.
#[tokio::test]
async fn e2ee_key_backup_lifecycle_and_replace_rules() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    // No backup yet.
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            Some(json!({"algorithm": "m.megolm_backup.v1", "auth_data": {"foo": "bar"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v1 = body["version"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], v1);
    assert_eq!(body["auth_data"]["foo"], "bar");
    assert_eq!(body["count"], 0);

    // Upload a key, then confirm worse keys never replace it.
    let key = |first: i64, fwd: i64, verified: bool| {
        json!({
            "first_message_index": first, "forwarded_count": fwd,
            "is_verified": verified, "session_data": {"a": "b"},
        })
    };
    let url = format!("/_matrix/client/v3/room_keys/keys/!foo:example.com/sessA?version={v1}");
    let (status, body) = env
        .req("PUT", &url, Some(&alice), Some(key(10, 5, false)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], 1);
    for worse in [key(11, 5, false), key(10, 6, false), key(11, 6, false)] {
        let (status, body) = env.req("PUT", &url, Some(&alice), Some(worse)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, got) = env.req("GET", &url, Some(&alice), None).await;
        assert_eq!(got["first_message_index"], 10, "worse key replaced: {got}");
        assert_eq!(got["forwarded_count"], 5);
        assert_eq!(got["is_verified"], false);
    }
    // A verified key beats an unverified one regardless of indices.
    env.req("PUT", &url, Some(&alice), Some(key(12, 9, true)))
        .await;
    let (_, got) = env.req("GET", &url, Some(&alice), None).await;
    assert_eq!(got["is_verified"], true, "{got}");
    assert_eq!(got["first_message_index"], 12);

    // A newer version exists: writes to the old one are refused and name
    // the current version.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            Some(json!({"algorithm": "m.megolm_backup.v1", "auth_data": {"v": 2}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v2 = body["version"].as_str().unwrap().to_owned();
    assert_ne!(v1, v2);
    let (status, body) = env
        .req("PUT", &url, Some(&alice), Some(key(0, 0, false)))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_WRONG_ROOM_KEYS_VERSION");
    assert_eq!(body["current_version"], v2);

    // The old version's keys stay readable in bulk shape until deletion
    // tombstones it; the latest pointer then still names v2.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/room_keys/keys?version={v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["rooms"]["!foo:example.com"]["sessions"]["sessA"]["is_verified"],
        true
    );
    let (status, _) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/room_keys/version/{v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/room_keys/version/{v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(body["version"], v2, "{body}");

    env.shutdown().await;
}

/// Room upgrade to an older version (v9): the replacement carries a
/// predecessor pointer and migrated state, the old room gets tombstoned,
/// and search spans both rooms (the Complement search-across-upgrade
/// shape).
#[tokio::test]
async fn room_upgrade_to_v9_and_search_across() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "private_chat", "name": "Old Room"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/up1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Message before upgrade"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, resp) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/upgrade"),
            Some(&alice),
            Some(json!({"new_version": "9"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let new_room_id = resp["replacement_room"].as_str().unwrap().to_owned();

    // The replacement is a v9 room pointing back at the predecessor, with
    // the transferable state migrated.
    let (status, create) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/state/m.room.create"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{create}");
    assert_eq!(create["room_version"], "9");
    assert_eq!(create["creator"], format!("@alice:{SERVER}"));
    assert_eq!(create["predecessor"]["room_id"], room_id);
    let (status, name) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/state/m.room.name"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{name}");
    assert_eq!(name["name"], "Old Room");

    // The old room is tombstoned toward the replacement.
    let (status, tomb) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.tombstone"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tomb}");
    assert_eq!(tomb["replacement_room"], new_room_id);

    // Life continues in the v9 room, and search spans both.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/send/m.room.message/up2"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Message after upgrade"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, results) = env
        .req(
            "POST",
            "/_matrix/client/v3/search",
            Some(&alice),
            Some(json!({
                "search_categories": {"room_events": {
                    "keys": ["content.body"],
                    "search_term": "upgrade",
                }}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{results}");
    assert_eq!(
        results["search_categories"]["room_events"]["count"], 2,
        "search should span predecessor and replacement: {results}"
    );

    env.shutdown().await;
}

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

    // Public room; v12 power-level override listing the creator must be
    // sanitized (MSC4289), not rejected.
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
                "power_level_content_override":
                    {"users": {format!("@alice:{SERVER}"): 100}, "users_default": 0},
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

// --- Remote join (the M3 exit criterion, crate level) --------------------

use saltator_federation::{FedState, FederationClient, KeyCache, OldVerifyKey};

/// Stand up a bare federation HTTP server for `server_name` over `rooms`,
/// authenticating callers against `caller_keys_base`. Returns its base URL.
async fn spawn_fed(
    server_name: &str,
    signer: Arc<saltator_roomserver::ServerSigner>,
    rooms: Option<Arc<RoomServer>>,
    caller_keys_base: Option<String>,
) -> String {
    let name = ruma::OwnedServerName::try_from(server_name).unwrap();
    let key_cache = match caller_keys_base {
        Some(base) => KeyCache::with_base_url(base),
        None => KeyCache::new(),
    };
    let mut state = FedState {
        server_name: name,
        signer,
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache,
        rooms: None,
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    };
    if let Some(r) = rooms {
        state = state.with_rooms(r);
    }
    let app = saltator_federation::router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn start_fed_rooms(
    server_name: &str,
    dir: &std::path::Path,
) -> (Arc<RoomServer>, Arc<saltator_roomserver::ServerSigner>) {
    let engine = Arc::new(RocksEngine::open(&dir.join(server_name)).unwrap());
    let name = ruma::OwnedServerName::try_from(server_name).unwrap();
    let (signer, _) = saltator_roomserver::ServerSigner::generate(name.clone(), "1".to_owned());
    let signer = Arc::new(signer);
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
    (rooms, signer)
}

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
    let projection = spawn_membership_projection(b_users.clone(), b_rooms.clone());

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
        b_rooms.clone(),
        media,
        CsConfig {
            server_name: b_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(b_signer.clone(), a_base)),
        b_signer.clone(),
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
    let projection = spawn_membership_projection(b_users.clone(), b_rooms.clone());

    // B's CS router (for registration + /sync).
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        b_rooms.clone(),
        media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    );
    let cs_router = saltator_cs_api::router(cs_state);

    // B's federation surface: authenticates A, records invites into b_users.
    let b_fed = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::with_base_url(a_key_base),
        rooms: Some(b_rooms.clone()),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
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

// --- Outbound federated invite (full round-trip) -------------------------

async fn cs_stack(
    server: &str,
    dir: &std::path::Path,
    fed_client_base: Option<String>,
) -> (
    Arc<RoomServer>,
    Arc<UserServer>,
    Arc<saltator_roomserver::ServerSigner>,
    axum::Router,
    tokio::task::JoinHandle<()>,
) {
    let engine = Arc::new(RocksEngine::open(&dir.join(server)).unwrap());
    let name = ruma::OwnedServerName::try_from(server).unwrap();
    let (signer, _) = saltator_roomserver::ServerSigner::generate(name.clone(), "1".to_owned());
    let signer = Arc::new(signer);
    let rooms = RoomServer::start(
        1,
        engine.clone(),
        signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let users = UserServer::start(
        1,
        engine,
        name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [rooms.shard_handle(), users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let projection = spawn_membership_projection(users.clone(), rooms.clone());
    let media = MediaStore::open(dir.join(format!("{server}-media"))).unwrap();
    let mut cs = CsState::new(
        users.clone(),
        rooms.clone(),
        media,
        CsConfig {
            server_name: name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    );
    if let Some(base) = fed_client_base {
        cs = cs.with_federation(
            Arc::new(FederationClient::with_base_url(signer.clone(), base)),
            signer.clone(),
        );
    }
    let router = saltator_cs_api::router(cs);
    (rooms, users, signer, router, projection)
}

async fn oneshot(
    router: &axum::Router,
    method: &'static str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    let bd = match body {
        Some(v) => {
            b = b.header("Content-Type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let resp = router.clone().oneshot(b.body(bd).unwrap()).await.unwrap();
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

async fn reg(router: &axum::Router, user: &str) -> String {
    let (_s, ch) = oneshot(
        router,
        "POST",
        "/_matrix/client/v3/register",
        None,
        Some(json!({"username":user,"password":"pw-12345678"})),
    )
    .await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let (_s, r) = oneshot(router, "POST", "/_matrix/client/v3/register", None, Some(json!({"username":user,"password":"pw-12345678","auth":{"type":"m.login.dummy","session":session}}))).await;
    r["access_token"].as_str().unwrap().to_owned()
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
        key_cache: KeyCache::with_base_url(a_key_base),
        rooms: Some(b_rooms.clone()),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
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
    let a_proj = spawn_membership_projection(a_users.clone(), a_rooms.clone());
    let a_media = MediaStore::open(dir.path().join("a-media")).unwrap();
    let a_cs = CsState::new(
        a_users.clone(),
        a_rooms.clone(),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base,
        )),
        a_signer.clone(),
    );
    let a_router = saltator_cs_api::router(a_cs);

    // bob registers on B.
    let bob = reg(&b_router, "bob").await;

    // alice registers on A, creates a room, and invites @bob:b.test.
    let alice = reg(&a_router, "alice").await;
    let (status, room) = oneshot(
        &a_router,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&alice),
        Some(json!({"preset":"private_chat"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc: String = room_id
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let (status, body) = oneshot(
        &a_router,
        "POST",
        &format!("/_matrix/client/v3/rooms/{enc}/invite"),
        Some(&alice),
        Some(json!({"user_id":"@bob:b.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "invite failed: {body}");

    // bob on B sees the invite.
    let (status, sync) = oneshot(
        &b_router,
        "GET",
        "/_matrix/client/v3/sync",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        sync["rooms"]["invite"].get(&room_id).is_some(),
        "invite missing from bob's sync: {sync}"
    );

    a_proj.abort();
    b_proj.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
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
        key_cache: KeyCache::with_base_url(a_key_base),
        rooms: Some(b_rooms.clone()),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
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
        a_rooms.clone(),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base,
        )),
        a_signer.clone(),
    );
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

    b_proj.abort();
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
        key_cache: KeyCache::with_base_url(a_key_base),
        rooms: Some(b_rooms.clone()),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
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
        a_rooms.clone(),
        a_media,
        CsConfig {
            server_name: a_name,
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(
            a_signer.clone(),
            b_fed_base.clone(),
        )),
        a_signer.clone(),
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
    let projection = spawn_membership_projection(b_users.clone(), b_rooms.clone());
    let media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        b_rooms.clone(),
        media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
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
        key_cache: KeyCache::with_base_url(a_key_base),
        rooms: Some(b_rooms.clone()),
        users: Some(b_users.clone()),
        client: None,
        edu_sink: Some(sink),
        media: None,
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

// --- Remote media fetch over federation ----------------------------------

#[tokio::test]
async fn client_downloads_remote_media_over_federation() {
    let dir = tempfile::tempdir().unwrap();

    // Node A: hosts media + serves it over federation. Needs a user shard
    // (media metadata) + media store + signer/key server.
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_dir = dir.path().join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    let a_engine = Arc::new(RocksEngine::open(&a_dir.join("db")).unwrap());
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
    let a_media = MediaStore::open(a_dir.join("media")).unwrap();

    // Store a real 64x64 PNG on A (so it can be thumbnailed).
    let png = {
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([0, 128, 255]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        buf
    };
    let png = png.as_slice();
    let media_id = a_media.store(png).await.unwrap();
    a_users
        .put_media(
            &media_id,
            saltator_userserver::MediaMeta {
                owner: "@alice:a.test".to_owned(),
                content_type: Some("image/png".to_owned()),
                filename: Some("test.png".to_owned()),
                size: png.len() as u64,
                created_ts: 0,
                pending: false,
            },
        )
        .await
        .unwrap();

    // A's federation endpoint: key server + media download.
    let a_fed = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::new(),
        rooms: Some(a_rooms.clone()),
        users: Some(a_users.clone()),
        client: None,
        edu_sink: None,
        media: Some(a_media.clone()),
    });

    // Node B: full CS stack, federation client aimed at A.
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    // B's key server so A can authenticate B's media request.
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    // A authenticates B against B's keys.
    let a_fed = Arc::new(FedState {
        key_cache: KeyCache::with_base_url(b_key_base),
        ..Arc::try_unwrap(a_fed).ok().unwrap()
    });
    let a_base = {
        let app = saltator_federation::router(a_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_rooms = RoomServer::start(
        1,
        b_engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        b_engine,
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
    let b_projection = spawn_membership_projection(b_users.clone(), b_rooms.clone());
    let b_media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        b_rooms.clone(),
        b_media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(b_signer.clone(), a_base)),
        b_signer.clone(),
    );
    let router = saltator_cs_api::router(cs_state);

    // Register bob on B, then download A's media over federation.
    let http = |method: &'static str, path: String, token: Option<String>| {
        let router = router.clone();
        async move {
            let mut rb = axum::http::Request::builder().method(method).uri(path);
            if let Some(t) = token {
                rb = rb.header("Authorization", format!("Bearer {t}"));
            }
            let resp =
                tower::ServiceExt::oneshot(router, rb.body(axum::body::Body::empty()).unwrap())
                    .await
                    .unwrap();
            let st = resp.status();
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let by = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (st, ct, by)
        }
    };
    let reg_body = |u: &str, s: Option<&str>| {
        let mut m = serde_json::Map::new();
        m.insert("username".into(), json!(u));
        m.insert("password".into(), json!("pw-12345678"));
        if let Some(s) = s {
            m.insert("auth".into(), json!({"type":"m.login.dummy","session":s}));
        }
        Value::Object(m)
    };
    let post = |path: String, body: Value| {
        let router = router.clone();
        async move {
            let rb = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("Content-Type", "application/json");
            let resp = tower::ServiceExt::oneshot(
                router,
                rb.body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
            let by = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<Value>(&by).unwrap_or(Value::Null)
        }
    };
    let ch = post("/_matrix/client/v3/register".into(), reg_body("bob", None)).await;
    let session = ch["session"].as_str().unwrap().to_owned();
    let reg = post(
        "/_matrix/client/v3/register".into(),
        reg_body("bob", Some(&session)),
    )
    .await;
    let bob = reg["access_token"].as_str().unwrap().to_owned();

    let (status, ct, body) = http(
        "GET",
        format!("/_matrix/client/v1/media/download/a.test/{media_id}"),
        Some(bob.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remote media download");
    assert_eq!(body, png, "downloaded bytes match A's media");
    assert_eq!(ct.as_deref(), Some("image/png"), "content-type preserved");

    // A thumbnail of the same remote media: fetched over federation and
    // scaled locally to a valid 32x32 PNG.
    let (status, ct, body) = http(
        "GET",
        format!(
            "/_matrix/client/v1/media/thumbnail/a.test/{media_id}?width=32&height=32&method=scale"
        ),
        Some(bob),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remote thumbnail");
    assert_eq!(ct.as_deref(), Some("image/png"));
    let thumb = image::load_from_memory(&body).expect("thumbnail is a valid image");
    assert!(
        thumb.width() <= 32 && thumb.height() <= 32,
        "thumbnail scaled down"
    );

    b_projection.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}

// --- Federation profile & directory queries ------------------------------

#[tokio::test]
async fn client_queries_remote_profile_and_directory() {
    let dir = tempfile::tempdir().unwrap();

    // Node A: user shard with alice (displayname) + an alias, served over
    // federation.
    let a_name = ruma::OwnedServerName::try_from("a.test").unwrap();
    let (a_signer, _) = saltator_roomserver::ServerSigner::generate(a_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let a_dir = dir.path().join("a");
    std::fs::create_dir_all(&a_dir).unwrap();
    let a_engine = Arc::new(RocksEngine::open(&a_dir.join("db")).unwrap());
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
    let alice = a_users
        .register("alice", Some("pw-12345678"), None, None, false, true)
        .await
        .unwrap()
        .0;
    a_users
        .set_profile(&alice, Some(Some("Alice A".to_owned())), None)
        .await
        .unwrap();
    a_users
        .create_alias("#lounge:a.test", "!room123:a.test", &alice)
        .await
        .unwrap();

    let a_fed = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: KeyCache::new(),
        rooms: Some(a_rooms.clone()),
        users: Some(a_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
    });

    // B key server so A can authenticate B's queries.
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    let a_fed = Arc::new(FedState {
        key_cache: KeyCache::with_base_url(b_key_base),
        ..Arc::try_unwrap(a_fed).ok().unwrap()
    });
    let a_base = {
        let app = saltator_federation::router(a_fed);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        format!("http://{addr}")
    };

    // Node B: full CS stack, federation client aimed at A.
    let b_dir = dir.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b_engine = Arc::new(RocksEngine::open(&b_dir.join("db")).unwrap());
    let b_rooms = RoomServer::start(
        1,
        b_engine.clone(),
        b_signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let b_users = UserServer::start(
        1,
        b_engine,
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
    let b_projection = spawn_membership_projection(b_users.clone(), b_rooms.clone());
    let b_media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        b_rooms.clone(),
        b_media,
        CsConfig {
            server_name: b_name.clone(),
            default_room_version: saltator_core::RoomVersion::V11,
            registration_enabled: true,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
        },
    )
    .with_federation(
        Arc::new(FederationClient::with_base_url(b_signer.clone(), a_base)),
        b_signer.clone(),
    );
    let router = saltator_cs_api::router(cs_state);

    let get = |path: String| {
        let router = router.clone();
        async move {
            let rb = axum::http::Request::builder().method("GET").uri(path);
            let resp =
                tower::ServiceExt::oneshot(router, rb.body(axum::body::Body::empty()).unwrap())
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
                    serde_json::from_slice::<Value>(&by).unwrap_or(Value::Null)
                },
            )
        }
    };

    // Remote profile query (no auth required on the CS profile endpoint).
    let (status, prof) = get("/_matrix/client/v3/profile/@alice:a.test".into()).await;
    assert_eq!(status, StatusCode::OK, "remote profile: {prof}");
    assert_eq!(prof["displayname"], "Alice A");

    // Remote alias resolution.
    let (status, dir_resp) = get("/_matrix/client/v3/directory/room/%23lounge:a.test".into()).await;
    assert_eq!(status, StatusCode::OK, "remote alias: {dir_resp}");
    assert_eq!(dir_resp["room_id"], "!room123:a.test");
    assert!(dir_resp["servers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "a.test"));

    b_projection.abort();
    a_rooms.shutdown().await.unwrap();
    a_users.shutdown().await.unwrap();
    b_rooms.shutdown().await.unwrap();
    b_users.shutdown().await.unwrap();
}
