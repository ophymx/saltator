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
