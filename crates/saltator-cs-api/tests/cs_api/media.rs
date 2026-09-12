//! The M2 exit criterion, at the crate level: two users register, chat,
//! and observe each other through the real HTTP surface (router-level
//! requests; the binary-level test covers real sockets).
use axum::http::StatusCode;
use saltator_cs_api::{CsConfig, CsState};
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::{spawn_membership_projection, UserServer};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
// --- Remote join (the M3 exit criterion, crate level) --------------------
use saltator_federation::{FedState, FederationClient, KeyCache};

use crate::harness::*;

/// Fallback keys (spec 1.2): served by /keys/claim once one-time keys
/// run dry, kept (not deleted) and marked used; sync advertises the
/// unused algorithms; a rotated key resets the flag.
#[tokio::test]
async fn fallback_keys_serve_after_otk_exhaustion() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let user = format!("@alice:{SERVER}");

    // A device identity, one OTK, and a fallback key.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({
                "device_keys": {
                    "user_id": user, "device_id": device_of(&env, &alice).await,
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                    "keys": {}, "signatures": {},
                },
                "one_time_keys": {"signed_curve25519:OTK1": {"key": "otk"}},
                "fallback_keys": {"signed_curve25519:FALL1": {"key": "fall1"}},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = device_of(&env, &alice).await;

    // Sync advertises the unused fallback algorithm.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync0["device_unused_fallback_key_types"],
        json!(["signed_curve25519"]),
        "{sync0}"
    );

    async fn claim(env: &Env, token: String, user: String, device: String) -> String {
        let (status, got) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/claim",
                Some(&token),
                Some(json!({"one_time_keys": {&user: {&device: "signed_curve25519"}}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{got}");
        got["one_time_keys"][&user][&device]
            .as_object()
            .and_then(|m| m.keys().next().cloned())
            .unwrap_or_default()
    }

    // First claim eats the OTK; the next two serve the SAME fallback.
    let k1 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(k1, "signed_curve25519:OTK1");
    let k2 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(k2, "signed_curve25519:FALL1");
    let k3 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(
        k3, "signed_curve25519:FALL1",
        "fallback must not be deleted"
    );

    // Used now — gone from the unused list until a new key rotates in.
    let (_, sync1) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync1["device_unused_fallback_key_types"],
        json!([]),
        "{sync1}"
    );
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"fallback_keys": {"signed_curve25519:FALL2": {"key": "fall2"}}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sync2) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync2["device_unused_fallback_key_types"],
        json!(["signed_curve25519"]),
        "{sync2}"
    );
    let k4 = claim(&env, alice, user, device).await;
    assert_eq!(k4, "signed_curve25519:FALL2");

    env.shutdown().await;
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
                blob: None,
            },
        )
        .await
        .unwrap();

    // A's federation endpoint: key server + media download.
    let a_fed = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::new()),
        rooms: Some(saltator_roomserver::RoomShards::single(a_rooms.clone())),
        users: Some(a_users.clone()),
        client: None,
        edu_sink: None,
        media: Some(a_media.clone()),
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });

    // Node B: full CS stack, federation client aimed at A.
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    // B's key server so A can authenticate B's media request.
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    // A authenticates B against B's keys.
    let a_fed = Arc::new(FedState {
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
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
    let b_projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );
    let b_media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        b_media,
        CsConfig {
            server_name: b_name.clone(),
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
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base)),
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
        key_cache: std::sync::Arc::new(KeyCache::new()),
        rooms: Some(saltator_roomserver::RoomShards::single(a_rooms.clone())),
        users: Some(a_users.clone()),
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    });

    // B key server so A can authenticate B's queries.
    let b_name = ruma::OwnedServerName::try_from("b.test").unwrap();
    let (b_signer, _) = saltator_roomserver::ServerSigner::generate(b_name.clone(), "1".to_owned());
    let b_signer = Arc::new(b_signer);
    let b_key_base = spawn_fed("b.test", b_signer.clone(), None, None).await;
    let a_fed = Arc::new(FedState {
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
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
    let b_projection = spawn_membership_projection(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
    );
    let b_media = MediaStore::open(b_dir.join("media")).unwrap();
    let cs_state = CsState::new(
        b_users.clone(),
        saltator_roomserver::RoomShards::single(b_rooms.clone()),
        b_media,
        CsConfig {
            server_name: b_name.clone(),
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
            b_signer.clone(),
            a_base.clone(),
        )),
        b_signer.clone(),
        Arc::new(KeyCache::with_base_url(a_base)),
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
