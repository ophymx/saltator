//! Shared harness: the Env fixture, environment constructors, and
//! every helper the topic modules use (all pub — imported via
//! `use crate::harness::*`).
use axum::body::Body;
use axum::http::{Request, StatusCode};
use saltator_cs_api::{AppServiceRegistration, CsConfig, CsState};
use saltator_federation::{FedState, FederationClient, KeyCache, OldVerifyKey};
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::{spawn_membership_projection, UserServer};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

pub const SERVER: &str = "hs.test";

pub struct Env {
    pub _dir: tempfile::TempDir,
    pub router: axum::Router,
    pub rooms: Arc<saltator_roomserver::RoomShards>,
    pub users: Arc<UserServer>,
    pub state: Arc<CsState>,
    pub projection: tokio::task::JoinHandle<()>,
    /// The metadata group, when the env runs one (slice 6).
    pub cluster: Option<saltator_cluster::MetadataHandle>,
    /// The fed-out shard, when the env runs one — kept alive here so the
    /// appservice push worker's leader gate holds for the env's lifetime.
    #[allow(dead_code)]
    pub fedout: Option<Arc<saltator_fedout::FedOutServer>>,
}

pub async fn start_env() -> Env {
    // Tests hammer the API far past real-client rates.
    start_env_cfg(saltator_cs_api::RateLimitConfig::disabled(), true).await
}

pub async fn start_env_with(rate_limits: saltator_cs_api::RateLimitConfig) -> Env {
    start_env_cfg(rate_limits, true).await
}

pub async fn start_env_cfg(
    rate_limits: saltator_cs_api::RateLimitConfig,
    allow_internal_fetch: bool,
) -> Env {
    start_env_full(
        rate_limits,
        allow_internal_fetch,
        Vec::new(),
        Vec::new(),
        false,
        None,
        false,
    )
    .await
}

/// An env whose config names bootstrap administrators, and optionally
/// registers an appservice — the two identity sources `is_admin` has to
/// tell apart.
pub async fn start_env_admin(admins: &[&str], appservices: Vec<AppServiceRegistration>) -> Env {
    start_env_admin_cfg(admins, appservices, false).await
}

/// A registration for tests: token + sender, plus an optional exclusive
/// users-namespace regex (empty = no namespaces). Built through the real
/// YAML parser so tests exercise the same construction as production.
pub fn test_registration(
    as_token: &str,
    sender_localpart: &str,
    users_regex: &str,
) -> AppServiceRegistration {
    let mut yaml = format!(
        "id: {sender_localpart}\nurl: null\nas_token: {as_token}\nhs_token: hs-{as_token}\nsender_localpart: {sender_localpart}\n"
    );
    if !users_regex.is_empty() {
        yaml.push_str(&format!(
            "namespaces:\n  users:\n  - exclusive: true\n    regex: '{users_regex}'\n"
        ));
    }
    saltator_appservice::parse_registration("test.yaml", &yaml).expect("test registration")
}

pub async fn start_env_admin_cfg(
    admins: &[&str],
    appservices: Vec<AppServiceRegistration>,
    registration_requires_token: bool,
) -> Env {
    start_env_admin_notices(admins, appservices, registration_requires_token, None).await
}

/// An admin env with server notices configured (slice 5): the notices
/// localpart is what turns the feature on.
pub async fn start_env_notices(admins: &[&str], localpart: &str) -> Env {
    start_env_admin_notices(admins, Vec::new(), false, Some(localpart.to_owned())).await
}

/// An admin env that also runs a single-node metadata group, so the
/// cluster endpoints have a control plane to talk to (slice 6).
pub async fn start_env_cluster(admins: &[&str]) -> Env {
    let admins = admins
        .iter()
        .map(|u| ruma::OwnedUserId::try_from(*u).unwrap())
        .collect();
    start_env_full(
        saltator_cs_api::RateLimitConfig::disabled(),
        true,
        admins,
        Vec::new(),
        false,
        None,
        true,
    )
    .await
}

pub async fn start_env_admin_notices(
    admins: &[&str],
    appservices: Vec<AppServiceRegistration>,
    registration_requires_token: bool,
    server_notices_localpart: Option<String>,
) -> Env {
    let admins = admins
        .iter()
        .map(|u| ruma::OwnedUserId::try_from(*u).unwrap())
        .collect();
    start_env_full(
        saltator_cs_api::RateLimitConfig::disabled(),
        true,
        admins,
        appservices,
        registration_requires_token,
        server_notices_localpart,
        false,
    )
    .await
}

pub async fn start_env_full(
    rate_limits: saltator_cs_api::RateLimitConfig,
    allow_internal_fetch: bool,
    admin_users: Vec<ruma::OwnedUserId>,
    appservices: Vec<AppServiceRegistration>,
    registration_requires_token: bool,
    server_notices_localpart: Option<String>,
    with_cluster: bool,
) -> Env {
    start_env_full_fedout(
        rate_limits,
        allow_internal_fetch,
        admin_users,
        appservices,
        registration_requires_token,
        server_notices_localpart,
        with_cluster,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_env_full_fedout(
    rate_limits: saltator_cs_api::RateLimitConfig,
    allow_internal_fetch: bool,
    admin_users: Vec<ruma::OwnedUserId>,
    appservices: Vec<AppServiceRegistration>,
    registration_requires_token: bool,
    server_notices_localpart: Option<String>,
    with_cluster: bool,
    with_fedout: bool,
) -> Env {
    start_env_sharded_inner(
        rate_limits,
        allow_internal_fetch,
        admin_users,
        appservices,
        registration_requires_token,
        server_notices_localpart,
        with_cluster,
        with_fedout,
        1,
    )
    .await
}

/// A multi-shard env: rooms spread across `room_shards` groups.
pub async fn start_env_sharded(room_shards: u16) -> Env {
    start_env_sharded_inner(
        saltator_cs_api::RateLimitConfig::disabled(),
        true,
        Vec::new(),
        Vec::new(),
        false,
        None,
        false,
        false,
        room_shards,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_env_sharded_inner(
    rate_limits: saltator_cs_api::RateLimitConfig,
    allow_internal_fetch: bool,
    admin_users: Vec<ruma::OwnedUserId>,
    appservices: Vec<AppServiceRegistration>,
    registration_requires_token: bool,
    server_notices_localpart: Option<String>,
    with_cluster: bool,
    with_fedout: bool,
    room_shards: u16,
) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server_name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (signer, _der) =
        saltator_roomserver::ServerSigner::generate(server_name.clone(), "0".to_owned());
    let signer = Arc::new(signer);
    let mut room_servers = Vec::new();
    for idx in 0..room_shards.max(1) {
        room_servers.push(
            RoomServer::start_shard(
                saltator_shard::ShardId::new(saltator_store::Keyspace::Room, idx),
                1,
                engine.clone(),
                signer.clone(),
                NoopNetworkFactory,
                Some("127.0.0.1:0".into()),
                None,
            )
            .await
            .unwrap(),
        );
    }
    let rooms = saltator_roomserver::RoomShards::new(room_servers);
    let users = UserServer::start(
        1,
        engine.clone(),
        server_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in rooms
        .iter()
        .map(|(_, s)| s.shard_handle().clone())
        .chain([users.shard_handle().clone()])
    {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    // A single-node metadata group over the same engine: a real control
    // plane for the cluster endpoints to read and mutate.
    const META_ADDR: &str = "127.0.0.1:7100";
    let cluster = if with_cluster {
        let meta = saltator_cluster::MetadataHandle::start(1, engine, Some(META_ADDR.into()), None)
            .await
            .unwrap();
        meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
        meta.bootstrap_cluster(
            saltator_cluster::ClusterConfig::default(),
            META_ADDR.to_owned(),
        )
        .await
        .unwrap();
        Some(meta)
    } else {
        None
    };
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
            registration_requires_token,
            max_upload_size: 1024 * 1024,
            well_known_client: Some("https://hs.test".into()),
            rate_limits,
            allow_internal_fetch,
            admin_users,
            server_notices_localpart,
        },
    );
    let state = if appservices.is_empty() {
        state
    } else {
        state.with_appservices(std::sync::Arc::new(saltator_cs_api::AppServices {
            services: appservices.into_iter().map(std::sync::Arc::new).collect(),
        }))
    };
    let state = match &cluster {
        Some(meta) => state.with_cluster(meta.clone()),
        None => state,
    };
    let fedout = if with_fedout {
        let engine: Arc<dyn saltator_store::KvEngine> =
            Arc::new(saltator_store::RocksEngine::open(&dir.path().join("fedout")).unwrap());
        let fedout = saltator_fedout::FedOutServer::start(
            1,
            engine,
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        fedout
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        Some(fedout)
    } else {
        None
    };
    let state = match &fedout {
        Some(f) => state.with_fedout(f.clone()),
        None => state,
    };
    Env {
        _dir: dir,
        router: saltator_cs_api::router(state.clone()),
        rooms,
        users,
        state,
        projection,
        cluster,
        fedout,
    }
}

impl Env {
    pub async fn req(
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

    pub async fn register(&self, localpart: &str, password: &str) -> String {
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
    pub async fn sync_until(&self, token: &str, pred: impl Fn(&Value) -> bool) -> Value {
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

    pub async fn shutdown(self) {
        self.projection.abort();
        if let Some(meta) = &self.cluster {
            meta.shutdown().await.unwrap();
        }
        for (_, shard) in self.rooms.iter() {
            shard.shutdown().await.unwrap();
        }
        self.users.shutdown().await.unwrap();
    }
}

/// Single-node fed-out shard + the unified delivery worker (step 4).
pub async fn start_fedout_delivery(
    dir: &std::path::Path,
    rooms: Arc<RoomServer>,
    client: Arc<FederationClient>,
    server_name: &str,
) -> (
    Arc<saltator_fedout::FedOutServer>,
    tokio::task::JoinHandle<()>,
) {
    let engine: Arc<dyn saltator_store::KvEngine> = Arc::new(
        saltator_store::RocksEngine::open(&dir.join(format!("fedout-{server_name}"))).unwrap(),
    );
    let fedout = saltator_fedout::FedOutServer::start(
        1,
        engine,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    fedout
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    let worker = saltator_federation::spawn_delivery_worker(
        fedout.clone(),
        saltator_roomserver::RoomShards::single(rooms.clone()),
        client,
        ruma::OwnedServerName::try_from(server_name).unwrap(),
        Arc::new(saltator_federation::DeliveryBackoff::default()),
    );
    (fedout, worker)
}

/// The session's device id, from /account/whoami.
pub async fn device_of(env: &Env, token: &str) -> String {
    let (_, who) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await;
    who["device_id"].as_str().unwrap().to_owned()
}

/// Stand up a bare federation HTTP server for `server_name` over `rooms`,
/// authenticating callers against `caller_keys_base`. Returns its base URL.
pub async fn spawn_fed(
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
        key_cache: std::sync::Arc::new(key_cache),
        rooms: None,
        users: None,
        client: None,
        edu_sink: None,
        media: None,
        delivery_backoff: None,
        appservices: None,
        txn_replay: saltator_federation::TxnReplayCache::default(),
    };
    if let Some(r) = rooms {
        state = state.with_room_server(r);
    }
    let app = saltator_federation::router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

pub async fn start_fed_rooms(
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

// --- Outbound federated invite (full round-trip) -------------------------

pub async fn cs_stack(
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
    let projection = spawn_membership_projection(
        users.clone(),
        saltator_roomserver::RoomShards::single(rooms.clone()),
    );
    let media = MediaStore::open(dir.join(format!("{server}-media"))).unwrap();
    let mut cs = CsState::new(
        users.clone(),
        saltator_roomserver::RoomShards::single(rooms.clone()),
        media,
        CsConfig {
            server_name: name,
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
    );
    if let Some(base) = fed_client_base {
        cs = cs.with_federation(
            Arc::new(FederationClient::with_base_url(
                signer.clone(),
                base.clone(),
            )),
            signer.clone(),
            Arc::new(KeyCache::with_base_url(base)),
        );
    }
    let router = saltator_cs_api::router(cs);
    (rooms, users, signer, router, projection)
}

pub async fn oneshot(
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

pub async fn reg(router: &axum::Router, user: &str) -> String {
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

// -- admin API authorization ------

pub const ADMIN_USERS: &str = "/_saltator/admin/v1/users";

pub const WHOAMI: &str = "/_matrix/client/v3/account/whoami";

/// A cross-signing identity like a real client builds: an ed25519 master
/// key, and a helper that signs subkeys with it under the user's entity.
pub struct CrossSigning {
    pub pair: ruma::signatures::Ed25519KeyPair,
    pub pub_b64: String,
}

impl CrossSigning {
    pub fn generate() -> Self {
        let der = ruma::signatures::Ed25519KeyPair::generate();
        let tmp = ruma::signatures::Ed25519KeyPair::from_der(&der, "tmp".into()).unwrap();
        let pub_b64 =
            ruma::serde::Base64::<ruma::serde::base64::Standard>::new(tmp.public_key().to_vec())
                .encode();
        // Cross-signing key ids are `ed25519:<unpadded-base64-pubkey>`, so
        // the pair's version must be the pubkey itself.
        let pair = ruma::signatures::Ed25519KeyPair::from_der(&der, pub_b64.clone()).unwrap();
        Self { pair, pub_b64 }
    }

    pub fn key_json(&self, user: &str, usage: &str) -> Value {
        json!({
            "user_id": user,
            "usage": [usage],
            "keys": { format!("ed25519:{}", self.pub_b64): self.pub_b64 },
        })
    }

    pub fn signed_by(&self, signer: &CrossSigning, user: &str, usage: &str) -> Value {
        let mut obj: ruma::CanonicalJsonObject =
            serde_json::from_value(self.key_json(user, usage)).unwrap();
        ruma::signatures::sign_json(user, &signer.pair, &mut obj).unwrap();
        serde_json::to_value(&obj).unwrap()
    }
}

/// A stub appservice: records transactions and pings, and answers the
/// query endpoints by provisioning the entity through the homeserver's
/// own router — exactly what a real bridge does, minus the bridge.
/// `(txn_id, body, bearer)` for every recorded stub request.
type StubLog = Arc<tokio::sync::Mutex<Vec<(String, Value, Option<String>)>>>;

pub struct StubAs {
    pub url: String,
    /// Every transaction PUT, including attempts answered 500.
    pub transactions: StubLog,
    /// Fail the next N transaction PUTs with 500.
    pub fail_next: Arc<std::sync::atomic::AtomicU32>,
    /// Wired after env construction so query handlers can drive the CS
    /// API: the router plus what the stub needs to provision with.
    pub hs: Arc<tokio::sync::Mutex<Option<(axum::Router, String /* room for aliases */)>>>,
    pub pings: Arc<tokio::sync::Mutex<Vec<Option<String>>>>,
}

pub async fn start_stub_as() -> StubAs {
    use axum::extract::{Path as AxPath, State as AxState};
    use axum::response::IntoResponse;
    use std::sync::atomic::Ordering;

    type Shared = (
        Arc<tokio::sync::Mutex<Vec<(String, Value, Option<String>)>>>,
        Arc<std::sync::atomic::AtomicU32>,
        Arc<tokio::sync::Mutex<Option<(axum::Router, String)>>>,
        Arc<tokio::sync::Mutex<Vec<Option<String>>>>,
    );
    let shared: Shared = (
        Arc::new(tokio::sync::Mutex::new(Vec::new())),
        Arc::new(std::sync::atomic::AtomicU32::new(0)),
        Arc::new(tokio::sync::Mutex::new(None)),
        Arc::new(tokio::sync::Mutex::new(Vec::new())),
    );

    pub async fn put_txn(
        AxState((txns, fail, _, _)): AxState<Shared>,
        AxPath(txn_id): AxPath<String>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::response::Response {
        let bearer = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::to_owned);
        txns.lock().await.push((txn_id, body, bearer));
        if fail
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
        }
        axum::Json(json!({})).into_response()
    }

    pub async fn get_room(
        AxState((_, _, hs, _)): AxState<Shared>,
        AxPath(alias): AxPath<String>,
    ) -> axum::response::Response {
        // A real bridge would create the portal room here; the stub
        // points a pre-made room at the queried alias.
        let Some((router, room_id)) = hs.lock().await.clone() else {
            return (StatusCode::NOT_FOUND, "").into_response();
        };
        let alias_enc = alias.replace('#', "%23").replace(':', "%3A");
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/_matrix/client/v3/directory/room/{alias_enc}"))
            .header("Authorization", "Bearer as-tok")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({ "room_id": room_id })).unwrap(),
            ))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        if resp.status().is_success() {
            axum::Json(json!({})).into_response()
        } else {
            (StatusCode::NOT_FOUND, "").into_response()
        }
    }

    pub async fn get_user(
        AxState((_, _, hs, _)): AxState<Shared>,
        AxPath(user_id): AxPath<String>,
    ) -> axum::response::Response {
        let Some((router, _)) = hs.lock().await.clone() else {
            return (StatusCode::NOT_FOUND, "").into_response();
        };
        let localpart = user_id
            .trim_start_matches('@')
            .split(':')
            .next()
            .unwrap()
            .to_owned();
        let req = Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("Authorization", "Bearer as-tok")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "type": "m.login.application_service",
                    "username": localpart,
                    "inhibit_login": true,
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        if resp.status().is_success() {
            axum::Json(json!({})).into_response()
        } else {
            (StatusCode::NOT_FOUND, "").into_response()
        }
    }

    pub async fn post_ping(
        AxState((_, _, _, pings)): AxState<Shared>,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        pings.lock().await.push(
            body.get("transaction_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        );
        axum::Json(json!({}))
    }

    let app = axum::Router::new()
        .route(
            "/_matrix/app/v1/transactions/{txn_id}",
            axum::routing::put(put_txn),
        )
        .route(
            "/_matrix/app/v1/rooms/{alias}",
            axum::routing::get(get_room),
        )
        .route(
            "/_matrix/app/v1/users/{user_id}",
            axum::routing::get(get_user),
        )
        .route("/_matrix/app/v1/ping", axum::routing::post(post_ping))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    StubAs {
        url,
        transactions: shared.0,
        fail_next: shared.1,
        hs: shared.2,
        pings: shared.3,
    }
}

/// A registration whose HS→AS direction points at the stub: exclusive
/// user namespace `@tg_.*`, alias namespace `#tg_.*`.
pub fn stub_registration(url: &str) -> AppServiceRegistration {
    saltator_appservice::parse_registration(
        "stub.yaml",
        &format!(
            concat!(
                "id: bridge\n",
                "url: {url}\n",
                "as_token: as-tok\n",
                "hs_token: hs-as-tok\n",
                "sender_localpart: bridge\n",
                "namespaces:\n",
                "  users:\n",
                "  - {{exclusive: true, regex: '@tg_.*'}}\n",
                "  aliases:\n",
                "  - {{exclusive: true, regex: '#tg_.*'}}\n",
            ),
            url = url
        ),
    )
    .unwrap()
}

pub async fn start_appservice_env(url: &str) -> Env {
    start_env_full_fedout(
        saltator_cs_api::RateLimitConfig::disabled(),
        true,
        Vec::new(),
        vec![stub_registration(url)],
        false,
        None,
        false,
        true,
    )
    .await
}

// -- UIA sessions + registration tokens (slice 3) -------------------------

pub const REG_TOKENS: &str = "/_saltator/admin/v1/registration_tokens";

pub const REGISTER: &str = "/_matrix/client/v3/register";

// -- room admin -------------------

pub const ADMIN_ROOMS: &str = "/_saltator/admin/v1/rooms";

pub async fn make_room(env: &Env, token: &str, name: &str) -> String {
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat", "name": name})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["room_id"].as_str().unwrap().to_owned()
}

// -- server notices ---------------

pub fn notice(body: &str) -> Value {
    json!({"content": {"msgtype": "m.text", "body": body}})
}

// -- cluster admin ----------------

pub const CLUSTER_NODES: &str = "/_saltator/admin/v1/cluster/nodes";
