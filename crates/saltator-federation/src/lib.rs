//! Server-server HTTP surface: X-Matrix request signing and
//! verification, published server keys, and outbound delivery
//! (spec.md §5.4).

mod backfill;
mod delivery;
mod directory;
mod drain;
mod fetcher;
mod hierarchy;
mod http_client;
mod inbound;
mod join_client;
mod joins;
mod keys;
mod media;
pub mod metrics;
mod outbound;
mod query;
mod resolver;
pub mod ssrf;
mod transactions;
mod user_keys;
mod xmatrix;

pub use backfill::{fetch_backfill, fetch_timestamp_to_event};
pub use delivery::{spawn_delivery_worker, DeliveryBackoff};
pub use directory::directory_body;
pub use drain::{drain_user_outbox_once, spawn_user_outbox_drain};
pub use fetcher::room_intent_executor;
pub use http_client::build_http_client;
pub use inbound::{AuthRejection, Authenticated};
pub use join_client::{
    join_remote_room, knock_remote_room, leave_remote_room, resident_of_room, JoinError,
    JoinResponse, KnockError, KnockResponse,
};
pub use keys::{trust_event_servers, KeyCache, KeyError};
pub use media::parse_multipart_file;
pub use outbound::{FederationClient, OutboundError};
pub use resolver::{ResolvedServer, ServerResolver};
pub use xmatrix::{
    parse_authorization, sign_request, signing_object, verify_request, AuthError, AuthParams,
};

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post, put};
use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedServerName};

use saltator_roomserver::{RoomServer, ServerSigner};

/// How far ahead `valid_until_ts` promises our keys: 24 h. The spec caps
/// what verifiers may honor at 7 days and tells origins not to serve
/// responses expiring in under an hour; a day keeps re-fetch traffic low
/// while bounding how long a compromised key stays trusted. Signed fresh
/// per request, so the horizon never goes stale.
const KEY_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000;

/// Sink for ephemeral data carried by inbound EDUs (typing, presence).
/// Implemented by the CS layer over its typing/presence maps; the
/// federation crate can't reach those directly (it must not depend on
/// cs-api).
pub trait EduSink: Send + Sync {
    /// A remote user started or stopped typing in a room.
    fn typing(&self, room_id: &str, user_id: &str, typing: bool);
    /// A remote user's presence changed.
    fn presence(&self, user_id: &str, presence: &str, status_msg: Option<String>);
}

/// A rotated-out signing key, served in `old_verify_keys`.
#[derive(Debug, Clone)]
pub struct OldVerifyKey {
    /// `ed25519:<version>`.
    pub key_id: String,
    pub public_key_b64: String,
    pub expired_ts_ms: u64,
}

/// Shared state of the federation router.
pub struct FedState {
    pub server_name: OwnedServerName,
    pub signer: Arc<ServerSigner>,
    /// Snapshot taken at startup; rotation is an offline operation.
    pub old_keys: Vec<OldVerifyKey>,
    /// Fetches and caches calling servers' keys for inbound auth. Shared
    /// (not owned) so a key learned on one path is available on the others:
    /// the CS API trusts a remote server's keys while performing a remote
    /// join, and inbound auth must not re-fetch them on the latency path of
    /// that server's first request to us.
    pub key_cache: Arc<KeyCache>,
    /// The room pipeline inbound PDUs route into. `None` in key-only
    /// deployments and auth-only tests.
    pub rooms: Option<Arc<saltator_roomserver::RoomShards>>,
    /// The user shard, for recording pending remote invites. `None` when
    /// no user server is wired.
    pub users: Option<Arc<saltator_userserver::UserServer>>,
    /// Outbound client, for fetches made while handling inbound requests
    /// (e.g. filling DAG gaps via `/get_missing_events`). `None` disables
    /// gap-filling.
    pub client: Option<Arc<FederationClient>>,
    /// Where inbound EDUs (typing/presence) are applied. `None` drops them.
    pub edu_sink: Option<Arc<dyn EduSink>>,
    /// Local blob store, for serving our media to other servers. `None`
    /// disables the federation media endpoint.
    pub media: Option<saltator_media::MediaStore>,
    /// Shared delivery-backoff registry: inbound authenticated traffic
    /// clears a destination's penalty (it is provably up). `None` when no
    /// delivery worker runs.
    pub delivery_backoff: Option<Arc<crate::delivery::DeliveryBackoff>>,
    /// Appservice query-on-miss (docs/design-appservices.md): a remote
    /// server asking about an alias or user an appservice owns gets the
    /// same blocking provision-then-answer as a local client. `None`
    /// when no appservices are registered.
    pub appservices: Option<Arc<saltator_appservice::AppServiceQuerier>>,
    /// Replay cache for inbound transactions (spec "Transactions": a
    /// repeated `(origin, txn_id)` gets the stored response without
    /// reprocessing). In-memory and bounded: PDU ingest is idempotent by
    /// event id and to-device dedupes by message_id durably, so this is
    /// the fast-path courtesy layer, not the correctness layer.
    pub txn_replay: TxnReplayCache,
}

/// Bounded FIFO replay cache for `(origin, txn_id) → response body`.
#[derive(Default)]
pub struct TxnReplayCache {
    inner: std::sync::Mutex<TxnReplayInner>,
}

#[derive(Default)]
struct TxnReplayInner {
    map: std::collections::HashMap<(String, String), serde_json::Value>,
    order: std::collections::VecDeque<(String, String)>,
}

impl TxnReplayCache {
    const CAP: usize = 1024;

    pub fn get(&self, origin: &str, txn_id: &str) -> Option<serde_json::Value> {
        self.inner
            .lock()
            .expect("txn replay lock")
            .map
            .get(&(origin.to_owned(), txn_id.to_owned()))
            .cloned()
    }

    pub fn put(&self, origin: &str, txn_id: &str, response: serde_json::Value) {
        let mut inner = self.inner.lock().expect("txn replay lock");
        let key = (origin.to_owned(), txn_id.to_owned());
        if inner.map.insert(key.clone(), response).is_none() {
            inner.order.push_back(key);
            if inner.order.len() > Self::CAP {
                if let Some(old) = inner.order.pop_front() {
                    inner.map.remove(&old);
                }
            }
        }
    }
}

impl FedState {
    /// Construct with a default (real-DNS) key cache and no room server.
    pub fn new(
        server_name: OwnedServerName,
        signer: Arc<ServerSigner>,
        old_keys: Vec<OldVerifyKey>,
    ) -> Self {
        Self {
            server_name,
            signer,
            old_keys,
            key_cache: Arc::new(KeyCache::new()),
            rooms: None,
            users: None,
            client: None,
            edu_sink: None,
            media: None,
            delivery_backoff: None,
            appservices: None,
            txn_replay: TxnReplayCache::default(),
        }
    }

    /// Attach the EDU sink (typing/presence) for inbound transactions.
    pub fn with_edu_sink(mut self, sink: Arc<dyn EduSink>) -> Self {
        self.edu_sink = Some(sink);
        self
    }

    /// Attach the media store so we can serve local media to other servers.
    pub fn with_media(mut self, media: saltator_media::MediaStore) -> Self {
        self.media = Some(media);
        self
    }

    /// Attach the room server so inbound transactions can be applied.
    pub fn with_rooms(mut self, rooms: Arc<saltator_roomserver::RoomShards>) -> Self {
        self.rooms = Some(rooms);
        self
    }

    /// Single-shard convenience for the test harnesses that construct a
    /// bare [`RoomServer`].
    pub fn with_room_server(self, rooms: Arc<RoomServer>) -> Self {
        self.with_rooms(saltator_roomserver::RoomShards::single(rooms))
    }

    /// Attach the user shard so inbound invites can be recorded.
    pub fn with_users(mut self, users: Arc<saltator_userserver::UserServer>) -> Self {
        self.users = Some(users);
        self
    }

    /// Attach an outbound client so inbound processing can fill DAG gaps.
    pub fn with_client(mut self, client: Arc<FederationClient>) -> Self {
        self.client = Some(client);
        self
    }
}

/// Build the server-server router. Serve this on the federation listener.
pub fn router(state: Arc<FedState>) -> axum::Router {
    axum::Router::new()
        .route("/_matrix/key/v2/server", get(serve_server_keys))
        .route("/_matrix/federation/v1/version", get(serve_version))
        .route("/_matrix/federation/v1/query/profile", get(query::profile))
        .route(
            "/_matrix/federation/v1/hierarchy/{room_id}",
            get(hierarchy::serve_hierarchy),
        )
        .route(
            "/_matrix/federation/v1/query/directory",
            get(query::directory),
        )
        .route(
            "/_matrix/federation/v1/send/{txn_id}",
            put(transactions::send_transaction),
        )
        .route(
            "/_matrix/federation/v1/make_join/{room_id}/{user_id}",
            get(joins::make_join),
        )
        .route(
            "/_matrix/federation/v1/make_knock/{room_id}/{user_id}",
            get(joins::make_knock),
        )
        .route(
            "/_matrix/federation/v1/send_knock/{room_id}/{event_id}",
            put(joins::send_knock),
        )
        .route(
            "/_matrix/federation/v1/event_auth/{room_id}/{event_id}",
            get(joins::event_auth),
        )
        .route(
            "/_matrix/federation/v2/invite/{room_id}/{event_id}",
            put(joins::invite),
        )
        .route(
            "/_matrix/federation/v1/media/download/{media_id}",
            get(media::download),
        )
        .route(
            "/_matrix/federation/v1/media/thumbnail/{media_id}",
            get(media::thumbnail),
        )
        .route(
            "/_matrix/federation/v1/event/{event_id}",
            get(backfill::event),
        )
        .route(
            "/_matrix/federation/v1/backfill/{room_id}",
            get(backfill::backfill),
        )
        .route(
            "/_matrix/federation/v1/get_missing_events/{room_id}",
            post(backfill::get_missing_events),
        )
        .route(
            "/_matrix/federation/v1/make_leave/{room_id}/{user_id}",
            get(joins::make_leave),
        )
        .route(
            "/_matrix/federation/v2/send_leave/{room_id}/{event_id}",
            put(joins::send_leave),
        )
        .route(
            "/_matrix/federation/v1/send_leave/{room_id}/{event_id}",
            put(joins::send_leave_v1),
        )
        .route(
            "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
            put(joins::send_join),
        )
        .route(
            "/_matrix/federation/v1/send_join/{room_id}/{event_id}",
            put(joins::send_join_v1),
        )
        .route(
            "/_matrix/federation/v1/user/keys/query",
            post(user_keys::keys_query),
        )
        .route(
            "/_matrix/federation/v1/user/keys/claim",
            post(user_keys::keys_claim),
        )
        .route(
            "/_matrix/federation/v1/user/devices/{user_id}",
            get(user_keys::user_devices),
        )
        .route(
            "/_matrix/federation/v1/state/{room_id}",
            get(backfill::state),
        )
        .route(
            "/_matrix/federation/v1/state_ids/{room_id}",
            get(backfill::state_ids),
        )
        .route(
            "/_matrix/federation/v1/timestamp_to_event/{room_id}",
            get(backfill::timestamp_to_event),
        )
        .route(
            "/_matrix/federation/v1/publicRooms",
            get(directory::public_rooms_get).post(directory::public_rooms_post),
        )
        // Key notary (spec "Querying keys through another server").
        .route("/_matrix/key/v2/query/{server_name}", get(notary_query_one))
        .route("/_matrix/key/v2/query", post(notary_query_batch))
        // ---- Spec'd endpoints we deliberately do NOT implement ----
        // Explicit stubs so the gap is visible here rather than discovered
        // mid-investigation (see docs/federation-endpoints.md).
        // Behaviour matches the fallback (404 M_UNRECOGNIZED, the spec's
        // signal for an unimplemented endpoint), so gating tests like
        // TestUnknownEndpoints are unaffected.
        //
        // v1 invite serves only room versions 1-2 (we support v8+); a 404
        // here is exactly the signal that makes senders stay on v2.
        .route(
            "/_matrix/federation/v1/invite/{room_id}/{event_id}",
            put(not_implemented),
        )
        // 3PID invites need an identity-server integration we don't have.
        .route(
            "/_matrix/federation/v1/exchange_third_party_invite/{room_id}",
            put(not_implemented),
        )
        // OpenID for integration managers.
        .route(
            "/_matrix/federation/v1/openid/userinfo",
            get(not_implemented),
        )
        // Policy servers (spec v1.18).
        .route("/_matrix/policy/v1/sign", post(not_implemented))
        // ---- end stubs ----
        // Unknown federation/key path → 404, wrong method on a known path
        // → 405, both with the M_UNRECOGNIZED body the spec expects.
        .fallback(|| async { unrecognized(axum::http::StatusCode::NOT_FOUND) })
        .method_not_allowed_fallback(|| async {
            unrecognized(axum::http::StatusCode::METHOD_NOT_ALLOWED)
        })
        .with_state(state)
}

/// Build a notary response (spec "Querying keys through another server"):
/// each requested server's raw signed key publication — ours directly,
/// others from the key cache (fetched or stale) — co-signed by us so the
/// requester can pin trust on this notary. Unreachable/unknown servers
/// are simply omitted, like Synapse.
async fn notary_response(state: &FedState, requests: Vec<(String, u64)>) -> serde_json::Value {
    let now = now_ms();
    let mut server_keys = Vec::new();
    for (server, min_valid_ms) in requests {
        let obj = if server == state.server_name.as_str() {
            server_keys_object(state).ok()
        } else {
            state
                .key_cache
                .raw_keys_for(&server, now, min_valid_ms)
                .await
        };
        let Some(mut obj) = obj else {
            continue;
        };
        if let Err(e) = state.signer.sign_json(&mut obj) {
            tracing::error!(error = %e, server, "notary: co-signing key response");
            continue;
        }
        server_keys.push(CanonicalJsonValue::Object(obj));
    }
    serde_json::Value::from(CanonicalJsonValue::Object(CanonicalJsonObject::from_iter(
        [(
            "server_keys".to_owned(),
            CanonicalJsonValue::Array(server_keys),
        )],
    )))
}

/// `GET /_matrix/key/v2/query/{serverName}` — unauthenticated, like
/// `/key/v2/server`.
async fn notary_query_one(
    State(state): State<Arc<FedState>>,
    axum::extract::Path(server_name): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    axum::Json(notary_response(&state, vec![(server_name, 0)]).await)
}

/// `POST /_matrix/key/v2/query` — the batch variant:
/// `{"server_keys": {server: {key_id: {"minimum_valid_until_ts": ts}}}}`.
/// An empty criteria object means "any key"; we honour the strictest
/// `minimum_valid_until_ts` given for a server.
async fn notary_query_batch(
    State(state): State<Arc<FedState>>,
    body: Option<axum::Json<serde_json::Value>>,
) -> axum::Json<serde_json::Value> {
    let mut requests = Vec::new();
    if let Some(map) = body
        .as_ref()
        .and_then(|b| b.0.get("server_keys"))
        .and_then(|v| v.as_object())
    {
        for (server, criteria) in map {
            let min_valid = criteria
                .as_object()
                .map(|c| {
                    c.values()
                        .filter_map(|v| v.get("minimum_valid_until_ts").and_then(|t| t.as_u64()))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            requests.push((server.clone(), min_valid));
        }
    }
    axum::Json(notary_response(&state, requests).await)
}

/// Stub for a spec'd endpoint we have not implemented: same 404
/// `M_UNRECOGNIZED` the fallback produces, but the route registration
/// makes the gap explicit (and grep-able) in the router above.
async fn not_implemented() -> axum::response::Response {
    unrecognized(axum::http::StatusCode::NOT_FOUND)
}

/// A Matrix `M_UNRECOGNIZED` error response with the given status.
fn unrecognized(status: axum::http::StatusCode) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(serde_json::json!({
            "errcode": "M_UNRECOGNIZED",
            "error": "Unrecognized request",
        })),
    )
        .into_response()
}

/// `GET /_matrix/federation/v1/version` — unauthenticated reachability
/// probe (spec "Server implementation").
async fn serve_version() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "server": {
            "name": "saltator",
            "version": env!("CARGO_PKG_VERSION"),
        }
    }))
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}

/// `GET /_matrix/key/v2/server` (spec "Publishing keys").
async fn serve_server_keys(
    State(state): State<Arc<FedState>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let object = server_keys_object(&state).map_err(|e| {
        tracing::error!(error = %e, "signing /key/v2/server response");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let value =
        serde_json::to_value(&object).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(value))
}

/// The signed key-publication object (extracted for tests).
fn server_keys_object(state: &FedState) -> Result<CanonicalJsonObject, String> {
    let mut verify_keys = CanonicalJsonObject::new();
    let mut key_obj = CanonicalJsonObject::new();
    key_obj.insert(
        "key".to_owned(),
        CanonicalJsonValue::String(state.signer.public_key_b64()),
    );
    verify_keys.insert(state.signer.key_id(), CanonicalJsonValue::Object(key_obj));

    let mut old_verify_keys = CanonicalJsonObject::new();
    for old in &state.old_keys {
        let mut key_obj = CanonicalJsonObject::new();
        key_obj.insert(
            "key".to_owned(),
            CanonicalJsonValue::String(old.public_key_b64.clone()),
        );
        key_obj.insert(
            "expired_ts".to_owned(),
            CanonicalJsonValue::Integer(
                ruma::Int::try_from(old.expired_ts_ms as i64).unwrap_or(ruma::Int::MAX),
            ),
        );
        old_verify_keys.insert(old.key_id.clone(), CanonicalJsonValue::Object(key_obj));
    }

    let mut object = CanonicalJsonObject::new();
    object.insert(
        "server_name".to_owned(),
        CanonicalJsonValue::String(state.server_name.as_str().to_owned()),
    );
    object.insert(
        "valid_until_ts".to_owned(),
        CanonicalJsonValue::Integer(
            ruma::Int::try_from((now_ms() + KEY_VALIDITY_MS) as i64).unwrap_or(ruma::Int::MAX),
        ),
    );
    object.insert(
        "verify_keys".to_owned(),
        CanonicalJsonValue::Object(verify_keys),
    );
    object.insert(
        "old_verify_keys".to_owned(),
        CanonicalJsonValue::Object(old_verify_keys),
    );
    state
        .signer
        .sign_json(&mut object)
        .map_err(|e| e.to_string())?;
    Ok(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_keys_response_is_well_formed_and_verifies() {
        let server_name: OwnedServerName = "example.test".try_into().unwrap();
        let (signer, _der) = ServerSigner::generate(server_name.clone(), "1".to_owned());
        let state = FedState::new(
            server_name,
            Arc::new(signer),
            vec![OldVerifyKey {
                key_id: "ed25519:0".to_owned(),
                public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                expired_ts_ms: 1_700_000_000_000,
            }],
        );
        let object = server_keys_object(&state).unwrap();

        assert_eq!(
            object.get("server_name"),
            Some(&CanonicalJsonValue::String("example.test".into()))
        );
        let verify_keys = match object.get("verify_keys") {
            Some(CanonicalJsonValue::Object(o)) => o,
            other => panic!("verify_keys: {other:?}"),
        };
        assert!(verify_keys.contains_key("ed25519:1"));
        let old = match object.get("old_verify_keys") {
            Some(CanonicalJsonValue::Object(o)) => o,
            other => panic!("old_verify_keys: {other:?}"),
        };
        let old_entry = match old.get("ed25519:0") {
            Some(CanonicalJsonValue::Object(o)) => o,
            other => panic!("old ed25519:0: {other:?}"),
        };
        assert!(old_entry.contains_key("expired_ts"));

        // valid_until_ts sits inside the spec window (>1h, ≤7d out).
        let valid_until = match object.get("valid_until_ts") {
            Some(CanonicalJsonValue::Integer(i)) => i64::from(*i) as u64,
            other => panic!("valid_until_ts: {other:?}"),
        };
        let now = now_ms();
        assert!(valid_until > now + 60 * 60 * 1000);
        assert!(valid_until <= now + 7 * 24 * 60 * 60 * 1000);

        // The response verifies against its own advertised key.
        let public_keys = state.signer.public_key_map();
        ruma::signatures::verify_json(&public_keys, &object).expect("signature verifies");
    }
}
