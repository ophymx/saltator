//! Server-server HTTP surface, request signing/verification, outbound
//! queues (spec.md §5.4). M3 work in progress: server keys + X-Matrix
//! request authentication.

mod backfill;
mod http_client;
mod inbound;
mod join_client;
mod joins;
mod keys;
mod media;
mod outbound;
mod query;
mod resolver;
mod sender;
mod transactions;
mod user_keys;
mod xmatrix;

pub use http_client::build_http_client;
pub use inbound::{AuthRejection, Authenticated};
pub use join_client::{
    join_remote_room, leave_remote_room, resident_of_room, JoinError, JoinResponse,
};
pub use keys::{KeyCache, KeyError};
pub use media::parse_multipart_file;
pub use outbound::{FederationClient, OutboundError};
pub use resolver::{ResolvedServer, ServerResolver};
pub use sender::spawn_sender;
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
    /// Fetches and caches calling servers' keys for inbound auth.
    pub key_cache: KeyCache,
    /// The room pipeline inbound PDUs route into. `None` in key-only
    /// deployments and auth-only tests.
    pub rooms: Option<Arc<RoomServer>>,
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
            key_cache: KeyCache::new(),
            rooms: None,
            users: None,
            client: None,
            edu_sink: None,
            media: None,
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
    pub fn with_rooms(mut self, rooms: Arc<RoomServer>) -> Self {
        self.rooms = Some(rooms);
        self
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
            "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
            put(joins::send_join),
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
        .with_state(state)
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

fn now_ms() -> u64 {
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
