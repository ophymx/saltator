//! The client-server HTTP surface (spec.md §6): axum routers translating
//! Matrix CS API requests (ruma wire types, OQ-2) into calls on the room
//! and user servers. This crate never touches storage directly — always
//! through `saltator-roomserver` / `saltator-userserver`.

mod error;
mod extract;
mod presence;
mod push_eval;
mod push_gateway;
mod ratelimit;
mod room_util;
mod routes;
mod txn;
mod typing;

use std::sync::Arc;

use axum::routing::{get, post, put};
use ruma::OwnedServerName;

use saltator_core::RoomVersion;
use saltator_federation::FederationClient;
use saltator_media::MediaStore;
use saltator_roomserver::{RoomServer, ServerSigner};
use saltator_userserver::UserServer;

pub use error::ApiError;
pub use presence::PresenceMap;
pub use push_gateway::spawn_push_delivery;
pub use ratelimit::RateLimitConfig;
pub use typing::TypingMap;

/// Client-facing configuration of the CS surface.
#[derive(Debug, Clone)]
pub struct CsConfig {
    pub server_name: OwnedServerName,
    /// Room version for `/createRoom` when the client names none.
    pub default_room_version: RoomVersion,
    /// Whether `POST /register` is open.
    pub registration_enabled: bool,
    /// Media upload cap in bytes.
    pub max_upload_size: u64,
    /// Base URL advertised in `/.well-known/matrix/client`
    /// (e.g. `https://matrix.example.org`); the well-known route is only
    /// served when set.
    pub well_known_client: Option<String>,
    /// Rate limiting of the abusable endpoints (login, registration,
    /// message sends). Disable for test harnesses that hammer the API.
    pub rate_limits: ratelimit::RateLimitConfig,
    /// Allow server-initiated fetches (URL previews, push gateways) to
    /// reach private/loopback addresses. MUST stay false in production —
    /// enable only in trusted, network-isolated test harnesses whose
    /// mock servers live on loopback/private IPs.
    pub allow_internal_fetch: bool,
}

/// Shared state of every CS route.
pub struct CsState {
    pub users: Arc<UserServer>,
    pub rooms: Arc<RoomServer>,
    pub media: MediaStore,
    pub config: CsConfig,
    /// Ephemeral typing state — shared with the federation surface, which
    /// updates it from inbound `m.typing` EDUs.
    pub typing: Arc<TypingMap>,
    /// Ephemeral presence — shared with the federation surface.
    pub presence: Arc<PresenceMap>,
    /// Outbound federation, present once the federation surface is wired
    /// (absent in client-only test harnesses). Enables joining remote
    /// rooms.
    pub federation: Option<Federation>,
    pub(crate) txns: txn::TxnCache,
    /// Per-user serialization of push-rule read-modify-writes: concurrent
    /// mutations (two parallel joins both copying upgrade rules, say)
    /// would otherwise lose one write.
    pub(crate) push_rule_locks:
        tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub(crate) rate_limiter: ratelimit::RateLimiter,
}

/// The bits of the federation surface the CS API drives directly: a signed
/// client for remote requests and our signing identity.
#[derive(Clone)]
pub struct Federation {
    pub client: Arc<FederationClient>,
    pub signer: Arc<ServerSigner>,
    /// Fetches remote servers' signing keys so imported events (send_join
    /// state, backfill) can be signature-verified before we trust them.
    pub key_cache: Arc<saltator_federation::KeyCache>,
}

/// Applies inbound EDUs (typing/presence) to the shared ephemeral maps —
/// the CS side of [`saltator_federation::EduSink`].
pub struct EphemeralEduSink {
    typing: Arc<TypingMap>,
    presence: Arc<PresenceMap>,
}

impl EphemeralEduSink {
    pub fn new(typing: Arc<TypingMap>, presence: Arc<PresenceMap>) -> Self {
        Self { typing, presence }
    }
}

impl saltator_federation::EduSink for EphemeralEduSink {
    fn typing(&self, room_id: &str, user_id: &str, typing: bool) {
        // Remote typing notifications expire on the same 30s cadence
        // clients refresh at.
        self.typing
            .set(room_id, user_id, typing, std::time::Duration::from_secs(30));
    }

    fn presence(&self, user_id: &str, presence: &str, status_msg: Option<String>) {
        self.presence.set(user_id, presence, status_msg);
    }
}

impl CsState {
    pub fn new(
        users: Arc<UserServer>,
        rooms: Arc<RoomServer>,
        media: MediaStore,
        config: CsConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            users,
            rooms,
            media,
            config,
            typing: Arc::new(TypingMap::new()),
            presence: Arc::new(PresenceMap::new()),
            federation: None,
            txns: txn::TxnCache::new(),
            push_rule_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            rate_limiter: ratelimit::RateLimiter::new(),
        })
    }

    /// Take one rate-limit token for `(kind, key)`; 429 when drained.
    pub(crate) fn rate_limit(&self, kind: ratelimit::Kind, key: &str) -> Result<(), ApiError> {
        self.rate_limiter
            .check(&self.config.rate_limits, kind, key)
            .map_err(ApiError::limit_exceeded)
    }

    /// The shared typing map (to pass to the federation surface).
    pub fn typing_map(&self) -> Arc<TypingMap> {
        self.typing.clone()
    }

    /// The shared presence map (to pass to the federation surface).
    pub fn presence_map(&self) -> Arc<PresenceMap> {
        self.presence.clone()
    }

    /// Attach outbound federation so `/join` can reach remote rooms.
    pub fn with_federation(
        mut self: Arc<Self>,
        client: Arc<FederationClient>,
        signer: Arc<ServerSigner>,
        key_cache: Arc<saltator_federation::KeyCache>,
    ) -> Arc<Self> {
        // `self` is freshly built here (single owner), so this is safe.
        Arc::get_mut(&mut self)
            .expect("with_federation called on a shared CsState")
            .federation = Some(Federation {
            client,
            signer,
            key_cache,
        });
        self
    }
}

/// Build the client-server router. Serve this on the client listener.
pub fn router(state: Arc<CsState>) -> axum::Router {
    use routes::{
        account, backup, keys, media, push, relations, rooms, search, session, spaces, sync,
        to_device,
    };

    let mut app = axum::Router::new()
        .route(
            "/_matrix/client/versions",
            get(session::get_supported_versions),
        )
        .route(
            "/.well-known/matrix/client",
            get(session::well_known_client),
        );

    // Endpoints under both `/r0` (legacy) and `/v3` prefixes.
    for prefix in ["/_matrix/client/r0", "/_matrix/client/v3"] {
        let p = |suffix: &str| format!("{prefix}{suffix}");
        app = app
            // -- session / account
            .route(&p("/capabilities"), get(session::get_capabilities))
            .route(&p("/register"), post(session::register))
            .route(&p("/register/available"), get(session::register_available))
            .route(&p("/login"), get(session::get_login_types))
            .route(&p("/login"), post(session::login))
            .route(&p("/logout"), post(session::logout))
            .route(&p("/logout/all"), post(session::logout_all))
            .route(&p("/refresh"), post(session::refresh))
            .route(&p("/account/whoami"), get(session::whoami))
            .route(&p("/account/password"), post(account::change_password))
            .route(&p("/account/deactivate"), post(account::deactivate))
            // -- profile / account data / filters / devices / push
            .route(&p("/profile/{user_id}"), get(account::get_profile))
            .route(
                &p("/profile/{user_id}/displayname"),
                get(account::get_displayname).put(account::set_displayname),
            )
            .route(
                &p("/profile/{user_id}/avatar_url"),
                get(account::get_avatar_url).put(account::set_avatar_url),
            )
            .route(
                &p("/user/{user_id}/account_data/{type}"),
                get(account::get_global_account_data).put(account::set_global_account_data),
            )
            .route(
                &p("/user/{user_id}/rooms/{room_id}/account_data/{type}"),
                get(account::get_room_account_data).put(account::set_room_account_data),
            )
            .route(&p("/user/{user_id}/filter"), post(account::create_filter))
            .route(
                &p("/user/{user_id}/filter/{filter_id}"),
                get(account::get_filter),
            )
            .route(&p("/devices"), get(account::get_devices))
            .route(
                &p("/devices/{device_id}"),
                get(account::get_device)
                    .put(account::update_device)
                    .delete(account::delete_device),
            )
            .route(&p("/pushrules/"), get(push::get_pushrules))
            .route(
                &p("/pushrules/global/{kind}/{rule_id}"),
                get(push::get_pushrule)
                    .put(push::put_pushrule)
                    .delete(push::delete_pushrule),
            )
            .route(
                &p("/pushrules/global/{kind}/{rule_id}/{attr}"),
                get(push::get_pushrule_attr).put(push::put_pushrule_attr),
            )
            .route(&p("/pushers"), get(push::get_pushers))
            .route(&p("/pushers/set"), post(push::set_pushers))
            .route(
                &p("/presence/{user_id}/status"),
                get(account::get_presence).put(account::set_presence),
            )
            // -- e2ee device keys
            .route(&p("/keys/upload"), post(keys::upload_keys))
            .route(&p("/keys/query"), post(keys::query_keys))
            .route(&p("/keys/claim"), post(keys::claim_keys))
            .route(&p("/keys/changes"), get(keys::key_changes))
            .route(
                &p("/keys/device_signing/upload"),
                post(keys::device_signing_upload),
            )
            .route(&p("/keys/signatures/upload"), post(keys::signatures_upload))
            // -- e2ee key backup
            .route(
                &p("/room_keys/version"),
                post(backup::create_version).get(backup::get_latest_version),
            )
            .route(
                &p("/room_keys/version/{version}"),
                get(backup::get_version)
                    .put(backup::put_version)
                    .delete(backup::delete_version),
            )
            .route(
                &p("/room_keys/keys"),
                put(backup::put_keys)
                    .get(backup::get_keys)
                    .delete(backup::delete_keys),
            )
            .route(
                &p("/room_keys/keys/{room_id}"),
                put(backup::put_room_keys)
                    .get(backup::get_room_keys)
                    .delete(backup::delete_room_keys),
            )
            .route(
                &p("/room_keys/keys/{room_id}/{session_id}"),
                put(backup::put_session_keys)
                    .get(backup::get_session_keys)
                    .delete(backup::delete_session_keys),
            )
            .route(
                &p("/sendToDevice/{event_type}/{txn_id}"),
                put(to_device::send_to_device),
            )
            // -- rooms
            .route(&p("/search"), post(search::search))
            .route(&p("/user_directory/search"), post(search::user_directory))
            .route(&p("/createRoom"), post(rooms::create_room))
            .route(
                &p("/join/{room_id_or_alias}"),
                post(rooms::join_by_id_or_alias),
            )
            .route(&p("/rooms/{room_id}/join"), post(rooms::join_room))
            .route(&p("/knock/{room_id_or_alias}"), post(rooms::knock_room))
            .route(&p("/rooms/{room_id}/leave"), post(rooms::leave_room))
            .route(&p("/rooms/{room_id}/upgrade"), post(rooms::upgrade_room))
            .route(&p("/rooms/{room_id}/forget"), post(rooms::forget_room))
            .route(&p("/rooms/{room_id}/invite"), post(rooms::invite_user))
            .route(&p("/rooms/{room_id}/kick"), post(rooms::kick_user))
            .route(&p("/rooms/{room_id}/ban"), post(rooms::ban_user))
            .route(&p("/rooms/{room_id}/unban"), post(rooms::unban_user))
            .route(
                &p("/rooms/{room_id}/send/{event_type}/{txn_id}"),
                put(rooms::send_message_event),
            )
            .route(&p("/rooms/{room_id}/state"), get(rooms::get_state_events))
            .route(
                &p("/rooms/{room_id}/state/{event_type}"),
                get(rooms::get_state_event_empty_key).put(rooms::send_state_event_empty_key),
            )
            // Clients (and Complement) also use a trailing slash for the
            // empty state key; axum treats that as a distinct path.
            .route(
                &p("/rooms/{room_id}/state/{event_type}/"),
                get(rooms::get_state_event_empty_key).put(rooms::send_state_event_empty_key),
            )
            .route(
                &p("/rooms/{room_id}/state/{event_type}/{state_key}"),
                get(rooms::get_state_event).put(rooms::send_state_event),
            )
            .route(
                &p("/rooms/{room_id}/event/{event_id}"),
                get(rooms::get_room_event),
            )
            .route(
                &p("/rooms/{room_id}/context/{event_id}"),
                get(rooms::get_context),
            )
            .route(&p("/rooms/{room_id}/members"), get(rooms::get_members))
            .route(
                &p("/rooms/{room_id}/joined_members"),
                get(rooms::get_joined_members),
            )
            .route(&p("/rooms/{room_id}/messages"), get(rooms::get_messages))
            .route(
                &p("/rooms/{room_id}/redact/{event_id}/{txn_id}"),
                put(rooms::redact_event),
            )
            .route(&p("/joined_rooms"), get(rooms::joined_rooms))
            .route(
                &p("/directory/room/{room_alias}"),
                get(rooms::get_alias)
                    .put(rooms::create_alias)
                    .delete(rooms::delete_alias),
            )
            .route(&p("/rooms/{room_id}/aliases"), get(rooms::get_room_aliases))
            .route(
                &p("/publicRooms"),
                get(rooms::public_rooms).post(rooms::public_rooms_filtered),
            )
            .route(
                &p("/directory/list/room/{room_id}"),
                get(rooms::get_visibility).put(rooms::set_visibility),
            )
            // -- sync / ephemeral
            .route(&p("/sync"), get(sync::sync_events))
            .route(
                &p("/rooms/{room_id}/receipt/{receipt_type}/{event_id}"),
                post(sync::send_receipt),
            )
            .route(
                &p("/rooms/{room_id}/read_markers"),
                post(sync::set_read_markers),
            )
            .route(
                &p("/rooms/{room_id}/typing/{user_id}"),
                put(sync::send_typing),
            );
    }

    // -- relations / threads (v1-only paths, spec v1.3+)
    app = app
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
            get(relations::get_relations),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
            get(relations::get_relations_by_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(relations::get_relations_by_type_and_event_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/threads",
            get(relations::get_threads),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
            get(rooms::timestamp_to_event),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/hierarchy",
            get(spaces::get_hierarchy),
        )
        .route(
            "/_matrix/client/v1/room_summary/{room_id_or_alias}",
            get(spaces::get_room_summary),
        );

    // -- media (authenticated endpoints only, Matrix 1.11+)
    app = app
        .route("/_matrix/media/v3/upload", post(media::upload))
        .route("/_matrix/media/v1/create", post(media::create_async))
        .route(
            "/_matrix/media/v3/upload/{server_name}/{media_id}",
            put(media::upload_async),
        )
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}",
            get(media::download),
        )
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}/{file_name}",
            get(media::download_named),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}",
            get(media::thumbnail),
        )
        .route("/_matrix/client/v1/media/config", get(media::config))
        .route(
            "/_matrix/client/v1/media/preview_url",
            get(media::preview_url),
        )
        .route("/_matrix/media/v3/preview_url", get(media::preview_url))
        // Legacy unauthenticated media (deprecated pre-1.11 surface, still
        // widely used by clients).
        .route(
            "/_matrix/media/v3/download/{server_name}/{media_id}",
            get(media::download_legacy),
        )
        .route(
            "/_matrix/media/v3/download/{server_name}/{media_id}/{file_name}",
            get(media::download_named_legacy),
        )
        .route(
            "/_matrix/media/v3/thumbnail/{server_name}/{media_id}",
            get(media::thumbnail_legacy),
        )
        .route("/_matrix/media/v3/config", get(media::config_legacy));

    // A handful of server-server / key endpoints are also exposed on the
    // client origin. In a real deployment a reverse proxy fronts one origin
    // for every `/_matrix/*` path (and Complement drives them all through a
    // single base URL), so these must be *known* routes here: a wrong method
    // then yields the spec's 405 M_UNRECOGNIZED instead of a bare 404.
    app = app
        .route("/_matrix/federation/v1/version", get(federation_version))
        .route("/_matrix/key/v2/query", post(notary_query))
        .route("/_matrix/key/v2/query/{server_name}", get(notary_query));

    app.fallback(unrecognized)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state)
}

async fn unrecognized() -> ApiError {
    ApiError::unrecognized()
}

/// `GET /_matrix/federation/v1/version` — the unauthenticated reachability
/// probe, also answered on the client origin (see the router comment).
async fn federation_version() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "server": {
            "name": "saltator",
            "version": env!("CARGO_PKG_VERSION"),
        }
    }))
}

/// `POST /_matrix/key/v2/query` and `GET /_matrix/key/v2/query/{serverName}`
/// — the key notary. saltator does not act as a notary for other servers'
/// keys, so it returns none; the route exists so wrong methods yield 405
/// and the endpoint is recognised (spec "Querying keys through another
/// server").
async fn notary_query() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "server_keys": [] }))
}

async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}
