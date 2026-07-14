//! The client-server HTTP surface (spec.md §6): axum routers translating
//! Matrix CS API requests (ruma wire types, OQ-2) into calls on the room
//! and user servers. This crate never touches storage directly — always
//! through `saltator-roomserver` / `saltator-userserver`.

mod error;
mod extract;
mod room_util;
mod routes;
mod txn;
mod typing;

use std::sync::Arc;

use axum::routing::{get, post, put};
use ruma::OwnedServerName;

use saltator_core::RoomVersion;
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_userserver::UserServer;

pub use error::ApiError;
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
}

/// Shared state of every CS route.
pub struct CsState {
    pub users: Arc<UserServer>,
    pub rooms: Arc<RoomServer>,
    pub media: MediaStore,
    pub config: CsConfig,
    pub typing: TypingMap,
    pub(crate) txns: txn::TxnCache,
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
            typing: TypingMap::new(),
            txns: txn::TxnCache::new(),
        })
    }
}

/// Build the client-server router. Serve this on the client listener.
pub fn router(state: Arc<CsState>) -> axum::Router {
    use routes::{account, media, rooms, session, sync};

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
            .route(&p("/pushrules/"), get(account::get_pushrules))
            .route(
                &p("/presence/{user_id}/status"),
                get(account::get_presence).put(account::set_presence),
            )
            // -- rooms
            .route(&p("/createRoom"), post(rooms::create_room))
            .route(
                &p("/join/{room_id_or_alias}"),
                post(rooms::join_by_id_or_alias),
            )
            .route(&p("/rooms/{room_id}/join"), post(rooms::join_room))
            .route(&p("/rooms/{room_id}/leave"), post(rooms::leave_room))
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
            .route(
                &p("/rooms/{room_id}/state/{event_type}/{state_key}"),
                get(rooms::get_state_event).put(rooms::send_state_event),
            )
            .route(
                &p("/rooms/{room_id}/event/{event_id}"),
                get(rooms::get_room_event),
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
            .route(&p("/publicRooms"), get(rooms::public_rooms))
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

    // -- media (authenticated endpoints only, Matrix 1.11+)
    app = app
        .route("/_matrix/media/v3/upload", post(media::upload))
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
        .route("/_matrix/client/v1/media/config", get(media::config));

    app.fallback(unrecognized)
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

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}
