//! The client-server HTTP surface (spec.md §6): axum routers translating
//! Matrix CS API requests (ruma wire types, OQ-2) into calls on the room
//! and user servers. This crate never touches storage directly — always
//! through `saltator-roomserver` / `saltator-userserver`.

pub mod appservice_push;
mod error;
mod extract;
mod presence;
mod push_eval;
mod push_gateway;
mod ratelimit;
mod room_util;
mod routes;
mod services;
mod txn;
mod typing;

use std::sync::Arc;

use axum::routing::{delete, get, post, put};
use ruma::{OwnedServerName, OwnedUserId};

use saltator_core::RoomVersion;
use saltator_federation::FederationClient;
use saltator_media::MediaStore;
use saltator_roomserver::{RoomShards, ServerSigner};
use saltator_userserver::UserServer;

pub use appservice_push::spawn_appservice_push;
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
    /// Require a registration token to register. Independent of
    /// `registration_enabled`: closed still means closed.
    pub registration_requires_token: bool,
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
    /// Server administrators named in config, unioned with the account
    /// flag by [`CsState::is_admin`]. This is the bootstrap: a fresh
    /// server has no admin account and no way to grant one, so the first
    /// administrator has to come from outside the database.
    pub admin_users: Vec<OwnedUserId>,
    /// Localpart of the account that delivers server notices, e.g.
    /// `notices` → `@notices:example.org`. `None` disables the feature.
    ///
    /// Off by default because turning it on creates and reserves an
    /// account: an operator should choose that name, not inherit it. Once
    /// set, the localpart is refused to `/register` — otherwise a user
    /// could take the name and receive, or send, what looks like server
    /// mail.
    pub server_notices_localpart: Option<String>,
}

pub use services::oidc::OidcProviderConfig;

/// Shared state of every CS route.
pub struct CsState {
    pub users: Arc<UserServer>,
    pub rooms: Arc<RoomShards>,
    /// The federation-out shard: durable home of outbound EDUs (step 4).
    /// `None` in stacks without delivery (most tests): enqueues are
    /// dropped with a warning — nothing outbound exists to deliver them.
    pub fedout: Option<Arc<saltator_fedout::FedOutServer>>,
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
    /// The cluster control plane, for the admin node/drain endpoints.
    /// `None` in stacks that run the shard servers without a metadata
    /// group (most tests): the cluster endpoints then say so.
    pub(crate) cluster: Option<saltator_cluster::MetadataHandle>,
    /// Registered application services: identity assertion
    /// (`?user_id=`/`?device_id=` masquerading), namespaces, `?ts`
    /// massaging, ghost registration, and outbound event push.
    pub(crate) appservices: Arc<AppServices>,
    /// Query-on-miss client over the same registrations (alias/user
    /// lookups block on the owning AS creating the entity).
    pub(crate) as_querier: saltator_appservice::AppServiceQuerier,
    /// The credential providers this server offers, the single place the
    /// list is built. Local
    /// passwords always; `with_oidc` appends external providers, and
    /// everything downstream (`GET /login`, the login path) derives from
    /// here so the advertisement and the login path cannot disagree.
    pub(crate) auth_providers: Vec<services::auth::AuthProvider>,
    /// Runtime state of the SSO browser flows; `None` until `with_oidc`
    /// configures a provider, and every SSO route 404s while it is.
    pub(crate) sso: Option<services::oidc::SsoRuntime>,
}

pub use saltator_appservice::{AppServiceRegistration, AppServices};

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
    /// Attach the federation-out shard for durable outbound EDUs.
    pub fn with_fedout(
        mut self: Arc<Self>,
        fedout: Arc<saltator_fedout::FedOutServer>,
    ) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("with_fedout called on a shared CsState")
            .fedout = Some(fedout);
        self
    }

    /// Attach the cluster control plane, enabling the admin node/drain
    /// endpoints.
    pub fn with_cluster(
        mut self: Arc<Self>,
        cluster: saltator_cluster::MetadataHandle,
    ) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("with_cluster called on a shared CsState")
            .cluster = Some(cluster);
        self
    }

    /// Attach application service registrations (loaded from registration
    /// files at startup).
    pub fn with_appservices(mut self: Arc<Self>, appservices: Arc<AppServices>) -> Arc<Self> {
        let state = Arc::get_mut(&mut self).expect("with_appservices called on a shared CsState");
        state.appservices = appservices;
        state.as_querier = saltator_appservice::AppServiceQuerier::new(state.appservices.clone());
        self
    }

    /// Whether the caller is a server administrator.
    ///
    /// The single resolution point, deliberately: no route reads the
    /// account's `admin` flag directly, so a later token-scope or
    /// external-IdP arm lands here and nowhere else.
    pub(crate) fn is_admin(&self, auth: &extract::Auth) -> Result<bool, ApiError> {
        // Appservices are never administrators: an AS identity is
        // synthesized from config and has no account row at all, so there
        // is nothing to carry the flag.
        if auth.appservice.is_some() {
            return Ok(false);
        }
        if self.config.admin_users.contains(&auth.user_id) {
            return Ok(true);
        }
        Ok(self
            .users
            .store()
            .account(auth.user_id.as_str())
            .map_err(ApiError::internal)?
            .is_some_and(|a| a.admin))
    }

    /// The admin/user-management domain service over this state's shards.
    pub(crate) fn admin(&self) -> services::admin::Admin<'_> {
        services::admin::Admin {
            users: &self.users,
            admin_users: &self.config.admin_users,
        }
    }

    /// The room-administration service: room inspection, shutdown and the
    /// join block.
    pub(crate) fn room_admin(&self) -> services::room_admin::RoomAdmin<'_> {
        services::room_admin::RoomAdmin {
            users: &self.users,
            rooms: &self.rooms,
            server_name: self.config.server_name.as_str(),
        }
    }

    /// The server-notices service.
    pub(crate) fn notices(&self) -> services::notices::Notices<'_> {
        services::notices::Notices {
            users: &self.users,
            rooms: &self.rooms,
            localpart: self.config.server_notices_localpart.as_deref(),
            room_version: self.config.default_room_version,
        }
    }

    /// The cluster-administration service.
    pub(crate) fn cluster_admin(&self) -> services::cluster_admin::ClusterAdmin<'_> {
        services::cluster_admin::ClusterAdmin {
            meta: self.cluster.as_ref(),
        }
    }

    /// The user-interactive-auth service.
    pub(crate) fn uia(&self) -> services::uia::Uia<'_> {
        services::uia::Uia {
            users: &self.users,
            sso: self.sso.as_ref(),
        }
    }

    /// The authentication service: login flows and credential
    /// verification.
    pub(crate) fn authn(&self) -> services::auth::Authn<'_> {
        services::auth::Authn {
            users: &self.users,
            providers: &self.auth_providers,
        }
    }

    /// Liveness/readiness, for the probes in front of this node.
    pub(crate) fn health(&self) -> services::health::Health<'_> {
        services::health::Health {
            users: &self.users,
            rooms: &self.rooms,
            cluster: self.cluster.as_ref(),
        }
    }

    /// The E2EE/device-list domain service over this state's shards.
    pub(crate) fn e2ee(&self) -> services::e2ee::E2ee<'_> {
        services::e2ee::E2ee {
            users: &self.users,
            rooms: &self.rooms,
            fedout: self.fedout.as_ref(),
            server_name: self.config.server_name.as_str(),
        }
    }

    pub fn new(
        users: Arc<UserServer>,
        rooms: Arc<RoomShards>,
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
            fedout: None,
            txns: txn::TxnCache::new(),
            push_rule_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            rate_limiter: ratelimit::RateLimiter::new(),
            appservices: Arc::new(AppServices::default()),
            as_querier: saltator_appservice::AppServiceQuerier::new(Arc::new(
                AppServices::default(),
            )),
            cluster: None,
            auth_providers: vec![services::auth::AuthProvider::LocalPassword],
            sso: None,
        })
    }

    /// Configure external OIDC identity providers (the OIDC slice).
    /// `public_base_url` is the browser-visible origin of this server —
    /// the IdP redirects back to `{public_base_url}/_saltator/client/oidc/callback`,
    /// and that exact URL must be registered with each provider.
    pub fn with_oidc(
        mut self: Arc<Self>,
        providers: Vec<OidcProviderConfig>,
        public_base_url: String,
    ) -> Arc<Self> {
        let state = Arc::get_mut(&mut self).expect("with_oidc called on a shared CsState");
        for cfg in providers {
            state
                .auth_providers
                .push(services::auth::AuthProvider::Oidc(
                    services::oidc::OidcProvider::new(cfg),
                ));
        }
        state.sso = Some(services::oidc::SsoRuntime::new(public_base_url));
        self
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
        account, admin, backup, health, keys, media, push, relations, rooms, search, session,
        spaces, sso, sync, to_device,
    };

    let mut app = axum::Router::new()
        .route(
            "/_matrix/client/versions",
            get(session::get_supported_versions),
        )
        .route(
            "/.well-known/matrix/client",
            get(session::well_known_client),
        )
        // The IdP's redirect target. Our own namespace, not `/_matrix`:
        // it is not a spec endpoint, and the spec leaves the callback
        // URL entirely to the server (decision 1).
        .route("/_saltator/client/oidc/callback", get(sso::oidc_callback))
        // Probes. Unauthenticated: whatever fronts this node holds no
        // token, and the bodies say nothing a prober should not see.
        .route("/_saltator/health/live", get(health::live))
        .route("/_saltator/health/ready", get(health::ready));

    // Endpoints under both `/r0` (legacy) and `/v3` prefixes.
    for prefix in ["/_matrix/client/r0", "/_matrix/client/v3"] {
        let p = |suffix: &str| format!("{prefix}{suffix}");
        app = app
            // -- session / account
            .route(&p("/capabilities"), get(session::get_capabilities))
            .route(&p("/register"), post(session::register))
            .route(&p("/register/available"), get(session::register_available))
            .route(&p("/login"), get(session::get_login_types))
            .route(&p("/login/sso/redirect"), get(sso::sso_redirect))
            .route(
                &p("/login/sso/redirect/{idp_id}"),
                get(sso::sso_redirect_idp),
            )
            .route(
                &p("/auth/m.login.sso/fallback/web"),
                get(sso::sso_fallback_web),
            )
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
        )
        .route(
            "/_matrix/client/v1/register/m.login.registration_token/validity",
            get(session::registration_token_validity),
        )
        .route(
            "/_matrix/client/v1/appservice/{appservice_id}/ping",
            post(routes::appservice::ping),
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

    // -- admin API. Our own namespace: no
    // `_synapse`-prefixed paths and no aliases for other servers' admin
    // tooling. Registered before the CORS layer deliberately — the admin
    // console may be served from a separate listener, and cross-origin
    // bearer-token calls need the same permissive treatment as the rest
    // of the API (there are no cookies anywhere, so this grants a browser
    // nothing it did not already hold a token for).
    app = app
        .route("/_saltator/admin/v1/users", get(admin::list_users))
        .route(
            "/_saltator/admin/v1/users/{user_id}",
            get(admin::user_detail),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/lock",
            post(admin::lock_user),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/unlock",
            post(admin::unlock_user),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/deactivate",
            post(admin::deactivate_user),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/reset_password",
            post(admin::reset_password),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/admin",
            put(admin::set_admin),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/devices",
            delete(admin::delete_all_devices),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/devices/{device_id}",
            delete(admin::delete_device),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/external_ids/{auth_provider}",
            put(admin::link_external_id).delete(admin::unlink_external_id),
        )
        .route(
            "/_saltator/admin/v1/auth_providers/{auth_provider}/users/{external_id}",
            get(admin::lookup_external_id),
        )
        .route(
            "/_saltator/admin/v1/users/{user_id}/notice",
            post(admin::send_notice),
        )
        .route(
            "/_saltator/admin/v1/cluster/nodes",
            get(admin::list_cluster_nodes),
        )
        .route(
            "/_saltator/admin/v1/cluster/nodes/{node_id}",
            delete(admin::remove_cluster_node),
        )
        .route(
            "/_saltator/admin/v1/cluster/nodes/{node_id}/drain",
            post(admin::drain_node),
        )
        .route(
            "/_saltator/admin/v1/cluster/nodes/{node_id}/undrain",
            post(admin::undrain_node),
        )
        .route("/_saltator/admin/v1/rooms", get(admin::list_rooms))
        .route(
            "/_saltator/admin/v1/rooms/{room_id}",
            get(admin::room_detail).delete(admin::shutdown_room),
        )
        .route(
            "/_saltator/admin/v1/rooms/{room_id}/block",
            put(admin::set_room_blocked),
        )
        .route(
            "/_saltator/admin/v1/blocked_rooms",
            get(admin::list_blocked_rooms),
        )
        .route(
            "/_saltator/admin/v1/registration_tokens",
            get(admin::list_registration_tokens).post(admin::create_registration_token),
        )
        .route(
            "/_saltator/admin/v1/registration_tokens/{token}",
            get(admin::get_registration_token).delete(admin::delete_registration_token),
        );

    let app = app
        .fallback(unrecognized)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    // The console mounts AFTER the CORS layer, and that placement is the
    // whole opt-out: `Router::layer` applies only to routes registered
    // before it, so `Access-Control-Allow-Origin: *` never lands on the
    // console's responses. The permissive layer exists for Matrix
    // clients; an admin console has no reason to be readable
    // cross-origin.
    //
    // `nest`, not `merge`: axum panics when merging two routers that both
    // carry a fallback, and the root has one (`unrecognized`). Nesting
    // gives the SPA its own inner fallback for client-side routes without
    // disturbing `M_UNRECOGNIZED` on `/_matrix/*`.
    #[cfg(feature = "admin-ui")]
    let app = app
        .nest(ADMIN_UI_PREFIX, saltator_admin_ui::router())
        // `nest` covers the bare prefix and `/{*rest}`, and a wildcard
        // needs at least one character — so the trailing-slash form, which
        // is exactly what the bundle's own asset URLs are relative to,
        // needs its own route.
        .route(
            &format!("{ADMIN_UI_PREFIX}/"),
            get(saltator_admin_ui::index),
        );

    app
}

/// Where the console is served. Under our own prefix, beside the API it
/// drives — the UI rides wherever the admin API rides, so same-origin
/// holds on the shared client listener and on the optional separate admin
/// listener alike.
#[cfg(feature = "admin-ui")]
pub const ADMIN_UI_PREFIX: &str = "/_saltator/admin/ui";

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
