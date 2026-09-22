//! Admin / user-management domain logic:
//! the operator's view of accounts. No HTTP anywhere; routes call this.
//!
//! Authorization is *not* here — it is resolved once in
//! [`crate::CsState::is_admin`] and enforced by the `AdminAuth` extractor,
//! so this service assumes the caller is already privileged.

use std::sync::Arc;

use ruma::{OwnedUserId, UserId};
use saltator_userserver::{AccountState, UserServer};
use serde::Serialize;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// Default and maximum page sizes for the user list. The cap exists
/// because the store's paginated reader is the only account enumeration
/// path; a caller asking for everything at once should not get it.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// Longest accepted provider key or external id. Both are opaque strings
/// that end up in a storage key, so the cap is about keeping keys sane
/// rather than about any format.
const MAX_KEY_LEN: usize = 255;

/// Validate one half of an identity link. Both halves are opaque — a
/// provider key is a stable identifier chosen by the operator, an
/// external id is whatever the IdP calls the subject — so the only rules
/// are the ones the key encoding actually needs: non-empty, no NUL (the
/// link tables separate their key parts with one), and bounded.
fn opaque_key(what: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(ApiError::invalid_param(format!("{what} must not be empty")));
    }
    if value.len() > MAX_KEY_LEN {
        return Err(ApiError::invalid_param(format!(
            "{what} must be at most {MAX_KEY_LEN} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(ApiError::invalid_param(format!(
            "{what} must not contain NUL"
        )));
    }
    Ok(())
}

/// The admin service. Borrow-cheap: construct per call site via
/// [`crate::CsState::admin`].
pub(crate) struct Admin<'a> {
    pub users: &'a Arc<UserServer>,
    /// Administrators granted by config. Needed here so a revoke that
    /// could not possibly take effect is refused rather than silently
    /// succeeding.
    pub admin_users: &'a [OwnedUserId],
}

/// One row of the user list. Deliberately small — the list is for
/// finding an account, [`UserDetail`] is for inspecting one.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct UserSummary {
    pub user_id: String,
    pub displayname: Option<String>,
    pub admin: bool,
    pub state: AccountState,
    pub erased: bool,
    pub created_ts: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserList {
    pub users: Vec<UserSummary>,
    /// Start key of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_from: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserDetail {
    #[serde(flatten)]
    pub summary: UserSummary,
    pub avatar_url: Option<String>,
    /// Whether a local password is set. The hash itself is never exposed,
    /// and its absence means only "no local credential" — not that the
    /// account is external or disabled.
    pub has_password: bool,
    pub devices: Vec<DeviceSummary>,
    /// Identity-provider links (slice 4). Empty until an operator writes
    /// one; nothing reads them until the OIDC slice.
    pub external_ids: Vec<ExternalIdEntry>,
}

/// One identity-provider link on an account.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ExternalIdEntry {
    pub auth_provider: String,
    pub external_id: String,
}

/// The answer to "who is this subject?" — the reverse lookup an operator
/// does when an IdP shows them a `sub` they cannot place.
#[derive(Debug, Serialize)]
pub(crate) struct ExternalIdOwner {
    pub auth_provider: String,
    pub external_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegTokenSummary {
    pub token: String,
    /// `None` = unlimited uses.
    pub uses_allowed: Option<u64>,
    pub used: u64,
    /// `None` = never expires.
    pub expiry_ts: Option<u64>,
    pub created_ts: u64,
    /// Whether the token would authorise a registration right now —
    /// computed, so an operator does not have to compare clocks and
    /// counters themselves.
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceSummary {
    pub device_id: String,
    pub display_name: Option<String>,
    pub created_ts: u64,
}

impl Admin<'_> {
    /// One page of accounts in user-id order, starting at `from`
    /// (inclusive).
    pub async fn list_users(&self, from: Option<&str>, limit: Option<usize>) -> Result<UserList> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let store = self.users.store();
        let (rows, next_from) = store
            .accounts(from, limit)
            .await
            .map_err(ApiError::internal)?;
        let mut users = Vec::with_capacity(rows.len());
        for (user_id, account) in rows {
            let displayname = store
                .profile(&user_id)
                .await
                .map_err(ApiError::internal)?
                .and_then(|p| p.displayname);
            users.push(UserSummary {
                user_id,
                displayname,
                admin: account.admin,
                state: account.state,
                erased: account.erased,
                created_ts: account.created_ts,
            });
        }
        Ok(UserList { users, next_from })
    }

    /// One account in full, or 404 if there is no such account.
    ///
    /// Note this is the *account* view: an appservice sender has no
    /// account row, so it is absent here even though it can authenticate.
    pub async fn user_detail(&self, user_id: &str) -> Result<UserDetail> {
        let store = self.users.store();
        let account = store
            .account(user_id)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::not_found("Unknown user"))?;
        let profile = store.profile(user_id).await.map_err(ApiError::internal)?;
        let mut devices: Vec<DeviceSummary> = store
            .devices(user_id)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .map(|(device_id, d)| DeviceSummary {
                device_id,
                display_name: d.display_name,
                created_ts: d.created_ts,
            })
            .collect();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let external_ids = store
            .external_ids(user_id)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .map(|(auth_provider, external_id)| ExternalIdEntry {
                auth_provider,
                external_id,
            })
            .collect();
        Ok(UserDetail {
            summary: UserSummary {
                user_id: user_id.to_owned(),
                displayname: profile.as_ref().and_then(|p| p.displayname.clone()),
                admin: account.admin,
                state: account.state,
                erased: account.erased,
                created_ts: account.created_ts,
            },
            avatar_url: profile.and_then(|p| p.avatar_url),
            has_password: account.password_hash.is_some(),
            devices,
            external_ids,
        })
    }

    /// Refuse an action that would strip the caller's own access.
    ///
    /// An administrator who locks, deactivates or demotes themselves has
    /// no way back through this API — the only recovery is editing config
    /// and restarting. Cheap to prevent, expensive to undo.
    fn not_self(actor: &UserId, target: &UserId, what: &str) -> Result<()> {
        if actor == target {
            return Err(ApiError::invalid_param(format!(
                "refusing to {what} your own account"
            )));
        }
        Ok(())
    }

    fn is_config_admin(&self, user: &UserId) -> bool {
        self.admin_users.iter().any(|u| u == user)
    }

    pub async fn set_locked(
        &self,
        actor: &UserId,
        target: &UserId,
        locked: bool,
    ) -> Result<UserDetail> {
        if locked {
            Self::not_self(actor, target, "lock")?;
        }
        self.users.set_locked(target, locked).await?;
        self.user_detail(target.as_str()).await
    }

    /// Deactivate, optionally marking the account erased.
    ///
    /// `erase` sets the marker and clears the profile. It does **not**
    /// redact the user's messages — that is not implemented, and calling
    /// this a complete erasure would be a lie to whoever is answering the
    /// data-subject request.
    pub async fn deactivate(
        &self,
        actor: &UserId,
        target: &UserId,
        erase: bool,
    ) -> Result<UserDetail> {
        Self::not_self(actor, target, "deactivate")?;
        self.users.deactivate(target).await?;
        if erase {
            self.users.set_erased(target).await?;
        }
        self.user_detail(target.as_str()).await
    }

    pub async fn set_admin(
        &self,
        actor: &UserId,
        target: &UserId,
        admin: bool,
    ) -> Result<UserDetail> {
        if !admin {
            Self::not_self(actor, target, "revoke administrator rights from")?;
            // The stored flag is only half the grant; clearing it while
            // config still names the user would report success and change
            // nothing an operator can observe.
            if self.is_config_admin(target) {
                return Err(ApiError::invalid_param(format!(
                    "{target} is an administrator via server config; \
                     remove them from client.admin_users instead"
                )));
            }
        }
        self.users.set_admin(target, admin).await?;
        self.user_detail(target.as_str()).await
    }

    pub async fn reset_password(
        &self,
        target: &UserId,
        new_password: &str,
        logout_devices: bool,
    ) -> Result<UserDetail> {
        if new_password.is_empty() {
            return Err(ApiError::invalid_param("password must not be empty"));
        }
        self.users
            .admin_set_password(target, new_password, logout_devices)
            .await?;
        self.user_detail(target.as_str()).await
    }

    // -- registration tokens ---------------------------------------------

    pub fn list_registration_tokens(&self) -> Result<Vec<RegTokenSummary>> {
        let now = crate::now_ms();
        let mut out: Vec<RegTokenSummary> = self
            .users
            .store()
            .registration_tokens()
            .map_err(ApiError::internal)?
            .into_iter()
            .map(|(token, t)| RegTokenSummary {
                valid: t.usable(now),
                token,
                uses_allowed: t.uses_allowed,
                used: t.used,
                expiry_ts: t.expiry_ts,
                created_ts: t.created_ts,
            })
            .collect();
        out.sort_by(|a, b| a.token.cmp(&b.token));
        Ok(out)
    }

    pub async fn create_registration_token(
        &self,
        token: Option<String>,
        uses_allowed: Option<u64>,
        expiry_ts: Option<u64>,
    ) -> Result<RegTokenSummary> {
        // A server-minted token is the safer default: an operator picking
        // one by hand tends to pick a guessable one.
        let token = match token {
            Some(t) if t.is_empty() => {
                return Err(ApiError::invalid_param("token must not be empty"))
            }
            Some(t) => t,
            None => saltator_userserver::generate_token(),
        };
        if let Some(expiry) = expiry_ts {
            if expiry <= crate::now_ms() {
                return Err(ApiError::invalid_param("expiry_ts is already in the past"));
            }
        }
        self.users
            .create_registration_token(&token, uses_allowed, expiry_ts)
            .await?;
        self.registration_token(&token)
    }

    pub fn registration_token(&self, token: &str) -> Result<RegTokenSummary> {
        let entry = self
            .users
            .store()
            .registration_token(token)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::not_found("Unknown registration token"))?;
        Ok(RegTokenSummary {
            valid: entry.usable(crate::now_ms()),
            token: token.to_owned(),
            uses_allowed: entry.uses_allowed,
            used: entry.used,
            expiry_ts: entry.expiry_ts,
            created_ts: entry.created_ts,
        })
    }

    pub async fn delete_registration_token(&self, token: &str) -> Result<()> {
        Ok(self.users.delete_registration_token(token).await?)
    }

    // -- identity links (slice 4) ----------------------------------------

    /// Link an account to its subject at an identity provider.
    ///
    /// Deliberately allowed before any provider is configured: Synapse's
    /// own docstring notes external ids "are not validated against
    /// configured IdPs… it might be useful to pre-configure users before
    /// enabling a new IdP", and that pre-link-then-switch-on path is how
    /// this deployment avoids a flag day when OIDC arrives.
    pub async fn link_external_id(
        &self,
        target: &UserId,
        auth_provider: &str,
        external_id: &str,
    ) -> Result<UserDetail> {
        opaque_key("auth_provider", auth_provider)?;
        opaque_key("external_id", external_id)?;
        self.users
            .link_external_id(target, auth_provider, external_id)
            .await?;
        self.user_detail(target.as_str()).await
    }

    /// Drop an account's link to one provider.
    ///
    /// Works on a deactivated account, which is the point: deactivation
    /// leaves links in place so a dead account's subject is not silently
    /// recycled, and this is the deliberate act that frees it.
    pub async fn unlink_external_id(
        &self,
        target: &UserId,
        auth_provider: &str,
    ) -> Result<UserDetail> {
        opaque_key("auth_provider", auth_provider)?;
        self.users.unlink_external_id(target, auth_provider).await?;
        self.user_detail(target.as_str()).await
    }

    /// Reverse lookup: the account behind a provider's subject.
    pub fn lookup_external_id(
        &self,
        auth_provider: &str,
        external_id: &str,
    ) -> Result<ExternalIdOwner> {
        opaque_key("auth_provider", auth_provider)?;
        opaque_key("external_id", external_id)?;
        let user_id = self
            .users
            .store()
            .external_id_owner(auth_provider, external_id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::not_found("No account is linked to that identity"))?;
        Ok(ExternalIdOwner {
            auth_provider: auth_provider.to_owned(),
            external_id: external_id.to_owned(),
            user_id,
        })
    }

    /// Revoke one session, or every session when `device_id` is `None`.
    pub async fn delete_devices(
        &self,
        target: &UserId,
        device_id: Option<&str>,
    ) -> Result<UserDetail> {
        // The account has to exist first: deleting devices of an unknown
        // user otherwise reports success against nothing.
        self.user_detail(target.as_str()).await?;
        match device_id {
            Some(id) => self.users.delete_device(target, id).await?,
            None => self.users.delete_all_devices(target).await?,
        }
        self.user_detail(target.as_str()).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use saltator_shard::NoopNetworkFactory;
    use saltator_store::RocksEngine;
    use saltator_userserver::UserServer;

    use super::{AccountState, Admin, ExternalIdEntry};

    const SERVER: &str = "hs.test";

    /// A bare user shard — the admin service reads accounts, profiles and
    /// devices and nothing else, so no rooms or delivery are needed.
    async fn stack() -> (tempfile::TempDir, Arc<UserServer>) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
        let users = UserServer::start(
            1,
            engine,
            ruma::OwnedServerName::try_from(SERVER).unwrap(),
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        users
            .shard_handle()
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        (dir, users)
    }

    /// A service with no config-named administrators — the default for
    /// tests that are not about the bootstrap allowlist.
    fn admin(users: &Arc<UserServer>) -> Admin<'_> {
        Admin {
            users,
            admin_users: &[],
        }
    }

    fn uid(localpart: &str) -> ruma::OwnedUserId {
        ruma::OwnedUserId::try_from(format!("@{localpart}:{SERVER}")).unwrap()
    }

    async fn register(users: &Arc<UserServer>, localpart: &str, password: Option<&str>) {
        users
            .register(localpart, password, None, None, false, false)
            .await
            .unwrap();
    }

    /// Pages are user-id ordered, `next_from` is the first key of the next
    /// page (not the last of this one), and the final page omits it.
    #[tokio::test]
    async fn list_users_paginates_in_order() {
        let (_dir, users) = stack().await;
        for lp in ["carol", "alice", "bob", "dave", "erin"] {
            register(&users, lp, Some("pw")).await;
        }
        let admin = admin(&users);

        let first = admin.list_users(None, Some(2)).await.unwrap();
        let ids: Vec<&str> = first.users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, ["@alice:hs.test", "@bob:hs.test"]);
        assert_eq!(first.next_from.as_deref(), Some("@carol:hs.test"));

        let second = admin
            .list_users(first.next_from.as_deref(), Some(2))
            .await
            .unwrap();
        let ids: Vec<&str> = second.users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, ["@carol:hs.test", "@dave:hs.test"]);

        let last = admin
            .list_users(second.next_from.as_deref(), Some(2))
            .await
            .unwrap();
        let ids: Vec<&str> = last.users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, ["@erin:hs.test"]);
        assert!(
            last.next_from.is_none(),
            "the final page must not advertise another"
        );
    }

    /// A page exactly filling the limit still reports no next page when
    /// nothing follows — the off-by-one that would make clients loop.
    #[tokio::test]
    async fn exact_fit_page_has_no_next() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        register(&users, "bob", Some("pw")).await;
        let page = admin(&users).list_users(None, Some(2)).await.unwrap();
        assert_eq!(page.users.len(), 2);
        assert!(page.next_from.is_none());
    }

    #[tokio::test]
    async fn detail_reports_profile_devices_and_credential() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let detail = admin(&users).user_detail("@alice:hs.test").await.unwrap();

        assert_eq!(detail.summary.state, AccountState::Active);
        assert!(!detail.summary.admin);
        // register() defaults the displayname to the localpart.
        assert_eq!(detail.summary.displayname.as_deref(), Some("alice"));
        assert!(detail.has_password);
        assert_eq!(detail.devices.len(), 1, "register mints one device");
    }

    /// `has_password` says "there is a local credential" and nothing more:
    /// a passwordless account is not thereby disabled or external.
    #[tokio::test]
    async fn passwordless_account_is_active_without_credential() {
        let (_dir, users) = stack().await;
        register(&users, "bridge", None).await;
        let detail = admin(&users).user_detail("@bridge:hs.test").await.unwrap();
        assert!(!detail.has_password);
        assert_eq!(detail.summary.state, AccountState::Active);
    }

    #[tokio::test]
    async fn deactivation_shows_in_list_and_detail() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
        users.deactivate(&alice).await.unwrap();

        let admin = admin(&users);
        assert_eq!(
            admin
                .user_detail("@alice:hs.test")
                .await
                .unwrap()
                .summary
                .state,
            AccountState::Deactivated
        );
        let page = admin.list_users(None, None).await.unwrap();
        assert_eq!(page.users[0].state, AccountState::Deactivated);
    }

    #[tokio::test]
    async fn unknown_user_is_not_found() {
        let (_dir, users) = stack().await;
        let err = admin(&users)
            .user_detail("@nobody:hs.test")
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::NOT_FOUND);
    }

    /// An oversized `limit` is clamped rather than honoured — the paginated
    /// reader is the only enumeration path and must stay bounded.
    #[tokio::test]
    async fn limit_is_clamped() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let page = admin(&users)
            .list_users(None, Some(usize::MAX))
            .await
            .unwrap();
        assert_eq!(page.users.len(), 1);
    }

    // -- lifecycle (slice 2) ---------------------------------------------

    /// Locking is reversible and non-destructive: the device survives, so
    /// unlocking restores the session rather than requiring a fresh login.
    #[tokio::test]
    async fn lock_is_reversible_and_keeps_devices() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let (root, alice) = (uid("root"), uid("alice"));

        let locked = admin(&users).set_locked(&root, &alice, true).await.unwrap();
        assert_eq!(locked.summary.state, AccountState::Locked);
        assert_eq!(locked.devices.len(), 1, "lock must not tear down sessions");

        let unlocked = admin(&users)
            .set_locked(&root, &alice, false)
            .await
            .unwrap();
        assert_eq!(unlocked.summary.state, AccountState::Active);
        assert_eq!(unlocked.devices.len(), 1);
    }

    /// Deactivation is terminal — unlocking must not resurrect an account.
    #[tokio::test]
    async fn deactivated_cannot_be_unlocked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let (root, alice) = (uid("root"), uid("alice"));
        admin(&users)
            .deactivate(&root, &alice, false)
            .await
            .unwrap();

        let err = admin(&users)
            .set_locked(&root, &alice, false)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            admin(&users)
                .user_detail(alice.as_str())
                .await
                .unwrap()
                .summary
                .state,
            AccountState::Deactivated
        );
    }

    /// Deactivation clears the credential and every session.
    #[tokio::test]
    async fn deactivate_tears_down_credential_and_sessions() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let detail = admin(&users)
            .deactivate(&uid("root"), &uid("alice"), false)
            .await
            .unwrap();
        assert_eq!(detail.summary.state, AccountState::Deactivated);
        assert!(!detail.has_password);
        assert!(detail.devices.is_empty());
        assert!(!detail.summary.erased, "erase is opt-in");
    }

    /// Erasure sets the marker and drops the profile. It does not redact
    /// messages — that is unimplemented, and this test documents the
    /// boundary rather than pretending otherwise.
    #[tokio::test]
    async fn erase_marks_and_clears_profile() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let detail = admin(&users)
            .deactivate(&uid("root"), &uid("alice"), true)
            .await
            .unwrap();
        assert!(detail.summary.erased);
        assert_eq!(detail.summary.displayname, None);
        assert_eq!(detail.avatar_url, None);
    }

    /// Erasing a live account would leave it able to log in, so the state
    /// machine refuses it outright.
    #[tokio::test]
    async fn erase_requires_deactivation() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let err = users.set_erased(&uid("alice")).await.unwrap_err();
        assert!(matches!(err, saltator_userserver::UserError::InvalidState));
    }

    #[tokio::test]
    async fn reset_password_revokes_sessions_when_asked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = uid("alice");

        let kept = admin(&users)
            .reset_password(&alice, "new-password", false)
            .await
            .unwrap();
        assert!(kept.has_password);
        assert_eq!(kept.devices.len(), 1, "logout_devices=false keeps them");

        let cleared = admin(&users)
            .reset_password(&alice, "newer-password", true)
            .await
            .unwrap();
        assert!(cleared.devices.is_empty());
        // The new password works.
        assert!(users
            .login_password("alice", "newer-password", None, None, false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn reset_password_refuses_deactivated_and_empty() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = uid("alice");

        let err = admin(&users)
            .reset_password(&alice, "", true)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);

        admin(&users)
            .deactivate(&uid("root"), &alice, false)
            .await
            .unwrap();
        let err = admin(&users)
            .reset_password(&alice, "anything", true)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    /// A locked account still accepts an admin password reset: the usual
    /// order is reset, then unlock.
    #[tokio::test]
    async fn reset_password_works_while_locked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let (root, alice) = (uid("root"), uid("alice"));
        admin(&users).set_locked(&root, &alice, true).await.unwrap();
        assert!(admin(&users)
            .reset_password(&alice, "new-password", true)
            .await
            .is_ok());
    }

    /// The three self-targeting actions that would strip the caller's own
    /// access are refused; the recoverable one (unlock) is not.
    #[tokio::test]
    async fn refuses_to_strip_the_callers_own_access() {
        let (_dir, users) = stack().await;
        register(&users, "root", Some("pw")).await;
        let root = uid("root");
        let svc = admin(&users);

        for err in [
            svc.set_locked(&root, &root, true).await.unwrap_err(),
            svc.deactivate(&root, &root, false).await.unwrap_err(),
            svc.set_admin(&root, &root, false).await.unwrap_err(),
        ] {
            assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        }
        // Still active: none of the refusals half-applied.
        assert_eq!(
            svc.user_detail(root.as_str()).await.unwrap().summary.state,
            AccountState::Active
        );
        // Granting to self is harmless and allowed.
        assert!(svc.set_admin(&root, &root, true).await.is_ok());
    }

    /// Revoking the stored flag from a config-named admin would report
    /// success and change nothing observable, so it is refused instead.
    #[tokio::test]
    async fn refuses_to_revoke_a_config_granted_admin() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = uid("alice");
        let svc = Admin {
            users: &users,
            admin_users: std::slice::from_ref(&alice),
        };
        let err = svc
            .set_admin(&uid("root"), &alice, false)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("admin_users"));
    }

    #[tokio::test]
    async fn admin_flag_round_trips() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let (root, alice) = (uid("root"), uid("alice"));
        let svc = admin(&users);
        assert!(
            svc.set_admin(&root, &alice, true)
                .await
                .unwrap()
                .summary
                .admin
        );
        assert!(
            !svc.set_admin(&root, &alice, false)
                .await
                .unwrap()
                .summary
                .admin
        );
    }

    /// Device revocation against an unknown account is a 404, not a
    /// success against nothing.
    #[tokio::test]
    async fn device_revocation_needs_a_real_account() {
        let (_dir, users) = stack().await;
        let err = admin(&users)
            .delete_devices(&uid("nobody"), None)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::NOT_FOUND);
    }

    // -- identity links (slice 4) ----------------------------------------

    /// A link is written to both indices: it shows on the account, and the
    /// reverse lookup finds the account from the subject.
    #[tokio::test]
    async fn link_is_visible_from_both_directions() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);

        let detail = svc
            .link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap();
        assert_eq!(
            detail.external_ids,
            [ExternalIdEntry {
                auth_provider: "oidc-keycloak".to_owned(),
                external_id: "sub-1".to_owned(),
            }]
        );

        let owner = svc.lookup_external_id("oidc-keycloak", "sub-1").unwrap();
        assert_eq!(owner.user_id, "@alice:hs.test");
        assert_eq!(
            svc.lookup_external_id("oidc-keycloak", "sub-2")
                .unwrap_err()
                .status,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    /// One account may be linked at several providers; the links are
    /// independent and provider-ordered.
    #[tokio::test]
    async fn one_account_links_to_several_providers() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        svc.link_external_id(&uid("alice"), "oidc-okta", "okta-9")
            .await
            .unwrap();
        let detail = svc
            .link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap();
        let pairs: Vec<(&str, &str)> = detail
            .external_ids
            .iter()
            .map(|e| (e.auth_provider.as_str(), e.external_id.as_str()))
            .collect();
        assert_eq!(pairs, [("oidc-keycloak", "sub-1"), ("oidc-okta", "okta-9")]);
    }

    /// Relinking the same account at the same provider replaces the
    /// subject — and releases the old one. A forward row left behind would
    /// reserve a subject nobody could ever claim again.
    #[tokio::test]
    async fn relinking_replaces_and_releases_the_old_subject() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        svc.link_external_id(&uid("alice"), "oidc-keycloak", "old-sub")
            .await
            .unwrap();
        let detail = svc
            .link_external_id(&uid("alice"), "oidc-keycloak", "new-sub")
            .await
            .unwrap();

        assert_eq!(detail.external_ids.len(), 1, "one link per provider");
        assert_eq!(detail.external_ids[0].external_id, "new-sub");
        assert_eq!(
            users
                .store()
                .external_id_owner("oidc-keycloak", "old-sub")
                .unwrap(),
            None,
            "the superseded forward row must be gone"
        );
    }

    /// Linking is idempotent: the same pair twice is not a conflict with
    /// itself.
    #[tokio::test]
    async fn relinking_the_same_pair_is_idempotent() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        for _ in 0..2 {
            svc.link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
                .await
                .unwrap();
        }
        let detail = svc.user_detail("@alice:hs.test").await.unwrap();
        assert_eq!(detail.external_ids.len(), 1);
    }

    /// A subject already claimed by another account is refused, and the
    /// refusal names the holder — the operator is privileged enough to
    /// know, and "conflict" without a subject is unactionable.
    #[tokio::test]
    async fn a_subject_belongs_to_exactly_one_account() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        register(&users, "bob", Some("pw")).await;
        let svc = admin(&users);
        svc.link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap();

        let err = svc
            .link_external_id(&uid("bob"), "oidc-keycloak", "sub-1")
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT);
        assert!(err.message.contains("@alice:hs.test"), "{}", err.message);
        // The refusal is total: bob gained nothing, alice lost nothing.
        assert!(svc
            .user_detail("@bob:hs.test")
            .await
            .unwrap()
            .external_ids
            .is_empty());
        assert_eq!(
            svc.lookup_external_id("oidc-keycloak", "sub-1")
                .unwrap()
                .user_id,
            "@alice:hs.test"
        );
    }

    /// Unlinking clears both indices, and doing it twice is a 404 rather
    /// than a silent success.
    #[tokio::test]
    async fn unlink_clears_both_indices() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        svc.link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap();

        let detail = svc
            .unlink_external_id(&uid("alice"), "oidc-keycloak")
            .await
            .unwrap();
        assert!(detail.external_ids.is_empty());
        assert_eq!(
            users
                .store()
                .external_id_owner("oidc-keycloak", "sub-1")
                .unwrap(),
            None
        );
        assert_eq!(
            svc.unlink_external_id(&uid("alice"), "oidc-keycloak")
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    /// Deactivation leaves links alone, so a dead account's subject is not
    /// silently recycled into a new account by the next SSO login. An
    /// explicit unlink is the deliberate act that frees it.
    #[tokio::test]
    async fn deactivation_keeps_the_link_until_it_is_unlinked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        register(&users, "bob", Some("pw")).await;
        let svc = admin(&users);
        svc.link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap();
        svc.deactivate(&uid("root"), &uid("alice"), false)
            .await
            .unwrap();

        assert_eq!(
            svc.lookup_external_id("oidc-keycloak", "sub-1")
                .unwrap()
                .user_id,
            "@alice:hs.test",
            "deactivation must not release the subject"
        );
        // And a new account cannot take it over by accident...
        assert_eq!(
            svc.link_external_id(&uid("bob"), "oidc-keycloak", "sub-1")
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::CONFLICT
        );
        // ...only after the operator unlinks it deliberately.
        svc.unlink_external_id(&uid("alice"), "oidc-keycloak")
            .await
            .unwrap();
        assert!(svc
            .link_external_id(&uid("bob"), "oidc-keycloak", "sub-1")
            .await
            .is_ok());
    }

    /// A deactivated account gains no new links: the state is terminal,
    /// and a link written now would still be there when the IdP is
    /// switched on.
    #[tokio::test]
    async fn deactivated_accounts_cannot_be_linked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        svc.deactivate(&uid("root"), &uid("alice"), false)
            .await
            .unwrap();
        let err = svc
            .link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }

    /// A locked account can be linked: locking is a temporary auth
    /// kill-switch, not a teardown, and pre-linking a locked user is a
    /// reasonable thing to do before unlocking them.
    #[tokio::test]
    async fn locked_accounts_can_be_linked() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        svc.set_locked(&uid("root"), &uid("alice"), true)
            .await
            .unwrap();
        assert!(svc
            .link_external_id(&uid("alice"), "oidc-keycloak", "sub-1")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn linking_an_unknown_account_is_not_found() {
        let (_dir, users) = stack().await;
        let err = admin(&users)
            .link_external_id(&uid("nobody"), "oidc-keycloak", "sub-1")
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::NOT_FOUND);
    }

    /// The two halves of a link are opaque, but they land in a storage key
    /// whose parts are NUL-separated — so empty, oversized and
    /// NUL-bearing values are refused at the boundary rather than
    /// corrupting a key.
    #[tokio::test]
    async fn link_halves_are_validated() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let svc = admin(&users);
        let alice = uid("alice");
        let long = "x".repeat(256);

        for (provider, external_id) in [
            ("", "sub-1"),
            ("oidc-keycloak", ""),
            ("oidc\0keycloak", "sub-1"),
            ("oidc-keycloak", "sub\0-1"),
            (long.as_str(), "sub-1"),
            ("oidc-keycloak", long.as_str()),
        ] {
            let err = svc
                .link_external_id(&alice, provider, external_id)
                .await
                .unwrap_err();
            assert_eq!(
                err.status,
                axum::http::StatusCode::BAD_REQUEST,
                "{provider:?}/{external_id:?} should be refused"
            );
        }
        assert!(svc
            .user_detail(alice.as_str())
            .await
            .unwrap()
            .external_ids
            .is_empty());
    }

    #[tokio::test]
    async fn device_revocation_removes_sessions() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = uid("alice");
        let before = admin(&users).user_detail(alice.as_str()).await.unwrap();
        let device = before.devices[0].device_id.clone();

        let after = admin(&users)
            .delete_devices(&alice, Some(&device))
            .await
            .unwrap();
        assert!(after.devices.is_empty());
        // The account itself is untouched — revoking a session is not a lock.
        assert_eq!(after.summary.state, AccountState::Active);
    }
}
