//! Admin / user-management domain logic (docs/design-admin-identity.md):
//! the operator's view of accounts. No HTTP anywhere; routes call this.
//!
//! Authorization is *not* here — it is resolved once in
//! [`crate::CsState::is_admin`] and enforced by the `AdminAuth` extractor,
//! so this service assumes the caller is already privileged.

use std::sync::Arc;

use saltator_userserver::{AccountState, UserServer};
use serde::Serialize;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// Default and maximum page sizes for the user list. The cap exists
/// because the store's paginated reader is the only account enumeration
/// path; a caller asking for everything at once should not get it.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// The admin service. Borrow-cheap: construct per call site via
/// [`crate::CsState::admin`].
pub(crate) struct Admin<'a> {
    pub users: &'a Arc<UserServer>,
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
    pub fn list_users(&self, from: Option<&str>, limit: Option<usize>) -> Result<UserList> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let store = self.users.store();
        let (rows, next_from) = store.accounts(from, limit).map_err(ApiError::internal)?;
        let mut users = Vec::with_capacity(rows.len());
        for (user_id, account) in rows {
            let displayname = store
                .profile(&user_id)
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
    pub fn user_detail(&self, user_id: &str) -> Result<UserDetail> {
        let store = self.users.store();
        let account = store
            .account(user_id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::not_found("Unknown user"))?;
        let profile = store.profile(user_id).map_err(ApiError::internal)?;
        let mut devices: Vec<DeviceSummary> = store
            .devices(user_id)
            .map_err(ApiError::internal)?
            .into_iter()
            .map(|(device_id, d)| DeviceSummary {
                device_id,
                display_name: d.display_name,
                created_ts: d.created_ts,
            })
            .collect();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
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
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use saltator_shard::NoopNetworkFactory;
    use saltator_store::RocksEngine;
    use saltator_userserver::UserServer;

    use super::{AccountState, Admin};

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
        let admin = Admin { users: &users };

        let first = admin.list_users(None, Some(2)).unwrap();
        let ids: Vec<&str> = first.users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, ["@alice:hs.test", "@bob:hs.test"]);
        assert_eq!(first.next_from.as_deref(), Some("@carol:hs.test"));

        let second = admin
            .list_users(first.next_from.as_deref(), Some(2))
            .unwrap();
        let ids: Vec<&str> = second.users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, ["@carol:hs.test", "@dave:hs.test"]);

        let last = admin
            .list_users(second.next_from.as_deref(), Some(2))
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
        let page = Admin { users: &users }.list_users(None, Some(2)).unwrap();
        assert_eq!(page.users.len(), 2);
        assert!(page.next_from.is_none());
    }

    #[tokio::test]
    async fn detail_reports_profile_devices_and_credential() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let detail = Admin { users: &users }
            .user_detail("@alice:hs.test")
            .unwrap();

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
        let detail = Admin { users: &users }
            .user_detail("@bridge:hs.test")
            .unwrap();
        assert!(!detail.has_password);
        assert_eq!(detail.summary.state, AccountState::Active);
    }

    #[tokio::test]
    async fn deactivation_shows_in_list_and_detail() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
        users.deactivate(&alice).await.unwrap();

        let admin = Admin { users: &users };
        assert_eq!(
            admin.user_detail("@alice:hs.test").unwrap().summary.state,
            AccountState::Deactivated
        );
        let page = admin.list_users(None, None).unwrap();
        assert_eq!(page.users[0].state, AccountState::Deactivated);
    }

    #[tokio::test]
    async fn unknown_user_is_not_found() {
        let (_dir, users) = stack().await;
        let err = Admin { users: &users }
            .user_detail("@nobody:hs.test")
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::NOT_FOUND);
    }

    /// An oversized `limit` is clamped rather than honoured — the paginated
    /// reader is the only enumeration path and must stay bounded.
    #[tokio::test]
    async fn limit_is_clamped() {
        let (_dir, users) = stack().await;
        register(&users, "alice", Some("pw")).await;
        let page = Admin { users: &users }
            .list_users(None, Some(usize::MAX))
            .unwrap();
        assert_eq!(page.users.len(), 1);
    }
}
