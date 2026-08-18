//! Authentication (docs/design-admin-identity.md slice 4): which login
//! flows this server offers, and verifying a presented credential against
//! one of them. No HTTP anywhere; routes call this.
//!
//! This is the seam an external identity provider drops into. Before it,
//! `GET /login` returned a literal `vec![LoginType::Password]` and `login`
//! rejected everything that was not `LoginInfo::Password`, so adding a
//! second way to authenticate meant editing both. Now both derive from
//! [`Authn::providers`], and the OIDC slice adds a variant and its arms.
//!
//! What stays outside: session minting. Tokens and devices are ours in
//! either world — an IdP proves *who* the user is, and this server then
//! issues its own access token exactly as it does today. That is
//! precisely what not delegating to MAS buys, so `login` still ends in
//! `UserServer::login_password`'s session creation and nowhere else.

use std::sync::Arc;

use ruma::api::client::session::get_login_types::v3::{LoginType, PasswordLoginType};
use ruma::api::client::session::login::v3::LoginInfo;
use ruma::api::client::uiaa::UserIdentifier;
use saltator_userserver::{Session, UserServer};

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// One configured way to prove an identity.
///
/// A single variant today, deliberately: local passwords are the only
/// credential this server can verify. The OIDC slice adds
/// `Oidc { idp_id, .. }` here, built from its own config block, and the
/// two `match`es below gain an arm each — no existing path is edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProvider {
    /// Argon2 password hashes held in this server's own account records.
    LocalPassword,
}

/// The authentication service. Borrow-cheap: construct per call site via
/// [`crate::CsState::authn`].
pub(crate) struct Authn<'a> {
    pub users: &'a Arc<UserServer>,
    /// The providers this server has configured. Passed in rather than
    /// assumed so the advertisement and the login path cannot disagree
    /// about what is on offer.
    pub providers: &'a [AuthProvider],
}

impl Authn<'_> {
    fn offers(&self, provider: AuthProvider) -> bool {
        self.providers.contains(&provider)
    }

    /// The flows for `GET /login`, in configured order. With only local
    /// passwords this is byte-identical to the literal it replaced.
    pub fn login_types(&self) -> Vec<LoginType> {
        self.providers
            .iter()
            .map(|p| match p {
                AuthProvider::LocalPassword => LoginType::Password(PasswordLoginType::new()),
            })
            .collect()
    }

    /// The account a login attempt names, before any credential is
    /// checked. The route needs this to key the rate limiter, which has
    /// to run *before* the expensive verify — so identifying and
    /// verifying are separate calls rather than one.
    ///
    /// May be a localpart or a full user id: canonicalisation belongs to
    /// the user server, which accepts both.
    pub fn identify(&self, info: &LoginInfo) -> Result<String> {
        match info {
            LoginInfo::Password(pw) => {
                #[allow(deprecated)]
                match (&pw.identifier, &pw.user) {
                    (Some(UserIdentifier::Matrix(m)), _) => Ok(m.user.clone()),
                    // The pre-1.1 top-level `user` field, still sent by
                    // old clients.
                    (None, Some(u)) => Ok(u.clone()),
                    _ => Err(ApiError::forbidden("Unsupported identifier type")),
                }
            }
            _ => Err(unsupported_login_type()),
        }
    }

    /// Verify a credential and mint a session for it.
    pub async fn login(
        &self,
        info: &LoginInfo,
        device_id: Option<String>,
        display_name: Option<String>,
        want_refresh: bool,
    ) -> Result<Session> {
        match info {
            LoginInfo::Password(pw) => {
                if !self.offers(AuthProvider::LocalPassword) {
                    return Err(unsupported_login_type());
                }
                let user = self.identify(info)?;
                Ok(self
                    .users
                    .login_password(&user, &pw.password, device_id, display_name, want_refresh)
                    .await?)
            }
            _ => Err(unsupported_login_type()),
        }
    }
}

/// A login type this server does not offer. The same message whether the
/// type is unknown or merely unconfigured: which providers are enabled is
/// what `GET /login` is for, and a failed login should not be a second,
/// noisier channel for it.
fn unsupported_login_type() -> ApiError {
    ApiError::forbidden("Unsupported login type")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ruma::api::client::session::login::v3::{LoginInfo, Password};
    use ruma::api::client::uiaa::{MatrixUserIdentifier, UserIdentifier};
    use saltator_shard::NoopNetworkFactory;
    use saltator_store::RocksEngine;
    use saltator_userserver::UserServer;

    use super::{AuthProvider, Authn};

    const SERVER: &str = "hs.test";
    const LOCAL: &[AuthProvider] = &[AuthProvider::LocalPassword];

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

    fn password_login(user: &str, password: &str) -> LoginInfo {
        LoginInfo::Password(Password::new(
            UserIdentifier::Matrix(MatrixUserIdentifier::new(user.to_owned())),
            password.to_owned(),
        ))
    }

    /// The advertisement is derived, not literal: it follows the provider
    /// list in both directions.
    #[tokio::test]
    async fn login_types_follow_the_configured_providers() {
        let (_dir, users) = stack().await;
        let offered = Authn {
            users: &users,
            providers: LOCAL,
        }
        .login_types();
        assert_eq!(offered.len(), 1);
        assert!(matches!(
            offered[0],
            ruma::api::client::session::get_login_types::v3::LoginType::Password(_)
        ));

        let none = Authn {
            users: &users,
            providers: &[],
        }
        .login_types();
        assert!(none.is_empty(), "a server with no providers offers none");
    }

    /// And the login path agrees with the advertisement: a password login
    /// against a server that does not offer passwords is refused before
    /// the credential is looked at, correct password or not.
    #[tokio::test]
    async fn password_login_needs_the_password_provider() {
        let (_dir, users) = stack().await;
        users
            .register("alice", Some("pw-12345678"), None, None, false, false)
            .await
            .unwrap();

        let err = Authn {
            users: &users,
            providers: &[],
        }
        .login(&password_login("alice", "pw-12345678"), None, None, false)
        .await
        .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);

        assert!(Authn {
            users: &users,
            providers: LOCAL,
        }
        .login(&password_login("alice", "pw-12345678"), None, None, false)
        .await
        .is_ok());
    }

    /// Both identifier forms name the same account — the localpart and the
    /// full user id — because the rate limiter keys off this and must not
    /// see two attempts as unrelated.
    #[tokio::test]
    async fn identify_accepts_both_identifier_forms() {
        let (_dir, users) = stack().await;
        let authn = Authn {
            users: &users,
            providers: LOCAL,
        };
        assert_eq!(
            authn.identify(&password_login("alice", "pw")).unwrap(),
            "alice"
        );
        assert_eq!(
            authn
                .identify(&password_login("@alice:hs.test", "pw"))
                .unwrap(),
            "@alice:hs.test"
        );
    }

    /// A wrong password is a plain forbidden, and mints nothing.
    #[tokio::test]
    async fn bad_credentials_are_refused() {
        let (_dir, users) = stack().await;
        users
            .register("alice", Some("pw-12345678"), None, None, false, false)
            .await
            .unwrap();
        let err = Authn {
            users: &users,
            providers: LOCAL,
        }
        .login(&password_login("alice", "wrong"), None, None, false)
        .await
        .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }
}
