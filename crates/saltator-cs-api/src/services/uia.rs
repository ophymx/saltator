//! User-interactive authentication (spec "User-Interactive Authentication
//! API"): the multi-stage challenge/response in front of registration and
//! the destructive account endpoints.
//!
//! Sessions are real state in the user shard. Before this, the `session`
//! string in a 401 was random and never stored, so a client could skip
//! straight to the auth-carrying request and no flow could have more than
//! one stage.
//!
//! Two properties are worth stating because they are easy to get wrong:
//!
//! * **A single-stage flow completes in one request.** The client is not
//!   required to fetch a session id first, and several conformance tests
//!   register with a bare `m.login.dummy` and no session. So an absent
//!   session id means "create one", never "reject".
//! * **A session is bound to the request that started it.** Completed
//!   stages are privilege; without the binding, a client could satisfy a
//!   password stage for something harmless and spend the session on
//!   something destructive.

use std::sync::Arc;

use ruma::api::client::uiaa::AuthData;
use ruma::UserId;
use saltator_userserver::{UserError, UserServer};

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

const DUMMY: &str = "m.login.dummy";
const PASSWORD: &str = "m.login.password";
const REGISTRATION_TOKEN: &str = "m.login.registration_token";
const SSO: &str = "m.login.sso";

/// What the caller is authenticating *for*, which decides both the flows
/// offered and how each stage is verified.
pub(crate) enum Purpose<'a> {
    /// Account creation. `requires_token` mirrors the server's config.
    Register { requires_token: bool },
    /// Re-authentication of an already-logged-in user before a sensitive
    /// change.
    Reauth(&'a UserId),
}

/// What a satisfied flow yields.
#[derive(Debug)]
pub(crate) struct UiaOk {
    /// The registration token the session accepted, to be consumed
    /// atomically by the register command.
    pub registration_token: Option<String>,
}

pub(crate) struct Uia<'a> {
    pub users: &'a Arc<UserServer>,
    /// SSO runtime, when OIDC is configured: re-authentication may then
    /// be satisfied through the browser instead of a password, which is
    /// the only option an SSO-only account has.
    pub sso: Option<&'a crate::services::oidc::SsoRuntime>,
}

impl Purpose<'_> {
    /// The flows to advertise. Matches Synapse's shape: requiring a token
    /// prepends the stage to every existing flow rather than replacing
    /// them, so the dummy stage still terminates the flow.
    ///
    /// `sso` adds an alternative *flow*, never a stage inside the
    /// password one: an account may have a password, a link, or both,
    /// and either alone must be enough.
    fn flows(&self, sso: bool) -> Vec<Vec<&'static str>> {
        match self {
            Purpose::Register {
                requires_token: false,
            } => vec![vec![DUMMY]],
            Purpose::Register {
                requires_token: true,
            } => vec![vec![REGISTRATION_TOKEN, DUMMY]],
            Purpose::Reauth(_) if sso => vec![vec![PASSWORD], vec![SSO]],
            Purpose::Reauth(_) => vec![vec![PASSWORD]],
        }
    }
}

fn flow_refs<'a>(flows: &'a [Vec<&'static str>]) -> Vec<&'a [&'static str]> {
    flows.iter().map(|f| f.as_slice()).collect()
}

impl Uia<'_> {
    /// Run the UIA check for `request_id`, which identifies the operation
    /// and is what the session is bound to. Distinct operations must pass
    /// distinct ids — that is the whole anti-replay mechanism.
    ///
    /// `Ok` means the flow is satisfied and the caller may proceed.
    pub async fn check(
        &self,
        purpose: &Purpose<'_>,
        request_id: &str,
        auth: Option<&AuthData>,
    ) -> Result<UiaOk> {
        let flows = purpose.flows(self.sso.is_some());
        let refs = flow_refs(&flows);
        let request_hash = *blake3::hash(request_id.as_bytes()).as_bytes();

        // No auth at all: the opening challenge. Nothing is stored — a
        // session row appears only once a stage actually completes, so
        // abandoned challenges cost nothing.
        let Some(auth) = auth else {
            return Err(ApiError::uiaa(&refs, saltator_userserver::generate_token()));
        };

        let session_id = auth
            .session()
            .map(str::to_owned)
            .unwrap_or_else(saltator_userserver::generate_token);

        let (stage, token) = self.verify_stage(purpose, auth, &refs, &session_id).await?;

        let (completed, registration_token) = self
            .users
            .complete_uia_stage(&session_id, request_hash, stage, token.as_deref())
            .await
            .map_err(|e| match e {
                // The session is real but belongs to another request. Not a
                // re-challenge: re-challenging would invite the client to
                // keep trying the same misuse.
                UserError::UiaRequestMismatch => {
                    ApiError::forbidden("Authentication session is for a different request")
                }
                other => ApiError::from(other),
            })?;

        if flows
            .iter()
            .any(|flow| flow.iter().all(|s| completed.iter().any(|c| c == s)))
        {
            return Ok(UiaOk { registration_token });
        }
        Err(ApiError::uiaa(&refs, session_id).with_completed(&completed))
    }

    /// Verify the single stage this request presents, returning its type
    /// and any payload the session must remember.
    async fn verify_stage(
        &self,
        purpose: &Purpose<'_>,
        auth: &AuthData,
        flows: &[&[&'static str]],
        session_id: &str,
    ) -> Result<(&'static str, Option<String>)> {
        match auth {
            AuthData::Dummy(_) => Ok((DUMMY, None)),

            // A fallback acknowledgement asserts a stage was completed in
            // a browser page. The SSO fallback is the only one we serve,
            // so honour it as `m.login.sso` when this session really did
            // finish one; otherwise it can still stand in for the stage
            // that needs no proof.
            AuthData::FallbackAcknowledgement(_) => {
                match self.take_sso_stage(purpose, session_id)? {
                    Some(stage) => Ok(stage),
                    None => Ok((DUMMY, None)),
                }
            }

            AuthData::RegistrationToken(t) => {
                if !matches!(purpose, Purpose::Register { .. }) {
                    return Err(ApiError::uiaa(flows, session_id.to_owned()));
                }
                let usable = self
                    .users
                    .store()
                    .registration_token(&t.token)
                    .map_err(ApiError::internal)?
                    .is_some_and(|entry| entry.usable(crate::now_ms()));
                if !usable {
                    // Validity is re-checked atomically at registration;
                    // this is the early, friendly rejection.
                    return Err(ApiError::uiaa_forbidden(flows, session_id.to_owned()));
                }
                Ok((REGISTRATION_TOKEN, Some(t.token.clone())))
            }

            AuthData::Password(pw) => {
                let Purpose::Reauth(user_id) = purpose else {
                    return Err(ApiError::uiaa(flows, session_id.to_owned()));
                };
                if let ruma::api::client::uiaa::UserIdentifier::Matrix(m) = &pw.identifier {
                    let claimed = m.user.trim_start_matches('@');
                    let expected = user_id.as_str().trim_start_matches('@');
                    if claimed != expected && Some(claimed) != expected.split(':').next() {
                        return Err(ApiError::forbidden("Identifier does not match session"));
                    }
                }
                if !self
                    .users
                    .verify_user_password(user_id, &pw.password)
                    .await?
                {
                    return Err(ApiError::uiaa_forbidden(flows, session_id.to_owned()));
                }
                Ok((PASSWORD, None))
            }

            // An explicit `{"type": "m.login.sso"}` lands here — ruma has
            // no variant for it, and clients send it as often as the bare
            // acknowledgement the spec describes. The proof is the
            // completed browser flow either way, never the label.
            //
            // Otherwise: a stage no flow here contains. Re-challenge
            // rather than error, so the client learns what is on offer.
            _ => match self.take_sso_stage(purpose, session_id)? {
                Some(stage) => Ok(stage),
                None => Err(ApiError::uiaa(flows, session_id.to_owned())),
            },
        }
    }

    /// Spend this session's completed SSO fallback, if it has one. The
    /// mark is single-use and bound to the user the IdP authenticated —
    /// honouring it for anyone else would be a session transplant.
    fn take_sso_stage(
        &self,
        purpose: &Purpose<'_>,
        session_id: &str,
    ) -> Result<Option<(&'static str, Option<String>)>> {
        // Purpose first: a mark is only ever spendable on re-auth, and
        // consuming one to then reject it would burn a real completion.
        let Purpose::Reauth(expected) = purpose else {
            return Ok(None);
        };
        let Some(user) = self.sso.and_then(|s| s.take_uia_done(session_id)) else {
            return Ok(None);
        };
        if user != expected.as_str() {
            return Err(ApiError::forbidden(
                "SSO authenticated a different user than this session",
            ));
        }
        Ok(Some((SSO, None)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ruma::api::client::uiaa::{AuthData, Dummy, RegistrationToken};
    use saltator_shard::NoopNetworkFactory;
    use saltator_store::RocksEngine;
    use saltator_userserver::UserServer;

    use super::{Purpose, Uia};

    const SERVER: &str = "hs.test";

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

    fn open() -> Purpose<'static> {
        Purpose::Register {
            requires_token: false,
        }
    }

    fn gated() -> Purpose<'static> {
        Purpose::Register {
            requires_token: true,
        }
    }

    /// No auth at all is the opening challenge, and it advertises the
    /// flows rather than just failing.
    #[tokio::test]
    async fn absent_auth_challenges_with_flows() {
        let (_dir, users) = stack().await;
        let err = Uia {
            users: &users,
            sso: None,
        }
        .check(&open(), "register:alice", None)
        .await
        .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.extra["flows"][0]["stages"][0], "m.login.dummy");
        assert!(err.extra["session"].is_string());
    }

    /// A single-stage flow completes in ONE request with no session id.
    /// Conformance tests register exactly this way, so requiring a session
    /// round trip would be a regression, not extra rigour.
    #[tokio::test]
    async fn single_stage_completes_without_a_session_id() {
        let (_dir, users) = stack().await;
        let ok = Uia {
            users: &users,
            sso: None,
        }
        .check(
            &open(),
            "register:alice",
            Some(&AuthData::Dummy(Dummy::new())),
        )
        .await
        .unwrap();
        assert!(ok.registration_token.is_none());
    }

    /// The security property: completed stages belong to the request they
    /// were completed for. Otherwise a password stage satisfied for
    /// something harmless could be spent on something destructive.
    #[tokio::test]
    async fn a_session_cannot_be_replayed_against_another_request() {
        let (_dir, users) = stack().await;
        let svc = Uia {
            users: &users,
            sso: None,
        };

        // Complete a stage for one request and learn its session id.
        let err = svc.check(&gated(), "op:a", None).await.unwrap_err();
        let session = err.extra["session"].as_str().unwrap().to_owned();
        let mut dummy = Dummy::new();
        dummy.session = Some(session.clone());
        svc.check(&gated(), "op:a", Some(&AuthData::Dummy(dummy.clone())))
            .await
            .unwrap_err(); // still needs the token stage

        // Same session, different operation.
        let err = svc
            .check(&gated(), "op:b", Some(&AuthData::Dummy(dummy)))
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    /// A two-stage flow accumulates across requests, and the interim
    /// challenge reports what is already done.
    #[tokio::test]
    async fn two_stage_flow_accumulates_and_reports_completed() {
        let (_dir, users) = stack().await;
        users
            .create_registration_token("invite-code", Some(1), None)
            .await
            .unwrap();
        let svc = Uia {
            users: &users,
            sso: None,
        };

        let mut dummy = Dummy::new();
        let err = svc
            .check(
                &gated(),
                "register:alice",
                Some(&AuthData::Dummy(dummy.clone())),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.extra["completed"][0], "m.login.dummy");
        let session = err.extra["session"].as_str().unwrap().to_owned();

        let mut token = RegistrationToken::new("invite-code".to_owned());
        token.session = Some(session.clone());
        let ok = svc
            .check(
                &gated(),
                "register:alice",
                Some(&AuthData::RegistrationToken(token)),
            )
            .await
            .unwrap();
        assert_eq!(ok.registration_token.as_deref(), Some("invite-code"));

        // The session remembers the token even though the last request
        // carried it — and would still remember it in the other order.
        dummy.session = Some(session);
        let ok = svc
            .check(&gated(), "register:alice", Some(&AuthData::Dummy(dummy)))
            .await
            .unwrap();
        assert_eq!(ok.registration_token.as_deref(), Some("invite-code"));
    }

    #[tokio::test]
    async fn unknown_or_exhausted_token_is_refused() {
        let (_dir, users) = stack().await;
        let svc = Uia {
            users: &users,
            sso: None,
        };

        let err = svc
            .check(
                &gated(),
                "register:alice",
                Some(&AuthData::RegistrationToken(RegistrationToken::new(
                    "nope".to_owned(),
                ))),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.extra["errcode"], "M_FORBIDDEN");

        // A token with no uses left is refused the same way.
        users
            .create_registration_token("spent", Some(0), None)
            .await
            .unwrap();
        let err = svc
            .check(
                &gated(),
                "register:alice",
                Some(&AuthData::RegistrationToken(RegistrationToken::new(
                    "spent".to_owned(),
                ))),
            )
            .await
            .unwrap_err();
        assert_eq!(err.extra["errcode"], "M_FORBIDDEN");
    }

    /// An expired token is refused even though it still exists.
    #[tokio::test]
    async fn expired_token_is_refused() {
        let (_dir, users) = stack().await;
        users
            .create_registration_token("stale", None, Some(1))
            .await
            .unwrap();
        let err = Uia {
            users: &users,
            sso: None,
        }
        .check(
            &gated(),
            "register:alice",
            Some(&AuthData::RegistrationToken(RegistrationToken::new(
                "stale".to_owned(),
            ))),
        )
        .await
        .unwrap_err();
        assert_eq!(err.extra["errcode"], "M_FORBIDDEN");
    }

    /// A stage that belongs to no flow here re-challenges rather than
    /// half-completing: presenting a registration token to a password
    /// re-auth must not count as progress.
    #[tokio::test]
    async fn stage_outside_the_flow_does_not_count() {
        let (_dir, users) = stack().await;
        users
            .register("alice", Some("pw"), None, None, false, true)
            .await
            .unwrap();
        let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
        let err = Uia {
            users: &users,
            sso: None,
        }
        .check(
            &Purpose::Reauth(&alice),
            "deactivate:@alice:hs.test",
            Some(&AuthData::RegistrationToken(RegistrationToken::new(
                "anything".to_owned(),
            ))),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(err.extra.get("completed").is_none());
    }
}
