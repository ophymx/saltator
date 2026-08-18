//! One OpenID Connect identity provider (docs/design-admin-identity.md,
//! "What the OIDC slice costs later"): discovery, JWKS, and the
//! authorization-code exchange. No route knowledge here — routes hold an
//! [`OidcProvider`] through [`super::auth::AuthProvider::Oidc`] and call
//! these.
//!
//! Trust model: the issuer is operator configuration, exactly as trusted
//! as the database path. What is *not* trusted is anything that arrives
//! through the browser — `code`, `state` — or anything the IdP asserts
//! about a user, which is only believed after the ID token's signature,
//! issuer, audience, expiry and nonce all check out against material
//! fetched from the configured issuer.

use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tokio::sync::RwLock;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// Operator configuration for one provider — the `[[oidc_providers]]`
/// block, modelled on Synapse's (`synapse/config/oidc.py:73-155`) but
/// with claim names in place of Jinja templates.
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// Stable identifier: the `{idp_id}` in `/login/sso/redirect/{idp_id}`
    /// and, prefixed `oidc-`, the `auth_provider` key in the identity
    /// link table. Renaming it orphans every linked account — that is
    /// what the prefix note on `T_EXTERNAL_ID` is about.
    pub idp_id: String,
    /// Human-readable name, shown by clients in the SSO button.
    pub name: String,
    /// Issuer URL; discovery fetches
    /// `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Requested scopes. Must include `openid`.
    pub scopes: Vec<String>,
    /// Send a PKCE challenge with the authorization request.
    pub pkce: bool,
    /// First SSO login may claim an existing *unlinked* account whose
    /// localpart matches — the grandfathering migration path. Off by
    /// default: on a server with passwords enabled it lets whoever
    /// controls a matching IdP subject take over the account.
    pub allow_existing_users: bool,
    /// First SSO login may create an account that does not exist yet.
    pub enable_registration: bool,
    /// The ID-token claim the localpart is derived from.
    pub localpart_claim: String,
    /// The claim used as display name for newly provisioned accounts.
    pub display_name_claim: String,
}

impl OidcProviderConfig {
    /// The `auth_provider` key this provider writes to the identity link
    /// table. Never derived from `name`, which is free to change.
    pub fn auth_provider_key(&self) -> String {
        format!("oidc-{}", self.idp_id)
    }
}

/// The provider's discovery document — the four fields we use.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// A configured provider plus its fetched-and-cached metadata. Both
/// caches fill on first use, not at startup: a homeserver must come up
/// (and serve password logins) with its IdP down.
pub struct OidcProvider {
    pub cfg: OidcProviderConfig,
    http: reqwest::Client,
    discovery: RwLock<Option<Arc<Discovery>>>,
    jwks: RwLock<Option<Arc<JwkSet>>>,
}

/// What a completed code exchange asserts, after full validation.
#[derive(Debug)]
pub struct VerifiedIdentity {
    /// The `sub` claim — the only durable identifier
    /// (`external_id` in the link table).
    pub subject: String,
    /// Localpart candidate from the configured claim, unsanitised.
    pub localpart: Option<String>,
    pub display_name: Option<String>,
}

impl OidcProvider {
    pub fn new(cfg: OidcProviderConfig) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            // Every URL we fetch is either operator config or came from
            // the discovery document it points at; a redirect elsewhere
            // is misconfiguration, not something to follow.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        Arc::new(Self {
            cfg,
            http,
            discovery: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    /// The discovery document, fetched once and held. A fetch failure is
    /// reported but not cached: the next login retries.
    pub async fn discovery(&self) -> Result<Arc<Discovery>> {
        if let Some(d) = self.discovery.read().await.as_ref() {
            return Ok(d.clone());
        }
        let mut slot = self.discovery.write().await;
        if let Some(d) = slot.as_ref() {
            return Ok(d.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        let doc: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(idp_unreachable)?
            .json()
            .await
            .map_err(idp_unreachable)?;
        // OIDC Discovery §4.3: the document must claim the issuer it was
        // fetched from, or we may be validating tokens against someone
        // else's keys.
        if doc.issuer.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
            return Err(ApiError::internal(format!(
                "OIDC provider {}: discovery document names issuer {}, config says {}",
                self.cfg.idp_id, doc.issuer, self.cfg.issuer
            )));
        }
        let doc = Arc::new(doc);
        *slot = Some(doc.clone());
        Ok(doc)
    }

    async fn jwks(&self, force_refetch: bool) -> Result<Arc<JwkSet>> {
        if !force_refetch {
            if let Some(j) = self.jwks.read().await.as_ref() {
                return Ok(j.clone());
            }
        }
        let uri = self.discovery().await?.jwks_uri.clone();
        let mut slot = self.jwks.write().await;
        if !force_refetch {
            if let Some(j) = slot.as_ref() {
                return Ok(j.clone());
            }
        }
        let set: JwkSet = self
            .http
            .get(&uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(idp_unreachable)?
            .json()
            .await
            .map_err(idp_unreachable)?;
        let set = Arc::new(set);
        *slot = Some(set.clone());
        Ok(set)
    }

    /// The URL to send the browser to. `state` is the round-trip key into
    /// the gateway's pending-auth map; `nonce` binds the eventual ID
    /// token to this request; `code_challenge` is the PKCE S256 challenge
    /// when the provider has PKCE on.
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: Option<&str>,
    ) -> Result<String> {
        let disc = self.discovery().await?;
        let mut url = reqwest::Url::parse(&disc.authorization_endpoint)
            .map_err(|e| ApiError::internal(format!("authorization_endpoint: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &self.cfg.scopes.join(" "))
                .append_pair("state", state)
                .append_pair("nonce", nonce);
            if let Some(challenge) = code_challenge {
                q.append_pair("code_challenge", challenge)
                    .append_pair("code_challenge_method", "S256");
            }
        }
        Ok(url.into())
    }

    /// Redeem an authorization code and validate the ID token that comes
    /// back: signature against the JWKS, issuer, audience, expiry, and
    /// the nonce minted at redirect time.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity> {
        let disc = self.discovery().await?;

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(v) = code_verifier {
            form.push(("code_verifier", v));
        }
        let resp: TokenResponse = self
            .http
            .post(&disc.token_endpoint)
            // client_secret_basic, every provider's mandatory-to-implement
            // method and Synapse's default.
            .basic_auth(&self.cfg.client_id, Some(&self.cfg.client_secret))
            .form(&form)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(idp_unreachable)?
            .json()
            .await
            .map_err(idp_unreachable)?;

        let claims = self
            .validate_id_token(&resp.id_token, expected_nonce)
            .await?;

        let str_claim = |name: &str| claims.get(name).and_then(|v| v.as_str()).map(str::to_owned);
        let subject =
            str_claim("sub").ok_or_else(|| ApiError::internal("ID token has no sub claim"))?;
        Ok(VerifiedIdentity {
            subject,
            localpart: str_claim(&self.cfg.localpart_claim),
            display_name: str_claim(&self.cfg.display_name_claim),
        })
    }

    async fn validate_id_token(
        &self,
        jwt: &str,
        expected_nonce: &str,
    ) -> Result<serde_json::Value> {
        let header = jsonwebtoken::decode_header(jwt).map_err(bad_id_token)?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
        ) {
            // Notably excludes the HMAC family: a symmetric alg would
            // make the client secret a signing key.
            return Err(bad_id_token(format!("refusing alg {:?}", header.alg)));
        }
        let find = |set: &Arc<JwkSet>| match &header.kid {
            Some(kid) => set.find(kid).cloned(),
            // No kid: unambiguous only when the set has a single key.
            None => match set.keys.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            },
        };
        let jwk = match find(&self.jwks(false).await?) {
            Some(jwk) => jwk,
            // Unknown kid usually means the IdP rotated its keys since we
            // cached; one forced refetch, then believe the miss.
            None => find(&self.jwks(true).await?)
                .ok_or_else(|| bad_id_token("no JWKS key matches the ID token"))?,
        };
        let key = DecodingKey::from_jwk(&jwk).map_err(bad_id_token)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.cfg.issuer.trim_end_matches('/')]);
        validation.set_audience(&[&self.cfg.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(jwt, &key, &validation)
            .map_err(bad_id_token)?;
        // The nonce ties this token to the redirect we issued; without the
        // check, a code obtained for any other request would do.
        if data.claims.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) {
            return Err(bad_id_token("nonce mismatch"));
        }
        Ok(data.claims)
    }
}

/// Gateway-local state of the SSO browser flows: everything between
/// "redirect the browser to the IdP" and "the browser came back".
///
/// Deliberately in-memory, not shard state: it is one browser's
/// half-finished redirect, worthless after fifteen minutes, and secret
/// only until it is spent. The cost is that the callback must land on
/// the node that issued the redirect — in a cluster, SSO needs sticky
/// routing until this moves behind a signed cookie. Documented in
/// docs/admin-api.md.
pub struct SsoRuntime {
    /// Public base URL of this server (scheme + host), the browser-visible
    /// origin the IdP redirects back to.
    pub public_base_url: String,
    pending: std::sync::Mutex<std::collections::HashMap<String, PendingAuth>>,
    /// UIA sessions whose `m.login.sso` stage the browser has completed,
    /// and the user the IdP vouched for. Consumed when the client retries
    /// the original request with a fallback acknowledgement.
    uia_done: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

/// One outstanding redirect, keyed by its `state` parameter.
pub struct PendingAuth {
    pub idp_id: String,
    pub nonce: String,
    /// PKCE verifier, when the provider has PKCE on.
    pub code_verifier: Option<String>,
    pub kind: PendingKind,
    pub created_ms: u64,
}

/// What the flow is for — where the browser goes when it succeeds.
pub enum PendingKind {
    /// An `m.login.sso` login: success redirects to the client's
    /// `redirectUrl` with a fresh login token appended.
    Login { client_redirect: String },
    /// The UIA fallback page for an existing session: success marks the
    /// stage done and tells the opener via the spec's postMessage.
    UiaFallback { session_id: String },
}

/// Outstanding redirects expire unspent after this long.
const PENDING_TTL_MS: u64 = 15 * 60 * 1000;
/// Hard cap on outstanding redirects: past this the map stops growing
/// and new SSO attempts are refused, which bounds what an unauthenticated
/// crawler hammering the redirect endpoint can pin in memory.
const PENDING_CAP: usize = 10_000;

impl SsoRuntime {
    pub fn new(public_base_url: String) -> Self {
        Self {
            public_base_url: public_base_url.trim_end_matches('/').to_owned(),
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
            uia_done: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The redirect_uri registered with every provider.
    pub fn callback_url(&self) -> String {
        format!("{}/_saltator/client/oidc/callback", self.public_base_url)
    }

    /// Store a pending flow, returning the `state` value that names it.
    pub fn begin(&self, auth: PendingAuth) -> Result<String> {
        let state = saltator_userserver::generate_token();
        let now = auth.created_ms;
        let mut map = self.pending.lock().expect("sso pending lock");
        map.retain(|_, p| now.saturating_sub(p.created_ms) < PENDING_TTL_MS);
        if map.len() >= PENDING_CAP {
            return Err(ApiError::limit_exceeded(30_000));
        }
        map.insert(state.clone(), auth);
        Ok(state)
    }

    /// Redeem `state`. Single-use: the entry is removed, so a replayed
    /// callback finds nothing.
    pub fn take(&self, state: &str, now_ms: u64) -> Option<PendingAuth> {
        self.pending
            .lock()
            .expect("sso pending lock")
            .remove(state)
            .filter(|p| now_ms.saturating_sub(p.created_ms) < PENDING_TTL_MS)
    }

    pub fn mark_uia_done(&self, session_id: &str, user_id: &str) {
        self.uia_done
            .lock()
            .expect("sso uia lock")
            .insert(session_id.to_owned(), user_id.to_owned());
    }

    /// Redeem a completed fallback for `session_id`; single-use, like the
    /// login token it substitutes for.
    pub fn take_uia_done(&self, session_id: &str) -> Option<String> {
        self.uia_done
            .lock()
            .expect("sso uia lock")
            .remove(session_id)
    }
}

/// PKCE (RFC 7636): the S256 challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()))
}

/// The IdP could not be reached or answered garbage. 502: the failure is
/// upstream of us, and saying so beats a generic 500 when an operator is
/// staring at a dead Keycloak.
fn idp_unreachable(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::BAD_GATEWAY,
        "M_UNKNOWN",
        format!("Identity provider unreachable: {e}"),
    )
}

/// The IdP answered, but the ID token does not check out. Forbidden — by
/// the time we are validating a token, the failure is an authentication
/// failure.
fn bad_id_token(e: impl std::fmt::Display) -> ApiError {
    ApiError::forbidden(format!("ID token rejected: {e}"))
}
