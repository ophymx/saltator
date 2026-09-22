//! The SSO browser flow (the OIDC slice): `/login/sso/redirect`, the
//! OIDC callback under our own namespace, and the `m.login.sso` UIA
//! fallback page. Thin, as routes must be — the OIDC protocol work lives
//! in [`crate::services::oidc`], and the one real policy decision here
//! (which account an IdP subject becomes) is [`map_subject`].
//!
//! These endpoints speak to a *browser*, not a Matrix client: errors
//! still come back as Matrix JSON (debuggable, if unlovely), successes
//! are redirects or small HTML pages.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use ruma::OwnedUserId;
use saltator_userserver::{generate_token, UserError};

use crate::error::ApiError;
use crate::services::oidc::{
    pkce_challenge, OidcProvider, PendingAuth, PendingKind, VerifiedIdentity,
};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

/// `GET /login/sso/redirect` — no provider named: with one configured,
/// use it; with several, a minimal picker page, since the spec leaves
/// the choice to the server.
pub async fn sso_redirect(
    State(state): State<Arc<CsState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response> {
    let redirect_url = client_redirect_param(&q)?;
    let authn = state.authn();
    let mut providers = authn.oidc_providers_all();
    let Some(first) = providers.next() else {
        return Err(ApiError::not_found("SSO is not configured"));
    };
    if providers.next().is_none() {
        let first = first.clone();
        return begin(&state, &first, login_kind(redirect_url)).await;
    }
    Ok(picker_page(
        &state,
        "/login/sso/redirect",
        &[("redirectUrl", redirect_url)],
    )
    .into_response())
}

/// `GET /login/sso/redirect/{idp_id}` — the client chose.
pub async fn sso_redirect_idp(
    State(state): State<Arc<CsState>>,
    Path(idp_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response> {
    let redirect_url = client_redirect_param(&q)?;
    let provider = state
        .authn()
        .oidc_provider(&idp_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("Unknown identity provider"))?;
    begin(&state, &provider, login_kind(redirect_url)).await
}

/// `GET /auth/m.login.sso/fallback/web?session=…` — the spec's UIA
/// fallback: a browser page that, once SSO succeeds, lets the client
/// re-submit its original request with this session and have the
/// `m.login.sso` stage count as complete.
pub async fn sso_fallback_web(
    State(state): State<Arc<CsState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response> {
    let session = q
        .get("session")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::invalid_param("Missing session parameter"))?;
    let kind = PendingKind::UiaFallback {
        session_id: session.clone(),
    };
    let authn = state.authn();
    if let Some(idp_id) = q.get("idp") {
        let provider = authn
            .oidc_provider(idp_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("Unknown identity provider"))?;
        return begin(&state, &provider, kind).await;
    }
    let mut providers = authn.oidc_providers_all();
    let Some(first) = providers.next() else {
        return Err(ApiError::not_found("SSO is not configured"));
    };
    if providers.next().is_none() {
        let first = first.clone();
        return begin(&state, &first, kind).await;
    }
    // The fallback path has no `{idp_id}` variant in the spec, so the
    // picker keeps the session and adds `idp` to this same URL.
    Ok(picker_page(
        &state,
        "/auth/m.login.sso/fallback/web",
        &[("session", session)],
    )
    .into_response())
}

/// `GET /_saltator/client/oidc/callback` — the IdP sent the browser
/// back. Everything in the query string is untrusted until the code
/// exchange and ID-token validation in the service say otherwise.
pub async fn oidc_callback(
    State(state): State<Arc<CsState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response> {
    let sso = state
        .sso
        .as_ref()
        .ok_or_else(|| ApiError::not_found("SSO is not configured"))?;
    let pending = q
        .get("state")
        .and_then(|s| sso.take(s, crate::now_ms()))
        .ok_or_else(|| {
            // Unknown, expired, replayed — or a callback for a redirect
            // another node issued (SSO needs sticky routing in a
            // cluster). One message for all of them.
            ApiError::forbidden("Unknown or expired SSO attempt; start again")
        })?;
    if let Some(error) = q.get("error") {
        // The IdP refused (user hit cancel, consent denied…). Their
        // error code is safe to echo now that state matched a flow we
        // actually started.
        return Err(ApiError::forbidden(format!(
            "Identity provider refused: {error} {}",
            q.get("error_description").map(String::as_str).unwrap_or("")
        )));
    }
    let code = q
        .get("code")
        .ok_or_else(|| ApiError::invalid_param("Missing code parameter"))?;
    let provider = state
        .authn()
        .oidc_provider(&pending.idp_id)
        .cloned()
        .ok_or_else(|| ApiError::internal("provider vanished mid-flow"))?;
    let identity = provider
        .exchange_code(
            code,
            &sso.callback_url(),
            pending.code_verifier.as_deref(),
            &pending.nonce,
        )
        .await?;

    match pending.kind {
        PendingKind::Login { client_redirect } => {
            let user_id = map_subject(&state, &provider, &identity).await?;
            // A locked or deactivated account fails here, and must fail
            // as a flat refusal: the caller is an unauthenticated
            // browser, and the precise "the account's state does not
            // allow this" would tell it the account exists and is
            // locked.
            let token = state
                .users
                .create_login_token(&user_id)
                .await
                .map_err(|e| match e {
                    UserError::NotFound | UserError::InvalidState => {
                        ApiError::forbidden("This identity may not log in")
                    }
                    other => other.into(),
                })?;
            let mut url = reqwest::Url::parse(&client_redirect)
                .map_err(|e| ApiError::invalid_param(format!("redirectUrl: {e}")))?;
            url.query_pairs_mut().append_pair("loginToken", &token);
            Ok(Redirect::temporary(url.as_str()).into_response())
        }
        PendingKind::UiaFallback { session_id } => {
            // Re-authentication proves an *existing* identity: only a
            // linked account will do, no grandfathering and no
            // provisioning on this path.
            let key = provider.cfg.auth_provider_key();
            let owner = state
                .users
                .store()
                .external_id_owner(&key, &identity.subject)
                .map_err(ApiError::internal)?
                .ok_or_else(|| {
                    ApiError::forbidden("This identity is not linked to any account here")
                })?;
            sso.mark_uia_done(&session_id, &owner);
            Ok(Html(FALLBACK_DONE_HTML).into_response())
        }
    }
}

/// Kick one browser flow off: mint state + nonce (+ PKCE), remember it,
/// and bounce the browser to the IdP.
async fn begin(
    state: &CsState,
    provider: &Arc<OidcProvider>,
    kind: PendingKind,
) -> Result<Response> {
    let sso = state
        .sso
        .as_ref()
        .ok_or_else(|| ApiError::not_found("SSO is not configured"))?;
    let nonce = generate_token();
    let code_verifier = provider.cfg.pkce.then(generate_token);
    let challenge = code_verifier.as_deref().map(pkce_challenge);
    let st = sso.begin(PendingAuth {
        idp_id: provider.cfg.idp_id.clone(),
        nonce: nonce.clone(),
        code_verifier,
        kind,
        created_ms: crate::now_ms(),
    })?;
    let url = provider
        .authorize_url(&sso.callback_url(), &st, &nonce, challenge.as_deref())
        .await?;
    Ok(Redirect::temporary(&url).into_response())
}

fn login_kind(redirect_url: &str) -> PendingKind {
    PendingKind::Login {
        client_redirect: redirect_url.to_owned(),
    }
}

fn client_redirect_param(q: &HashMap<String, String>) -> Result<&String> {
    q.get("redirectUrl")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::invalid_param("Missing redirectUrl parameter"))
}

/// The account an IdP-verified subject logs in as — the policy heart of
/// the slice. In order: the identity link table decides; failing that,
/// `allow_existing_users` may claim a matching unlinked account; failing
/// that, `enable_registration` may create one. Both fallbacks write the
/// link, so they run once per account, ever — from the second login the
/// table answers.
async fn map_subject(
    state: &CsState,
    provider: &Arc<OidcProvider>,
    identity: &VerifiedIdentity,
) -> Result<OwnedUserId> {
    let users = &state.users;
    let key = provider.cfg.auth_provider_key();
    if let Some(owner) = users
        .store()
        .external_id_owner(&key, &identity.subject)
        .map_err(ApiError::internal)?
    {
        return OwnedUserId::try_from(owner).map_err(ApiError::internal);
    }

    let localpart = identity
        .localpart
        .as_deref()
        .map(sanitize_localpart)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| {
            ApiError::forbidden(format!(
                "No usable {} claim to derive a username from",
                provider.cfg.localpart_claim
            ))
        })?;
    let user_id = OwnedUserId::try_from(format!("@{localpart}:{}", state.config.server_name))
        .map_err(|e| ApiError::forbidden(format!("Derived username is invalid: {e}")))?;

    let exists = users
        .store()
        .account(user_id.as_str())
        .await
        .map_err(ApiError::internal)?
        .is_some();
    if !exists && provider.cfg.enable_registration {
        match users
            .register(&localpart, None, None, None, false, true)
            .await
        {
            Ok(_) => {
                if let Some(name) = &identity.display_name {
                    // Best-effort nicety; the account is already made.
                    let _ = users
                        .set_profile(&user_id, Some(Some(name.clone())), None)
                        .await;
                }
                users
                    .link_external_id(&user_id, &key, &identity.subject)
                    .await?;
                return Ok(user_id);
            }
            // Two first logins racing on the same localpart: the loser
            // falls through to the existing-account rules.
            Err(UserError::UserExists) => {}
            Err(e) => return Err(e.into()),
        }
    } else if !exists {
        return Err(ApiError::forbidden(
            "No account for this identity, and this provider may not create one",
        ));
    }

    if !provider.cfg.allow_existing_users {
        return Err(ApiError::forbidden(
            "An account with this name exists but is not linked to this identity; \
             pre-link it via the admin API or enable allow_existing_users",
        ));
    }
    // Grandfathering claims an *unlinked* account only. An account
    // already linked at this provider belongs to that subject, and a
    // second subject presenting a matching username must not take it:
    // `LinkExternalId` treats a re-link as a replace (an administrator
    // repointing an account, which is a different act entirely), so
    // without this check the write would silently succeed.
    let already_linked = users
        .store()
        .external_ids(user_id.as_str())
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .any(|(p, _)| p == key);
    if already_linked {
        return Err(ApiError::forbidden(
            "That account is linked to a different identity at this provider",
        ));
    }
    match users
        .link_external_id(&user_id, &key, &identity.subject)
        .await
    {
        Ok(()) => Ok(user_id),
        // The subject is linked elsewhere: it raced another account, or
        // an administrator pointed it at one.
        Err(UserError::ExternalIdInUse(_)) => Err(ApiError::forbidden(
            "This identity is already linked to a different account",
        )),
        Err(e) => Err(e.into()),
    }
}

/// Matrix "historical" localpart grammar is wide, but new names should be
/// strict (`[a-z0-9._=/-]`): lowercase what can be, drop what cannot.
fn sanitize_localpart(raw: &str) -> String {
    raw.to_lowercase()
        .chars()
        .filter(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '=' | '/' | '-'))
        .collect()
}

/// The picker shown when several providers are configured and the URL
/// named none: plain links back into `base_path` with `idp` appended.
fn picker_page(state: &CsState, base_path: &str, params: &[(&str, &str)]) -> Html<String> {
    let mut items = String::new();
    for provider in state.authn().oidc_providers_all() {
        let mut href = format!("{base_path}/{}", urlencode(&provider.cfg.idp_id));
        let mut sep = '?';
        // The fallback path has no idp path segment; it takes `idp` as a
        // query parameter instead.
        if base_path.contains("fallback") {
            href = format!("{base_path}?idp={}", urlencode(&provider.cfg.idp_id));
            sep = '&';
        }
        for (k, v) in params {
            href.push(sep);
            sep = '&';
            href.push_str(&format!("{k}={}", urlencode(v)));
        }
        items.push_str(&format!(
            "<li><a href=\"{}\">{}</a></li>\n",
            escape_html(&href),
            escape_html(&provider.cfg.name)
        ));
    }
    Html(format!(
        "<!DOCTYPE html><html><head><title>Sign in</title></head><body>\
         <h1>Sign in with</h1><ul>{items}</ul></body></html>"
    ))
}

/// The page the UIA fallback ends on — the spec's completion signal.
const FALLBACK_DONE_HTML: &str = r#"<!DOCTYPE html><html><head><title>Authentication complete</title></head><body>
<p>Authentication complete. You can close this window.</p>
<script>
if (window.onAuthDone) { window.onAuthDone(); }
else if (window.opener && window.opener.postMessage) { window.opener.postMessage("authDone", "*"); }
</script>
</body></html>"#;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
