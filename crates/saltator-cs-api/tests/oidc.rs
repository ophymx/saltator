//! The OIDC login slice end to end, against a stub identity provider
//! that serves a real discovery document, a real JWKS, and signs real
//! RS256 ID tokens — so the code exchange, signature check, issuer /
//! audience / nonce validation and account mapping are all exercised for
//! real. Only the IdP's own login UI is absent, and that is the one part
//! this server never sees.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use saltator_cs_api::{CsConfig, CsState, OidcProviderConfig};
use saltator_media::MediaStore;
use saltator_roomserver::RoomServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::UserServer;

const SERVER: &str = "hs.test";
const CLIENT_ID: &str = "saltator-test";
const CLIENT_REDIRECT: &str = "https://client.example/complete";

/// A throwaway 2048-bit RSA key, generated for this file and used
/// nowhere else. The JWKS below is its public half.
const IDP_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC17Zg0tAu1bZ2k
m5yK0i7nD1S3qipTWOxaiP03xyFQkqQYoBQB8TY39an1kMV3ikJiNeK9U6+n84Jk
m7To2qIgkqZkZbTvNbDgg+6RVEAsZO2fu4uWBXjPppdOgdLk/Ek9//fbVSYypebD
bZQeUUA4Np+hi724rHTa0Vj09OOCf6aVtoH97xFI2Ss5ygOaVoh5Cbb3ws97ML+o
o5ulNGzCIMPbhH5Bz1LcmP8mFGHHXoiW5tNzicBnC+QkPs6K1GyT0BEi0vHY/mp8
pSi+xdanqlE29eFxA2W+K0ylW/XRqNhnja+K1sJwfqo6LeEMRVEI7UkbZV7Lop0J
ViUwBHaPAgMBAAECggEARss+q9+WINMXgasWNwUEQGC8YD4k+0sCqlZdZvujsKVn
mreMIZdaOFtt+EOOO+6+11XNtkve8lW1W24l72jIpzE5856KUn2Lp0pfpwjocf4S
Y9KIxme5s+BJR8EILpgn7irxqdWQKCxbyJeXCFcozNcgti3ZNYhSbqYBXkz/TVO0
K1/MyAajq5/j8/HPtjVOfWaXs9gHRi/6WxKhEa+JSx3DfVQiDGvL9tNuybrPUB7x
8CONWqBRyCE3HeSl1BmSW/s1Huxpo9RiSR212kWGBEC0XVrkrmbh4KqyfGdl8vgV
jYwe8oxOFJfAGQ96SyVOY5TNRolvh015wtMp0/5slQKBgQDX98vla6eDKNkIM37d
FzRDzWwbLKGiWiVDpqrkdTLPBQPZx2jvtx+/avqJIjjK7Qq3v3mi3SrTldGwr8Ri
PjHnDdeJUSEePvG5eHRK+fY4AAWhmHmd2fLkrHkOkzpOrcWcbHHhLjh7E77PGeaw
pMxFNY7W+TpDpr6ISlnLwZLeZQKBgQDXpoZIbsUi8bQfHIAgKbFqnODy8i+gCNhd
QUxB4Km/KNPev92WRpFlrFvWC09nqe9+PG5qHqXpTe6tBuSpEsaGK5X+hmCgbe+z
LLH34ii2D61km5jJjB383C/Mk9tPu85PM+nJIAo/qfw76BVTXHCX+b5AjR5coZIc
/AJHyFqH4wKBgQCoOmPfX85qgqUcmFBYFD0oG5n8SPXXK3Ufj3JK52gejn+DYqvB
HtpiFwj1TW0D1UWmAEbVsIYtruRaR3AoPt5MZyHf2wx7LPjKSqP7y14aHRpF2CnT
5fQoYJkj21dt9jqaMHc8uu5QIP9e/4QNUTG1L5UGq7jQ/dApBhGQgEbRaQKBgFF0
ErB1Nnz2cqR1rWd4mAy+6LCbDaYS8TZ4HYechkEv+KbgLaA/U1fl/GIir4FmTJGP
3dyzatNunkI4olHCR74R5HvY4dJ289zneuk4QUxTK5ketF0cUY9a06sgBexd8ZU0
9I8FTRmy6RTvmm58MgMVT+kt5FP0qy3LekkGwjslAoGAXLRMPuIa6eDK2LsLVZwy
x52ybNi7ZMB4BpxFNECa334RQ/ABaCyslcBeq48aw90lyAWta6cA9lAjOuf+87z0
1MPIt+wZp4XazDlBYu3bBxRllwyqY2jUOG6R228n60VnsfSMa03IrYEFhjVimSiv
ehF83YKb8pZOM75jU1wbyQg=
-----END PRIVATE KEY-----"#;

const IDP_JWK_N: &str = "te2YNLQLtW2dpJucitIu5w9Ut6oqU1jsWoj9N8chUJKkGKAUAfE2N_Wp9ZDFd4pCYjXivVOvp_OCZJu06NqiIJKmZGW07zWw4IPukVRALGTtn7uLlgV4z6aXToHS5PxJPf_321UmMqXmw22UHlFAODafoYu9uKx02tFY9PTjgn-mlbaB_e8RSNkrOcoDmlaIeQm298LPezC_qKObpTRswiDD24R-Qc9S3Jj_JhRhx16IlubTc4nAZwvkJD7OitRsk9ARItLx2P5qfKUovsXWp6pRNvXhcQNlvitMpVv10ajYZ42vitbCcH6qOi3hDEVRCO1JG2Vey6KdCVYlMAR2jw";
const IDP_KID: &str = "test-key-1";

/// What the stub IdP will assert, smuggled through the authorization
/// `code` so each test can ask for a different user without a second
/// stub: `sub|preferred_username|name`. The flow appends the nonce it
/// saw on the authorize URL, which is how the stub knows to echo it —
/// a real IdP remembers it from the authorization request.
fn code_for(sub: &str, username: &str, name: &str) -> String {
    format!("{sub}|{username}|{name}")
}

/// Start the stub IdP. Returns its issuer URL.
async fn start_idp() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());

    let disc_issuer = issuer.clone();
    let token_issuer = issuer.clone();
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let i = disc_issuer.clone();
                async move {
                    axum::Json(json!({
                        "issuer": i,
                        "authorization_endpoint": format!("{i}/authorize"),
                        "token_endpoint": format!("{i}/token"),
                        "jwks_uri": format!("{i}/jwks"),
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            axum::routing::get(|| async {
                axum::Json(json!({
                    "keys": [{
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": IDP_KID,
                        "n": IDP_JWK_N,
                        "e": "AQAB",
                    }]
                }))
            }),
        )
        .route(
            "/token",
            axum::routing::post(move |body: String| {
                let issuer = token_issuer.clone();
                async move {
                    let code = form_field(&body, "code").unwrap_or_default();
                    let mut parts = code.splitn(4, '|');
                    let sub = parts.next().unwrap_or("").to_owned();
                    let username = parts.next().unwrap_or("").to_owned();
                    let name = parts.next().unwrap_or("").to_owned();
                    let nonce = parts.next().unwrap_or("").to_owned();

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut claims = json!({
                        "iss": issuer,
                        "aud": CLIENT_ID,
                        "sub": sub,
                        "exp": now + 300,
                        "iat": now,
                        "nonce": nonce,
                    });
                    if !username.is_empty() {
                        claims["preferred_username"] = json!(username);
                    }
                    if !name.is_empty() {
                        claims["name"] = json!(name);
                    }
                    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                    header.kid = Some(IDP_KID.to_owned());
                    let key = jsonwebtoken::EncodingKey::from_rsa_pem(IDP_KEY_PEM.as_bytes())
                        .expect("test idp key");
                    let id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
                    axum::Json(json!({
                        "access_token": "idp-access-token",
                        "token_type": "Bearer",
                        "id_token": id_token,
                    }))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    issuer
}

fn form_field(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

fn urldecode(s: &str) -> String {
    let bytes = s.replace('+', " ").into_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                16,
            ) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Env {
    _dir: tempfile::TempDir,
    router: axum::Router,
    users: Arc<UserServer>,
    issuer: String,
}

struct ProviderOpts {
    allow_existing_users: bool,
    enable_registration: bool,
}

impl Default for ProviderOpts {
    fn default() -> Self {
        Self {
            allow_existing_users: false,
            enable_registration: true,
        }
    }
}

async fn start_env(opts: ProviderOpts) -> Env {
    let issuer = start_idp().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server_name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (signer, _der) =
        saltator_roomserver::ServerSigner::generate(server_name.clone(), "0".to_owned());
    let rooms = RoomServer::start(
        1,
        engine.clone(),
        Arc::new(signer),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let users = UserServer::start(
        1,
        engine.clone(),
        server_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [rooms.shard_handle(), users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let media = MediaStore::open(dir.path().join("media")).unwrap();
    let state = CsState::new(
        users.clone(),
        rooms.clone(),
        media,
        CsConfig {
            server_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    )
    .with_oidc(
        vec![OidcProviderConfig {
            idp_id: "stub".into(),
            name: "Stub SSO".into(),
            issuer: issuer.clone(),
            client_id: CLIENT_ID.into(),
            client_secret: "shh".into(),
            scopes: vec!["openid".into(), "profile".into()],
            // Off: the stub's token endpoint ignores the verifier, so
            // leaving it on would test nothing extra here.
            pkce: false,
            allow_existing_users: opts.allow_existing_users,
            enable_registration: opts.enable_registration,
            localpart_claim: "preferred_username".into(),
            display_name_claim: "name".into(),
        }],
        "https://hs.test".into(),
    );
    Env {
        _dir: dir,
        router: saltator_cs_api::router(state),
        users,
        issuer,
    }
}

impl Env {
    /// A raw GET: SSO endpoints answer with redirects and HTML, not JSON.
    async fn get(&self, path: &str) -> (StatusCode, Option<String>, String) {
        let resp = self
            .router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            location,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    async fn post_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    /// `DELETE /devices/{id}` — one of the endpoints behind UIA
    /// re-authentication, and what these tests drive the SSO stage with.
    async fn delete_device(&self, token: &str, device: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/_matrix/client/v3/devices/{device}"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Walk the browser half of the flow: redirect out, callback back.
    /// Returns the login token the client would be handed.
    async fn sso_login(&self, code: &str) -> std::result::Result<String, (StatusCode, Value)> {
        let (status, location, _) = self
            .get(&format!(
                "/_matrix/client/v3/login/sso/redirect?redirectUrl={CLIENT_REDIRECT}"
            ))
            .await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        let authorize = location.expect("redirect to the IdP");
        assert!(
            authorize.starts_with(&self.issuer),
            "should bounce to the IdP, got {authorize}"
        );
        let state = query_param(&authorize, "state").expect("state parameter");
        let nonce = query_param(&authorize, "nonce").expect("nonce parameter");
        // The IdP would authenticate the user here; the stub needs only
        // the code, which carries what it will assert — plus the nonce a
        // real IdP would have remembered from this same URL.
        let (status, location, body) = self
            .get(&format!(
                "/_saltator/client/oidc/callback?state={state}&code={}",
                urlencode(&format!("{code}|{nonce}"))
            ))
            .await;
        if status != StatusCode::TEMPORARY_REDIRECT {
            return Err((status, serde_json::from_str(&body).unwrap_or(Value::Null)));
        }
        let back = location.expect("redirect back to the client");
        assert!(back.starts_with(CLIENT_REDIRECT), "got {back}");
        Ok(query_param(&back, "loginToken").expect("loginToken parameter"))
    }
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `GET /login` advertises SSO *and* the token flow SSO ends in, with
/// the provider listed — without it a client has no way to start.
#[tokio::test]
async fn login_advertises_sso_and_token() {
    let env = start_env(ProviderOpts::default()).await;
    let (status, body) = {
        let (s, _, b) = env.get("/_matrix/client/v3/login").await;
        (s, serde_json::from_str::<Value>(&b).unwrap())
    };
    assert_eq!(status, StatusCode::OK);
    let flows: Vec<&str> = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["type"].as_str().unwrap())
        .collect();
    assert!(flows.contains(&"m.login.password"), "{body}");
    assert!(flows.contains(&"m.login.sso"), "{body}");
    assert!(flows.contains(&"m.login.token"), "{body}");
    let sso = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["type"] == "m.login.sso")
        .unwrap();
    assert_eq!(sso["identity_providers"][0]["id"], "stub");
    assert_eq!(sso["identity_providers"][0]["name"], "Stub SSO");
}

/// The whole flow on a fresh server: SSO provisions the account, links
/// it, and the login token redeems for a working session.
#[tokio::test]
async fn first_sso_login_provisions_and_links() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice Example"))
        .await
        .expect("sso flow");

    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");
    let access = body["access_token"].as_str().unwrap();

    // The session works, and the account really exists.
    let resp = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v3/account/whoami")
                .header("Authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The link was written, so this is a one-time provisioning.
    let owner = env
        .users
        .store()
        .external_id_owner("oidc-stub", "subject-1")
        .unwrap();
    assert_eq!(owner.as_deref(), Some("@alice:hs.test"));
    // And the display name came from the ID token.
    let profile = env.users.store().profile("@alice:hs.test").unwrap();
    assert_eq!(
        profile.and_then(|p| p.displayname).as_deref(),
        Some("Alice Example")
    );
}

/// The link, not the username, decides. A second login whose IdP username
/// has since changed still lands on the account the subject is linked to.
#[tokio::test]
async fn subject_link_outranks_the_username_claim() {
    let env = start_env(ProviderOpts::default()).await;
    env.sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("first login");

    let token = env
        .sso_login(&code_for("subject-1", "alice-renamed", "Alice"))
        .await
        .expect("second login");
    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");
    assert!(
        env.users
            .store()
            .account("@alice-renamed:hs.test")
            .unwrap()
            .is_none(),
        "a renamed claim must not spawn a second account"
    );
}

/// A login token redeems exactly once.
#[tokio::test]
async fn login_token_is_single_use() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("sso flow");
    let body = json!({"type": "m.login.token", "token": token});
    let (status, _) = env
        .post_json("/_matrix/client/v3/login", body.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env.post_json("/_matrix/client/v3/login", body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "second redemption must fail");
}

/// An unknown token is refused, and looks exactly like a spent one.
#[tokio::test]
async fn unknown_login_token_is_refused() {
    let env = start_env(ProviderOpts::default()).await;
    let (status, _) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": "not-a-token"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The callback is single-use too: replaying it finds no pending flow.
#[tokio::test]
async fn callback_state_cannot_be_replayed() {
    let env = start_env(ProviderOpts::default()).await;
    let (_, location, _) = env
        .get(&format!(
            "/_matrix/client/v3/login/sso/redirect?redirectUrl={CLIENT_REDIRECT}"
        ))
        .await;
    let authorize = location.unwrap();
    let state = query_param(&authorize, "state").unwrap();
    let nonce = query_param(&authorize, "nonce").unwrap();
    let code = urlencode(&format!(
        "{}|{nonce}",
        code_for("subject-1", "alice", "Alice")
    ));
    let path = format!("/_saltator/client/oidc/callback?state={state}&code={code}");

    let (status, _, _) = env.get(&path).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let (status, _, _) = env.get(&path).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "replayed state must fail");
}

/// An unrecognised state — a callback nobody asked for — is refused
/// before any code is exchanged.
#[tokio::test]
async fn callback_without_a_pending_flow_is_refused() {
    let env = start_env(ProviderOpts::default()).await;
    let (status, _, _) = env
        .get("/_saltator/client/oidc/callback?state=made-up&code=whatever")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// With `allow_existing_users` off, an SSO identity whose mapped name
/// belongs to an existing unlinked account is refused rather than
/// silently taking it over.
#[tokio::test]
async fn existing_account_is_not_claimed_by_default() {
    let env = start_env(ProviderOpts::default()).await;
    env.users
        .register("alice", Some("pw-12345678"), None, None, false, true)
        .await
        .unwrap();

    let err = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect_err("must not claim the account");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert!(
        env.users
            .store()
            .external_id_owner("oidc-stub", "subject-1")
            .unwrap()
            .is_none(),
        "no link may be written on a refused claim"
    );
}

/// With it on, the same login grandfathers the account and writes the
/// link — the migration path for a server that already has users.
#[tokio::test]
async fn allow_existing_users_grandfathers_the_account() {
    let env = start_env(ProviderOpts {
        allow_existing_users: true,
        ..ProviderOpts::default()
    })
    .await;
    env.users
        .register("alice", Some("pw-12345678"), None, None, false, true)
        .await
        .unwrap();

    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("grandfathered login");
    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");
    assert_eq!(
        env.users
            .store()
            .external_id_owner("oidc-stub", "subject-1")
            .unwrap()
            .as_deref(),
        Some("@alice:hs.test"),
        "grandfathering must persist the link, so it happens once"
    );

    // The password still works: a link does not displace a credential.
    let (status, _) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "pw-12345678"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// A second IdP subject cannot grandfather its way onto an account that
/// is already linked to a different one.
#[tokio::test]
async fn grandfathering_cannot_steal_a_linked_account() {
    let env = start_env(ProviderOpts {
        allow_existing_users: true,
        ..ProviderOpts::default()
    })
    .await;
    env.sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("first login");

    let err = env
        .sso_login(&code_for("subject-2", "alice", "Impostor"))
        .await
        .expect_err("a different subject must not take the account");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert_eq!(
        env.users
            .store()
            .external_id_owner("oidc-stub", "subject-1")
            .unwrap()
            .as_deref(),
        Some("@alice:hs.test"),
        "the original link must survive"
    );
}

/// With registration off, SSO authenticates only accounts that already
/// exist and are linked — an operator's closed server stays closed.
#[tokio::test]
async fn registration_disabled_refuses_unknown_identities() {
    let env = start_env(ProviderOpts {
        enable_registration: false,
        ..ProviderOpts::default()
    })
    .await;
    let err = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect_err("must not provision");
    assert_eq!(err.0, StatusCode::FORBIDDEN);

    // Pre-linking through the admin surface is the supported way in, and
    // it works with registration off.
    let (_, session) = env
        .users
        .register("alice", Some("pw-12345678"), None, None, false, true)
        .await
        .unwrap();
    drop(session);
    env.users
        .link_external_id(
            &ruma::OwnedUserId::try_from("@alice:hs.test").unwrap(),
            "oidc-stub",
            "subject-1",
        )
        .await
        .unwrap();
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("pre-linked login");
    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:hs.test");
}

/// A claim that maps to nothing usable is refused rather than guessed at.
#[tokio::test]
async fn missing_username_claim_is_refused() {
    let env = start_env(ProviderOpts::default()).await;
    let err = env
        .sso_login(&code_for("subject-1", "", ""))
        .await
        .expect_err("no username claim");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

/// Usernames from an IdP are sanitised into the strict localpart
/// grammar, not passed through.
#[tokio::test]
async fn username_claim_is_sanitised() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "Alice O'Brien", "Alice"))
        .await
        .expect("sso flow");
    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@aliceobrien:hs.test");
}

/// A locked account cannot be logged into through SSO either — the
/// kill-switch covers every credential, not just passwords.
#[tokio::test]
async fn locked_account_cannot_sso() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("first login");
    let user = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();
    env.users.set_locked(&user, true).await.unwrap();

    // The token minted before the lock must not redeem afterwards.
    let (status, _) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nor may a fresh flow mint one.
    let err = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect_err("locked account");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

/// Re-authentication may go through the browser: with SSO configured,
/// the destructive endpoints offer `m.login.sso` alongside the password
/// flow, the fallback page completes it, and the retried request goes
/// through. This is the only way an account with no password can pass
/// UIA at all.
#[tokio::test]
async fn sso_satisfies_reauth_via_the_uia_fallback() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("sso flow");
    let (status, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access = body["access_token"].as_str().unwrap().to_owned();
    let device = body["device_id"].as_str().unwrap().to_owned();

    // A destructive endpoint challenges, and SSO is among the flows.
    let (status, body) = env.delete_device(&access, &device, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let flows: Vec<&str> = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["stages"][0].as_str().unwrap())
        .collect();
    assert!(flows.contains(&"m.login.sso"), "{body}");
    let session = body["session"].as_str().unwrap().to_owned();

    // The client opens the fallback page, which bounces to the IdP.
    let (status, location, _) = env
        .get(&format!(
            "/_matrix/client/v3/auth/m.login.sso/fallback/web?session={session}"
        ))
        .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let authorize = location.unwrap();
    let state = query_param(&authorize, "state").unwrap();
    let nonce = query_param(&authorize, "nonce").unwrap();
    let code = urlencode(&format!(
        "{}|{nonce}",
        code_for("subject-1", "alice", "Alice")
    ));
    let (status, _, page) = env
        .get(&format!(
            "/_saltator/client/oidc/callback?state={state}&code={code}"
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("authDone"), "the page must signal the opener");

    // Now the original request, retried with the same session, passes.
    let (status, body) = env
        .delete_device(
            &access,
            &device,
            json!({"auth": {"type": "m.login.sso", "session": session}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The fallback is single-use: a completed SSO stage cannot be spent
/// twice, so a captured session id is worthless after the first retry.
#[tokio::test]
async fn a_completed_sso_fallback_cannot_be_reused() {
    let env = start_env(ProviderOpts::default()).await;
    let token = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("sso flow");
    let (_, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token}),
        )
        .await;
    let access = body["access_token"].as_str().unwrap().to_owned();

    // A second session, whose device is the one we will delete: deleting
    // our own would revoke the token this test still needs.
    let token2 = env
        .sso_login(&code_for("subject-1", "alice", "Alice"))
        .await
        .expect("second sso flow");
    let (_, body) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": token2}),
        )
        .await;
    let device = body["device_id"].as_str().unwrap().to_owned();

    let (_, body) = env.delete_device(&access, &device, json!({})).await;
    let session = body["session"].as_str().unwrap().to_owned();
    let (_, location, _) = env
        .get(&format!(
            "/_matrix/client/v3/auth/m.login.sso/fallback/web?session={session}"
        ))
        .await;
    let authorize = location.unwrap();
    let state = query_param(&authorize, "state").unwrap();
    let nonce = query_param(&authorize, "nonce").unwrap();
    let code = urlencode(&format!(
        "{}|{nonce}",
        code_for("subject-1", "alice", "Alice")
    ));
    env.get(&format!(
        "/_saltator/client/oidc/callback?state={state}&code={code}"
    ))
    .await;

    // First retry spends the completed stage.
    let (status, _) = env
        .delete_device(
            &access,
            &device,
            json!({"auth": {"type": "m.login.sso", "session": session}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A *fresh* session cannot ride on it: the mark is gone. (The device
    // need not exist — the challenge comes before any lookup.)
    let (_, body) = env.delete_device(&access, "DEVICETWO", json!({})).await;
    let fresh = body["session"].as_str().unwrap().to_owned();
    let (status, _) = env
        .delete_device(
            &access,
            "DEVICETWO",
            json!({"auth": {"type": "m.login.sso", "session": fresh}}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unbacked SSO claim must re-challenge"
    );
}

/// An SSO identity linked to nobody cannot satisfy re-authentication:
/// the fallback proves an existing link, and never provisions.
#[tokio::test]
async fn uia_fallback_refuses_an_unlinked_identity() {
    let env = start_env(ProviderOpts::default()).await;
    let (_, location, _) = env
        .get("/_matrix/client/v3/auth/m.login.sso/fallback/web?session=some-session")
        .await;
    let authorize = location.expect("redirect to the IdP");
    let state = query_param(&authorize, "state").unwrap();
    let nonce = query_param(&authorize, "nonce").unwrap();
    let code = urlencode(&format!(
        "{}|{nonce}",
        code_for("nobody", "nobody", "Nobody")
    ));
    let (status, _, _) = env
        .get(&format!(
            "/_saltator/client/oidc/callback?state={state}&code={code}"
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        env.users
            .store()
            .account("@nobody:hs.test")
            .unwrap()
            .is_none(),
        "the reauth path must never create an account"
    );
}

/// With no provider configured the SSO surface is absent entirely, and
/// `GET /login` goes back to advertising passwords alone.
#[tokio::test]
async fn sso_routes_are_absent_without_a_provider() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server_name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (signer, _der) =
        saltator_roomserver::ServerSigner::generate(server_name.clone(), "0".to_owned());
    let rooms = RoomServer::start(
        1,
        engine.clone(),
        Arc::new(signer),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let users = UserServer::start(
        1,
        engine.clone(),
        server_name.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [rooms.shard_handle(), users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let media = MediaStore::open(dir.path().join("media")).unwrap();
    let state = CsState::new(
        users.clone(),
        rooms,
        media,
        CsConfig {
            server_name,
            default_room_version: saltator_core::RoomVersion::V12,
            registration_enabled: true,
            registration_requires_token: false,
            max_upload_size: 1024 * 1024,
            well_known_client: None,
            rate_limits: saltator_cs_api::RateLimitConfig::disabled(),
            allow_internal_fetch: true,
            admin_users: Vec::new(),
            server_notices_localpart: None,
        },
    );
    let env = Env {
        _dir: dir,
        router: saltator_cs_api::router(state),
        users,
        issuer: String::new(),
    };

    let (status, _, body) = env.get("/_matrix/client/v3/login").await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_str(&body).unwrap();
    let flows: Vec<&str> = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["type"].as_str().unwrap())
        .collect();
    assert_eq!(flows, vec!["m.login.password"], "{body}");

    let (status, _, _) = env
        .get(&format!(
            "/_matrix/client/v3/login/sso/redirect?redirectUrl={CLIENT_REDIRECT}"
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And a token login is refused: no SSO means no way to have got one.
    let (status, _) = env
        .post_json(
            "/_matrix/client/v3/login",
            json!({"type": "m.login.token", "token": "anything"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
