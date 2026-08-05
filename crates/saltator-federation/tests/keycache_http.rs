//! End-to-end federation auth over real HTTP:
//! - a node publishes keys; a `KeyCache` fetches and verifies them
//! - node A signs a request with `FederationClient`; node B's
//!   `Authenticated` extractor fetches A's keys and verifies the signature
//! - a tampered signature is rejected

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use saltator_federation::{
    router, Authenticated, FedState, FederationClient, KeyCache, OldVerifyKey,
};
use saltator_roomserver::ServerSigner;

fn fed_state(name: &str, key_cache: KeyCache) -> Arc<FedState> {
    let name: ruma::OwnedServerName = name.try_into().unwrap();
    let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
    Arc::new(FedState {
        server_name: name,
        signer: Arc::new(signer),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: Arc::new(key_cache),
        rooms: None,
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    })
}

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn keycache_fetches_and_verifies_over_http() {
    let state = fed_state("node.test", KeyCache::new());
    let base = spawn(router(state)).await;

    let cache = KeyCache::with_base_url(base);
    let keys = cache
        .keys_for("node.test", 1_000)
        .await
        .expect("fetch keys");
    assert!(keys.get("node.test").unwrap().contains_key("ed25519:1"));

    // Second call is served from cache.
    let keys2 = cache.keys_for("node.test", 1_001).await.unwrap();
    assert_eq!(
        keys.get("node.test").unwrap().len(),
        keys2.get("node.test").unwrap().len()
    );
}

// A minimal authenticated endpoint using the real extractor, to prove the
// inbound path end to end.
async fn echo_origin(
    State(_state): State<Arc<FedState>>,
    auth: Authenticated,
) -> axum::Json<serde_json::Value> {
    let body: serde_json::Value = auth.json().unwrap();
    axum::Json(serde_json::json!({ "origin": auth.origin, "echo": body }))
}

#[tokio::test]
async fn signed_request_authenticates_across_two_nodes() {
    // Node A: the caller. Serve its key endpoint so B can fetch A's keys.
    let a = fed_state("a.test", KeyCache::new());
    let a_signer = a.signer.clone();
    let a_base = spawn(router(a)).await;

    // Node B: the receiver. Its key cache resolves every origin at A's
    // address (only A calls it in this test).
    let b = fed_state("b.test", KeyCache::with_base_url(a_base));
    let b_app = axum::Router::new()
        .route(
            "/_matrix/federation/v1/echo",
            post(echo_origin).put(echo_origin),
        )
        .with_state(b.clone());
    let b_base = spawn(b_app).await;

    // A signs a PUT to B and delivers it.
    let client = FederationClient::with_base_url(a_signer, b_base);
    let body = serde_json::json!({ "hello": "world" });
    let resp = client
        .put("b.test", "/_matrix/federation/v1/echo", &body)
        .await
        .expect("authenticated request succeeds");
    assert_eq!(resp["origin"], "a.test");
    assert_eq!(resp["echo"], body);
}

#[tokio::test]
async fn tampered_signature_is_rejected() {
    let a = fed_state("a.test", KeyCache::new());
    let a_signer = a.signer.clone();
    let a_base = spawn(router(a)).await;

    let b = fed_state("b.test", KeyCache::with_base_url(a_base));
    let b_app = axum::Router::new()
        .route(
            "/_matrix/federation/v1/echo",
            post(echo_origin).put(echo_origin),
        )
        .with_state(b.clone());
    let b_base = spawn(b_app).await;

    // Sign for one path but send to another: B reconstructs the signed
    // object from the real request line, so verification must fail.
    let client = FederationClient::with_base_url(a_signer.clone(), b_base.clone());
    let auth = saltator_federation::sign_request(
        &a_signer,
        "POST",
        "/_matrix/federation/v1/other",
        "b.test",
        Some(&ruma::CanonicalJsonValue::try_from(serde_json::json!({ "hello": "world" })).unwrap()),
    )
    .unwrap();
    let http = reqwest::Client::new();
    let status = http
        .post(format!("{b_base}/_matrix/federation/v1/echo"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&serde_json::json!({ "hello": "world" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 401);
    // silence unused warning on the typed client
    let _ = &client;
}
