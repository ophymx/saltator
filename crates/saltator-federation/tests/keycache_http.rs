//! End-to-end: KeyCache fetches a node's published keys over HTTP and
//! verifies the self-signature (the fetch→verify→cache loop).
use saltator_federation::{router, FedState, KeyCache};
use saltator_roomserver::ServerSigner;
use std::sync::Arc;

#[tokio::test]
async fn keycache_fetches_and_verifies_over_http() {
    let name: ruma::OwnedServerName = "node.test".try_into().unwrap();
    let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
    let signer = Arc::new(signer);
    let state = Arc::new(FedState {
        server_name: name,
        signer: signer.clone(),
        old_keys: vec![],
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });

    let cache = KeyCache::with_base_url(format!("http://{addr}"));
    let keys = cache
        .keys_for("node.test", 1_000)
        .await
        .expect("fetch keys");
    assert!(keys.get("node.test").unwrap().contains_key("ed25519:1"));

    // Second call hits the cache (server still reachable, but this must
    // succeed regardless).
    let keys2 = cache.keys_for("node.test", 1_001).await.unwrap();
    assert_eq!(
        keys.get("node.test").unwrap().len(),
        keys2.get("node.test").unwrap().len()
    );
}
