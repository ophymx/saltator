//! The federation TLS transport end to end: an HTTPS federation listener
//! (axum-server + rustls) presenting a self-signed cert, reached by our
//! outbound client trusting that cert as an extra CA. This is exactly the
//! shape Complement expects (HS serves HTTPS on the federation port; peers
//! trust a private CA).

use std::sync::Arc;

use saltator_federation::{build_http_client, router, FedState, OldVerifyKey};
use saltator_roomserver::ServerSigner;

#[tokio::test]
async fn outbound_client_reaches_https_federation_listener() {
    // rustls needs a process-default crypto provider before any TLS use.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // A self-signed cert valid for 127.0.0.1 (the address we bind).
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    // Federation router (unauth /version is enough to prove the transport).
    let name: ruma::OwnedServerName = "127.0.0.1".try_into().unwrap();
    let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
    let state = Arc::new(FedState::new(
        name,
        Arc::new(signer),
        Vec::<OldVerifyKey>::new(),
    ));
    let app = router(state);

    // Bind first to learn the ephemeral port, then serve HTTPS over it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // A plain client (system roots only) must reject the self-signed cert.
    let untrusting = build_http_client(None, true);
    let rejected = untrusting
        .get(format!("https://{addr}/_matrix/federation/v1/version"))
        .send()
        .await;
    assert!(
        rejected.is_err(),
        "self-signed cert must not be trusted by default"
    );

    // A client trusting our cert as an extra CA connects over TLS.
    let trusting = build_http_client(Some(cert.cert.pem().as_bytes()), true);
    let resp = trusting
        .get(format!("https://{addr}/_matrix/federation/v1/version"))
        .send()
        .await
        .expect("HTTPS request succeeds when the cert is trusted");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["server"]["name"], "saltator");
}
