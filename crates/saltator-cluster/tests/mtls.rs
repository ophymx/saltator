//! The internal control plane over mutual TLS (security review 2026-08-13,
//! Vuln 4): a node holding a certificate the server's CA trusts joins the
//! metadata group; a node whose certificate the CA does not trust cannot,
//! and neither can a plaintext client. This is the authentication the
//! plaintext surface lacked — anyone who could reach the port could drive
//! the cluster's Raft groups.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::{
    join_cluster_with_tls, serve_internal_with_tls, ClusterConfig, InternalTls, MetadataHandle,
};
use saltator_shard::ShardRegistry;
use saltator_store::RocksEngine;

/// A self-signed cert with `hs.test` as a DNS SAN, used as both a node's
/// identity and — because a self-signed cert is its own root — as the CA
/// that verifies it. Two independent certs model "signed by our CA" vs
/// "signed by someone else's".
struct Cred {
    cert: String,
    key: String,
}

fn cred() -> Cred {
    let c = rcgen::generate_simple_self_signed(vec!["hs.test".to_string()]).unwrap();
    Cred {
        cert: c.cert.pem(),
        key: c.key_pair.serialize_pem(),
    }
}

/// mTLS where this node presents `id` and trusts `ca` as the peer CA.
fn tls(id: &Cred, ca: &Cred) -> InternalTls {
    InternalTls::from_pem(
        id.cert.as_bytes(),
        id.key.as_bytes(),
        ca.cert.as_bytes(),
        "hs.test",
    )
}

fn ephemeral_addr() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn spawn_serve(
    meta: MetadataHandle,
    registry: ShardRegistry,
    addr: std::net::SocketAddr,
    tls: Option<InternalTls>,
) -> tokio::sync::oneshot::Sender<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_internal_with_tls(
        meta,
        registry,
        saltator_shard::ExecutorRegistry::new(),
        "hs.test".into(),
        vec![],
        addr,
        tls,
        async {
            let _ = stop_rx.await;
        },
    ));
    stop_tx
}

#[tokio::test]
async fn mtls_admits_a_trusted_node_and_rejects_an_untrusted_one() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();

    // The cluster CA is node 1's self-signed cert; node 2 is signed by (is)
    // the same cert, so it chains to the CA. The attacker holds a wholly
    // separate cert.
    let ca = cred();
    let attacker = cred();
    let addr1 = ephemeral_addr();

    // --- Node 1: metadata group + TLS internal listener ---
    let e1 = Arc::new(RocksEngine::open(&dir.path().join("n1")).unwrap());
    let reg1 = ShardRegistry::new();
    let m1 = MetadataHandle::start_with_tls(
        1,
        e1,
        Some(addr1.to_string()),
        Some(&reg1),
        Some(tls(&ca, &ca)),
    )
    .await
    .unwrap();
    m1.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    m1.bootstrap_cluster(ClusterConfig::default(), addr1.to_string())
        .await
        .unwrap();
    let _s1 = spawn_serve(m1.clone(), reg1, addr1, Some(tls(&ca, &ca)));

    // --- The attacker: a cert the CA did not sign cannot join ---
    // Its client trusts node 1 (so the server side of TLS succeeds), but
    // node 1's listener rejects the attacker's client cert, so no join
    // completes before the short deadline.
    let attacker_tls = tls(&attacker, &ca);
    let refused = join_cluster_with_tls(
        &[addr1.to_string()],
        99,
        "127.0.0.1:9",
        Duration::from_secs(3),
        Some(&attacker_tls.client()),
    )
    .await;
    assert!(
        refused.is_err(),
        "a node without a CA-signed cert must not be admitted"
    );

    // A plaintext client is refused for the same reason — it never gets
    // past the TLS handshake.
    let plaintext = join_cluster_with_tls(
        &[addr1.to_string()],
        98,
        "127.0.0.1:9",
        Duration::from_secs(3),
        None,
    )
    .await;
    assert!(
        plaintext.is_err(),
        "a plaintext client must not be admitted"
    );

    // The roster still holds only node 1 — neither refused attempt landed.
    assert_eq!(m1.roster().await.unwrap().len(), 1);

    // --- Node 2: a CA-trusted cert joins and becomes a metadata voter ---
    let addr2 = ephemeral_addr();
    let e2 = Arc::new(RocksEngine::open(&dir.path().join("n2")).unwrap());
    let reg2 = ShardRegistry::new();
    let m2 = MetadataHandle::start_with_tls(2, e2, None, Some(&reg2), Some(tls(&ca, &ca)))
        .await
        .unwrap();
    let _s2 = spawn_serve(m2.clone(), reg2, addr2, Some(tls(&ca, &ca)));
    join_cluster_with_tls(
        &[addr1.to_string()],
        2,
        &addr2.to_string(),
        Duration::from_secs(20),
        Some(&tls(&ca, &ca).client()),
    )
    .await
    .unwrap();
    m2.wait_for_leader(Duration::from_secs(10)).await.unwrap();

    // The trusted node is now in the roster and a metadata voter.
    let roster = m1.roster().await.unwrap();
    assert_eq!(roster.len(), 2, "trusted node joined: {roster:?}");
    assert!(m1.voter_ids().contains(&2));

    m1.shutdown().await.unwrap();
    m2.shutdown().await.unwrap();
}
