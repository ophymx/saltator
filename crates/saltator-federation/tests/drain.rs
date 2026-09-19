//! The marker-coordinated user-outbox drain + the user shard's v2
//! migration: rows staged in a
//! v1 user store end up in fed-out exactly once, the marker gates the
//! drop, and the drop loses nothing.

use std::sync::Arc;
use std::time::Duration;

use saltator_federation::drain_user_outbox_once;
use saltator_fedout::FedOutServer;
use saltator_shard::NoopNetworkFactory;
use saltator_store::{KvEngine, RocksEngine};
use saltator_userserver::{OutboundEdu as LegacyEdu, UserServer};

#[tokio::test]
async fn drain_moves_rows_once_then_v2_drops_the_table() {
    let dir = tempfile::tempdir().unwrap();
    let engine: Arc<dyn KvEngine> = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let users = UserServer::start(
        1,
        engine.clone(),
        ruma::OwnedServerName::try_from("hs.test").unwrap(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let fedout = FedOutServer::start(
        1,
        engine,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for wait in [
        users
            .shard_handle()
            .wait_for_leader(Duration::from_secs(10)),
        fedout
            .shard_handle()
            .wait_for_leader(Duration::from_secs(10)),
    ] {
        wait.await.unwrap();
    }

    // Legacy rows in the user-shard outbox (the pre-upgrade world; the
    // enqueue command still exists — command enums are append-only).
    users
        .queue_outbound_edus(vec![
            LegacyEdu {
                destination: "a.test".into(),
                json: b"{\"n\":1}".to_vec(),
            },
            LegacyEdu {
                destination: "b.test".into(),
                json: b"{\"n\":2}".to_vec(),
            },
            LegacyEdu {
                destination: "a.test".into(),
                json: b"{\"n\":3}".to_vec(),
            },
        ])
        .await
        .unwrap();
    let tail = users.store().edu_outbox_tail().unwrap();
    assert!(tail > 0);

    // First pass drains everything and reports completion.
    assert!(drain_user_outbox_once(&users, &fedout).await.unwrap());
    assert_eq!(fedout.store().drain_marker().unwrap(), tail);
    let a_rows = fedout.store().edu_outbox("a.test", 10).unwrap();
    let b_rows = fedout.store().edu_outbox("b.test", 10).unwrap();
    assert_eq!((a_rows.len(), b_rows.len()), (2, 1));

    // Idempotency: a second pass (crash-and-resume) adds nothing.
    assert!(drain_user_outbox_once(&users, &fedout).await.unwrap());
    assert_eq!(
        fedout.store().edu_outbox("a.test", 10).unwrap().len(),
        2,
        "re-drain must not duplicate"
    );

    // The gate condition now holds (marker >= tail); the v2 migration
    // drops the drained table. Only the *stored* version is asserted: the
    // code version moves with every later schema step and is not what
    // this test is about.
    assert_eq!(users.shard_handle().schema_versions().unwrap().0, 1);
    users
        .shard_handle()
        .propose_migrate(2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(users.shard_handle().schema_versions().unwrap().0, 2);
    assert_eq!(users.store().edu_outbox_tail().unwrap(), 0);
    // Fed-out rows are untouched by the user-shard drop.
    assert_eq!(fedout.store().edu_outbox("a.test", 10).unwrap().len(), 2);

    fedout.shutdown().await.unwrap();
    users.shutdown().await.unwrap();
}
