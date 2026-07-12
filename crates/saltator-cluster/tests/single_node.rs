//! M0 exit criterion: a 1-node "cluster" starts, persists, restarts
//! (spec.md §12). Runs the metadata group in-process over a temp dir,
//! writes through Raft, tears everything down, reopens the same data dir,
//! and verifies recovery without re-initialization.

use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::types::MetaCommand;
use saltator_cluster::MetadataHandle;
use saltator_store::RocksEngine;

#[tokio::test]
async fn single_node_bootstrap_persist_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db");

    // --- first life: bootstrap, write ---
    {
        let engine = Arc::new(RocksEngine::open(&db_path).unwrap());
        let meta = MetadataHandle::start(1, engine, Some("127.0.0.1:17400".into()))
            .await
            .unwrap();
        let leader = meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
        assert_eq!(leader, 1);

        meta.write(MetaCommand::Set {
            key: "cluster/created".into(),
            value: b"m0".to_vec(),
        })
        .await
        .unwrap();

        assert_eq!(
            meta.read("cluster/created").await.unwrap(),
            Some(b"m0".to_vec())
        );

        meta.shutdown().await.unwrap();
        // engine dropped here; RocksDB lock released
    }

    // --- second life: recover from disk, no bootstrap_addr provided ---
    {
        let engine = Arc::new(RocksEngine::open(&db_path).unwrap());
        // bootstrap_addr = None: if recovery failed, there is no leader and
        // wait_for_leader below would time out.
        let meta = MetadataHandle::start(1, engine, None).await.unwrap();
        let leader = meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
        assert_eq!(leader, 1);

        // Durable state survived the restart.
        assert_eq!(
            meta.read("cluster/created").await.unwrap(),
            Some(b"m0".to_vec())
        );

        // And the group still accepts writes.
        let resp = meta
            .write(MetaCommand::Set {
                key: "cluster/created".into(),
                value: b"m0-again".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(resp.previous, Some(b"m0".to_vec()));

        meta.shutdown().await.unwrap();
    }

    // --- third life: restart WITH a bootstrap addr (the binary's path) ---
    // Must detect the initialized group and recover, not re-initialize.
    {
        let engine = Arc::new(RocksEngine::open(&db_path).unwrap());
        let meta = MetadataHandle::start(1, engine, Some("127.0.0.1:17400".into()))
            .await
            .unwrap();
        let leader = meta.wait_for_leader(Duration::from_secs(10)).await.unwrap();
        assert_eq!(leader, 1);
        assert_eq!(
            meta.read("cluster/created").await.unwrap(),
            Some(b"m0-again".to_vec())
        );
        meta.shutdown().await.unwrap();
    }
}
