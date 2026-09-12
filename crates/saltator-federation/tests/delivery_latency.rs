//! Head-of-line blocking in outbound delivery (roadmap "federation
//! delivery latency"): a slow destination must not tax healthy ones.
//! One mock federation endpoint serves every destination (the X-Matrix
//! `destination` field says who a request was for) and answers slowly
//! for one of them; the healthy destination's transaction must arrive
//! without waiting behind the slow round trip.

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use saltator_federation::{spawn_delivery_worker, DeliveryBackoff, FederationClient};
use saltator_fedout::{FedOutServer, OutboundEdu};
use saltator_roomserver::{RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use tokio::time::Instant;

/// How long the slow destination sits on each request. Well above any
/// local scheduling noise, well below test-timeout territory.
const SLOW: Duration = Duration::from_secs(2);

/// `(destination, arrived_at)` for every transaction PUT the mock saw.
type Arrivals = Arc<std::sync::Mutex<Vec<(String, Instant)>>>;

fn destination_of(headers: &axum::http::HeaderMap) -> String {
    // X-Matrix auth carries `destination="..."` — who the caller thinks
    // it is talking to.
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split("destination=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
        })
        .unwrap_or_default()
        .to_owned()
}

async fn start_mock(arrivals: Arrivals) -> String {
    async fn send_txn(
        axum::extract::State(arrivals): axum::extract::State<Arrivals>,
        headers: axum::http::HeaderMap,
    ) -> axum::Json<serde_json::Value> {
        let dest = destination_of(&headers);
        arrivals
            .lock()
            .unwrap()
            .push((dest.clone(), Instant::now()));
        if dest.starts_with("a-slow") {
            tokio::time::sleep(SLOW).await;
        }
        axum::Json(serde_json::json!({ "pdus": {} }))
    }
    let app = axum::Router::new()
        .route(
            "/_matrix/federation/v1/send/{txn}",
            axum::routing::put(send_txn),
        )
        .with_state(arrivals);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A slow destination must not delay a healthy one's delivery. The slow
/// server is named to sort FIRST in the per-pass destination order, so
/// under sequential delivery the healthy PUT waited out the full slow
/// round trip — this assertion is the measurement that motivated the
/// concurrent fan-out, and the regression guard that keeps it.
#[tokio::test]
async fn slow_destination_does_not_stall_healthy_ones() {
    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let signer = Arc::new(signer);

    let arrivals: Arrivals = Default::default();
    let mock = start_mock(arrivals.clone()).await;

    let rooms_engine = Arc::new(RocksEngine::open(&dir.path().join("rooms")).unwrap());
    let rooms = RoomServer::start(
        1,
        rooms_engine,
        signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let fedout_engine: Arc<dyn saltator_store::KvEngine> =
        Arc::new(RocksEngine::open(&dir.path().join("fedout")).unwrap());
    let fedout = FedOutServer::start(
        1,
        fedout_engine,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for wait in [rooms.shard_handle(), fedout.shard_handle()] {
        wait.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    let client = Arc::new(FederationClient::with_base_url(signer.clone(), mock));
    let worker = spawn_delivery_worker(
        fedout.clone(),
        rooms.clone(),
        client,
        hs,
        Arc::new(DeliveryBackoff::default()),
    );

    // Ten slow destinations ahead of one healthy one — the worst-case
    // pass shape. Sequentially that is 10 × SLOW before "fast.test" gets
    // its turn; concurrently the healthy PUT starts immediately.
    let mut edus: Vec<OutboundEdu> = (0..10)
        .map(|i| OutboundEdu {
            destination: format!("a-slow-{i}.test"),
            json: br#"{"edu_type":"m.typing","content":{}}"#.to_vec(),
        })
        .collect();
    edus.push(OutboundEdu {
        destination: "fast.test".to_owned(),
        json: br#"{"edu_type":"m.typing","content":{}}"#.to_vec(),
    });
    let t0 = Instant::now();
    fedout.enqueue_edus(edus).await.unwrap();

    // Wait for the healthy destination's transaction to arrive.
    let fast_after = loop {
        if let Some(at) = arrivals
            .lock()
            .unwrap()
            .iter()
            .find(|(d, _)| d == "fast.test")
            .map(|(_, at)| *at)
        {
            break at - t0;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(25),
            "fast.test never got its transaction (arrivals so far: {:?})",
            arrivals
                .lock()
                .unwrap()
                .iter()
                .map(|(d, at)| (d.clone(), *at - t0))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    worker.abort();
    fedout.shutdown().await.unwrap();

    assert!(
        fast_after < SLOW,
        "healthy destination waited {fast_after:?} — stalled behind the slow peers \
         (sequential delivery); expected well under one slow round trip ({SLOW:?})"
    );
}
