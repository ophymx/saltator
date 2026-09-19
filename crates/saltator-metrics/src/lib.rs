//! Prometheus metrics: the recorder, the exporter that serves it, and the
//! HTTP instrumentation layer. Operator reference: `docs/observability.md`.
//!
//! Only this crate knows there is an exporter. Everything that *emits* a
//! measurement — shard runtime, federation delivery — calls the `metrics`
//! facade macros directly, which are no-ops until a recorder is installed.
//! That is what lets those crates' test suites run with no recorder at
//! all, and what keeps a Prometheus dependency out of the middle of the
//! server.

mod http;

use std::net::SocketAddr;
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub use http::instrument_http;

/// Histogram buckets, in seconds. One set for every histogram: these are
/// all latencies, and they span the range this server actually produces —
/// a local RocksDB apply at the bottom, a cross-continent federation round
/// trip in the middle, and a bucket above the 10s mark so that "gave up"
/// is visible as its own count rather than hidden in `+Inf`.
const BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// How often the recorder's maintenance hook runs. No idle timeout is
/// configured, so today it has little to do — and that is deliberate:
/// these series are cumulative, and a counter that stopped moving is
/// still telling the truth, so nothing here should expire on its own.
/// The tick exists because it is the documented hook, and it is what an
/// idle-timeout policy would hang off if one is ever wanted.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Install the process-wide recorder. Call once, from `main`, and only
/// when metrics are configured — the facade's global slot is set-once, so
/// a second call is an error rather than a silent no-op, and this returns
/// that error rather than swallowing it.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    let recorder = PrometheusBuilder::new()
        .set_buckets(BUCKETS)
        .map_err(|e| anyhow::anyhow!("configuring metric buckets: {e}"))?
        .build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)
        .map_err(|e| anyhow::anyhow!("installing the metrics recorder: {e}"))?;
    // This crate's own process-level series, described here — once, at
    // install — for the same reason `main` calls every other crate's
    // `describe()` at startup: no set site pays the describe lock again.
    metrics::describe_gauge!(
        "saltator_uptime_seconds",
        "Seconds since this process started"
    );
    metrics::describe_gauge!(
        "saltator_build_info",
        "Always 1; the version label is the payload"
    );
    Ok(handle)
}

/// The exporter's router: `GET /metrics`, and nothing else. Anything else
/// on this listener would be a second, unauthenticated administrative
/// surface, which is exactly what putting it on its own port avoids.
pub fn router(handle: PrometheusHandle) -> axum::Router {
    axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let handle = handle.clone();
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    handle.render(),
                )
            }
        }),
    )
}

/// Serve the exporter on its own listener and keep the registry swept.
///
/// Binding failure is returned, not logged: a metrics port that silently
/// did not come up is worse than one that refuses to start, because the
/// first symptom is a dashboard that was never going to have data.
pub async fn serve(
    addr: SocketAddr,
    handle: PrometheusHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding the metrics listener on {addr}: {e}"))?;
    tracing::info!(listen = %addr, "metrics listening");

    let upkeep = handle.clone();
    let mut upkeep_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(UPKEEP_INTERVAL) => upkeep.run_upkeep(),
                _ = upkeep_shutdown.wait_for(|stop| *stop) => return,
            }
        }
    });

    let app = router(handle);
    Ok(tokio::spawn(async move {
        let served = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown.wait_for(|stop| *stop).await;
            })
            .await;
        if let Err(e) = served {
            tracing::error!(error = %e, "metrics listener stopped");
        }
    }))
}

/// Run `sample` every `interval` until shutdown. Gauges that describe
/// current state — leadership, applied index, queue depth — are read on a
/// tick rather than written at every change: the source of truth is the
/// shard handle, and polling it means no hot path pays for a gauge, and no
/// gauge can drift from the thing it claims to describe.
pub fn spawn_sampler<F>(
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    sample: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            sample();
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.wait_for(|stop| *stop) => return,
            }
        }
    })
}

/// Seconds since this process started serving. Cheaper to reason about
/// than a start-timestamp gauge: a restart shows as a drop to zero on the
/// same graph as whatever else went wrong at that moment.
pub fn set_uptime(uptime: Duration) {
    metrics::gauge!("saltator_uptime_seconds").set(uptime.as_secs_f64());
}

/// `saltator_build_info{version}` — always 1. The value carries nothing;
/// the label is the point, so a graph of a regression can be joined
/// against the version that introduced it.
pub fn set_build_info(version: &'static str) {
    metrics::gauge!("saltator_build_info", "version" => version).set(1.0);
}
