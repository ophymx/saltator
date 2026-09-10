//! The exporter, end to end: drive requests through the instrumentation
//! layer, scrape `/metrics`, and read what came out.
//!
//! One test function, deliberately. The recorder is a process-wide
//! set-once global, so a second `install()` in the same binary fails —
//! which is the behaviour `install()` promises, and the reason everything
//! that needs a recorder shares this one.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt;

async fn body_string(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("reading body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 body")
}

#[tokio::test]
async fn exports_what_the_layer_measured() {
    let handle = saltator_metrics::install().expect("first install succeeds");

    let app = saltator_metrics::instrument_http(
        axum::Router::new()
            .route("/rooms/{room_id}/send", get(|| async { "sent" }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR })),
        "client",
    );

    // Two DIFFERENT rooms through the SAME template, so the assertion
    // below is about collapsing and not about a single request.
    for room in ["!a:example.org", "!b:example.org"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/rooms/{room}/send"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Nothing routes here: it must not mint a series of its own.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/nothing/here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let scrape = body_string(
        saltator_metrics::router(handle.clone())
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("scrape"),
    )
    .await;

    // The template carries the label, and both rooms landed on it.
    assert!(
        scrape.contains(
            r#"saltator_http_requests_total{surface="client",method="GET",route="/rooms/{room_id}/send",status="200"} 2"#
        ),
        "expected one series for two rooms through one template:\n{scrape}"
    );
    // …and no room id reached the registry, which is the whole cardinality
    // rule in one assertion.
    assert!(
        !scrape.contains("example.org"),
        "a room id leaked into a label:\n{scrape}"
    );
    assert!(scrape.contains(r#"route="<unmatched>""#), "{scrape}");
    assert!(scrape.contains(r#"status="500""#), "{scrape}");

    // Histograms render as buckets, not summaries: the exporter was given
    // explicit bucket bounds, and a quantile-summary render here would
    // mean they were dropped.
    assert!(
        scrape.contains("saltator_http_request_duration_seconds_bucket"),
        "expected bucketed histograms:\n{scrape}"
    );
    assert!(
        scrape.contains("# HELP saltator_http_requests_total"),
        "{scrape}"
    );

    // Build info is a label carrier whose value is always 1.
    saltator_metrics::set_build_info("9.9.9");
    let scrape = body_string(
        saltator_metrics::router(handle)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("scrape"),
    )
    .await;
    assert!(
        scrape.contains(r#"saltator_build_info{version="9.9.9"} 1"#),
        "{scrape}"
    );

    // The set-once contract: a second recorder cannot be installed, and
    // saying so is better than a silent no-op that leaves an operator
    // wondering why a second exporter is empty.
    assert!(saltator_metrics::install().is_err());
}
