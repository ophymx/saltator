//! Request instrumentation, as one layer applied from `main`.
//!
//! Applied by `main` to the routers it builds rather than inside
//! `saltator-cs-api` / `saltator-federation`: the measurement is the same
//! on both surfaces, and neither crate has to know it is being measured.

use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

/// Releases the in-flight slot on drop. A straight-line decrement after
/// the handler's await would never run for a request whose future is
/// dropped — a client that hung up mid-long-poll (routine for /sync) or a
/// handler that panicked — and each of those would ratchet the gauge up
/// forever. Drop runs on completion, cancellation, and unwind alike.
struct InFlightGuard(metrics::Gauge);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

/// The method label draws from a fixed set. Hyper forwards ANY token a
/// client sends as an extension method, so labeling it verbatim would let
/// an unauthenticated caller mint unbounded series — the same cardinality
/// attack the route-template collapse in `measure` exists to stop.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "<other>",
    }
}

/// Wrap a router so every request through it is counted and timed.
///
/// `surface` distinguishes the client-server API from federation. They
/// have different callers, different auth, and different failure meanings
/// — a 401 on the client port is a user typing a bad password; on the
/// federation port it is a signature that did not verify.
pub fn instrument_http(router: axum::Router, surface: &'static str) -> axum::Router {
    describe();
    router.layer(axum::middleware::from_fn_with_state(surface, measure))
}

/// Once per router built, never per request: `describe_*` locks the
/// recorder and rewrites a map entry, which is not a thing to do on the
/// path every request takes.
fn describe() {
    metrics::describe_counter!(
        "saltator_http_requests_total",
        "HTTP requests served, by surface, method, route template and status"
    );
    metrics::describe_histogram!(
        "saltator_http_request_duration_seconds",
        "Time to produce a response, by surface, method and route template"
    );
    metrics::describe_gauge!(
        "saltator_http_requests_in_flight",
        "Requests currently being served, by surface"
    );
}

async fn measure(State(surface): State<&'static str>, req: Request, next: Next) -> Response {
    // The ROUTE TEMPLATE, never the path. `/rooms/{roomId}/send/…` is one
    // series; the path it matched would be one series per message ever
    // sent, which is an unbounded write into our own process memory driven
    // by whatever a client cares to request. A request that matched
    // nothing has no template, and every one of those collapses into a
    // single series on purpose.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".to_owned());
    let method = method_label(req.method());

    let in_flight = metrics::gauge!("saltator_http_requests_in_flight", "surface" => surface);
    in_flight.increment(1.0);
    let in_flight = InFlightGuard(in_flight);
    let started = Instant::now();
    let response = next.run(req).await;
    drop(in_flight);

    let elapsed = started.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    metrics::counter!(
        "saltator_http_requests_total",
        "surface" => surface,
        "method" => method,
        "route" => route.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(
        "saltator_http_request_duration_seconds",
        "surface" => surface,
        "method" => method,
        "route" => route,
    )
    .record(elapsed);

    response
}
