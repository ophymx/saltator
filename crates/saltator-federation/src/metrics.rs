//! Federation delivery measurements (`docs/design-observability.md`).
//!
//! **No destination label, ever.** A remote server name is
//! attacker-supplied — any server can claim any `origin`, and any user in
//! a room puts its server in our destination set — so a `dest` label is an
//! unbounded write into this process's own memory. These series aggregate;
//! *which* destination is failing stays a log line, where `delivery.rs`
//! already emits it with the error attached.

use std::time::Duration;

/// Register every series' help text, once, at startup. Not from the
/// delivery loop: `describe_*` locks the recorder and rewrites a map
/// entry, and a busy server sends transactions far more often than it
/// starts.
pub fn describe() {
    metrics::describe_histogram!(
        "saltator_federation_pdu_queue_delay_seconds",
        "Event creation to the start of the transaction carrying it"
    );
    metrics::describe_histogram!(
        "saltator_federation_pdu_put_duration_seconds",
        "Round trip of one outbound /send transaction"
    );
    metrics::describe_counter!(
        "saltator_federation_pdus_sent_total",
        "PDUs handed to a remote server in an acked transaction"
    );
    metrics::describe_counter!(
        "saltator_federation_transactions_total",
        "Outbound federation transactions, by kind and whether the remote acked"
    );
    metrics::describe_gauge!(
        "saltator_federation_destinations_backed_off",
        "Remote servers currently in a delivery backoff window"
    );
}

/// Split the wait a PDU experiences into the two halves that have
/// different fixes. `queue` is event creation → this transaction's PUT
/// starting: our own apply, the worker's wake-up, and any pass already in
/// flight — all ours to shorten. `put` is the round trip: network plus the
/// receiving server's ingest, none of it ours. `delivery.rs` already
/// computed both for its debug log (roadmap: "instrument deliver_pdus
/// latency, then attack the dominant term"); this is where the aggregate
/// that names the dominant term comes from.
///
/// `queue` is optional because only locally-authored events carry a
/// timestamp from OUR clock — a transaction of purely relayed events has
/// no trustworthy queue sample, but its round trip and PDU count are
/// still ours to record.
pub(crate) fn observe_pdu_transaction(queue: Option<Duration>, put: Duration, pdus: usize) {
    if let Some(queue) = queue {
        metrics::histogram!("saltator_federation_pdu_queue_delay_seconds")
            .record(queue.as_secs_f64());
    }
    metrics::histogram!("saltator_federation_pdu_put_duration_seconds").record(put.as_secs_f64());
    metrics::counter!("saltator_federation_pdus_sent_total").increment(pdus as u64);
}

/// One outbound transaction's fate. `kind` separates PDUs from EDUs
/// because only the first is ordered and cursor-tracked: a failed EDU
/// transaction is retried from the outbox, a failed PDU transaction stalls
/// that destination's cursor and everything behind it.
pub(crate) fn observe_transaction(kind: &'static str, ok: bool) {
    metrics::counter!(
        "saltator_federation_transactions_total",
        "kind" => kind,
        "outcome" => if ok { "ok" } else { "error" },
    )
    .increment(1);
}

/// How many destinations are serving a backoff penalty right now. The
/// count, not the names: a rise here is the signal ("we are failing to
/// reach more servers than usual"), and identifying them is a log query,
/// not a time series.
///
/// Sampled from the node's gauge tick (`saltator_metrics::spawn_sampler`)
/// like every other current-state gauge, rather than written by the
/// delivery worker at pass boundaries — a pass over many failing
/// destinations blocks for destinations × timeout, which is exactly when
/// a pass-boundary write would go stale. `delivering` is fed-out
/// leadership: only the delivering node's backoff map describes anything;
/// everyone else reports zero.
pub fn sample_delivery_gauges(backoff: &crate::DeliveryBackoff, delivering: bool) {
    let count = if delivering { backoff.backed_off() } else { 0 };
    metrics::gauge!("saltator_federation_destinations_backed_off").set(count as f64);
}
