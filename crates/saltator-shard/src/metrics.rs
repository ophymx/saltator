//! Shard-runtime measurements, emitted through the `metrics` facade.
//!
//! The facade is a no-op until `saltator-metrics` installs a recorder, so
//! nothing here costs anything in a test binary and this crate never
//! depends on an exporter (`docs/design-observability.md`).
//!
//! Every series is labeled `keyspace` and `shard` — spec.md §7's own
//! phrasing — and by nothing else. A shard is the unit that has a leader,
//! a log, and an apply loop, so it is the unit whose numbers can be read
//! without further breakdown; adding a command-type label here would put
//! app-level meaning into the runtime, where it does not belong.

use std::time::Duration;

use crate::handle::ProposeOutcome;
use crate::ShardId;

/// Register every series' help text. Called once at startup, never from
/// a hot path: `describe_*` takes the recorder's lock and rewrites a map
/// entry, and paying that on every proposal and every applied batch would
/// make the measurement itself the thing worth measuring.
pub fn describe() {
    metrics::describe_counter!(
        "saltator_shard_proposals_total",
        "Raft proposals, by how they resolved: applied here, forwarded to the leader, or failed"
    );
    metrics::describe_histogram!(
        "saltator_shard_proposal_duration_seconds",
        "Time from proposing a command to holding its response"
    );
    metrics::describe_histogram!(
        "saltator_shard_apply_duration_seconds",
        "Time to apply one committed batch to the state machine and commit its write batch"
    );
    metrics::describe_counter!(
        "saltator_shard_applied_entries_total",
        "Committed log entries applied to the state machine"
    );
    metrics::describe_gauge!(
        "saltator_shard_leader",
        "1 when this node leads the shard's Raft group, 0 otherwise"
    );
    metrics::describe_gauge!(
        "saltator_shard_seq",
        "Latest emitted change sequence number in applied state"
    );
    metrics::describe_gauge!("saltator_shard_voters", "Voting members of the Raft group");
}

// Label values are passed as cheaply as the facade allows, because these
// run on the propose and apply hot paths and the macros evaluate their
// label expressions whether or not a recorder is installed:
// `Keyspace::name()` is a `&'static str` (zero-alloc borrowed), and only
// the shard index is formatted — once per call, cloned where a second
// macro needs it.

pub(crate) fn observe_proposal(shard: ShardId, elapsed: Duration, outcome: &ProposeOutcome) {
    let index = shard.index.to_string();
    metrics::counter!(
        "saltator_shard_proposals_total",
        "keyspace" => shard.keyspace.name(),
        "shard" => index.clone(),
        "outcome" => outcome.kind,
    )
    .increment(1);
    metrics::histogram!(
        "saltator_shard_proposal_duration_seconds",
        "keyspace" => shard.keyspace.name(),
        "shard" => index,
        "outcome" => outcome.kind,
    )
    .record(elapsed.as_secs_f64());
}

/// One state-machine apply call: the whole batch, not the entry. Openraft
/// hands the batch to the store as one unit and it commits as one write
/// batch, so the batch is what has a duration; entries are counted
/// separately, and the ratio between them is the group-commit win.
pub(crate) fn observe_apply(shard: ShardId, elapsed: Duration, entries: usize) {
    let index = shard.index.to_string();
    metrics::histogram!(
        "saltator_shard_apply_duration_seconds",
        "keyspace" => shard.keyspace.name(),
        "shard" => index.clone(),
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "saltator_shard_applied_entries_total",
        "keyspace" => shard.keyspace.name(),
        "shard" => index,
    )
    .increment(entries as u64);
}

/// Current shard state, sampled on a tick rather than written on change
/// (see `saltator_metrics::spawn_sampler`). `is_leader` is the one an
/// operator reads first: it says which node is answering writes for this
/// group, and a cluster where it is 0 everywhere is a cluster in an
/// election.
pub fn sample_shard_gauges(shard: ShardId, is_leader: bool, seq: Option<u64>, voters: usize) {
    let index = shard.index.to_string();
    metrics::gauge!(
        "saltator_shard_leader",
        "keyspace" => shard.keyspace.name(),
        "shard" => index.clone(),
    )
    .set(if is_leader { 1.0 } else { 0.0 });
    // The metadata group has no app sequence of its own; absent means
    // absent, rather than a zero that reads like "nothing has happened".
    if let Some(seq) = seq {
        metrics::gauge!(
            "saltator_shard_seq",
            "keyspace" => shard.keyspace.name(),
            "shard" => index.clone(),
        )
        .set(seq as f64);
    }
    metrics::gauge!(
        "saltator_shard_voters",
        "keyspace" => shard.keyspace.name(),
        "shard" => index,
    )
    .set(voters as f64);
}
