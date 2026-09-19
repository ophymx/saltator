//! Dead-node failure detection: the metadata leader pings every roster
//! node's internal
//! Status RPC and, after a grace period of continuous failure, marks the
//! node [`NodeStatus::Unreachable`] — which recomputes placement without
//! it, so its room-group replicas re-place onto surviving nodes. When the
//! node answers again it is restored to `Active` and rendezvous hands its
//! groups back.
//!
//! This is deliberately a *placement-only* verdict, the automatic half of
//! what `drain` already does by hand: the node keeps its roster entry and
//! its metadata-group vote, so a false positive costs data movement, not
//! quorum. Only the leader runs the detector (leadership itself proves
//! quorum contact, so its view is the least partitioned one available),
//! and its counters reset on leadership change — a new leader re-earns
//! the grace period before condemning anyone.

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;
use tonic::transport::ClientTlsConfig;

use crate::placement::NodeStatus;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::StatusRequest;
use crate::types::NodeId;
use crate::MetadataHandle;

/// Consecutive successful pings before an `Unreachable` node is restored
/// — hysteresis so a node gasping once per grace period doesn't slosh
/// its groups back and forth.
const RECOVERY_STREAK: u32 = 3;

/// What one round of observation concluded about a node.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Active and failing for at least the grace period.
    MarkUnreachable,
    /// Unreachable and answering steadily again.
    MarkReachable,
    None,
}

#[derive(Default)]
struct Observed {
    /// Start of the current unbroken failure run (Active nodes).
    failing_since: Option<Instant>,
    /// Current unbroken success run (Unreachable nodes).
    ok_streak: u32,
}

/// The per-node hysteresis state machine, pure so the timing rules are
/// testable without a cluster: an `Active` node must fail *continuously*
/// for `grace` (any success resets the clock); an `Unreachable` node must
/// answer [`RECOVERY_STREAK`] pings in a row.
struct Tracker {
    grace: Duration,
    nodes: HashMap<NodeId, Observed>,
}

impl Tracker {
    fn new(grace: Duration) -> Self {
        Self {
            grace,
            nodes: HashMap::new(),
        }
    }

    /// Forget everything — on losing (or newly gaining) leadership, so
    /// stale counters from another era never condemn a node early.
    fn reset(&mut self) {
        self.nodes.clear();
    }

    fn observe(&mut self, node: NodeId, status: NodeStatus, ok: bool, now: Instant) -> Verdict {
        match status {
            // Draining is operator intent; the detector keeps no opinion.
            NodeStatus::Draining => {
                self.nodes.remove(&node);
                Verdict::None
            }
            NodeStatus::Active => {
                if ok {
                    self.nodes.remove(&node);
                    return Verdict::None;
                }
                let entry = self.nodes.entry(node).or_default();
                entry.ok_streak = 0;
                let since = *entry.failing_since.get_or_insert(now);
                if now.duration_since(since) >= self.grace {
                    self.nodes.remove(&node);
                    Verdict::MarkUnreachable
                } else {
                    Verdict::None
                }
            }
            NodeStatus::Unreachable => {
                let entry = self.nodes.entry(node).or_default();
                entry.failing_since = None;
                if !ok {
                    entry.ok_streak = 0;
                    return Verdict::None;
                }
                entry.ok_streak += 1;
                if entry.ok_streak >= RECOVERY_STREAK {
                    self.nodes.remove(&node);
                    Verdict::MarkReachable
                } else {
                    Verdict::None
                }
            }
        }
    }

    /// Drop state for nodes no longer in the roster.
    fn retain(&mut self, roster: &crate::Roster) {
        self.nodes.retain(|id, _| roster.contains_key(id));
    }
}

/// One liveness probe: a fresh connection (deliberately not cached — the
/// dial is the probe) and a Status round trip, all inside `timeout`.
async fn ping(addr: &str, tls: Option<&ClientTlsConfig>, timeout: Duration) -> bool {
    let probe = async {
        let channel = crate::forward::connect(addr, tls).await.ok()?;
        ControlServiceClient::new(channel)
            .status(StatusRequest {})
            .await
            .ok()
    };
    matches!(tokio::time::timeout(timeout, probe).await, Ok(Some(_)))
}

/// Spawn the failure detector. `grace` is how long a node must fail
/// continuously before re-placement (`cluster.dead_node_grace_secs`);
/// the probe cadence and timeout derive from it. Runs (and no-ops) on
/// every node — only the current metadata leader acts.
pub fn spawn(
    meta: MetadataHandle,
    self_node: NodeId,
    grace: Duration,
    tls: Option<ClientTlsConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = (grace / 5).clamp(Duration::from_secs(1), Duration::from_secs(10));
        let ping_timeout = interval.min(Duration::from_secs(3));
        let mut tracker = Tracker::new(grace);
        let mut was_leader = false;
        loop {
            tokio::time::sleep(interval).await;
            if !meta.is_leader() {
                tracker.reset();
                was_leader = false;
                continue;
            }
            if !was_leader {
                // Fresh leadership: start the grace clocks from here.
                tracker.reset();
                was_leader = true;
            }
            // The Unreachable variant is undecodable by pre-v3 binaries;
            // hold off until the stored schema proves every voter is v3.
            match meta.shard_handle().schema_versions() {
                Ok((stored, _)) if stored >= 3 => {}
                _ => continue,
            }
            let Ok(roster) = meta.roster_local() else {
                continue;
            };
            for (id, info) in &roster {
                if *id == self_node {
                    // Holding leadership is proof of life; clear a mark a
                    // previous leader left on us (e.g. after a healed
                    // partition).
                    if info.status == NodeStatus::Unreachable {
                        match meta.mark_reachable(*id).await {
                            Ok(_) => tracing::info!(node = id, "liveness: self recovered"),
                            Err(e) => tracing::debug!(node = id, error = %e,
                                "liveness: self mark_reachable failed"),
                        }
                    }
                    continue;
                }
                let ok = ping(&info.advertise_addr, tls.as_ref(), ping_timeout).await;
                match tracker.observe(*id, info.status, ok, Instant::now()) {
                    Verdict::MarkUnreachable => match meta.mark_unreachable(*id).await {
                        Ok(true) => tracing::warn!(
                            node = id, addr = %info.advertise_addr, grace = ?grace,
                            "liveness: node unreachable; re-placing its groups",
                        ),
                        Ok(false) => {}
                        Err(e) => tracing::debug!(node = id, error = %e,
                            "liveness: mark_unreachable refused; will retry"),
                    },
                    Verdict::MarkReachable => match meta.mark_reachable(*id).await {
                        Ok(true) => tracing::info!(
                            node = id, addr = %info.advertise_addr,
                            "liveness: node recovered; restoring it to placement",
                        ),
                        Ok(false) => {}
                        Err(e) => tracing::debug!(node = id, error = %e,
                            "liveness: mark_reachable failed; will retry"),
                    },
                    Verdict::None => {}
                }
            }
            tracker.retain(&roster);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::from_secs(30);

    fn tracker() -> Tracker {
        Tracker::new(GRACE)
    }

    #[test]
    fn active_node_is_condemned_only_after_continuous_failure() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.observe(2, NodeStatus::Active, false, t0), Verdict::None);
        // Still inside the grace period.
        assert_eq!(
            t.observe(2, NodeStatus::Active, false, t0 + GRACE / 2),
            Verdict::None
        );
        // One success resets the clock entirely...
        assert_eq!(
            t.observe(2, NodeStatus::Active, true, t0 + GRACE / 2),
            Verdict::None
        );
        assert_eq!(
            t.observe(2, NodeStatus::Active, false, t0 + GRACE),
            Verdict::None,
            "the pre-success failure run must not count"
        );
        // ...so condemnation needs a fresh, unbroken grace period.
        assert_eq!(
            t.observe(2, NodeStatus::Active, false, t0 + GRACE * 2 + GRACE / 2),
            Verdict::MarkUnreachable
        );
    }

    #[test]
    fn unreachable_node_recovers_after_a_steady_streak() {
        let mut t = tracker();
        let now = Instant::now();
        for _ in 0..RECOVERY_STREAK - 1 {
            assert_eq!(
                t.observe(2, NodeStatus::Unreachable, true, now),
                Verdict::None
            );
        }
        // A wobble resets the streak.
        assert_eq!(
            t.observe(2, NodeStatus::Unreachable, false, now),
            Verdict::None
        );
        for _ in 0..RECOVERY_STREAK - 1 {
            assert_eq!(
                t.observe(2, NodeStatus::Unreachable, true, now),
                Verdict::None
            );
        }
        assert_eq!(
            t.observe(2, NodeStatus::Unreachable, true, now),
            Verdict::MarkReachable
        );
    }

    #[test]
    fn draining_nodes_are_never_judged() {
        let mut t = tracker();
        let t0 = Instant::now();
        for i in 0..10 {
            assert_eq!(
                t.observe(2, NodeStatus::Draining, false, t0 + GRACE * i),
                Verdict::None
            );
        }
    }

    #[test]
    fn reset_restarts_the_grace_clock() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.observe(2, NodeStatus::Active, false, t0), Verdict::None);
        t.reset();
        // Post-reset, the old failing_since is gone: even well past the
        // original grace deadline the run starts over.
        assert_eq!(
            t.observe(2, NodeStatus::Active, false, t0 + GRACE * 2),
            Verdict::None
        );
        assert_eq!(
            t.observe(2, NodeStatus::Active, false, t0 + GRACE * 3),
            Verdict::MarkUnreachable
        );
    }
}
