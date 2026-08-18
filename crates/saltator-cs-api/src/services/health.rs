//! Liveness and readiness (the step-5 follow-up named in
//! [`super::cluster_admin`]): the signal a load balancer polls to decide
//! whether this node should receive traffic.
//!
//! The gap this closes: draining a node marks it as no longer a placement
//! target, but nothing told the thing in front of it to stop sending
//! requests. A drained node keeps its old local state and stops receiving
//! updates, so reads go stale and writes — which forward to the leader
//! and then wait for *local* applied state to catch up — hang. Taking it
//! out of service was a manual step, and manual steps are missed at
//! exactly the wrong moment.
//!
//! Two questions, deliberately kept apart, because an orchestrator does
//! different things with the answers:
//!
//! * **Live** — is this process working at all? A false answer should get
//!   it killed and restarted.
//! * **Ready** — should it be sent traffic *now*? A false answer should
//!   get it removed from the pool and left alone. Draining answers false
//!   here and true above: the node is perfectly healthy, it is leaving.
//!
//! Conflating the two is the classic way to turn a rolling drain into a
//! crash loop.
//!
//! Unauthenticated, because a load balancer has no credentials — so the
//! body says only what a prober needs and never enumerates the cluster.

use std::sync::Arc;

use saltator_cluster::{MetadataHandle, NodeStatus};
use saltator_roomserver::RoomServer;
use saltator_userserver::UserServer;

/// Why a node is not ready. Ordered by what an operator should look at
/// first; the first failing check is the one reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotReady {
    /// An administrator has drained this node. It is leaving; stop
    /// sending it traffic. Not an error, and not a reason to restart it.
    Draining,
    /// A shard this node serves has no leader it can see — a quorum loss
    /// or an election in flight. Writes would hang, so hold traffic off
    /// until it settles.
    NoShardLeader,
}

impl NotReady {
    pub fn reason(self) -> &'static str {
        match self {
            NotReady::Draining => "draining",
            NotReady::NoShardLeader => "no_shard_leader",
        }
    }

    /// Human-facing detail. Safe for an unauthenticated prober: it names
    /// a condition, never a node, address or topology.
    pub fn detail(self) -> &'static str {
        match self {
            NotReady::Draining => "This node is draining and must not receive new requests.",
            NotReady::NoShardLeader => {
                "A shard has no reachable leader; writes would not complete."
            }
        }
    }
}

pub(crate) struct Health<'a> {
    pub users: &'a Arc<UserServer>,
    pub rooms: &'a Arc<RoomServer>,
    /// `None` in stacks without a control plane (single-node without
    /// clustering, and most test harnesses): there is then no roster to
    /// be draining in, and readiness rests on the shard checks alone.
    pub cluster: Option<&'a MetadataHandle>,
}

impl Health<'_> {
    /// Whether the process is functioning. Answering at all is most of
    /// the answer — the request was routed, the runtime is scheduling,
    /// the router is up — so this deliberately does no I/O and takes no
    /// locks. A check that can block is a check that can wedge a restart
    /// loop onto a node that was merely busy.
    pub fn live(&self) -> bool {
        true
    }

    /// Whether this node should be sent traffic. Gathers the two facts
    /// [`decide`] needs; the judgement itself is there, where it can be
    /// tested across states this node cannot easily be put into (a
    /// single-node cluster refuses to drain its last active node).
    pub fn ready(&self) -> Result<(), NotReady> {
        // `None` when there is no control plane at all — no roster, so
        // nothing to be draining in.
        let status = self.cluster.and_then(|meta| {
            meta.roster_local()
                .ok()
                .and_then(|roster| roster.get(&meta.node_id()).map(|info| info.status))
        });
        let shard_leaders = [self.users.shard_handle(), self.rooms.shard_handle()]
            .iter()
            .all(|h| h.current_leader().is_some());
        decide(status, shard_leaders)
    }
}

/// The readiness rule, over the two facts that decide it.
///
/// Order matters: draining is reported ahead of a missing leader because
/// it is a deliberate operator action, and a node on its way out can
/// legitimately lose leaders as it stands groups down. Reporting that as
/// `no_shard_leader` would send someone hunting a fault that is not there.
fn decide(status: Option<NodeStatus>, shard_leaders: bool) -> Result<(), NotReady> {
    if status == Some(NodeStatus::Draining) {
        return Err(NotReady::Draining);
    }
    if !shard_leaders {
        return Err(NotReady::NoShardLeader);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decide, NotReady};
    use saltator_cluster::NodeStatus;

    #[test]
    fn an_active_node_with_leaders_is_ready() {
        assert!(decide(Some(NodeStatus::Active), true).is_ok());
    }

    /// No control plane (single-node without clustering, most test
    /// harnesses): there is no roster to be draining in, so readiness
    /// rests on the shards alone.
    #[test]
    fn no_control_plane_still_reports_ready() {
        assert!(decide(None, true).is_ok());
        assert_eq!(decide(None, false), Err(NotReady::NoShardLeader));
    }

    /// The point of the endpoint: a drained node must fall out of the
    /// load balancer pool by itself.
    #[test]
    fn draining_is_not_ready() {
        assert_eq!(
            decide(Some(NodeStatus::Draining), true),
            Err(NotReady::Draining)
        );
    }

    /// And draining outranks a missing leader — a node standing its
    /// groups down has both, and only one of them is the reason.
    #[test]
    fn draining_outranks_a_missing_leader() {
        assert_eq!(
            decide(Some(NodeStatus::Draining), false),
            Err(NotReady::Draining)
        );
    }

    #[test]
    fn a_shard_without_a_leader_is_not_ready() {
        assert_eq!(
            decide(Some(NodeStatus::Active), false),
            Err(NotReady::NoShardLeader)
        );
    }
}
