//! Cluster administration (docs/design-admin-identity.md slice 6): what
//! the cluster looks like, and how a node leaves it. No HTTP anywhere;
//! routes call this.
//!
//! Removing a node is two operations, not one, and the split is the whole
//! design:
//!
//! 1. **Drain.** The node stops being a placement target. Each data
//!    group's leader then reconciles it out of the voter set by the
//!    ordinary mechanism — there is no drain-specific code path in the
//!    reconciler, which is why this works for every group including the
//!    ones the draining node leads. Throughout, it stays a metadata voter,
//!    which is what lets it *hear* the placement update telling it to
//!    stand down.
//! 2. **Remove.** Once it holds nothing, it leaves the metadata group and
//!    the roster.
//!
//! Doing both at once would cut the node off from the metadata group while
//! it still led groups, leaving it unable to learn it should release them.
//!
//! **A drained node must be taken out of service.** It keeps its old local
//! state but stops receiving updates, so reads go stale and writes — which
//! forward to the leader and then wait for *local* applied state to catch
//! up — hang. Nothing here can enforce that; there is no readiness
//! endpoint for a load balancer to poll yet, and adding one is the honest
//! follow-up.

use saltator_cluster::placement::RosterError;
use saltator_cluster::{ClusterError, MetadataHandle, NodeStatus};
use saltator_shard::ShardId;
use serde::Serialize;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

pub(crate) struct ClusterAdmin<'a> {
    /// `None` when no metadata group is wired (test stacks that run the
    /// shard servers directly).
    pub meta: Option<&'a MetadataHandle>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NodeRow {
    pub node_id: u64,
    pub advertise_addr: String,
    /// `active` or `draining`.
    pub status: String,
    /// Data groups this node is assigned to host, as
    /// `Keyspace/index`. Empty on a fully drained node — which is the
    /// signal that it is safe to stop and remove.
    pub groups: Vec<String>,
    pub metadata_voter: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct NodeList {
    /// The node that answered. Roster and placement are read from its own
    /// applied state, so on a follower they can trail the leader by a
    /// replication round trip.
    pub view_from: u64,
    /// The metadata leader — the node that drain, undrain and remove must
    /// be issued to.
    pub leader: Option<u64>,
    pub nodes: Vec<NodeRow>,
}

fn status_name(status: NodeStatus) -> &'static str {
    match status {
        NodeStatus::Active => "active",
        NodeStatus::Draining => "draining",
    }
}

/// Render a placement group number for a human. Unknown keyspaces print
/// as the raw number rather than being hidden.
fn group_label(group: u64) -> String {
    match ShardId::from_group(group) {
        Some(shard) => shard.to_string(),
        None => group.to_string(),
    }
}

/// Map a cluster-layer failure to its HTTP shape. The roster refusals are
/// caller errors with distinct causes; everything else is ours.
fn map_error(e: ClusterError) -> ApiError {
    match e {
        ClusterError::Roster(RosterError::UnknownNode) => {
            ApiError::not_found("No such node in the cluster roster")
        }
        ClusterError::Roster(cause) => ApiError::invalid_param(cause.to_string()),
        other => ApiError::internal(other),
    }
}

impl ClusterAdmin<'_> {
    fn handle(&self) -> Result<&MetadataHandle> {
        self.meta.ok_or_else(|| {
            ApiError::invalid_param("This server is not running a cluster control plane")
        })
    }

    /// The metadata leader, or an error naming it.
    ///
    /// Roster changes are leader-only: they read-modify-write control-plane
    /// records and change metadata group membership. Rather than invent a
    /// forwarding RPC for an operator-frequency call, say plainly where to
    /// go — `GET /cluster/nodes` reports the same thing.
    fn require_leader(&self) -> Result<&MetadataHandle> {
        let meta = self.handle()?;
        if meta.is_leader() {
            return Ok(meta);
        }
        let where_to = match meta.leader_hint() {
            Some((id, addr)) => format!("node {id} ({addr})"),
            None => "the metadata leader, which is currently unknown".to_owned(),
        };
        Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "M_UNKNOWN",
            format!("Cluster changes must be made on {where_to}"),
        ))
    }

    /// The roster as this node sees it, joined with the placement.
    pub fn list_nodes(&self) -> Result<NodeList> {
        let meta = self.handle()?;
        let roster = meta.roster_local().map_err(ApiError::internal)?;
        let placement = meta.placement_local().map_err(ApiError::internal)?;
        let voters = meta.voter_ids();
        let nodes = roster
            .into_iter()
            .map(|(node_id, info)| NodeRow {
                node_id,
                advertise_addr: info.advertise_addr,
                status: status_name(info.status).to_owned(),
                groups: placement
                    .groups_for(node_id)
                    .into_iter()
                    .map(group_label)
                    .collect(),
                metadata_voter: voters.contains(&node_id),
            })
            .collect();
        Ok(NodeList {
            view_from: meta.node_id(),
            leader: meta.leader_hint().map(|(id, _)| id),
            nodes,
        })
    }

    pub async fn drain(&self, node_id: u64) -> Result<NodeList> {
        let meta = self.require_leader()?;
        meta.drain_node(node_id).await.map_err(map_error)?;
        self.list_nodes()
    }

    pub async fn undrain(&self, node_id: u64) -> Result<NodeList> {
        let meta = self.require_leader()?;
        meta.undrain_node(node_id).await.map_err(map_error)?;
        self.list_nodes()
    }

    /// Forget a drained node.
    ///
    /// The operator is expected to have stopped it first: this is the
    /// bookkeeping that follows a shutdown, not a way to shut a node down
    /// remotely.
    pub async fn remove(&self, node_id: u64) -> Result<NodeList> {
        let meta = self.require_leader()?;
        if node_id == meta.node_id() {
            // Removing the node you are talking to would take the metadata
            // leader out of its own group mid-request. Legal in Raft,
            // needlessly exciting over HTTP.
            return Err(ApiError::invalid_param(
                "Remove this node from another node in the cluster",
            ));
        }
        meta.remove_node(node_id).await.map_err(map_error)?;
        self.list_nodes()
    }
}
