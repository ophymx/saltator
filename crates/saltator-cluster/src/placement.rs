//! Shard placement (spec.md §4.2): which nodes host a replica of each data
//! shard group.
//!
//! The metadata group is not placed here — every cluster node is a metadata
//! voter (see [`MetadataHandle::admit_node`](crate::MetadataHandle)).
//! Placement governs the RF-replicated room and user groups. Assignment is
//! by rendezvous (highest-random-weight) hashing so that a node join or
//! leave reshuffles only ~1/N of groups instead of remapping everything.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use saltator_shard::ShardId;
use saltator_store::Keyspace;

use crate::types::NodeId;

/// Cluster-wide topology, fixed at bootstrap (OQ-5: shard count does not
/// change over a cluster's life). Persisted in the metadata group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub room_shards: u16,
    pub user_shards: u16,
    pub replication_factor: u8,
}

impl Default for ClusterConfig {
    /// Matches the topology the room/user servers currently instantiate
    /// (one group each). The spec's 64/16 default lands once those servers
    /// become multi-shard; raising the counts here is all that changes on
    /// the placement side.
    fn default() -> Self {
        Self {
            room_shards: 1,
            user_shards: 1,
            replication_factor: 3,
        }
    }
}

impl ClusterConfig {
    /// The data shard groups this topology comprises: room groups, user
    /// groups, then the federation-out group, by their on-the-wire group
    /// number. Fed-out is a constant single shard (no config field — and
    /// therefore no persisted-format change; a config knob arrives with
    /// M-scale resharding behind a meta-schema migration).
    pub fn data_groups(&self) -> Vec<u64> {
        let mut groups =
            Vec::with_capacity(self.room_shards as usize + self.user_shards as usize + 1);
        for i in 0..self.room_shards {
            groups.push(ShardId::new(Keyspace::Room, i).group());
        }
        for i in 0..self.user_shards {
            groups.push(ShardId::new(Keyspace::User, i).group());
        }
        groups.push(ShardId::new(Keyspace::FedOut, 0).group());
        groups
    }
}

/// A node's cluster-membership record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Full participant: eligible to host shard replicas.
    Active,
    /// Being removed: keeps serving but hosts no new replicas.
    Draining,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub advertise_addr: String,
    pub status: NodeStatus,
}

/// The cluster's node roster, keyed by node id.
pub type Roster = BTreeMap<NodeId, NodeInfo>;

/// The node ids currently eligible to host replicas.
pub fn active_nodes(roster: &Roster) -> BTreeSet<NodeId> {
    roster
        .iter()
        .filter(|(_, i)| i.status == NodeStatus::Active)
        .map(|(id, _)| *id)
        .collect()
}

/// Why a roster transition was refused (docs/design-admin-identity.md
/// slice 6). Separate from the storage errors so the admin surface can map
/// each to the right status without string matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    #[error("no such node in the cluster roster")]
    UnknownNode,
    #[error("refusing to drain the last active node")]
    LastActiveNode,
    #[error("the node must be drained before it is removed")]
    NotDraining,
}

/// The roster after draining `node`: it stops being a placement target
/// but stays in the roster and in the metadata group, which is what lets
/// it keep receiving the placement update telling it to step down.
///
/// Pure so the guards are testable without a cluster. Idempotent — an
/// already-draining node drains again without complaint.
pub fn plan_drain(roster: &Roster, node: NodeId) -> Result<Roster, RosterError> {
    let info = roster.get(&node).ok_or(RosterError::UnknownNode)?;
    // Draining the last active node would leave every group unplaceable
    // and the cluster with nowhere to put its data. There is no
    // "gracefully shut down the whole cluster" operation, and this is not
    // it.
    if info.status == NodeStatus::Active && active_nodes(roster).len() <= 1 {
        return Err(RosterError::LastActiveNode);
    }
    let mut next = roster.clone();
    next.entry(node)
        .and_modify(|i| i.status = NodeStatus::Draining);
    Ok(next)
}

/// The roster after returning `node` to service. Idempotent, and always
/// allowed: an operator who drained the wrong node needs the way back.
pub fn plan_undrain(roster: &Roster, node: NodeId) -> Result<Roster, RosterError> {
    if !roster.contains_key(&node) {
        return Err(RosterError::UnknownNode);
    }
    let mut next = roster.clone();
    next.entry(node)
        .and_modify(|i| i.status = NodeStatus::Active);
    Ok(next)
}

/// The roster after forgetting `node` entirely.
///
/// Only a drained node may be removed. Removal takes it out of the
/// metadata group, and a node still hosting replicas needs that
/// membership to learn it should step down — so removing an active node
/// would strand exactly the replicas the operation is meant to release.
pub fn plan_removal(roster: &Roster, node: NodeId) -> Result<Roster, RosterError> {
    let info = roster.get(&node).ok_or(RosterError::UnknownNode)?;
    if info.status != NodeStatus::Draining {
        return Err(RosterError::NotDraining);
    }
    let mut next = roster.clone();
    next.remove(&node);
    Ok(next)
}

/// The replica node set for each data group, ordered by rendezvous rank
/// (first = highest weight — the natural leader preference).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    groups: BTreeMap<u64, Vec<NodeId>>,
}

impl Placement {
    /// The replica set for `group` (empty if the group is unplaced).
    pub fn replicas(&self, group: u64) -> &[NodeId] {
        self.groups.get(&group).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The data groups `node` is assigned to host.
    pub fn groups_for(&self, node: NodeId) -> Vec<u64> {
        self.groups
            .iter()
            .filter(|(_, r)| r.contains(&node))
            .map(|(g, _)| *g)
            .collect()
    }

    /// All placed groups with their replica sets.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &[NodeId])> {
        self.groups.iter().map(|(g, r)| (*g, r.as_slice()))
    }
}

/// Assign replicas to each data group by rendezvous hashing over the
/// active nodes.
///
/// INTERIM POLICY: every group goes to EVERY active node (RF is floored
/// at the node count). The whole serving surface currently assumes local
/// applied state for every shard — startup waits for each group's
/// leadership, and CS/federation reads hit the local store directly — so
/// a node outside a group's replica set could neither boot nor serve
/// (found by the churn soak: a 4th node wedged at "awaiting join").
/// `replication_factor` becomes a real cap once data-plane routing for
/// unhosted shards exists; the rendezvous ranking already yields the
/// stable per-group orderings that cap will truncate to.
pub fn assign(config: &ClusterConfig, nodes: &BTreeSet<NodeId>) -> Placement {
    let rf = (config.replication_factor as usize).max(nodes.len());
    let mut groups = BTreeMap::new();
    for g in config.data_groups() {
        let mut ranked: Vec<NodeId> = nodes.iter().copied().collect();
        // Highest weight first; equal weights break by ascending node id
        // (sort_by is stable and `ranked` starts id-sorted).
        ranked.sort_by(|a, b| score(g, *b).cmp(&score(g, *a)).then(a.cmp(b)));
        ranked.truncate(rf);
        groups.insert(g, ranked);
    }
    Placement { groups }
}

/// Rendezvous weight of `node` for `group`: a splitmix64 mix of both, so
/// weights are well-distributed and independent across groups.
fn score(group: u64, node: NodeId) -> u64 {
    let mut x =
        group.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ node.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(ids: &[NodeId]) -> BTreeSet<NodeId> {
        ids.iter().copied().collect()
    }

    fn big_config() -> ClusterConfig {
        ClusterConfig {
            room_shards: 64,
            user_shards: 16,
            replication_factor: 3,
        }
    }

    fn roster(ids: &[(NodeId, NodeStatus)]) -> Roster {
        ids.iter()
            .map(|(id, status)| {
                (
                    *id,
                    NodeInfo {
                        advertise_addr: format!("10.0.0.{id}:7000"),
                        status: *status,
                    },
                )
            })
            .collect()
    }

    /// Draining stops a node being a placement target while leaving it in
    /// the roster — it still needs the metadata group to hear that it
    /// should step down.
    #[test]
    fn draining_removes_a_node_from_placement_only() {
        let before = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Active)]);
        let after = plan_drain(&before, 2).unwrap();
        assert_eq!(after.len(), 2, "still in the roster");
        assert_eq!(after[&2].status, NodeStatus::Draining);
        assert_eq!(active_nodes(&after), nodes(&[1]));
        for (_g, r) in assign(&big_config(), &active_nodes(&after)).iter() {
            assert_eq!(r, [1], "a draining node hosts nothing");
        }
    }

    /// The cluster always keeps somewhere to put its data. There is no
    /// "shut the whole cluster down" operation, and drain is not it.
    #[test]
    fn the_last_active_node_cannot_be_drained() {
        let one = roster(&[(1, NodeStatus::Active)]);
        assert_eq!(plan_drain(&one, 1), Err(RosterError::LastActiveNode));

        // Also when others exist but are already draining.
        let mixed = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Draining)]);
        assert_eq!(plan_drain(&mixed, 1), Err(RosterError::LastActiveNode));
        // ...and draining the already-draining one is a harmless no-op.
        assert_eq!(plan_drain(&mixed, 2).unwrap(), mixed);
    }

    #[test]
    fn undrain_returns_a_node_to_placement() {
        let drained = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Draining)]);
        let after = plan_undrain(&drained, 2).unwrap();
        assert_eq!(active_nodes(&after), nodes(&[1, 2]));
        // Idempotent, and unknown nodes are still refused.
        assert_eq!(plan_undrain(&after, 2).unwrap(), after);
        assert_eq!(plan_undrain(&after, 9), Err(RosterError::UnknownNode));
    }

    /// Removal is only legal after a drain: an active node still hosts
    /// replicas, and taking it out of the metadata group is what would
    /// strand them.
    #[test]
    fn only_a_drained_node_can_be_removed() {
        let live = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Active)]);
        assert_eq!(plan_removal(&live, 2), Err(RosterError::NotDraining));
        assert_eq!(plan_removal(&live, 9), Err(RosterError::UnknownNode));

        let drained = plan_drain(&live, 2).unwrap();
        let after = plan_removal(&drained, 2).unwrap();
        assert_eq!(after.keys().copied().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn assignment_is_deterministic() {
        let cfg = big_config();
        let ns = nodes(&[1, 2, 3, 4, 5]);
        assert_eq!(assign(&cfg, &ns), assign(&cfg, &ns));
    }

    #[test]
    fn interim_policy_places_every_group_on_every_node() {
        // Until data-plane routing for unhosted shards exists, every
        // active node must host every group (see `assign`); a node
        // outside a replica set could neither boot nor serve.
        let cfg = big_config();
        let ns = nodes(&[1, 2, 3, 4, 5]);
        for (_g, r) in assign(&cfg, &ns).iter() {
            assert_eq!(r.len(), 5, "every node hosts every group");
            let uniq: BTreeSet<_> = r.iter().copied().collect();
            assert_eq!(uniq.len(), r.len(), "replicas must be distinct nodes");
        }
        for (_g, r) in assign(&cfg, &nodes(&[1, 2])).iter() {
            assert_eq!(r.len(), 2);
        }
    }

    #[test]
    fn node_join_displaces_at_most_one_replica_per_group() {
        let cfg = big_config();
        let before = assign(&cfg, &nodes(&[1, 2, 3]));
        let after = assign(&cfg, &nodes(&[1, 2, 3, 4]));
        // Rendezvous's minimal-churn guarantee is per group: a join adds only
        // the newcomer and evicts at most one incumbent — never a wholesale
        // remap of who hosts what.
        for (g, before_r) in before.iter() {
            let before_set: BTreeSet<_> = before_r.iter().copied().collect();
            let after_set: BTreeSet<_> = after.replicas(g).iter().copied().collect();
            let added: Vec<_> = after_set.difference(&before_set).copied().collect();
            let removed: Vec<_> = before_set.difference(&after_set).copied().collect();
            assert!(
                added.iter().all(|n| *n == 4),
                "group {g} added a non-newcomer: {added:?}"
            );
            assert!(
                added.len() <= 1 && removed.len() <= 1,
                "group {g} churned more than one replica: +{added:?} -{removed:?}"
            );
        }
        // The new node actually took on work.
        assert!(!after.groups_for(4).is_empty(), "newcomer got no groups");
    }
}
