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
    /// Failed liveness checks: hosts no replicas until it answers again.
    /// Set and cleared only by the metadata leader's failure detector
    /// ([`crate::liveness`]) — operator intent stays `Draining`. Appended
    /// after the original variants so pre-v3 roster encodings are
    /// byte-identical; writing it is gated on meta schema ≥ 3.
    Unreachable,
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

/// The roster after the failure detector loses `node`: placement stops
/// targeting it, exactly like a drain, but under a status the detector
/// may also clear again. Only an `Active` node transitions — `Draining`
/// is operator intent and stays put (also keeping `plan_removal`'s
/// contract intact for a node that dies mid-drain). A no-op transition
/// returns the roster unchanged, which callers detect to skip the write.
pub fn plan_mark_unreachable(roster: &Roster, node: NodeId) -> Result<Roster, RosterError> {
    let info = roster.get(&node).ok_or(RosterError::UnknownNode)?;
    if info.status != NodeStatus::Active {
        return Ok(roster.clone());
    }
    // Same floor as drain: placement must always have somewhere to put
    // data. Beyond the floor, marking is deliberately permissive — a
    // majority of dead data-group voters already means those groups
    // cannot commit membership changes, and the mark never makes that
    // worse (the node stays a metadata voter throughout).
    if active_nodes(roster).len() <= 1 {
        return Err(RosterError::LastActiveNode);
    }
    let mut next = roster.clone();
    next.entry(node)
        .and_modify(|i| i.status = NodeStatus::Unreachable);
    Ok(next)
}

/// The roster after the failure detector hears from `node` again. Only
/// an `Unreachable` node transitions — the detector must never undo an
/// operator's drain.
pub fn plan_mark_reachable(roster: &Roster, node: NodeId) -> Result<Roster, RosterError> {
    let info = roster.get(&node).ok_or(RosterError::UnknownNode)?;
    if info.status != NodeStatus::Unreachable {
        return Ok(roster.clone());
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
/// For ROOM groups, `replication_factor` is a real cap (phase 3
/// policy): the replica set is the rendezvous top-RF, and nodes outside
/// it serve the group remotely (Read/Subscribe RPCs, intents) — the
/// data-plane routing phase 2 built. Clusters with fewer nodes than RF
/// place on every node; growth past RF is what starts excluding.
///
/// The USER and FED-OUT groups keep the every-active-node floor: their
/// serving surfaces are still local-only on every node (sync and auth
/// read the user shard locally; §"One delivery worker" reads the
/// fed-out tables under its leader) — capping them would demote nodes
/// that have no remote path to fall back on. Their generalization rides
/// the same primitives later (design §scope).
pub fn assign(config: &ClusterConfig, rf_cap: Option<u8>, nodes: &BTreeSet<NodeId>) -> Placement {
    let room_rf = match rf_cap {
        // The debug cap overrides the configured RF outright — it forces
        // exclusion even below `replication_factor` (2a harness).
        Some(cap) => (cap as usize).max(1),
        None => (config.replication_factor as usize).min(nodes.len()).max(1),
    };
    let mut groups = BTreeMap::new();
    for g in config.data_groups() {
        let is_room = ShardId::from_group(g).is_some_and(|s| s.keyspace == Keyspace::Room);
        let rf = if is_room { room_rf } else { nodes.len() };
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
        for (_g, r) in assign(&big_config(), None, &active_nodes(&after)).iter() {
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

    /// The failure detector's transitions: Active ⇄ Unreachable only.
    /// Draining is operator intent and must survive the node dying.
    #[test]
    fn unreachable_marks_only_active_nodes_and_back() {
        let live = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Active)]);
        let marked = plan_mark_unreachable(&live, 2).unwrap();
        assert_eq!(marked[&2].status, NodeStatus::Unreachable);
        assert_eq!(active_nodes(&marked), nodes(&[1]), "out of placement");
        for (_g, r) in assign(&big_config(), None, &active_nodes(&marked)).iter() {
            assert_eq!(r, [1], "an unreachable node hosts nothing");
        }

        // Re-marking is a no-op (unchanged roster, so callers skip the
        // write), and recovery restores Active.
        assert_eq!(plan_mark_unreachable(&marked, 2).unwrap(), marked);
        let restored = plan_mark_reachable(&marked, 2).unwrap();
        assert_eq!(restored, live);
        assert_eq!(plan_mark_reachable(&restored, 2).unwrap(), restored);

        // A draining node is never marked, and never "recovered".
        let draining = plan_drain(&live, 2).unwrap();
        assert_eq!(plan_mark_unreachable(&draining, 2).unwrap(), draining);
        assert_eq!(plan_mark_reachable(&draining, 2).unwrap(), draining);

        assert_eq!(
            plan_mark_unreachable(&live, 9),
            Err(RosterError::UnknownNode)
        );
        assert_eq!(plan_mark_reachable(&live, 9), Err(RosterError::UnknownNode));
    }

    /// Same floor as drain: the detector must never leave placement with
    /// nowhere to put data, however dead the rest of the cluster looks.
    #[test]
    fn the_last_active_node_cannot_be_marked_unreachable() {
        let mixed = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Unreachable)]);
        assert_eq!(
            plan_mark_unreachable(&mixed, 1),
            Err(RosterError::LastActiveNode)
        );
    }

    /// A dead node can still be retired: drain applies to an unreachable
    /// node (skipping the Active-only floor guard correctly counts the
    /// survivors), and removal then proceeds as usual.
    #[test]
    fn an_unreachable_node_can_be_drained_and_removed() {
        let live = roster(&[(1, NodeStatus::Active), (2, NodeStatus::Active)]);
        let marked = plan_mark_unreachable(&live, 2).unwrap();
        let drained = plan_drain(&marked, 2).unwrap();
        assert_eq!(drained[&2].status, NodeStatus::Draining);
        let after = plan_removal(&drained, 2).unwrap();
        assert_eq!(after.keys().copied().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn assignment_is_deterministic() {
        let cfg = big_config();
        let ns = nodes(&[1, 2, 3, 4, 5]);
        assert_eq!(assign(&cfg, None, &ns), assign(&cfg, None, &ns));
    }

    #[test]
    fn replication_factor_caps_room_groups_only() {
        // Phase 3 policy: RF is a real cap for ROOM groups — more nodes
        // than RF means some nodes serve those groups remotely. The
        // user and fed-out groups keep the every-node floor until their
        // serving surfaces generalize.
        let cfg = big_config(); // rf = 3
        let ns = nodes(&[1, 2, 3, 4, 5]);
        for (g, r) in assign(&cfg, None, &ns).iter() {
            let ks = ShardId::from_group(g).expect("known keyspace").keyspace;
            match ks {
                Keyspace::Room => assert_eq!(r.len(), 3, "room replica set is the top-RF"),
                _ => assert_eq!(r.len(), 5, "user/fed-out stay on every node"),
            }
            let uniq: BTreeSet<_> = r.iter().copied().collect();
            assert_eq!(uniq.len(), r.len(), "replicas must be distinct nodes");
        }
        for (_g, r) in assign(&cfg, None, &nodes(&[1, 2])).iter() {
            assert_eq!(r.len(), 2, "below RF, every node hosts every group");
        }
        // Every node still takes on SOME room work at 5 nodes / RF 3.
        let placed = assign(&cfg, None, &ns);
        for n in &ns {
            assert!(!placed.groups_for(*n).is_empty(), "node {n} got no groups");
        }
    }

    #[test]
    fn node_join_displaces_at_most_one_replica_per_group() {
        let cfg = big_config();
        let before = assign(&cfg, None, &nodes(&[1, 2, 3]));
        let after = assign(&cfg, None, &nodes(&[1, 2, 3, 4]));
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
