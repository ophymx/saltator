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

/// Assign `min(RF, |nodes|)` replicas to each data group by rendezvous
/// hashing over the active nodes.
pub fn assign(config: &ClusterConfig, nodes: &BTreeSet<NodeId>) -> Placement {
    let rf = (config.replication_factor as usize).min(nodes.len());
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

    #[test]
    fn assignment_is_deterministic() {
        let cfg = big_config();
        let ns = nodes(&[1, 2, 3, 4, 5]);
        assert_eq!(assign(&cfg, &ns), assign(&cfg, &ns));
    }

    #[test]
    fn replication_factor_respected_and_capped() {
        let cfg = big_config();
        // Plenty of nodes → exactly RF replicas per group, all distinct.
        for (_g, r) in assign(&cfg, &nodes(&[1, 2, 3, 4, 5])).iter() {
            assert_eq!(r.len(), 3);
            let uniq: BTreeSet<_> = r.iter().copied().collect();
            assert_eq!(uniq.len(), r.len(), "replicas must be distinct nodes");
        }
        // Fewer nodes than RF → capped at the node count.
        for (_g, r) in assign(&cfg, &nodes(&[1, 2])).iter() {
            assert_eq!(r.len(), 2);
        }
    }

    #[test]
    fn load_is_roughly_balanced() {
        let cfg = big_config();
        let ns = nodes(&[1, 2, 3, 4, 5]);
        let placement = assign(&cfg, &ns);
        let total_slots = (cfg.room_shards as usize + cfg.user_shards as usize) * 3;
        let ideal = total_slots / 5;
        for id in [1, 2, 3, 4, 5] {
            let count = placement.groups_for(id).len();
            // Within 40% of the ideal share — rendezvous is balanced in
            // expectation, loose bound guards against a pathological hash.
            assert!(
                count >= ideal * 6 / 10 && count <= ideal * 14 / 10,
                "node {id} hosts {count}, ideal ~{ideal}"
            );
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
