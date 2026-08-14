//! The cluster implementation of the migration gate: before a leader
//! proposes a schema migration, every voter's *binary* must confirm —
//! over the internal ControlService — that it speaks the target version
//! for that shard's keyspace. Proposing earlier would hand a voter a
//! command it cannot apply and wedge the replica; enforcing this in code
//! (not documentation) was an explicit design decision.

use tonic::transport::ClientTlsConfig;

use saltator_shard::migrate::MigrationGate;
use saltator_shard::{NodeId, ShardHandle, ShardId};

use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::StatusRequest;

/// Probes voters through the internal RPC. One instance per shard.
pub struct ClusterGate {
    handle: ShardHandle,
    self_node: NodeId,
    /// This binary's schema versions per keyspace discriminant — what we
    /// report for ourselves without a loopback RPC.
    self_schemas: Vec<(u32, u32)>,
    /// Present on multi-node deployments: the voter probe is mutual-TLS,
    /// same as every other internal client (security review 2026-08-13,
    /// Vuln 4).
    tls: Option<ClientTlsConfig>,
}

impl ClusterGate {
    pub fn new(
        handle: ShardHandle,
        self_node: NodeId,
        self_schemas: Vec<(u32, u32)>,
        tls: Option<ClientTlsConfig>,
    ) -> Self {
        Self {
            handle,
            self_node,
            self_schemas,
            tls,
        }
    }

    fn supports(schemas: &[(u32, u32)], keyspace: u32, target: u32) -> bool {
        schemas
            .iter()
            .any(|(ks, v)| *ks == keyspace && *v >= target)
    }
}

impl MigrationGate for ClusterGate {
    async fn voters_ready(&self, shard: ShardId, target: u32) -> bool {
        let keyspace = shard.keyspace as u32;
        for (node_id, addr) in self.handle.voters() {
            if node_id == self.self_node {
                if !Self::supports(&self.self_schemas, keyspace, target) {
                    return false;
                }
                continue;
            }
            let Ok(channel) = crate::forward::connect(&addr, self.tls.as_ref()).await else {
                tracing::debug!(node_id, %addr, "migration gate: voter unreachable");
                return false;
            };
            let mut client = ControlServiceClient::new(channel);
            let Ok(resp) = client.status(StatusRequest {}).await else {
                tracing::debug!(node_id, %addr, "migration gate: status failed");
                return false;
            };
            let schemas: Vec<(u32, u32)> = resp
                .into_inner()
                .schemas
                .into_iter()
                .map(|s| (s.keyspace, s.schema_version))
                .collect();
            if !Self::supports(&schemas, keyspace, target) {
                tracing::info!(
                    node_id,
                    %addr,
                    target,
                    "migration gate: voter binary does not support target yet"
                );
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ClusterGate;

    #[test]
    fn supports_matches_keyspace_and_min_version() {
        let schemas = [(1u32, 2u32), (2, 1)];
        assert!(ClusterGate::supports(&schemas, 1, 2));
        assert!(ClusterGate::supports(&schemas, 1, 1));
        assert!(!ClusterGate::supports(&schemas, 1, 3));
        assert!(!ClusterGate::supports(&schemas, 2, 2));
        assert!(!ClusterGate::supports(&schemas, 9, 1));
    }
}
