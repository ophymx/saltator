//! Cluster plane: the metadata Raft group, node lifecycle, and the internal
//! RPC surface (spec.md §4, §8).
//!
//! M0 scope: single-node bootstrap of the metadata group over the local KV
//! engine, plus the gRPC skeleton the multi-node path (M4) will fill out.

pub mod network;
pub mod rpc;
pub mod storage;
pub mod types;

pub mod proto {
    #![allow(clippy::all)]
    tonic::include_proto!("saltator.internal.v1");
}

use std::sync::Arc;
use std::time::Duration;

use openraft::{BasicNode, Config as RaftConfig, Raft};

use saltator_store::KvEngine;

use storage::{MetaLogStore, MetaStateMachine};
use types::{MetaCommand, MetaResponse, NodeId, TypeConfig};

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("raft error: {0}")]
    Raft(String),
    #[error("storage error: {0}")]
    Storage(String),
}

type Result<T> = std::result::Result<T, ClusterError>;

fn raft_err(e: impl std::fmt::Display) -> ClusterError {
    ClusterError::Raft(e.to_string())
}

/// Handle to the running metadata group on this node.
#[derive(Clone)]
pub struct MetadataHandle {
    node_id: NodeId,
    raft: Raft<TypeConfig>,
    sm: MetaStateMachine,
}

impl MetadataHandle {
    /// Start the metadata Raft group over `engine`.
    ///
    /// If the group has never been initialized on this node and
    /// `bootstrap_addr` is `Some`, it is initialized as a single-voter
    /// cluster with this node at that address (spec.md §4.4 "Bootstrap").
    /// On restart, persisted vote/log/membership are picked up and
    /// initialization is skipped.
    pub async fn start(
        node_id: NodeId,
        engine: Arc<dyn KvEngine>,
        bootstrap_addr: Option<String>,
    ) -> Result<Self> {
        let config = RaftConfig {
            cluster_name: "saltator-meta".to_string(),
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        };
        let config = Arc::new(config.validate().map_err(raft_err)?);

        let log_store = MetaLogStore::new(engine.clone());
        let sm = MetaStateMachine::new(engine.clone());

        let raft = Raft::new(
            node_id,
            config,
            network::GrpcRaftNetworkFactory,
            log_store,
            sm.clone(),
        )
        .await
        .map_err(raft_err)?;

        let handle = Self { node_id, raft, sm };

        if !handle.is_initialized().await? {
            if let Some(addr) = bootstrap_addr {
                tracing::info!(node_id, %addr, "bootstrapping metadata group (single voter)");
                let members = std::collections::BTreeMap::from([(node_id, BasicNode::new(addr))]);
                handle.raft.initialize(members).await.map_err(raft_err)?;
            } else {
                tracing::info!(node_id, "metadata group not initialized; awaiting join");
            }
        } else {
            tracing::info!(node_id, "metadata group recovered from disk");
        }

        Ok(handle)
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn raft(&self) -> &Raft<TypeConfig> {
        &self.raft
    }

    async fn is_initialized(&self) -> Result<bool> {
        // Queries raft state directly; the metrics watch is not guaranteed
        // to reflect recovered membership this early after Raft::new.
        self.raft.is_initialized().await.map_err(raft_err)
    }

    /// Wait until this node has a leader (itself, single-node).
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<NodeId> {
        let metrics = self
            .raft
            .wait(Some(timeout))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .map_err(raft_err)?;
        Ok(metrics.current_leader.expect("leader present per wait"))
    }

    /// Linearizable write through the metadata group.
    pub async fn write(&self, cmd: MetaCommand) -> Result<MetaResponse> {
        let resp = self.raft.client_write(cmd).await.map_err(raft_err)?;
        Ok(resp.data)
    }

    /// Linearizable read: confirm leadership/lease, then read applied state.
    pub async fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.raft.ensure_linearizable().await.map_err(raft_err)?;
        self.sm
            .get(key)
            .map_err(|e| ClusterError::Storage(e.to_string()))
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.raft
            .shutdown()
            .await
            .map_err(|e| raft_err(format!("{e:?}")))
    }
}

/// Serve the internal gRPC surface (control channel) until `shutdown`
/// resolves. mTLS wiring lands with multi-node (M4); M0 binds plaintext on
/// the internal listener.
pub async fn serve_internal(
    handle: MetadataHandle,
    server_name: String,
    listen: std::net::SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let svc = rpc::InternalRpc::new(handle, server_name);
    let svc = Arc::new(svc);

    tonic::transport::Server::builder()
        .add_service(proto::raft_service_server::RaftServiceServer::from_arc(
            svc.clone(),
        ))
        .add_service(proto::control_service_server::ControlServiceServer::from_arc(svc))
        .serve_with_shutdown(listen, shutdown)
        .await?;
    Ok(())
}
