//! The per-shard runtime handle: start the Raft group, propose commands,
//! read applied state, subscribe to the change stream.

use std::sync::Arc;
use std::time::Duration;

use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Config as RaftConfig, Raft};
use tokio::sync::broadcast;

use saltator_store::KvEngine;

use crate::app::{ReadCtx, ShardApp};
use crate::registry::ShardRegistry;
use crate::storage::{ShardLogStore, ShardStateMachine};
use crate::{raft_err, NodeId, Result, ShardError, ShardId, TypeConfig};

/// One change-stream record: an app-defined payload at a position in the
/// shard's sequence order. Feeds `/sync`, federation out, and projections
/// (spec.md §5.2 step 6). The stream is best-effort: a lagged subscriber
/// gets `RecvError::Lagged` and must catch up from seq-indexed applied
/// state.
#[derive(Debug, Clone)]
pub struct ChangeRecord {
    pub seq: u64,
    pub payload: Arc<[u8]>,
}

/// Buffered change records per shard before slow subscribers start
/// lagging out.
const CHANGE_STREAM_CAPACITY: usize = 1024;

/// Handle to one running shard Raft group on this node.
#[derive(Clone)]
pub struct ShardHandle {
    shard: ShardId,
    node_id: NodeId,
    raft: Raft<TypeConfig>,
    engine: Arc<dyn KvEngine>,
    changes: broadcast::Sender<ChangeRecord>,
}

impl ShardHandle {
    /// Start the shard's Raft group over `engine`, interpreting commands
    /// with `app`.
    ///
    /// If the group has never been initialized on this node and
    /// `bootstrap_addr` is `Some`, it is initialized as a single-voter
    /// cluster with this node at that address (spec.md §4.4 "Bootstrap").
    /// On restart, persisted vote/log/membership are picked up and
    /// initialization is skipped. The group registers itself in
    /// `registry` for incoming-RPC routing.
    pub async fn start<A: ShardApp>(
        shard: ShardId,
        node_id: NodeId,
        engine: Arc<dyn KvEngine>,
        app: Arc<A>,
        network: impl RaftNetworkFactory<TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Self> {
        let config = RaftConfig {
            cluster_name: format!("saltator-{shard}"),
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        };
        let config = Arc::new(config.validate().map_err(raft_err)?);

        let (changes, _) = broadcast::channel(CHANGE_STREAM_CAPACITY);
        let log_store = ShardLogStore::new(shard, engine.clone());
        let sm = ShardStateMachine::new(shard, engine.clone(), app, changes.clone());

        let raft = Raft::new(node_id, config, network, log_store, sm)
            .await
            .map_err(raft_err)?;

        if let Some(reg) = registry {
            reg.register(shard.group(), raft.clone());
        }

        let handle = Self {
            shard,
            node_id,
            raft,
            engine,
            changes,
        };

        if !handle.is_initialized().await? {
            if let Some(addr) = bootstrap_addr {
                tracing::info!(%shard, node_id, %addr, "bootstrapping shard group (single voter)");
                let members = std::collections::BTreeMap::from([(node_id, BasicNode::new(addr))]);
                handle.raft.initialize(members).await.map_err(raft_err)?;
            } else {
                tracing::info!(%shard, node_id, "shard group not initialized; awaiting join");
            }
        } else {
            tracing::info!(%shard, node_id, "shard group recovered from disk");
        }

        Ok(handle)
    }

    pub fn shard(&self) -> ShardId {
        self.shard
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

    /// Wait until this shard has a leader.
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<NodeId> {
        let metrics = self
            .raft
            .wait(Some(timeout))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .map_err(raft_err)?;
        Ok(metrics.current_leader.expect("leader present per wait"))
    }

    /// Propose a command through the shard's Raft group and return the
    /// app's response bytes. Linearizable.
    pub async fn propose(&self, command: Vec<u8>) -> Result<Vec<u8>> {
        let resp = self.raft.client_write(command).await.map_err(raft_err)?;
        Ok(resp.data)
    }

    /// Confirm leadership/lease so that a subsequent [`read_ctx`]
    /// (Self::read_ctx) read is linearizable (spec.md §9).
    pub async fn ensure_linearizable(&self) -> Result<()> {
        self.raft.ensure_linearizable().await.map_err(raft_err)?;
        Ok(())
    }

    /// Read access to the shard's applied app state.
    pub fn read_ctx(&self) -> ReadCtx {
        ReadCtx::new(self.shard, self.engine.clone())
    }

    /// Current per-shard sequence number (0 before anything was emitted).
    pub fn seq(&self) -> Result<u64> {
        crate::storage::read_seq(&*self.engine, self.shard)
            .map_err(|e| ShardError::Storage(e.to_string()))
    }

    /// Subscribe to the shard change stream from *now*. Records before the
    /// subscription (and past the buffer on lag) must be read from
    /// seq-indexed applied state.
    pub fn subscribe(&self) -> broadcast::Receiver<ChangeRecord> {
        self.changes.subscribe()
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.raft
            .shutdown()
            .await
            .map_err(|e| raft_err(format!("{e:?}")))
    }
}

// ---------------------------------------------------------------------------
// Noop network
// ---------------------------------------------------------------------------

/// Network factory for shard groups with no peers (single-node clusters
/// and tests). Any actual send is a bug at this stage and reports the
/// target unreachable.
pub struct NoopNetworkFactory;

impl RaftNetworkFactory<TypeConfig> for NoopNetworkFactory {
    type Network = NoopConnection;

    async fn new_client(&mut self, _target: NodeId, _node: &crate::Node) -> Self::Network {
        NoopConnection
    }
}

pub struct NoopConnection;

fn unreachable_err<E: std::error::Error>() -> RPCError<NodeId, crate::Node, E> {
    RPCError::Unreachable(Unreachable::new(&std::io::Error::other(
        "no network configured for this shard group (single-node)",
    )))
}

impl RaftNetwork<TypeConfig> for NoopConnection {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> std::result::Result<
        AppendEntriesResponse<NodeId>,
        RPCError<NodeId, crate::Node, RaftError<NodeId>>,
    > {
        Err(unreachable_err())
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> std::result::Result<VoteResponse<NodeId>, RPCError<NodeId, crate::Node, RaftError<NodeId>>>
    {
        Err(unreachable_err())
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> std::result::Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, crate::Node, RaftError<NodeId, openraft::error::InstallSnapshotError>>,
    > {
        Err(unreachable_err())
    }
}
