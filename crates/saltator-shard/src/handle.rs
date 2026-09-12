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

/// How long a non-leader [`ShardHandle::propose`] keeps retrying to reach
/// a leader (its own group re-electing, or forwarding to the current
/// leader) before giving up. Covers an election (timeout ceiling 3s) with
/// slack.
const FORWARD_DEADLINE: Duration = Duration::from_secs(10);
/// Pause between forward/re-election attempts.
const FORWARD_RETRY_PAUSE: Duration = Duration::from_millis(150);
/// How long the read-your-writes barrier waits for the forwarded write to
/// appear in LOCAL applied state. Expiry is not an error — the write is
/// committed either way — but is logged: local reads may briefly not see
/// it.
const FORWARD_APPLY_BARRIER: Duration = Duration::from_secs(5);

/// Outcome of forwarding one proposal to another node.
pub enum ForwardOutcome {
    /// The remote node led the group and applied the command.
    Applied { response: Vec<u8>, log_index: u64 },
    /// The remote node is not the leader; its best hint of who is.
    Redirect { leader_addr: Option<String> },
}

/// How a proposal ended, kept beside its result so the metric layer can
/// label it. "Slow" means something different for each: a slow `local` is
/// this group's own commit path, a slow `forwarded` includes a round trip
/// to another node plus the read-your-writes barrier, and an `error` is
/// usually an election in progress rather than a broken write.
pub(crate) struct ProposeOutcome {
    pub(crate) result: Result<Vec<u8>>,
    pub(crate) kind: &'static str,
}

impl ProposeOutcome {
    fn local(response: Vec<u8>) -> Self {
        Self {
            result: Ok(response),
            kind: "local",
        }
    }

    fn forwarded(response: Vec<u8>) -> Self {
        Self {
            result: Ok(response),
            kind: "forwarded",
        }
    }

    fn failed(error: ShardError) -> Self {
        Self {
            result: Err(error),
            kind: "error",
        }
    }
}

/// Cross-node proposal transport, implemented by the cluster crate over
/// the internal ControlService. Lets a follower serve writes by handing
/// them to the leader (spec.md §9) — the piece that makes ANY node able
/// to serve a client's request, so a load balancer needs no leader
/// awareness.
pub trait ProposeForwarder: Send + Sync {
    fn forward(
        &self,
        addr: String,
        group: u64,
        command: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ForwardOutcome>> + Send>>;
}

/// Handle to one running shard Raft group on this node.
#[derive(Clone)]
pub struct ShardHandle {
    shard: ShardId,
    node_id: NodeId,
    raft: Raft<TypeConfig>,
    engine: Arc<dyn KvEngine>,
    changes: broadcast::Sender<ChangeRecord>,
    /// The command interpreter, kept for read-side replay
    /// ([`Self::replay`]); apply runs through the state machine's own
    /// clone.
    app: Arc<dyn ShardApp>,
    /// The app's declared schema version (the layout this binary speaks).
    app_schema_version: u32,
    /// Set once at startup (shared across clones); absent in single-node
    /// deployments and tests, where a non-leader propose keeps its old
    /// fail-fast behavior.
    forwarder: Arc<std::sync::OnceLock<Arc<dyn ProposeForwarder>>>,
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
        stores: impl Into<saltator_store::Stores>,
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

        let stores = stores.into();
        // Downgrade protection: state written by a newer schema must
        // never be reinterpreted by this binary (see
        // docs/design-schema-migrations.md).
        let app_schema_version = app.schema_version();
        let stored = crate::storage::stored_schema_version(&*stores.state, shard)
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        if stored > app_schema_version {
            return Err(ShardError::SchemaTooNew {
                shard,
                stored,
                supported: app_schema_version,
            });
        }

        let (changes, _) = broadcast::channel(CHANGE_STREAM_CAPACITY);
        let log_store = ShardLogStore::new(shard, stores.log.clone());
        let sm = ShardStateMachine::new(shard, stores.state.clone(), app.clone(), changes.clone());
        let app: Arc<dyn ShardApp> = app;

        let raft = Raft::new(node_id, config, network, log_store, sm)
            .await
            .map_err(raft_err)?;

        let handle = Self {
            shard,
            node_id,
            raft,
            // The handle reads applied state (schema cell, app reads):
            // the state engine.
            engine: stores.state,
            changes,
            app,
            app_schema_version,
            forwarder: Arc::new(std::sync::OnceLock::new()),
        };

        if let Some(reg) = registry {
            reg.register(shard.group(), handle.clone());
        }

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

    /// Add `node_id` (reachable at `addr`) to this group as a learner and
    /// block until it has replicated enough log to be caught up. Must be
    /// called on the leader (spec.md §4.4 "Node join").
    pub async fn add_learner(&self, node_id: NodeId, addr: String) -> Result<()> {
        self.raft
            .add_learner(node_id, BasicNode::new(addr), true)
            .await
            .map_err(raft_err)?;
        Ok(())
    }

    /// Replace this group's voter set with `voters` (a membership change).
    /// Must be called on the leader; learners not in the set are demoted,
    /// so callers include the existing voters plus any additions.
    pub async fn set_voters(&self, voters: std::collections::BTreeSet<NodeId>) -> Result<()> {
        self.raft
            .change_membership(voters, false)
            .await
            .map_err(raft_err)?;
        Ok(())
    }

    /// This group's current voter set, from the last observed metrics.
    pub fn voter_ids(&self) -> std::collections::BTreeSet<NodeId> {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect()
    }

    /// The current leader this node believes in, if any.
    pub fn current_leader(&self) -> Option<NodeId> {
        self.raft.metrics().borrow().current_leader
    }

    /// The address the membership config records for `node_id`, if known.
    pub fn node_addr(&self, node_id: NodeId) -> Option<String> {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .nodes()
            .find(|(id, _)| **id == node_id)
            .map(|(_, n)| n.addr.clone())
    }

    /// Whether this node currently believes itself to be the leader.
    /// Current voters and their advertised addresses, from the applied
    /// membership. The migration gate probes these before proposing.
    pub fn voters(&self) -> Vec<(NodeId, String)> {
        let metrics = self.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership().clone();
        membership
            .nodes()
            .filter(|(id, _)| membership.voter_ids().any(|v| v == **id))
            .map(|(id, node)| (*id, node.addr.clone()))
            .collect()
    }

    pub fn is_leader(&self) -> bool {
        self.current_leader() == Some(self.node_id)
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
    /// `(stored, code)` schema versions: what the applied state is in vs
    /// what this binary speaks. `stored < code` means a migration is due.
    pub fn schema_versions(&self) -> Result<(u32, u32)> {
        Ok((
            crate::storage::stored_schema_version(&*self.engine, self.shard)
                .map_err(|e| ShardError::Storage(e.to_string()))?,
            self.app_schema_version,
        ))
    }

    /// Propose one schema-migration step (`to` must be stored + 1).
    /// `Ok(Ok(()))` = migrated; `Ok(Err(reason))` = declined by the state
    /// machine (stale step, unknown migration) — safe to re-evaluate and
    /// retry; `Err` = Raft/storage failure.
    pub async fn propose_migrate(&self, to: u32) -> Result<std::result::Result<(), String>> {
        let mut cmd = vec![crate::storage::RUNTIME_CMD_PREFIX];
        cmd.extend(
            postcard::to_stdvec(&crate::storage::RuntimeCommand::Migrate { to })
                .map_err(|e| ShardError::Codec(e.to_string()))?,
        );
        let resp = self.propose(cmd).await?;
        match postcard::from_bytes::<crate::storage::RuntimeResponse>(&resp)
            .map_err(|e| ShardError::Codec(e.to_string()))?
        {
            crate::storage::RuntimeResponse::Ok => Ok(Ok(())),
            crate::storage::RuntimeResponse::Rejected(reason) => Ok(Err(reason)),
        }
    }

    pub async fn propose(&self, command: Vec<u8>) -> Result<Vec<u8>> {
        let started = std::time::Instant::now();
        let outcome = self.propose_inner(command).await;
        // Latency and outcome are recorded together, and the outcome
        // distinguishes a write this node accepted from one it had to
        // forward: both are "slow proposals" on a latency graph, but only
        // the second says the client reached the wrong node.
        crate::metrics::observe_proposal(self.shard, started.elapsed(), &outcome);
        outcome.result
    }

    async fn propose_inner(&self, command: Vec<u8>) -> ProposeOutcome {
        use openraft::error::ClientWriteError;
        let deadline = tokio::time::Instant::now() + FORWARD_DEADLINE;
        // Standing leader hint from the last redirect, used when our own
        // Raft doesn't know the leader yet (mid-election).
        let mut hint: Option<String> = None;
        loop {
            // Leadership may have arrived here since the last attempt, so
            // the local write is always tried first.
            let forward = match self.raft.client_write(command.clone()).await {
                Ok(resp) => return ProposeOutcome::local(resp.data),
                Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => f,
                Err(e) => return ProposeOutcome::failed(raft_err(e)),
            };
            if let Some(fwd) = self.forwarder.get() {
                let addr = forward.leader_node.map(|n| n.addr).or_else(|| hint.take());
                if let Some(addr) = addr {
                    match fwd.forward(addr, self.shard.group(), command.clone()).await {
                        Ok(ForwardOutcome::Applied {
                            response,
                            log_index,
                        }) => {
                            // Read-your-writes: the client's next read may
                            // hit THIS node, so don't ack until our applied
                            // state contains the write. Expiry only warns —
                            // the write is committed regardless.
                            if self
                                .raft
                                .wait(Some(FORWARD_APPLY_BARRIER))
                                .applied_index_at_least(
                                    Some(log_index),
                                    "forwarded write applied locally",
                                )
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    shard = %self.shard,
                                    log_index,
                                    "forwarded write acked before local apply caught up"
                                );
                            }
                            return ProposeOutcome::forwarded(response);
                        }
                        Ok(ForwardOutcome::Redirect { leader_addr }) => hint = leader_addr,
                        // Transport failure (leader died, election under
                        // way): retry the loop.
                        Err(e) => {
                            tracing::debug!(shard = %self.shard, error = %e, "proposal forward failed; retrying");
                        }
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return ProposeOutcome::failed(ShardError::Raft(format!(
                    "{}: no leader reachable to accept the proposal",
                    self.shard
                )));
            }
            tokio::time::sleep(FORWARD_RETRY_PAUSE).await;
        }
    }

    /// Install the cross-node proposal transport (once, at startup, before
    /// the handle is cloned into servers). Without it a non-leader propose
    /// fails after the retry deadline instead of forwarding.
    pub fn set_forwarder(&self, forwarder: Arc<dyn ProposeForwarder>) {
        let _ = self.forwarder.set(forwarder);
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

    /// Reconstruct change records `(from_seq, from_seq + limit]` from
    /// applied state via the app's [`ShardApp::replay`] — the backfill
    /// half of a gap-free subscription. Locally consistent; pair with
    /// [`Self::ensure_linearizable`] where the caller needs it.
    pub fn replay(&self, from_seq: u64, limit: usize) -> Result<Vec<ChangeRecord>> {
        let ctx = self.read_ctx();
        let records = self
            .app
            .replay(&ctx, from_seq, limit)
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        Ok(records
            .into_iter()
            .map(|(seq, payload)| ChangeRecord { seq, payload })
            .collect())
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
