//! Cluster plane: the metadata Raft group, node lifecycle, and the internal
//! RPC surface (spec.md §4, §8).
//!
//! The metadata group runs on the generic shard runtime as shard `Meta/0`
//! with [`MetaApp`] as its state machine; this crate owns the typed
//! command surface and the gRPC transport that all shard groups share.

pub mod forward;
pub mod gate;
pub mod join;
pub mod network;
pub mod placement;
pub mod reconcile;
pub mod remote;
mod rpc;
pub mod tls;

pub use gate::ClusterGate;
pub use tls::InternalTls;
pub mod types;

pub use join::{join_cluster, join_cluster_with_tls};
pub use placement::{ClusterConfig, NodeInfo, NodeStatus, Placement, Roster};
pub use reconcile::{reconcile_once, spawn_reconciler, LocalGroup, LocalGroups};

pub mod proto {
    #![allow(clippy::all)]
    tonic::include_proto!("saltator.internal.v1");
}

use std::sync::Arc;
use std::time::Duration;

use saltator_shard::{ApplyCtx, ShardApp, ShardHandle, ShardId, ShardRegistry, APP_TABLE_FIRST};
use saltator_store::{Result as StoreResult, StoreError};

use types::{MetaCommand, MetaResponse, NodeId};

/// The metadata KV table (the group's only app table).
const T_KV: u8 = APP_TABLE_FIRST;

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("raft error: {0}")]
    Raft(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("codec error: {0}")]
    Codec(String),
    /// A roster transition the cluster refused. Kept as the typed error so
    /// callers can map each cause to its own status code rather than
    /// matching on a message.
    #[error("{0}")]
    Roster(#[from] placement::RosterError),
}

type Result<T> = std::result::Result<T, ClusterError>;

impl From<saltator_shard::ShardError> for ClusterError {
    fn from(e: saltator_shard::ShardError) -> Self {
        use saltator_shard::ShardError as E;
        match e {
            E::Raft(m) => ClusterError::Raft(m),
            E::Storage(m) => ClusterError::Storage(m),
            E::Codec(m) => ClusterError::Codec(m),
            e @ E::SchemaTooNew { .. } => ClusterError::Storage(e.to_string()),
        }
    }
}

/// The metadata group's command interpreter: a linearizable KV store
/// which, from schema v2, also emits a change stream (the placement
/// watch: `Subscribe(group 0)`, docs/design-room-sharding-phase2.md).
pub struct MetaApp;

/// The metadata group's schema version (see docs/design-schema-migrations.md).
/// v2: every committed Set/Delete emits a [`MetaChange`] and journals it
/// under its seq (`T_CHANGES`) for subscription backfill.
pub const META_SCHEMA_VERSION: u32 = 2;

/// Seq-indexed change journal (v2): `seq (u64 BE) → postcard(MetaChange)`.
const T_CHANGES: u8 = APP_TABLE_FIRST + 1;

impl ShardApp for MetaApp {
    fn schema_version(&self) -> u32 {
        META_SCHEMA_VERSION
    }

    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        // A committed command that fails to decode means log corruption or
        // a broken upgrade — fatal, not skippable.
        let cmd: MetaCommand = postcard::from_bytes(command)
            .map_err(|e| StoreError::Engine(format!("meta command decode: {e}")))?;
        let (key, previous) = match cmd {
            MetaCommand::Set { key, value } => {
                let prev = ctx.get(T_KV, key.as_bytes())?;
                ctx.put(T_KV, key.as_bytes(), value);
                (key, prev)
            }
            MetaCommand::Delete { key } => {
                let prev = ctx.get(T_KV, key.as_bytes())?;
                ctx.delete(T_KV, key.as_bytes());
                (key, prev)
            }
        };
        // Emit + journal, gated on the STORED schema version: apply must
        // stay deterministic across binaries replaying the same log, so
        // the behavior turns on only once the migration to v2 committed
        // (which the ClusterGate holds until every voter runs a v2-aware
        // binary).
        if stored_meta_schema(ctx)? >= 2 {
            let payload = postcard::to_stdvec(&types::MetaChange { key })
                .map_err(|e| StoreError::Engine(format!("meta change encode: {e}")))?;
            let seq = ctx.emit(payload.clone());
            ctx.put(T_CHANGES, &seq.to_be_bytes(), payload);
        }
        postcard::to_stdvec(&MetaResponse { previous })
            .map_err(|e| StoreError::Engine(format!("meta response encode: {e}")))
    }

    fn migrate(&self, _ctx: &mut ApplyCtx<'_>, to: u32) -> StoreResult<()> {
        match to {
            // v2 adds the change journal going forward; no existing data
            // transforms. Pre-v2 history is simply not replayable, which
            // watchers tolerate: metadata is latest-value, and they
            // subscribe from the current seq.
            2 => Ok(()),
            other => Err(StoreError::Engine(format!(
                "no migration registered for meta schema step v{other}"
            ))),
        }
    }

    fn replay(
        &self,
        ctx: &saltator_shard::ReadCtx,
        from_seq: u64,
        limit: usize,
    ) -> StoreResult<Vec<(u64, Arc<[u8]>)>> {
        let start = (from_seq + 1).to_be_bytes();
        Ok(ctx
            .scan(T_CHANGES, &start, &[], limit, false)?
            .into_iter()
            .map(|(k, v)| {
                let mut seq_bytes = [0u8; 8];
                seq_bytes.copy_from_slice(&k[..8]);
                (
                    u64::from_be_bytes(seq_bytes),
                    Arc::from(v.into_boxed_slice()),
                )
            })
            .collect())
    }
}

/// The stored (not binary) meta schema version, seen through the apply
/// context so a migration in the same batch is visible.
fn stored_meta_schema(ctx: &ApplyCtx<'_>) -> StoreResult<u32> {
    Ok(match ctx.get(saltator_shard::T_SCHEMA, b"version")? {
        Some(b) => postcard::from_bytes(&b)
            .map_err(|e| StoreError::Engine(format!("schema cell decode: {e}")))?,
        None => 1,
    })
}

/// Metadata keys for the cluster control-plane records (spec.md §4.2).
pub const K_CONFIG: &str = "cluster/config";
pub const K_ROSTER: &str = "cluster/roster";
pub const K_PLACEMENT: &str = "cluster/placement";

/// postcard-decode an optional metadata value.
fn decode_blob<T: serde::de::DeserializeOwned>(bytes: Option<Vec<u8>>) -> Result<Option<T>> {
    match bytes {
        Some(b) => Ok(Some(
            postcard::from_bytes(&b).map_err(|e| ClusterError::Codec(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// Handle to the running metadata group on this node.
#[derive(Clone)]
pub struct MetadataHandle {
    inner: ShardHandle,
    /// Serializes control-plane read-modify-write updates (roster/placement)
    /// so concurrent joins on the leader can't clobber each other.
    updates: Arc<tokio::sync::Mutex<()>>,
    /// Debug-only replication cap for placement (see
    /// `cluster.rf_cap_unsafe`); shared across clones, set once at boot.
    rf_cap: Arc<std::sync::OnceLock<u8>>,
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
        stores: impl Into<saltator_store::Stores>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Self> {
        Self::start_with_tls(node_id, stores, bootstrap_addr, registry, None).await
    }

    /// [`start`](Self::start) with mutual TLS on the metadata group's peer
    /// connections (security review 2026-08-13, Vuln 4). The server side is
    /// configured separately, in [`serve_internal_with_tls`].
    pub async fn start_with_tls(
        node_id: NodeId,
        stores: impl Into<saltator_store::Stores>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
        tls: Option<tls::InternalTls>,
    ) -> Result<Self> {
        let factory = network::GrpcRaftNetworkFactory::new(ShardId::METADATA)
            .with_tls(tls.as_ref().map(|t| t.client()));
        let inner = ShardHandle::start(
            ShardId::METADATA,
            node_id,
            stores,
            Arc::new(MetaApp),
            factory,
            bootstrap_addr,
            registry,
        )
        .await?;
        Ok(Self {
            inner,
            updates: Arc::new(tokio::sync::Mutex::new(())),
            rf_cap: Arc::new(std::sync::OnceLock::new()),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    pub fn raft(&self) -> &openraft::Raft<types::TypeConfig> {
        self.inner.raft()
    }

    /// The underlying shard handle (migration supervisor wiring, change
    /// subscription).
    pub fn shard_handle(&self) -> &saltator_shard::ShardHandle {
        &self.inner
    }

    /// Set the debug-only replication cap (`cluster.rf_cap_unsafe`)
    /// before any placement write. No-op if already set.
    pub fn set_rf_cap_unsafe(&self, cap: u8) {
        let _ = self.rf_cap.set(cap);
        tracing::warn!(
            cap,
            "rf_cap_unsafe active: placement will EXCLUDE nodes (debug only)"
        );
    }

    fn rf_cap(&self) -> Option<u8> {
        self.rf_cap.get().copied()
    }

    /// Subscribe to the metadata change stream from now (schema v2:
    /// every committed Set/Delete emits a [`types::MetaChange`]). The
    /// local half of the placement watch; remote watchers use
    /// `Subscribe(group 0)`.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<saltator_shard::ChangeRecord> {
        self.inner.subscribe()
    }

    /// Wait until this node has a leader (itself, single-node).
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<NodeId> {
        Ok(self.inner.wait_for_leader(timeout).await?)
    }

    /// Whether this node is the metadata-group leader (only the leader can
    /// admit new nodes).
    pub fn is_leader(&self) -> bool {
        self.inner.is_leader()
    }

    /// The current leader and its advertised address, for redirecting a join
    /// request that reached a follower.
    pub fn leader_hint(&self) -> Option<(NodeId, String)> {
        let leader = self.inner.current_leader()?;
        let addr = self.inner.node_addr(leader)?;
        Some((leader, addr))
    }

    /// Admit `node_id` (reachable at `addr`) to the cluster: add it as a
    /// metadata learner and promote it into the voter set, then record it in
    /// the roster and recompute shard placement. Must be called on the
    /// leader (spec.md §4.4 "Node join").
    pub async fn admit_node(&self, node_id: NodeId, addr: String) -> Result<()> {
        // Serialize the whole admit so concurrent joins can't interleave the
        // roster/placement read-modify-write.
        let _guard = self.updates.lock().await;

        self.inner.add_learner(node_id, addr.clone()).await?;
        let mut voters = self.inner.voter_ids();
        voters.insert(node_id);
        self.inner.set_voters(voters).await?;

        let mut roster = self.roster().await?;
        roster.insert(
            node_id,
            NodeInfo {
                advertise_addr: addr,
                status: NodeStatus::Active,
            },
        );
        self.write_roster(&roster).await?;
        Ok(())
    }

    // -- node removal (docs/design-admin-identity.md slice 6) -------------
    //
    // Two steps on purpose, mirroring how a node arrives. `admit_node` is
    // one call because a joiner has no state to release; leaving does.
    //
    //   1. drain  — stop being a placement target. Each data group's
    //      leader reconciles the node out of its voter set on the next
    //      tick. The node stays a metadata voter throughout, which is what
    //      lets it *receive* the placement update: a group it leads can
    //      only be reconciled by itself.
    //   2. remove — once it holds nothing, take it out of the metadata
    //      group and forget it.
    //
    // Collapsing these into one call would cut the node off from the
    // metadata group while it still led groups, leaving it unable to learn
    // it should step down.

    /// Mark `node_id` draining and recompute placement without it. Must be
    /// called on the leader.
    pub async fn drain_node(&self, node_id: NodeId) -> Result<Roster> {
        self.update_roster(|roster| placement::plan_drain(roster, node_id))
            .await
    }

    /// Return `node_id` to service and recompute placement with it. Must
    /// be called on the leader.
    pub async fn undrain_node(&self, node_id: NodeId) -> Result<Roster> {
        self.update_roster(|roster| placement::plan_undrain(roster, node_id))
            .await
    }

    /// Remove a drained `node_id` from the metadata group and the roster.
    /// Must be called on the leader.
    ///
    /// The metadata membership change comes first: if the process dies
    /// between the two writes, a node that is out of the group but still
    /// in the roster is visible and can be removed again, whereas the
    /// reverse leaves an invisible voter holding a quorum share.
    pub async fn remove_node(&self, node_id: NodeId) -> Result<Roster> {
        let _guard = self.updates.lock().await;
        let roster = self.roster().await?;
        let next = placement::plan_removal(&roster, node_id)?;

        let mut voters = self.inner.voter_ids();
        if voters.remove(&node_id) {
            // `retain = false`: the node is dropped as a learner too, not
            // demoted into one. A removed node must stop receiving the log.
            self.inner.set_voters(voters).await?;
        }
        self.write_roster(&next).await?;
        Ok(next)
    }

    /// Apply a roster transition and republish the placement derived from
    /// it, under the same lock that serializes joins.
    async fn update_roster(
        &self,
        plan: impl FnOnce(&Roster) -> std::result::Result<Roster, placement::RosterError>,
    ) -> Result<Roster> {
        let _guard = self.updates.lock().await;
        let roster = self.roster().await?;
        let next = plan(&roster)?;
        self.write_roster(&next).await?;
        Ok(next)
    }

    /// Persist a roster and the placement it implies. Placement second:
    /// it is derived, so a crash between the two leaves a placement that
    /// is merely stale, and the next roster change recomputes it.
    async fn write_roster(&self, roster: &Roster) -> Result<()> {
        let config = self.cluster_config().await?.unwrap_or_default();
        let placement = placement::assign(&config, self.rf_cap(), &placement::active_nodes(roster));
        self.set_blob(K_ROSTER, roster).await?;
        self.set_blob(K_PLACEMENT, &placement).await?;
        Ok(())
    }

    /// Write the control-plane records for a fresh single-node cluster: the
    /// topology, a roster holding just this node, and its placement. Called
    /// once at bootstrap on the founding leader.
    pub async fn bootstrap_cluster(&self, config: ClusterConfig, self_addr: String) -> Result<()> {
        let _guard = self.updates.lock().await;
        let mut roster = Roster::new();
        roster.insert(
            self.node_id(),
            NodeInfo {
                advertise_addr: self_addr,
                status: NodeStatus::Active,
            },
        );
        // Config first: the placement `write_roster` derives is read back
        // from it.
        self.set_blob(K_CONFIG, &config).await?;
        self.write_roster(&roster).await?;
        Ok(())
    }

    /// The cluster topology, if the control plane has been bootstrapped.
    pub async fn cluster_config(&self) -> Result<Option<ClusterConfig>> {
        self.get_blob(K_CONFIG).await
    }

    /// The current node roster (linearizable read; leader only).
    pub async fn roster(&self) -> Result<Roster> {
        Ok(self.get_blob(K_ROSTER).await?.unwrap_or_default())
    }

    /// The current shard placement (linearizable read; leader only).
    pub async fn placement(&self) -> Result<Placement> {
        Ok(self.get_blob(K_PLACEMENT).await?.unwrap_or_default())
    }

    /// The shard placement from this node's applied state — may be stale on
    /// a follower, but does not require leadership. This is how a joining or
    /// follower node learns which groups it should host.
    pub fn placement_local(&self) -> Result<Placement> {
        Ok(self.get_blob_local(K_PLACEMENT)?.unwrap_or_default())
    }

    /// The node roster from this node's applied state (see
    /// [`placement_local`](Self::placement_local)).
    pub fn roster_local(&self) -> Result<Roster> {
        Ok(self.get_blob_local(K_ROSTER)?.unwrap_or_default())
    }

    /// The cluster topology from this node's applied state (see
    /// [`placement_local`](Self::placement_local)). `None` until the
    /// founder's bootstrap record has replicated to this node; the
    /// record is immutable after founding, so a stale read cannot
    /// return a wrong value, only a not-yet one.
    pub fn cluster_config_local(&self) -> Result<Option<ClusterConfig>> {
        self.get_blob_local(K_CONFIG)
    }

    async fn get_blob<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        decode_blob(self.read(key).await?)
    }

    fn get_blob_local<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        decode_blob(self.read_local(key)?)
    }

    async fn set_blob<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let value = postcard::to_stdvec(value).map_err(|e| ClusterError::Codec(e.to_string()))?;
        self.write(MetaCommand::Set {
            key: key.to_owned(),
            value,
        })
        .await?;
        Ok(())
    }

    /// Linearizable write through the metadata group.
    pub async fn write(&self, cmd: MetaCommand) -> Result<MetaResponse> {
        let command = postcard::to_stdvec(&cmd).map_err(|e| ClusterError::Codec(e.to_string()))?;
        let resp = self.inner.propose(command).await?;
        postcard::from_bytes(&resp).map_err(|e| ClusterError::Codec(e.to_string()))
    }

    /// Linearizable read: confirm leadership/lease, then read applied state.
    pub async fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.ensure_linearizable().await?;
        self.inner
            .read_ctx()
            .get(T_KV, key.as_bytes())
            .map_err(|e| ClusterError::Storage(e.to_string()))
    }

    /// This node's current view of the metadata voter set.
    pub fn voter_ids(&self) -> std::collections::BTreeSet<NodeId> {
        self.inner.voter_ids()
    }

    /// Read applied state on this node without a linearizability check — may
    /// be stale on a follower. For diagnostics and intra-cluster convergence
    /// checks, not for serving clients.
    pub fn read_local(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner
            .read_ctx()
            .get(T_KV, key.as_bytes())
            .map_err(|e| ClusterError::Storage(e.to_string()))
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.inner.shutdown().await?)
    }
}

/// Serve the internal gRPC surface (control channel) until `shutdown`
/// resolves. Incoming Raft messages route to any shard group registered in
/// `registry`. Plaintext — for loopback single-node and test harnesses;
/// multi-node deployments use [`serve_internal_with_tls`].
pub async fn serve_internal(
    handle: MetadataHandle,
    registry: ShardRegistry,
    executors: saltator_shard::ExecutorRegistry,
    server_name: String,
    schemas: Vec<(u32, u32)>,
    listen: std::net::SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_internal_with_tls(
        handle,
        registry,
        executors,
        server_name,
        schemas,
        listen,
        None,
        shutdown,
    )
    .await
}

/// [`serve_internal`] with mutual TLS: when `tls` is set the listener
/// requires and verifies a client certificate signed by the cluster CA, so
/// only a cluster member can reach `RaftService`/`ControlService` — the
/// authentication the plaintext surface lacked (security review
/// 2026-08-13, Vuln 4).
#[allow(clippy::too_many_arguments)]
pub async fn serve_internal_with_tls(
    handle: MetadataHandle,
    registry: ShardRegistry,
    executors: saltator_shard::ExecutorRegistry,
    server_name: String,
    schemas: Vec<(u32, u32)>,
    listen: std::net::SocketAddr,
    tls: Option<tls::InternalTls>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let svc = rpc::InternalRpc::new(handle, registry, executors, server_name, schemas);
    let svc = Arc::new(svc);

    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = &tls {
        builder = builder.tls_config(tls.server())?;
    }
    builder
        .add_service(proto::raft_service_server::RaftServiceServer::from_arc(
            svc.clone(),
        ))
        .add_service(proto::control_service_server::ControlServiceServer::from_arc(svc.clone()))
        .add_service(proto::bulk_service_server::BulkServiceServer::from_arc(svc))
        .serve_with_shutdown(listen, shutdown)
        .await?;
    Ok(())
}
