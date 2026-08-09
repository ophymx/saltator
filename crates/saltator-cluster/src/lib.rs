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
mod rpc;

pub use gate::ClusterGate;
pub mod types;

pub use join::join_cluster;
pub use placement::{ClusterConfig, NodeInfo, NodeStatus, Placement, Roster};
pub use reconcile::{reconcile_once, spawn_reconciler, LocalGroup};

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

/// The metadata group's command interpreter: a linearizable KV store.
pub struct MetaApp;

/// The metadata group's schema version (see docs/design-schema-migrations.md).
pub const META_SCHEMA_VERSION: u32 = 1;

impl ShardApp for MetaApp {
    fn schema_version(&self) -> u32 {
        META_SCHEMA_VERSION
    }

    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        // A committed command that fails to decode means log corruption or
        // a broken upgrade — fatal, not skippable.
        let cmd: MetaCommand = postcard::from_bytes(command)
            .map_err(|e| StoreError::Engine(format!("meta command decode: {e}")))?;
        let previous = match cmd {
            MetaCommand::Set { key, value } => {
                let prev = ctx.get(T_KV, key.as_bytes())?;
                ctx.put(T_KV, key.as_bytes(), value);
                prev
            }
            MetaCommand::Delete { key } => {
                let prev = ctx.get(T_KV, key.as_bytes())?;
                ctx.delete(T_KV, key.as_bytes());
                prev
            }
        };
        postcard::to_stdvec(&MetaResponse { previous })
            .map_err(|e| StoreError::Engine(format!("meta response encode: {e}")))
    }
}

/// Metadata keys for the cluster control-plane records (spec.md §4.2).
const K_CONFIG: &str = "cluster/config";
const K_ROSTER: &str = "cluster/roster";
const K_PLACEMENT: &str = "cluster/placement";

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
        let inner = ShardHandle::start(
            ShardId::METADATA,
            node_id,
            stores,
            Arc::new(MetaApp),
            network::GrpcRaftNetworkFactory::new(ShardId::METADATA),
            bootstrap_addr,
            registry,
        )
        .await?;
        Ok(Self {
            inner,
            updates: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    pub fn raft(&self) -> &openraft::Raft<types::TypeConfig> {
        self.inner.raft()
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

        let config = self.cluster_config().await?.unwrap_or_default();
        let mut roster = self.roster().await?;
        roster.insert(
            node_id,
            NodeInfo {
                advertise_addr: addr,
                status: NodeStatus::Active,
            },
        );
        let placement = placement::assign(&config, &placement::active_nodes(&roster));
        self.set_blob(K_ROSTER, &roster).await?;
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
        let placement = placement::assign(&config, &placement::active_nodes(&roster));
        self.set_blob(K_CONFIG, &config).await?;
        self.set_blob(K_ROSTER, &roster).await?;
        self.set_blob(K_PLACEMENT, &placement).await?;
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
/// `registry`. mTLS wiring lands with multi-node (M4); until then this
/// binds plaintext on the internal listener.
pub async fn serve_internal(
    handle: MetadataHandle,
    registry: ShardRegistry,
    server_name: String,
    schemas: Vec<(u32, u32)>,
    listen: std::net::SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let svc = rpc::InternalRpc::new(handle, registry, server_name, schemas);
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
