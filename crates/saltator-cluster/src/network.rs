//! Raft networking over the internal gRPC control channel (spec.md §8).
//!
//! openraft requests/responses travel as versioned postcard bytes inside
//! proto `RaftPayload` envelopes. All Raft groups multiplex over the same
//! `RaftService`, discriminated by `group` (0 = metadata).

use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::{Deserialize, Serialize};
use tonic::transport::{Channel, ClientTlsConfig};

use saltator_shard::ShardId;

use crate::proto::raft_service_client::RaftServiceClient;
use crate::proto::RaftPayload;
use crate::types::{Node, NodeId, TypeConfig, CODEC_VERSION};

pub const METADATA_GROUP: u64 = ShardId::METADATA.group();

/// One factory per shard group; `group` tags every outgoing envelope so
/// the receiving node can route to the right Raft instance.
pub struct GrpcRaftNetworkFactory {
    group: u64,
    /// Present on multi-node deployments: every peer channel is mutual-TLS
    /// (security review 2026-08-13, Vuln 4). `None` = plaintext (loopback
    /// single-node and test harnesses).
    tls: Option<ClientTlsConfig>,
}

impl GrpcRaftNetworkFactory {
    pub fn new(shard: ShardId) -> Self {
        Self {
            group: shard.group(),
            tls: None,
        }
    }

    /// Carry a client TLS config, so every peer connection this factory
    /// opens is mutual-TLS.
    pub fn with_tls(mut self, tls: Option<ClientTlsConfig>) -> Self {
        self.tls = tls;
        self
    }
}

impl RaftNetworkFactory<TypeConfig> for GrpcRaftNetworkFactory {
    type Network = GrpcRaftConnection;

    async fn new_client(&mut self, target: NodeId, node: &Node) -> Self::Network {
        GrpcRaftConnection {
            group: self.group,
            target,
            addr: node.addr.clone(),
            tls: self.tls.clone(),
            client: None,
        }
    }
}

pub struct GrpcRaftConnection {
    group: u64,
    target: NodeId,
    addr: String,
    tls: Option<ClientTlsConfig>,
    client: Option<RaftServiceClient<Channel>>,
}

impl GrpcRaftConnection {
    async fn client(&mut self) -> Result<&mut RaftServiceClient<Channel>, Unreachable> {
        if self.client.is_none() {
            let channel = crate::forward::connect(&self.addr, self.tls.as_ref())
                .await
                .map_err(|e| Unreachable::new(&e))?;
            self.client = Some(RaftServiceClient::new(channel));
        }
        Ok(self.client.as_mut().expect("client just set"))
    }
}

fn to_payload<T: Serialize>(group: u64, req: &T) -> Result<RaftPayload, NetworkError> {
    Ok(RaftPayload {
        group,
        codec_version: CODEC_VERSION,
        payload: postcard::to_stdvec(req).map_err(|e| NetworkError::new(&e))?,
    })
}

fn from_payload<T: for<'de> Deserialize<'de>>(p: &RaftPayload) -> Result<T, NetworkError> {
    postcard::from_bytes(&p.payload).map_err(|e| NetworkError::new(&e))
}

impl RaftNetwork<TypeConfig> for GrpcRaftConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        tracing::trace!(target = self.target, "append_entries");
        let payload = to_payload(self.group, &rpc).map_err(RPCError::Network)?;
        let client = self.client().await.map_err(RPCError::Unreachable)?;
        let resp = client
            .append_entries(payload)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        from_payload(resp.get_ref()).map_err(RPCError::Network)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        tracing::debug!(target = self.target, "vote");
        let payload = to_payload(self.group, &rpc).map_err(RPCError::Network)?;
        let client = self.client().await.map_err(RPCError::Unreachable)?;
        let resp = client
            .vote(payload)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        from_payload(resp.get_ref()).map_err(RPCError::Network)
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, Node, RaftError<NodeId, InstallSnapshotError>>,
    > {
        tracing::debug!(target = self.target, "install_snapshot");
        let payload = to_payload(self.group, &rpc).map_err(RPCError::Network)?;
        let client = self.client().await.map_err(RPCError::Unreachable)?;
        let resp = client
            .install_snapshot(payload)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        from_payload(resp.get_ref()).map_err(RPCError::Network)
    }
}
