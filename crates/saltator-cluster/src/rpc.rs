//! Server side of the internal gRPC surface: RaftService + ControlService.

// tonic::Status is large by design and fixed by the generated trait
// signatures.
#![allow(clippy::result_large_err)]

use openraft::Raft;
use tonic::{Request, Response, Status};

use saltator_shard::{ShardRegistry, TypeConfig};

use crate::proto::control_service_server::ControlService;
use crate::proto::raft_service_server::RaftService;
use crate::proto::{
    JoinRequest, JoinResponse, ProposeRequest, ProposeResponse, RaftPayload, StatusRequest,
    StatusResponse,
};
use crate::types::CODEC_VERSION;
use crate::MetadataHandle;

pub struct InternalRpc {
    handle: MetadataHandle,
    registry: ShardRegistry,
    server_name: String,
    /// This binary's app schema versions per keyspace discriminant,
    /// reported in Status for the migration gate.
    schemas: Vec<(u32, u32)>,
}

impl InternalRpc {
    pub fn new(
        handle: MetadataHandle,
        registry: ShardRegistry,
        server_name: String,
        schemas: Vec<(u32, u32)>,
    ) -> Self {
        Self {
            handle,
            registry,
            server_name,
            schemas,
        }
    }

    /// Envelope checks + route to the addressed shard group's Raft
    /// instance.
    fn route(&self, p: &RaftPayload) -> Result<Raft<TypeConfig>, Status> {
        if p.codec_version != CODEC_VERSION {
            return Err(Status::failed_precondition(format!(
                "codec version mismatch: got {}, want {}",
                p.codec_version, CODEC_VERSION
            )));
        }
        self.registry
            .get(p.group)
            .ok_or_else(|| Status::not_found(format!("no shard group {} on this node", p.group)))
    }
}

fn decode<T: for<'de> serde::Deserialize<'de>>(p: &RaftPayload) -> Result<T, Status> {
    postcard::from_bytes(&p.payload)
        .map_err(|e| Status::invalid_argument(format!("payload decode: {e}")))
}

fn encode<T: serde::Serialize>(group: u64, v: &T) -> Result<RaftPayload, Status> {
    Ok(RaftPayload {
        group,
        codec_version: CODEC_VERSION,
        payload: postcard::to_stdvec(v)
            .map_err(|e| Status::internal(format!("payload encode: {e}")))?,
    })
}

#[tonic::async_trait]
impl RaftService for InternalRpc {
    async fn append_entries(
        &self,
        request: Request<RaftPayload>,
    ) -> Result<Response<RaftPayload>, Status> {
        let p = request.into_inner();
        let raft = self.route(&p)?;
        let resp = raft
            .append_entries(decode(&p)?)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(encode(p.group, &resp)?))
    }

    async fn vote(&self, request: Request<RaftPayload>) -> Result<Response<RaftPayload>, Status> {
        let p = request.into_inner();
        let raft = self.route(&p)?;
        let resp = raft
            .vote(decode(&p)?)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(encode(p.group, &resp)?))
    }

    async fn install_snapshot(
        &self,
        request: Request<RaftPayload>,
    ) -> Result<Response<RaftPayload>, Status> {
        let p = request.into_inner();
        let raft = self.route(&p)?;
        let resp = raft
            .install_snapshot(decode(&p)?)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(encode(p.group, &resp)?))
    }
}

#[tonic::async_trait]
impl ControlService for InternalRpc {
    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let metrics = self.handle.raft().metrics().borrow().clone();
        Ok(Response::new(StatusResponse {
            node_id: self.handle.node_id(),
            server_name: self.server_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            initialized: metrics.membership_config.membership().voter_ids().count() > 0,
            leader: metrics.current_leader,
            last_applied: metrics.last_applied.map(|l| l.index).unwrap_or(0),
            schemas: self
                .schemas
                .iter()
                .map(|(keyspace, schema_version)| crate::proto::ShardSchema {
                    keyspace: *keyspace,
                    schema_version: *schema_version,
                })
                .collect(),
        }))
    }

    /// Admit a node to the metadata group. Only the leader can apply the
    /// change; a follower answers with a redirect to the leader so the
    /// caller can retry there.
    async fn join(&self, request: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        let req = request.into_inner();
        if self.handle.is_leader() {
            self.handle
                .admit_node(req.node_id, req.advertise_addr)
                .await
                .map_err(|e| Status::internal(format!("admit node: {e}")))?;
            Ok(Response::new(JoinResponse {
                joined: true,
                leader_id: Some(self.handle.node_id()),
                leader_addr: None,
            }))
        } else {
            let (leader_id, leader_addr) = match self.handle.leader_hint() {
                Some((id, addr)) => (Some(id), Some(addr)),
                None => (None, None),
            };
            Ok(Response::new(JoinResponse {
                joined: false,
                leader_id,
                leader_addr,
            }))
        }
    }

    /// A proposal forwarded from a non-leader node: apply it through the
    /// addressed group's Raft if we lead it, else hand back a leader hint.
    async fn propose(
        &self,
        request: Request<ProposeRequest>,
    ) -> Result<Response<ProposeResponse>, Status> {
        use openraft::error::{ClientWriteError, RaftError};
        let req = request.into_inner();
        let raft = self.registry.get(req.group).ok_or_else(|| {
            Status::not_found(format!("no shard group {} on this node", req.group))
        })?;
        match raft.client_write(req.command).await {
            Ok(resp) => Ok(Response::new(ProposeResponse {
                applied: true,
                response: resp.data,
                log_index: resp.log_id.index,
                leader_id: None,
                leader_addr: None,
            })),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => {
                Ok(Response::new(ProposeResponse {
                    applied: false,
                    response: Vec::new(),
                    log_index: 0,
                    leader_id: f.leader_id,
                    leader_addr: f.leader_node.map(|n| n.addr),
                }))
            }
            Err(e) => Err(Status::internal(format!("propose: {e}"))),
        }
    }
}
