//! Server side of the internal gRPC surface: RaftService + ControlService.

// tonic::Status is large by design and fixed by the generated trait
// signatures.
#![allow(clippy::result_large_err)]

use tonic::{Request, Response, Status};

use crate::network::METADATA_GROUP;
use crate::proto::control_service_server::ControlService;
use crate::proto::raft_service_server::RaftService;
use crate::proto::{RaftPayload, StatusRequest, StatusResponse};
use crate::types::CODEC_VERSION;
use crate::MetadataHandle;

pub struct InternalRpc {
    handle: MetadataHandle,
    server_name: String,
}

impl InternalRpc {
    pub fn new(handle: MetadataHandle, server_name: String) -> Self {
        Self {
            handle,
            server_name,
        }
    }

    fn check_envelope(&self, p: &RaftPayload) -> Result<(), Status> {
        if p.codec_version != CODEC_VERSION {
            return Err(Status::failed_precondition(format!(
                "codec version mismatch: got {}, want {}",
                p.codec_version, CODEC_VERSION
            )));
        }
        // Until the generic shard runtime lands (M4), only the metadata
        // group exists.
        if p.group != METADATA_GROUP {
            return Err(Status::not_found(format!("unknown raft group {}", p.group)));
        }
        Ok(())
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
        self.check_envelope(&p)?;
        let resp = self
            .handle
            .raft()
            .append_entries(decode(&p)?)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(encode(p.group, &resp)?))
    }

    async fn vote(&self, request: Request<RaftPayload>) -> Result<Response<RaftPayload>, Status> {
        let p = request.into_inner();
        self.check_envelope(&p)?;
        let resp = self
            .handle
            .raft()
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
        self.check_envelope(&p)?;
        let resp = self
            .handle
            .raft()
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
        }))
    }
}
