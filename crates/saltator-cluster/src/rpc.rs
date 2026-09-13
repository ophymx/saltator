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
    ChangeFrame, ExecuteRequest, ExecuteResponse, JoinRequest, JoinResponse, ProposeRequest,
    ProposeResponse, RaftPayload, ReadRequest, ReadResponse, StatusRequest, StatusResponse,
    SubscribeRequest,
};
use crate::types::CODEC_VERSION;
use crate::MetadataHandle;

pub struct InternalRpc {
    handle: MetadataHandle,
    registry: ShardRegistry,
    executors: saltator_shard::ExecutorRegistry,
    server_name: String,
    /// This binary's app schema versions per keyspace discriminant,
    /// reported in Status for the migration gate.
    schemas: Vec<(u32, u32)>,
}

impl InternalRpc {
    pub fn new(
        handle: MetadataHandle,
        registry: ShardRegistry,
        executors: saltator_shard::ExecutorRegistry,
        server_name: String,
        schemas: Vec<(u32, u32)>,
    ) -> Self {
        Self {
            handle,
            registry,
            executors,
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
            .map(|h| h.raft().clone())
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
        let raft = self
            .registry
            .get(req.group)
            .map(|h| h.raft().clone())
            .ok_or_else(|| {
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

    /// A storage-level read against a shard's applied state
    /// (docs/design-room-sharding-phase2.md): served only at the group's
    /// leader, after a read-index barrier — linearizable, and
    /// read-your-writes for any client that just forwarded a proposal to
    /// the same leader. Non-leaders answer with a hint, like Propose.
    async fn read(&self, request: Request<ReadRequest>) -> Result<Response<ReadResponse>, Status> {
        let req = request.into_inner();
        let handle = self.registry.get(req.group).ok_or_else(|| {
            Status::not_found(format!("no shard group {} on this node", req.group))
        })?;
        if handle.ensure_linearizable().await.is_err() || !handle.is_leader() {
            // Not the leader (or lost leadership under the barrier):
            // point the caller at the believed leader.
            let leader_id = handle.current_leader();
            let leader_addr = leader_id.and_then(|id| handle.node_addr(id));
            return Ok(Response::new(ReadResponse {
                served: false,
                result: Vec::new(),
                leader_id,
                leader_addr,
            }));
        }
        let op: saltator_shard::ReadOp = postcard::from_bytes(&req.op)
            .map_err(|e| Status::invalid_argument(format!("read op decode: {e}")))?;
        let value = if matches!(op, saltator_shard::ReadOp::Voters) {
            // Membership lives in the raft handle, not app storage; the
            // leader's committed view is the authoritative one.
            saltator_shard::ReadValue::Voters(handle.voter_ids().into_iter().collect())
        } else {
            let seq = handle
                .seq()
                .map_err(|e| Status::internal(format!("seq: {e}")))?;
            saltator_shard::read::execute(&handle.read_ctx(), seq, &op)
                .map_err(|e| Status::invalid_argument(format!("read: {e}")))?
        };
        Ok(Response::new(ReadResponse {
            served: true,
            result: postcard::to_stdvec(&value)
                .map_err(|e| Status::internal(format!("read result encode: {e}")))?,
            leader_id: None,
            leader_addr: None,
        }))
    }

    /// An app-level intent executed at this node, provided this node
    /// leads the group (the pipeline reads current state — a follower
    /// executing would build commands against a stale view and, worse,
    /// bypass the leader's room-lock serialization). Non-leaders hint.
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let req = request.into_inner();
        let handle = self.registry.get(req.group).ok_or_else(|| {
            Status::not_found(format!("no shard group {} on this node", req.group))
        })?;
        if !handle.is_leader() {
            let leader_id = handle.current_leader();
            let leader_addr = leader_id.and_then(|id| handle.node_addr(id));
            return Ok(Response::new(ExecuteResponse {
                served: false,
                result: Vec::new(),
                leader_id,
                leader_addr,
            }));
        }
        let executor = self.executors.get(req.group).ok_or_else(|| {
            Status::failed_precondition(format!("no executor registered for group {}", req.group))
        })?;
        let result = executor
            .execute(req.intent)
            .await
            .map_err(|e| Status::internal(format!("execute: {e}")))?;
        Ok(Response::new(ExecuteResponse {
            served: true,
            result,
            leader_id: None,
            leader_addr: None,
        }))
    }

    type SubscribeStream =
        std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<ChangeFrame, Status>> + Send>>;

    /// A change-stream subscription with server-side backfill: replay
    /// `(from_seq, applied]` from seq-indexed state, then splice into the
    /// live broadcast — gap-free at the seam, because the broadcast is
    /// subscribed BEFORE the final replay batch and frames at or below
    /// the last replayed seq are dropped. Served by any replica.
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        const REPLAY_BATCH: usize = 256;
        let req = request.into_inner();
        let handle = self.registry.get(req.group).ok_or_else(|| {
            Status::not_found(format!("no shard group {} on this node", req.group))
        })?;
        // Refuse an unreplayable app AT ACCEPT TIME: a mid-stream error is
        // indistinguishable from a dropped connection to the client (which
        // reconnects forever), while an accept-time refusal is terminal.
        handle
            .replay(req.from_seq, 1)
            .map_err(|e| Status::failed_precondition(format!("replay: {e}")))?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ChangeFrame, Status>>(64);
        tokio::spawn(async move {
            let mut last = req.from_seq;
            // Live first, then backfill up to and past the subscription
            // point: anything the broadcast buffers meanwhile is deduped
            // by the `seq > last` filter below.
            let mut live = handle.subscribe();
            loop {
                let batch = match handle.replay(last, REPLAY_BATCH) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Status::failed_precondition(format!("replay: {e}"))))
                            .await;
                        return;
                    }
                };
                let done = batch.len() < REPLAY_BATCH;
                for rec in batch {
                    last = rec.seq;
                    if tx
                        .send(Ok(ChangeFrame {
                            seq: rec.seq,
                            payload: rec.payload.to_vec(),
                        }))
                        .await
                        .is_err()
                    {
                        return; // subscriber went away
                    }
                }
                if done {
                    break;
                }
            }
            loop {
                match live.recv().await {
                    Ok(rec) => {
                        if rec.seq <= last {
                            continue; // already replayed
                        }
                        // A hole here means the broadcast dropped records
                        // while we drained the backfill; fill from state.
                        if rec.seq > last + 1 {
                            match handle.replay(last, (rec.seq - last) as usize) {
                                Ok(batch) => {
                                    for r in batch {
                                        if r.seq >= rec.seq {
                                            break;
                                        }
                                        if tx
                                            .send(Ok(ChangeFrame {
                                                seq: r.seq,
                                                payload: r.payload.to_vec(),
                                            }))
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx
                                        .send(Err(Status::internal(format!("gap replay: {e}"))))
                                        .await;
                                    return;
                                }
                            }
                        }
                        last = rec.seq;
                        if tx
                            .send(Ok(ChangeFrame {
                                seq: rec.seq,
                                payload: rec.payload.to_vec(),
                            }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Fall back to replay from the last delivered seq;
                        // the next loop iteration resumes live.
                        live = live.resubscribe();
                        loop {
                            let batch = match handle.replay(last, REPLAY_BATCH) {
                                Ok(b) => b,
                                Err(e) => {
                                    let _ = tx
                                        .send(Err(Status::internal(format!("lag replay: {e}"))))
                                        .await;
                                    return;
                                }
                            };
                            let done = batch.len() < REPLAY_BATCH;
                            for r in batch {
                                last = r.seq;
                                if tx
                                    .send(Ok(ChangeFrame {
                                        seq: r.seq,
                                        payload: r.payload.to_vec(),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            if done {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}
