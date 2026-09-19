//! Client side of the unhosted-shard data plane: storage-level reads at
//! the group's leader and gap-free change subscriptions, against a
//! replica set from the placement. The counterpart of `forward.rs` for reads —
//! same authed dialer, same channel cache, same leader-hint retarget
//! discipline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig};

use saltator_shard::{ChangeRecord, ReadOp, ReadValue, ShardError};

use crate::forward::connect;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{ExecuteRequest, ReadRequest, SubscribeRequest};

/// How many redirect/replica hops one read attempts before giving up —
/// covers a stale leader hint plus an election.
const READ_MAX_HOPS: usize = 6;
/// Pause between hops when nobody claims leadership yet.
const READ_RETRY_PAUSE: Duration = Duration::from_millis(150);
/// Reconnect pause for a dropped subscription stream.
const SUBSCRIBE_RETRY_PAUSE: Duration = Duration::from_millis(500);

type Result<T> = std::result::Result<T, ShardError>;

/// A remote shard group: one group id + the addresses that host it
/// (rendezvous order — first is the natural leader preference). Cheap to
/// clone; channels are cached per address underneath.
#[derive(Clone)]
pub struct RemoteShard {
    group: u64,
    replicas: Arc<Mutex<Vec<String>>>,
    /// Last address that served us — tried first on the next read.
    preferred: Arc<Mutex<Option<String>>>,
    channels: Arc<Mutex<HashMap<String, Channel>>>,
    tls: Option<ClientTlsConfig>,
}

impl RemoteShard {
    pub fn new(group: u64, replicas: Vec<String>, tls: Option<ClientTlsConfig>) -> Self {
        Self {
            group,
            replicas: Arc::new(Mutex::new(replicas)),
            preferred: Arc::new(Mutex::new(None)),
            channels: Arc::new(Mutex::new(HashMap::new())),
            tls,
        }
    }

    pub fn group(&self) -> u64 {
        self.group
    }

    /// Replace the replica address list (placement changed).
    pub fn set_replicas(&self, replicas: Vec<String>) {
        *self.replicas.lock().expect("replicas lock") = replicas;
    }

    async fn channel(&self, addr: &str) -> Result<Channel> {
        if let Some(ch) = self.channels.lock().expect("channels lock").get(addr) {
            return Ok(ch.clone());
        }
        let ch = connect(addr, self.tls.as_ref()).await?;
        self.channels
            .lock()
            .expect("channels lock")
            .insert(addr.to_owned(), ch.clone());
        Ok(ch)
    }

    fn drop_channel(&self, addr: &str) {
        self.channels.lock().expect("channels lock").remove(addr);
    }

    /// The candidate order for the next attempt: the last known-good
    /// address first, then the replica list.
    fn candidates(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = self.preferred.lock().expect("preferred lock").clone() {
            out.push(p);
        }
        for r in self.replicas.lock().expect("replicas lock").iter() {
            if !out.contains(r) {
                out.push(r.clone());
            }
        }
        out
    }

    /// Execute one read at the group's leader (linearizable). Follows
    /// leader hints and falls through the replica list, the same
    /// discipline as proposal forwarding.
    pub async fn read(&self, op: &ReadOp) -> Result<ReadValue> {
        let op_bytes = postcard::to_stdvec(op)
            .map_err(|e| ShardError::Codec(format!("read op encode: {e}")))?;
        let mut queue: std::collections::VecDeque<String> = self.candidates().into();
        let mut last_err = None;
        for _ in 0..READ_MAX_HOPS {
            let Some(addr) = queue.pop_front() else {
                tokio::time::sleep(READ_RETRY_PAUSE).await;
                queue = self.candidates().into();
                continue;
            };
            let channel = match self.channel(&addr).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let mut client = ControlServiceClient::new(channel);
            let resp = match client
                .read(ReadRequest {
                    group: self.group,
                    op: op_bytes.clone(),
                })
                .await
            {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    self.drop_channel(&addr);
                    last_err = Some(ShardError::Raft(format!("read rpc {addr}: {e}")));
                    continue;
                }
            };
            if resp.served {
                *self.preferred.lock().expect("preferred lock") = Some(addr);
                return postcard::from_bytes(&resp.result)
                    .map_err(|e| ShardError::Codec(format!("read result decode: {e}")));
            }
            // Redirect: put the hinted leader at the head of the queue.
            if let Some(hint) = resp.leader_addr {
                if hint != addr {
                    queue.push_front(hint);
                    continue;
                }
            }
            tokio::time::sleep(READ_RETRY_PAUSE).await;
        }
        Err(last_err.unwrap_or_else(|| {
            ShardError::Raft(format!("group {}: no replica served the read", self.group))
        }))
    }

    /// Execute one app-level intent at the group's leader — the write
    /// path for a shard this node does not host. Same hint-following
    /// discipline as [`Self::read`].
    pub async fn execute(&self, intent: Vec<u8>) -> Result<Vec<u8>> {
        let mut queue: std::collections::VecDeque<String> = self.candidates().into();
        let mut last_err = None;
        for _ in 0..READ_MAX_HOPS {
            let Some(addr) = queue.pop_front() else {
                tokio::time::sleep(READ_RETRY_PAUSE).await;
                queue = self.candidates().into();
                continue;
            };
            let channel = match self.channel(&addr).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let mut client = ControlServiceClient::new(channel);
            let resp = match client
                .execute(ExecuteRequest {
                    group: self.group,
                    intent: intent.clone(),
                })
                .await
            {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    self.drop_channel(&addr);
                    last_err = Some(ShardError::Raft(format!("execute rpc {addr}: {e}")));
                    continue;
                }
            };
            if resp.served {
                *self.preferred.lock().expect("preferred lock") = Some(addr);
                return Ok(resp.result);
            }
            if let Some(hint) = resp.leader_addr {
                if hint != addr {
                    queue.push_front(hint);
                    continue;
                }
            }
            tokio::time::sleep(READ_RETRY_PAUSE).await;
        }
        Err(last_err.unwrap_or_else(|| {
            ShardError::Raft(format!(
                "group {}: no replica served the intent",
                self.group
            ))
        }))
    }

    /// A gap-free change stream from `from_seq` (exclusive) that
    /// reconnects on stream errors, resuming from the last seen seq. Any
    /// replica serves it (tailing consumers tolerate replication lag).
    /// The stream ends only when every replica refuses (e.g. the app has
    /// no replay) — surfaced as a final Err item.
    pub fn subscribe(
        &self,
        from_seq: u64,
    ) -> impl futures_util::Stream<Item = Result<ChangeRecord>> {
        let this = self.clone();
        async_stream::try_stream! {
            let mut last = from_seq;
            let mut refused = 0usize;
            loop {
                let candidates = this.candidates();
                let n = candidates.len().max(1);
                let mut connected = false;
                for addr in candidates {
                    let Ok(channel) = this.channel(&addr).await else {
                        continue;
                    };
                    let mut client = ControlServiceClient::new(channel);
                    let stream = client
                        .subscribe(SubscribeRequest {
                            group: this.group,
                            from_seq: last,
                        })
                        .await;
                    let mut stream = match stream {
                        Ok(s) => s.into_inner(),
                        Err(e) => {
                            // A refusal (unknown group / no replay) from
                            // EVERY replica is terminal, not retriable.
                            refused += 1;
                            if refused >= n {
                                Err(ShardError::Raft(format!(
                                    "group {}: no replica serves subscriptions: {e}",
                                    this.group
                                )))?;
                            }
                            continue;
                        }
                    };
                    connected = true;
                    refused = 0;
                    loop {
                        match stream.message().await {
                            Ok(Some(frame)) => {
                                if frame.seq <= last {
                                    continue;
                                }
                                last = frame.seq;
                                yield ChangeRecord {
                                    seq: frame.seq,
                                    payload: frame.payload.into(),
                                };
                            }
                            Ok(None) | Err(_) => {
                                this.drop_channel(&addr);
                                break; // reconnect, resuming from `last`
                            }
                        }
                    }
                    break; // re-enter candidate selection after a drop
                }
                if !connected {
                    tokio::time::sleep(SUBSCRIBE_RETRY_PAUSE).await;
                }
            }
        }
    }
}

impl saltator_shard::RemoteReader for RemoteShard {
    fn read(
        &self,
        op: saltator_shard::ReadOp,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<saltator_shard::ReadValue>> + Send + '_>,
    > {
        Box::pin(async move { RemoteShard::read(self, &op).await })
    }
}

impl saltator_shard::RemoteShardBackend for RemoteShard {
    fn execute(
        &self,
        intent: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        Box::pin(RemoteShard::execute(self, intent))
    }

    fn subscribe(
        &self,
        from_seq: u64,
    ) -> std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<saltator_shard::ChangeRecord>> + Send + 'static>,
    > {
        Box::pin(RemoteShard::subscribe(self, from_seq))
    }

    fn set_replicas(&self, replicas: Vec<String>) {
        RemoteShard::set_replicas(self, replicas)
    }
}

/// Fetch a whole-shard transfer payload for `group` from the first
/// candidate that serves it — over a FRESH channel per attempt, i.e. a
/// dedicated TCP connection: bulk bytes never share a connection with
/// control traffic (spec.md §8's connection classes, client side).
pub async fn fetch_checkpoint(
    group: u64,
    candidates: &[String],
    tls: Option<&ClientTlsConfig>,
) -> Result<saltator_shard::transfer::TransferSnapshot> {
    let mut last_err = None;
    for addr in candidates {
        let channel = match connect(addr, tls).await {
            Ok(c) => c,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let mut client = crate::proto::bulk_service_client::BulkServiceClient::new(channel)
            .max_decoding_message_size(usize::MAX);
        let stream = match client
            .fetch_checkpoint(crate::proto::CheckpointRequest { group })
            .await
        {
            Ok(s) => s.into_inner(),
            Err(e) => {
                last_err = Some(ShardError::Raft(format!("fetch_checkpoint {addr}: {e}")));
                continue;
            }
        };
        let mut bytes = Vec::new();
        let mut stream = stream;
        let mut failed = false;
        loop {
            match stream.message().await {
                Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.data),
                Ok(None) => break,
                Err(e) => {
                    last_err = Some(ShardError::Raft(format!("checkpoint stream {addr}: {e}")));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            continue;
        }
        return postcard::from_bytes(&bytes)
            .map_err(|e| ShardError::Codec(format!("transfer decode: {e}")));
    }
    Err(last_err
        .unwrap_or_else(|| ShardError::Raft(format!("group {group}: no checkpoint source"))))
}

// -- media blobs --------------------------------------------------------------
//
// Blobs are
// not Raft data: they move by these two calls, over the bulk channel, and
// their replica set comes from `placement::blob_replicas` rather than from
// the stored placement.

/// Bytes per blob frame. Matches the checkpoint chunk — comfortably under
/// any gRPC message ceiling while keeping the frame count low for a
/// 50 MiB upload.
const BLOB_CHUNK: usize = 1 << 20;

/// Fetch one blob from the first candidate that has it.
///
/// `Ok(None)` is the meaningful answer "no replica holds this" — every
/// candidate answered NOT_FOUND — and becomes the client's 404. An error
/// means we could not get a straight answer from anyone, which is not the
/// same thing and must not be reported as a missing blob.
pub async fn fetch_blob(
    blob_id: &str,
    candidates: &[String],
    tls: Option<&ClientTlsConfig>,
) -> Result<Option<Vec<u8>>> {
    let mut last_err = None;
    let mut saw_answer = false;
    for addr in candidates {
        let channel = match connect(addr, tls).await {
            Ok(c) => c,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let mut client = crate::proto::bulk_service_client::BulkServiceClient::new(channel)
            .max_decoding_message_size(usize::MAX);
        let stream = match client
            .fetch_blob(crate::proto::FetchBlobRequest {
                blob_id: blob_id.to_owned(),
            })
            .await
        {
            Ok(s) => s.into_inner(),
            Err(e) if e.code() == tonic::Code::NotFound => {
                // A definite "not here" from a reachable peer.
                saw_answer = true;
                continue;
            }
            Err(e) => {
                last_err = Some(ShardError::Raft(format!("fetch_blob {addr}: {e}")));
                continue;
            }
        };
        let mut stream = stream;
        let mut bytes = Vec::new();
        let mut failed = false;
        loop {
            match stream.message().await {
                Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.data),
                Ok(None) => break,
                Err(e) => {
                    last_err = Some(ShardError::Raft(format!("blob stream {addr}: {e}")));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            continue;
        }
        return Ok(Some(bytes));
    }
    // Everyone we reached said "not here": that is an answer, not a
    // failure. Only report an error if nobody gave us one at all.
    if saw_answer {
        return Ok(None);
    }
    match last_err {
        Some(e) => Err(e),
        // No candidates at all — a single-node cluster, or a roster that
        // has not converged yet. Nothing holds it that we know of.
        None => Ok(None),
    }
}

/// Push one blob to `addr`, over a fresh (bulk) connection.
pub async fn store_blob(
    blob_id: &str,
    bytes: &[u8],
    addr: &str,
    tls: Option<&ClientTlsConfig>,
) -> Result<()> {
    let channel = connect(addr, tls).await?;
    let mut client = crate::proto::bulk_service_client::BulkServiceClient::new(channel)
        .max_encoding_message_size(usize::MAX);
    // The first frame names the blob and carries no data; the rest carry
    // data only. An empty blob is therefore just the naming frame.
    let mut frames = Vec::with_capacity(bytes.len() / BLOB_CHUNK + 2);
    frames.push(crate::proto::BlobChunk {
        data: Vec::new(),
        blob_id: Some(blob_id.to_owned()),
    });
    for c in bytes.chunks(BLOB_CHUNK) {
        frames.push(crate::proto::BlobChunk {
            data: c.to_vec(),
            blob_id: None,
        });
    }
    let resp = client
        .store_blob(futures_util::stream::iter(frames))
        .await
        .map_err(|e| ShardError::Raft(format!("store_blob {addr}: {e}")))?;
    let echoed = resp.into_inner().blob_id;
    if echoed != blob_id {
        return Err(ShardError::Raft(format!(
            "store_blob {addr}: stored as {echoed:?}, expected {blob_id:?}"
        )));
    }
    Ok(())
}

/// Ask `addr` whether it holds `blob_id`. Existence only — no bytes move.
///
/// An unreachable peer is an error, never a `false`: the caller uses this
/// to decide whether deleting its own copy is safe, and "I could not ask"
/// must never read as "yes, someone else has it".
pub async fn has_blob(blob_id: &str, addr: &str, tls: Option<&ClientTlsConfig>) -> Result<bool> {
    let channel = connect(addr, tls).await?;
    let mut client = crate::proto::bulk_service_client::BulkServiceClient::new(channel);
    let resp = client
        .has_blob(crate::proto::FetchBlobRequest {
            blob_id: blob_id.to_owned(),
        })
        .await
        .map_err(|e| ShardError::Raft(format!("has_blob {addr}: {e}")))?;
    Ok(resp.into_inner().present)
}
