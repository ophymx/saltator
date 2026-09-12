//! Client side of the unhosted-shard data plane
//! (docs/design-room-sharding-phase2.md): storage-level reads at the
//! group's leader and gap-free change subscriptions, against a replica
//! set from the placement. The counterpart of `forward.rs` for reads —
//! same authed dialer, same channel cache, same leader-hint retarget
//! discipline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig};

use saltator_shard::{ChangeRecord, ReadOp, ReadValue, ShardError};

use crate::forward::connect;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::{ReadRequest, SubscribeRequest};

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
