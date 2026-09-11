//! The federation-out shard: durable ownership of "what have I promised
//! to deliver to whom" (docs/design-federation-out.md, roadmap step 4).
//!
//! State: per-destination PDU delivery cursors (keyed by source room
//! shard from day one), the outbound EDU outbox (moved here from the
//! user shard), and the drained-up-to marker that coordinates that
//! cross-shard move. The delivery *worker* lives in saltator-federation
//! (it needs the HTTP client and roomserver reads); this crate is the
//! domain layer: state machine, commands, readers, handle.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use saltator_shard::{
    ApplyCtx, ReadCtx, ShardApp, ShardHandle, ShardId, ShardRegistry, APP_TABLE_FIRST,
};
use saltator_store::{Keyspace, Result as StoreResult, StoreError};

/// M1-style single shard; placement/resharding is M-scale work (the
/// cursor key's `room_shard` component already anticipates it).
pub const FED_OUT_SHARD: ShardId = ShardId::new(Keyspace::FedOut, 0);

/// This binary's schema version for this shard app — bump together with
/// a `migrate` arm (see docs/design-schema-migrations.md).
pub const SCHEMA_VERSION: u32 = 2;

/// `room_shard (u16 BE) ++ destination → postcard(u64)` — the room-shard
/// seq fully delivered to `destination`. Absent = nothing delivered yet
/// (the worker seeds from the current tip on first contact, not from
/// zero: history predating the shard is backfill's business).
pub const T_PDU_CURSOR: u8 = APP_TABLE_FIRST;
/// `destination ++ 0x00 ++ seq (u64 BE) → EDU JSON` — the durable
/// outbound EDU outbox (moved from the user shard; same row shape).
pub const T_EDU_OUTBOX: u8 = APP_TABLE_FIRST + 1;
/// `b"user_outbox_drained" → postcard(u64)` — the drained-up-to marker
/// for the user-shard outbox move: the highest user-shard outbox row
/// seq already enqueued here. The user shard's v2 migration gate reads
/// this from its local replica (docs/design-federation-out.md §drain).
pub const T_DRAIN: u8 = APP_TABLE_FIRST + 2;

/// `as_id ++ 0x00 ++ room_shard (u16 BE) → postcard(u64)` — the
/// room-shard seq fully delivered to an application service (v2,
/// docs/design-appservices.md). Same charter as the PDU cursor: an AS
/// transaction is a promise of delivery, so its progress is fed-out
/// state. Absent = never delivered (the push worker seeds from the
/// current tip: history predating AS support is not replayed at a
/// bridge).
pub const T_AS_CURSOR: u8 = APP_TABLE_FIRST + 3;

const K_DRAIN_MARKER: &[u8] = b"user_outbox_drained";

#[derive(Debug, thiserror::Error)]
pub enum FedOutError {
    #[error("shard: {0}")]
    Shard(#[from] saltator_shard::ShardError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("codec: {0}")]
    Codec(String),
}

type Result<T> = std::result::Result<T, FedOutError>;

/// One outbound federation EDU: the complete EDU object as raw JSON and
/// the server it must reach. (Mirror of the user shard's historical
/// type; defined here so enqueuers depend on the delivery domain.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEdu {
    pub destination: String,
    pub json: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FedOutCommand {
    /// Queue EDUs into the durable outbox.
    EnqueueEdus { entries: Vec<OutboundEdu> },
    /// Drop delivered outbox rows for `destination` at seq `<= up_to`.
    AckEdus { destination: String, up_to: u64 },
    /// Record that everything in `room_shard`'s timeline up to `up_to`
    /// has been delivered to `destination`.
    AdvancePduCursor {
        room_shard: u16,
        destination: String,
        up_to: u64,
    },
    /// Advance the user-outbox drain marker (monotonic; stale values are
    /// ignored so re-drains are idempotent).
    SetDrainMarker { up_to: u64 },
    /// Record that everything in `room_shard`'s timeline up to `up_to`
    /// has been delivered to appservice `as_id` (monotonic, like the PDU
    /// cursor).
    AdvanceAsCursor {
        as_id: String,
        room_shard: u16,
        up_to: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FedOutResponse {
    Ok,
}

fn dest_key(destination: &str, rest: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(destination.len() + 1 + rest.len());
    k.extend_from_slice(destination.as_bytes());
    k.push(0);
    k.extend_from_slice(rest);
    k
}

fn as_cursor_key(as_id: &str, room_shard: u16) -> Vec<u8> {
    let mut k = Vec::with_capacity(as_id.len() + 3);
    k.extend_from_slice(as_id.as_bytes());
    k.push(0);
    k.extend_from_slice(&room_shard.to_be_bytes());
    k
}

fn cursor_key(room_shard: u16, destination: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + destination.len());
    k.extend_from_slice(&room_shard.to_be_bytes());
    k.extend_from_slice(destination.as_bytes());
    k
}

/// The shard's command interpreter.
pub struct FedOutApp;

impl ShardApp for FedOutApp {
    fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    fn migrate(&self, ctx: &mut ApplyCtx<'_>, to: u32) -> StoreResult<()> {
        let _ = ctx;
        match to {
            // v2: appservice delivery cursors (T_AS_CURSOR) — a new,
            // empty table; nothing to rewrite.
            2 => Ok(()),
            other => Err(StoreError::Engine(format!(
                "no migration registered for fedout schema step v{other}"
            ))),
        }
    }

    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        let cmd: FedOutCommand = postcard::from_bytes(command)
            .map_err(|e| StoreError::Engine(format!("fedout command decode: {e}")))?;
        match cmd {
            FedOutCommand::EnqueueEdus { entries } => {
                for edu in entries {
                    // The emitted seq keys the row (unique, ordered) and
                    // wakes the delivery worker through the change stream.
                    let seq = ctx.emit(edu.json.clone());
                    ctx.put(
                        T_EDU_OUTBOX,
                        &dest_key(&edu.destination, &seq.to_be_bytes()),
                        edu.json,
                    );
                }
            }
            FedOutCommand::AckEdus { destination, up_to } => {
                let start = dest_key(&destination, &[]);
                let end = dest_key(&destination, &(up_to + 1).to_be_bytes());
                for (key, _) in ctx.range(T_EDU_OUTBOX, &start, &end)? {
                    ctx.delete(T_EDU_OUTBOX, &key);
                }
            }
            FedOutCommand::AdvancePduCursor {
                room_shard,
                destination,
                up_to,
            } => {
                let key = cursor_key(room_shard, &destination);
                // Monotonic: a stale ack (reordered proposals around a
                // failover) must not rewind delivery.
                let current: u64 = match ctx.get(T_PDU_CURSOR, &key)? {
                    Some(b) => postcard::from_bytes(&b)
                        .map_err(|e| StoreError::Engine(format!("cursor decode: {e}")))?,
                    None => 0,
                };
                if up_to > current {
                    let enc = postcard::to_stdvec(&up_to)
                        .map_err(|e| StoreError::Engine(format!("cursor encode: {e}")))?;
                    ctx.put(T_PDU_CURSOR, &key, enc);
                }
            }
            FedOutCommand::AdvanceAsCursor {
                as_id,
                room_shard,
                up_to,
            } => {
                let key = as_cursor_key(&as_id, room_shard);
                let current: u64 = match ctx.get(T_AS_CURSOR, &key)? {
                    Some(b) => postcard::from_bytes(&b)
                        .map_err(|e| StoreError::Engine(format!("as cursor decode: {e}")))?,
                    None => 0,
                };
                if up_to > current {
                    let enc = postcard::to_stdvec(&up_to)
                        .map_err(|e| StoreError::Engine(format!("as cursor encode: {e}")))?;
                    ctx.put(T_AS_CURSOR, &key, enc);
                }
            }
            FedOutCommand::SetDrainMarker { up_to } => {
                let current: u64 = match ctx.get(T_DRAIN, K_DRAIN_MARKER)? {
                    Some(b) => postcard::from_bytes(&b)
                        .map_err(|e| StoreError::Engine(format!("marker decode: {e}")))?,
                    None => 0,
                };
                if up_to > current {
                    let enc = postcard::to_stdvec(&up_to)
                        .map_err(|e| StoreError::Engine(format!("marker encode: {e}")))?;
                    ctx.put(T_DRAIN, K_DRAIN_MARKER, enc);
                }
            }
        }
        postcard::to_stdvec(&FedOutResponse::Ok)
            .map_err(|e| StoreError::Engine(format!("fedout response encode: {e}")))
    }
}

/// Read-side access to applied fed-out state. Constructible on any node
/// (every replica applies every entry): the delivery worker reads it on
/// the leader; the user-shard migration gate reads the drain marker
/// from its local replica.
pub struct FedOutStore {
    read: ReadCtx,
}

impl FedOutStore {
    /// Destinations with pending outbox EDUs.
    pub fn edu_destinations(&self) -> StoreResult<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for (k, _) in self.read.range(T_EDU_OUTBOX, &[], &[])? {
            let dest = k
                .split(|b| *b == 0)
                .next()
                .map(|d| String::from_utf8_lossy(d).into_owned())
                .unwrap_or_default();
            if out.last().map(String::as_str) != Some(dest.as_str()) {
                out.push(dest);
            }
        }
        Ok(out)
    }

    /// Pending outbox EDUs for a destination, oldest first: `(seq, EDU
    /// JSON)`, at most `limit`.
    pub fn edu_outbox(&self, destination: &str, limit: usize) -> StoreResult<Vec<(u64, Vec<u8>)>> {
        let start = dest_key(destination, &[]);
        let mut end = destination.as_bytes().to_vec();
        end.push(1);
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_EDU_OUTBOX, &start, &end)? {
            if out.len() >= limit {
                break;
            }
            let seq_bytes: [u8; 8] = k[start.len()..]
                .try_into()
                .map_err(|_| StoreError::Engine("outbox key: bad seq".into()))?;
            out.push((u64::from_be_bytes(seq_bytes), v));
        }
        Ok(out)
    }

    /// The PDU delivery cursor for `(room_shard, destination)`; `None`
    /// = never contacted (the worker seeds from the current tip).
    pub fn pdu_cursor(&self, room_shard: u16, destination: &str) -> StoreResult<Option<u64>> {
        Ok(
            match self
                .read
                .get(T_PDU_CURSOR, &cursor_key(room_shard, destination))?
            {
                Some(b) => Some(
                    postcard::from_bytes(&b)
                        .map_err(|e| StoreError::Engine(format!("cursor decode: {e}")))?,
                ),
                None => None,
            },
        )
    }

    /// All PDU cursors: `(room_shard, destination, seq)`.
    pub fn pdu_cursors(&self) -> StoreResult<Vec<(u16, String, u64)>> {
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_PDU_CURSOR, &[], &[])? {
            if k.len() < 2 {
                continue;
            }
            let room_shard = u16::from_be_bytes([k[0], k[1]]);
            let dest = String::from_utf8_lossy(&k[2..]).into_owned();
            let seq: u64 = postcard::from_bytes(&v)
                .map_err(|e| StoreError::Engine(format!("cursor decode: {e}")))?;
            out.push((room_shard, dest, seq));
        }
        Ok(out)
    }

    /// The appservice delivery cursor for `(as_id, room_shard)`; `None`
    /// = never delivered (the push worker seeds from the current tip).
    pub fn as_cursor(&self, as_id: &str, room_shard: u16) -> StoreResult<Option<u64>> {
        Ok(
            match self
                .read
                .get(T_AS_CURSOR, &as_cursor_key(as_id, room_shard))?
            {
                Some(b) => Some(
                    postcard::from_bytes(&b)
                        .map_err(|e| StoreError::Engine(format!("as cursor decode: {e}")))?,
                ),
                None => None,
            },
        )
    }

    /// The user-outbox drain marker (0 = nothing drained).
    pub fn drain_marker(&self) -> StoreResult<u64> {
        Ok(match self.read.get(T_DRAIN, K_DRAIN_MARKER)? {
            Some(b) => postcard::from_bytes(&b)
                .map_err(|e| StoreError::Engine(format!("marker decode: {e}")))?,
            None => 0,
        })
    }
}

/// Handle to the running fed-out shard on this node.
pub struct FedOutServer {
    handle: ShardHandle,
}

impl FedOutServer {
    /// Start the fed-out shard on this node.
    pub async fn start(
        node_id: u64,
        stores: impl Into<saltator_store::Stores>,
        network: impl openraft::RaftNetworkFactory<saltator_shard::TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Arc<Self>> {
        let handle = ShardHandle::start(
            FED_OUT_SHARD,
            node_id,
            stores,
            Arc::new(FedOutApp),
            network,
            bootstrap_addr,
            registry,
        )
        .await?;
        Ok(Arc::new(Self { handle }))
    }

    pub fn shard_handle(&self) -> &ShardHandle {
        &self.handle
    }

    pub fn store(&self) -> FedOutStore {
        FedOutStore {
            read: self.handle.read_ctx(),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<saltator_shard::handle::ChangeRecord> {
        self.handle.subscribe()
    }

    async fn propose(&self, cmd: &FedOutCommand) -> Result<()> {
        let bytes = postcard::to_stdvec(cmd).map_err(|e| FedOutError::Codec(e.to_string()))?;
        let resp = self.handle.propose(bytes).await?;
        let _: FedOutResponse =
            postcard::from_bytes(&resp).map_err(|e| FedOutError::Codec(e.to_string()))?;
        Ok(())
    }

    /// Queue outbound EDUs durably; the delivery worker drains them.
    pub async fn enqueue_edus(&self, entries: Vec<OutboundEdu>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        self.propose(&FedOutCommand::EnqueueEdus { entries }).await
    }

    /// Drop delivered outbox rows (called by the worker after a
    /// destination accepted the transaction).
    pub async fn ack_edus(&self, destination: &str, up_to: u64) -> Result<()> {
        self.propose(&FedOutCommand::AckEdus {
            destination: destination.to_owned(),
            up_to,
        })
        .await
    }

    /// Record delivery progress for a destination against a room shard.
    pub async fn advance_pdu_cursor(
        &self,
        room_shard: u16,
        destination: &str,
        up_to: u64,
    ) -> Result<()> {
        self.propose(&FedOutCommand::AdvancePduCursor {
            room_shard,
            destination: destination.to_owned(),
            up_to,
        })
        .await
    }

    /// Advance the user-outbox drain marker (monotonic).
    pub async fn set_drain_marker(&self, up_to: u64) -> Result<()> {
        self.propose(&FedOutCommand::SetDrainMarker { up_to }).await
    }

    /// Record appservice delivery progress against a room shard.
    pub async fn advance_as_cursor(&self, as_id: &str, room_shard: u16, up_to: u64) -> Result<()> {
        self.propose(&FedOutCommand::AdvanceAsCursor {
            as_id: as_id.to_owned(),
            room_shard,
            up_to,
        })
        .await
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.handle.shutdown().await?)
    }

    /// Wait until the shard has a leader.
    pub async fn wait_for_leader(&self, timeout: Duration) -> Result<u64> {
        Ok(self.handle.wait_for_leader(timeout).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use saltator_shard::NoopNetworkFactory;
    use saltator_store::{KvEngine, RocksEngine};

    async fn start() -> (tempfile::TempDir, Arc<FedOutServer>) {
        let dir = tempfile::tempdir().unwrap();
        let engine: Arc<dyn KvEngine> =
            Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
        let server = FedOutServer::start(
            1,
            engine,
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        server
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        (dir, server)
    }

    #[tokio::test]
    async fn outbox_enqueue_ack_roundtrip() {
        let (_dir, server) = start().await;
        server
            .enqueue_edus(vec![
                OutboundEdu {
                    destination: "a.test".into(),
                    json: b"{\"a\":1}".to_vec(),
                },
                OutboundEdu {
                    destination: "b.test".into(),
                    json: b"{\"b\":1}".to_vec(),
                },
                OutboundEdu {
                    destination: "a.test".into(),
                    json: b"{\"a\":2}".to_vec(),
                },
            ])
            .await
            .unwrap();
        let store = server.store();
        assert_eq!(store.edu_destinations().unwrap(), vec!["a.test", "b.test"]);
        let rows = store.edu_outbox("a.test", 10).unwrap();
        assert_eq!(rows.len(), 2);
        // Ack through the first row only; the second stays.
        server.ack_edus("a.test", rows[0].0).await.unwrap();
        let rows = store.edu_outbox("a.test", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, b"{\"a\":2}".to_vec());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pdu_cursor_is_monotonic() {
        let (_dir, server) = start().await;
        assert_eq!(server.store().pdu_cursor(0, "a.test").unwrap(), None);
        server.advance_pdu_cursor(0, "a.test", 10).await.unwrap();
        // A stale ack must not rewind.
        server.advance_pdu_cursor(0, "a.test", 5).await.unwrap();
        assert_eq!(server.store().pdu_cursor(0, "a.test").unwrap(), Some(10));
        assert_eq!(
            server.store().pdu_cursors().unwrap(),
            vec![(0, "a.test".to_owned(), 10)]
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn as_cursor_is_monotonic_and_scoped() {
        let (_dir, server) = start().await;
        assert_eq!(server.store().as_cursor("irc", 0).unwrap(), None);
        server.advance_as_cursor("irc", 0, 10).await.unwrap();
        server.advance_as_cursor("irc", 0, 4).await.unwrap();
        server.advance_as_cursor("telegram", 0, 7).await.unwrap();
        assert_eq!(server.store().as_cursor("irc", 0).unwrap(), Some(10));
        assert_eq!(server.store().as_cursor("telegram", 0).unwrap(), Some(7));
        assert_eq!(server.store().as_cursor("irc", 1).unwrap(), None);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn drain_marker_is_monotonic() {
        let (_dir, server) = start().await;
        assert_eq!(server.store().drain_marker().unwrap(), 0);
        server.set_drain_marker(7).await.unwrap();
        server.set_drain_marker(3).await.unwrap();
        assert_eq!(server.store().drain_marker().unwrap(), 7);
        server.shutdown().await.unwrap();
    }
}
