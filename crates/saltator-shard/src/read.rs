//! Storage-level read operations for the remote Read RPC
//! (docs/design-room-sharding-phase2.md): the read half of the store
//! trait as a wire enum, executed against a shard's applied state at
//! its leader after a read-index barrier. Opaque postcard bytes inside
//! the proto envelope, like every other internal payload.

use serde::{Deserialize, Serialize};

use crate::app::{ReadCtx, APP_TABLE_MIN};
use crate::{Result, ShardError};

/// One remote read. Keys are app-level (the storage prefix is the
/// serving side's business), so an op can never name another shard's
/// data; the table floor keeps runtime-reserved tables unreadable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadOp {
    Get {
        table: u8,
        key: Vec<u8>,
    },
    /// Whole range `[start, end)` (whole table when `end` is empty).
    Range {
        table: u8,
        start: Vec<u8>,
        end: Vec<u8>,
    },
    /// Bounded scan: at most `limit` entries, from the end (reverse key
    /// order) when `reverse`.
    Scan {
        table: u8,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: u32,
        reverse: bool,
    },
    /// The shard's current sequence number.
    Seq,
}

/// A [`ReadOp`]'s result, matched by variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadValue {
    Value(Option<Vec<u8>>),
    Entries(Vec<(Vec<u8>, Vec<u8>)>),
    Seq(u64),
}

/// Execute one op against applied state. The caller owns linearizability
/// (`ensure_linearizable` before, on the leader).
pub fn execute(ctx: &ReadCtx, seq: u64, op: &ReadOp) -> Result<ReadValue> {
    let table_of = |t: u8| -> Result<u8> {
        if t < APP_TABLE_MIN {
            return Err(ShardError::Storage(format!(
                "read op names runtime-reserved table {t}"
            )));
        }
        Ok(t)
    };
    let storage = |e: saltator_store::StoreError| ShardError::Storage(e.to_string());
    Ok(match op {
        ReadOp::Get { table, key } => {
            ReadValue::Value(ctx.get(table_of(*table)?, key).map_err(storage)?)
        }
        ReadOp::Range { table, start, end } => {
            ReadValue::Entries(ctx.range(table_of(*table)?, start, end).map_err(storage)?)
        }
        ReadOp::Scan {
            table,
            start,
            end,
            limit,
            reverse,
        } => ReadValue::Entries(
            ctx.scan(table_of(*table)?, start, end, *limit as usize, *reverse)
                .map_err(storage)?,
        ),
        ReadOp::Seq => ReadValue::Seq(seq),
    })
}
