//! The room keyspace state machine: a deterministic interpreter for
//! precomputed [`AppendEvent`] commands, plus typed read access to the
//! applied state.

use saltator_shard::{ApplyCtx, ReadCtx, ShardApp};
use saltator_store::{Result as StoreResult, StoreError};

use crate::types::{
    AppendEvent, ChangePayload, RoomCommand, RoomMeta, RoomResponse, SeqEntry, StateGroup,
    StoredEvent, T_EVENT, T_GROUP, T_ROOM, T_SEQ,
};

fn codec_err(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Engine(format!("{what}: {e}"))
}

fn enc<T: serde::Serialize>(what: &str, v: &T) -> StoreResult<Vec<u8>> {
    postcard::to_stdvec(v).map_err(|e| codec_err(what, e))
}

fn dec<T: for<'de> serde::Deserialize<'de>>(what: &str, b: &[u8]) -> StoreResult<T> {
    postcard::from_bytes(b).map_err(|e| codec_err(what, e))
}

/// Key of a state group: `room_id ++ 0x00 ++ group (BE)`. Room IDs cannot
/// contain NUL, so the prefix is unambiguous.
pub(crate) fn group_key(room_id: &str, group: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(room_id.len() + 9);
    k.extend_from_slice(room_id.as_bytes());
    k.push(0);
    k.extend_from_slice(&group.to_be_bytes());
    k
}

pub struct RoomApp;

impl ShardApp for RoomApp {
    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        let RoomCommand::Append(cmd) = dec::<RoomCommand>("room command decode", command)?;
        let resp = apply_append(ctx, &cmd)?;
        enc("room response encode", &resp)
    }
}

fn apply_append(ctx: &mut ApplyCtx<'_>, cmd: &AppendEvent) -> StoreResult<RoomResponse> {
    // Idempotence: re-applying a persisted event is a no-op (also the
    // contract cross-shard projections rely on, spec.md §4.1).
    if ctx.get(T_EVENT, cmd.event_id.as_bytes())?.is_some() {
        return Ok(RoomResponse::Duplicate {
            event_id: cmd.event_id.clone(),
        });
    }

    if let Some(rejected) = &cmd.rejected {
        // Rejected events are stored (they may be referenced as prev/auth
        // events by later PDUs) but have no extremity, current-state, or
        // change-stream effects. State-rejected events do carry a state
        // group (state after = state before) plus any groups a prev-fork
        // merge created, so the allocator must advance too.
        let stored = StoredEvent {
            raw: cmd.raw.clone(),
            seq: 0,
            state_group_after: cmd.state_group_after,
            depth: cmd.depth,
            rejected: Some(rejected.clone()),
        };
        ctx.put(
            T_EVENT,
            cmd.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
        for (id, group) in &cmd.new_groups {
            ctx.put(
                T_GROUP,
                &group_key(&cmd.room_id, *id),
                enc("state group encode", group)?,
            );
        }
        if let Some(b) = ctx.get(T_ROOM, cmd.room_id.as_bytes())? {
            let mut meta: RoomMeta = dec("room meta decode", &b)?;
            if cmd.next_group > meta.next_group {
                meta.next_group = cmd.next_group;
                ctx.put(
                    T_ROOM,
                    cmd.room_id.as_bytes(),
                    enc("room meta encode", &meta)?,
                );
            }
        }
        return Ok(RoomResponse::Rejected {
            event_id: cmd.event_id.clone(),
            reason: rejected.reason().to_owned(),
        });
    }

    let seq = ctx.emit(enc(
        "change payload encode",
        &ChangePayload {
            room_id: cmd.room_id.clone(),
            event_id: cmd.event_id.clone(),
        },
    )?);

    let stored = StoredEvent {
        raw: cmd.raw.clone(),
        seq,
        state_group_after: cmd.state_group_after,
        depth: cmd.depth,
        rejected: None,
    };
    ctx.put(
        T_EVENT,
        cmd.event_id.as_bytes(),
        enc("event encode", &stored)?,
    );
    ctx.put(
        T_SEQ,
        &seq.to_be_bytes(),
        enc(
            "seq entry encode",
            &SeqEntry {
                room_id: cmd.room_id.clone(),
                event_id: cmd.event_id.clone(),
            },
        )?,
    );

    for (id, group) in &cmd.new_groups {
        ctx.put(
            T_GROUP,
            &group_key(&cmd.room_id, *id),
            enc("state group encode", group)?,
        );
    }

    let meta = match &cmd.create_version {
        Some(version) => RoomMeta {
            version: version.clone(),
            create_event_id: cmd.event_id.clone(),
            current_group: cmd.new_current_group,
            next_group: cmd.next_group,
            extremities: cmd.new_extremities.clone(),
        },
        None => {
            let mut meta: RoomMeta = match ctx.get(T_ROOM, cmd.room_id.as_bytes())? {
                Some(b) => dec("room meta decode", &b)?,
                None => {
                    return Err(StoreError::Engine(format!(
                        "append to unknown room {} (non-create)",
                        cmd.room_id
                    )))
                }
            };
            meta.current_group = cmd.new_current_group;
            meta.next_group = cmd.next_group;
            meta.extremities = cmd.new_extremities.clone();
            meta
        }
    };
    ctx.put(
        T_ROOM,
        cmd.room_id.as_bytes(),
        enc("room meta encode", &meta)?,
    );

    Ok(RoomResponse::Accepted {
        event_id: cmd.event_id.clone(),
        seq,
    })
}

// ---------------------------------------------------------------------------
// Typed reads
// ---------------------------------------------------------------------------

/// Typed read access to a room shard's applied state.
#[derive(Clone)]
pub struct RoomStore {
    read: ReadCtx,
}

impl RoomStore {
    pub fn new(read: ReadCtx) -> Self {
        Self { read }
    }

    pub fn event(&self, event_id: &str) -> StoreResult<Option<StoredEvent>> {
        match self.read.get(T_EVENT, event_id.as_bytes())? {
            Some(b) => Ok(Some(dec("event decode", &b)?)),
            None => Ok(None),
        }
    }

    pub fn meta(&self, room_id: &str) -> StoreResult<Option<RoomMeta>> {
        match self.read.get(T_ROOM, room_id.as_bytes())? {
            Some(b) => Ok(Some(dec("room meta decode", &b)?)),
            None => Ok(None),
        }
    }

    pub fn group(&self, room_id: &str, group: u64) -> StoreResult<Option<StateGroup>> {
        match self.read.get(T_GROUP, &group_key(room_id, group))? {
            Some(b) => Ok(Some(dec("state group decode", &b)?)),
            None => Ok(None),
        }
    }

    /// Materialize a state group into a full `(type, state_key) →
    /// event_id` map by walking the delta chain.
    pub fn resolve_group(
        &self,
        room_id: &str,
        group: u64,
    ) -> StoreResult<std::collections::BTreeMap<(String, String), String>> {
        let mut chain = Vec::new();
        let mut cursor = Some(group);
        while let Some(id) = cursor {
            let g = self.group(room_id, id)?.ok_or_else(|| {
                StoreError::Engine(format!("state group {id} missing in {room_id}"))
            })?;
            cursor = g.parent;
            chain.push(g);
        }
        let mut map = std::collections::BTreeMap::new();
        for g in chain.into_iter().rev() {
            for (k, v) in g.entries {
                map.insert(k, v);
            }
        }
        Ok(map)
    }

    /// Timeline entries with `seq > from`, oldest first, across all rooms
    /// of the shard.
    pub fn timeline(&self, from: u64, limit: usize) -> StoreResult<Vec<(u64, SeqEntry)>> {
        let start = (from + 1).to_be_bytes();
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_SEQ, &start, &[])? {
            if out.len() >= limit {
                break;
            }
            let seq = u64::from_be_bytes(
                k.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("seq key width".into()))?,
            );
            out.push((seq, dec("seq entry decode", &v)?));
        }
        Ok(out)
    }
}
