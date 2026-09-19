//! The room keyspace state machine: a deterministic interpreter for
//! precomputed [`AppendEvent`] commands, plus typed read access to the
//! applied state.

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_core::validation;
use saltator_core::RoomVersion;
use saltator_shard::{ApplyCtx, ReadCtx, ShardApp};
use saltator_store::{Result as StoreResult, StoreError};

use crate::types::{
    AppendEvent, ChangePayload, ImportHistory, ImportRoom, ImportSegment, ReceiptCmd,
    ReceiptRecord, RoomCommand, RoomMeta, RoomResponse, SeqEntry, StateGroup, StoredEvent, T_EVENT,
    T_GROUP, T_HISTORY, T_RECEIPT, T_REDACT, T_ROOM, T_ROOM_SEQ, T_SEQ,
};

fn codec_err(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Engine(format!("{what}: {e}"))
}

/// One page of [`RoomStore::rooms`]: the rows, and the start key of the
/// page after this one (`None` on the last page).
pub type RoomPage = (Vec<(String, RoomMeta)>, Option<String>);

fn enc<T: serde::Serialize>(what: &str, v: &T) -> StoreResult<Vec<u8>> {
    postcard::to_stdvec(v).map_err(|e| codec_err(what, e))
}

fn dec<T: for<'de> serde::Deserialize<'de>>(what: &str, b: &[u8]) -> StoreResult<T> {
    postcard::from_bytes(b).map_err(|e| codec_err(what, e))
}

fn get_typed<T: for<'de> serde::Deserialize<'de>>(
    ctx: &mut ApplyCtx<'_>,
    what: &str,
    table: u8,
    key: &[u8],
) -> StoreResult<Option<T>> {
    match ctx.get(table, key)? {
        Some(b) => Ok(Some(dec(what, &b)?)),
        None => Ok(None),
    }
}

/// `room_id ++ 0x00 ++ n (BE)` — key shape shared by `T_GROUP` (n = group
/// id) and `T_ROOM_SEQ` (n = shard seq). Room IDs cannot contain NUL, so
/// the prefix is unambiguous.
pub(crate) fn room_u64_key(room_id: &str, n: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(room_id.len() + 9);
    k.extend_from_slice(room_id.as_bytes());
    k.push(0);
    k.extend_from_slice(&n.to_be_bytes());
    k
}

/// Exclusive upper bound for all `room_u64_key(room_id, _)` keys.
pub(crate) fn room_u64_end(room_id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(room_id.len() + 1);
    k.extend_from_slice(room_id.as_bytes());
    k.push(1);
    k
}

/// Key of a receipt: `room_id ++ 0x00 ++ user_id ++ 0x00 ++ receipt_type
/// ++ 0x00 ++ thread` — one receipt position per thread (`thread` is
/// empty for the unthreaded receipt, `"main"` or a thread-root event id
/// for threaded ones).
fn receipt_key(room_id: &str, user_id: &str, receipt_type: &str, thread: &str) -> Vec<u8> {
    let mut k =
        Vec::with_capacity(room_id.len() + user_id.len() + receipt_type.len() + thread.len() + 3);
    k.extend_from_slice(room_id.as_bytes());
    k.push(0);
    k.extend_from_slice(user_id.as_bytes());
    k.push(0);
    k.extend_from_slice(receipt_type.as_bytes());
    k.push(0);
    k.extend_from_slice(thread.as_bytes());
    k
}

pub struct RoomApp;

impl ShardApp for RoomApp {
    fn schema_version(&self) -> u32 {
        crate::SCHEMA_VERSION
    }

    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        let resp = match dec::<RoomCommand>("room command decode", command)? {
            RoomCommand::Append(cmd) => apply_append(ctx, &cmd)?,
            RoomCommand::Receipt(cmd) => apply_receipt(ctx, &cmd)?,
            RoomCommand::Import(cmd) => apply_import(ctx, &cmd)?,
            RoomCommand::ImportHistory(cmd) => apply_import_history(ctx, &cmd)?,
            RoomCommand::ImportSegment(cmd) => apply_import_segment(ctx, &cmd)?,
        };
        enc("room response encode", &resp)
    }

    /// Change-stream backfill for remote subscribers: every emit writes a
    /// `T_SEQ` row in the same apply, so the payload at any seq is
    /// re-derivable — byte-identical, since [`SeqEntry`] carries a
    /// superset of [`ChangePayload`]'s fields and postcard is
    /// deterministic.
    fn replay(
        &self,
        ctx: &saltator_shard::ReadCtx,
        from_seq: u64,
        limit: usize,
    ) -> StoreResult<Vec<(u64, std::sync::Arc<[u8]>)>> {
        let start = (from_seq + 1).to_be_bytes();
        let mut out = Vec::new();
        for (k, v) in ctx.scan(T_SEQ, &start, &[], limit, false)? {
            let seq = u64::from_be_bytes(
                k.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("seq key width".into()))?,
            );
            let payload = match dec::<SeqEntry>("seq entry decode", &v)? {
                SeqEntry::Event { room_id, event_id } => ChangePayload::Event { room_id, event_id },
                SeqEntry::Receipt { room_id, .. } => ChangePayload::Receipt { room_id },
            };
            out.push((seq, enc("change payload encode", &payload)?.into()));
        }
        Ok(out)
    }
}

fn apply_receipt(ctx: &mut ApplyCtx<'_>, cmd: &ReceiptCmd) -> StoreResult<RoomResponse> {
    let key = receipt_key(
        &cmd.room_id,
        &cmd.user_id,
        &cmd.receipt_type,
        cmd.thread_id.as_deref().unwrap_or(""),
    );
    // Idempotence: re-acking the same event is a no-op (no seq burn).
    if let Some(b) = ctx.get(T_RECEIPT, &key)? {
        let existing: ReceiptRecord = dec("receipt decode", &b)?;
        if existing.event_id == cmd.event_id {
            return Ok(RoomResponse::Receipt { seq: 0 });
        }
    }
    let seq = ctx.emit(enc(
        "change payload encode",
        &ChangePayload::Receipt {
            room_id: cmd.room_id.clone(),
        },
    )?);
    ctx.put(
        T_SEQ,
        &seq.to_be_bytes(),
        enc(
            "seq entry encode",
            &SeqEntry::Receipt {
                room_id: cmd.room_id.clone(),
                user_id: cmd.user_id.clone(),
                receipt_type: cmd.receipt_type.clone(),
                event_id: cmd.event_id.clone(),
                ts: cmd.ts,
            },
        )?,
    );
    ctx.put(
        T_RECEIPT,
        &key,
        enc(
            "receipt encode",
            &ReceiptRecord {
                event_id: cmd.event_id.clone(),
                thread_id: cmd.thread_id.clone(),
                ts: cmd.ts,
                seq,
            },
        )?,
    );
    Ok(RoomResponse::Receipt { seq })
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
            history_idx: None,
            imported: false,
            relay: false,
        };
        ctx.put(
            T_EVENT,
            cmd.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
        for (id, group) in &cmd.new_groups {
            ctx.put(
                T_GROUP,
                &room_u64_key(&cmd.room_id, *id),
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
        &ChangePayload::Event {
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
        history_idx: None,
        imported: false,
        // Resident-applied send_join/send_leave memberships fan out; the
        // pipeline sets this only on those paths.
        relay: cmd.relay,
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
            &SeqEntry::Event {
                room_id: cmd.room_id.clone(),
                event_id: cmd.event_id.clone(),
            },
        )?,
    );
    ctx.put(
        T_ROOM_SEQ,
        &room_u64_key(&cmd.room_id, seq),
        cmd.event_id.as_bytes(),
    );
    if let Some(target) = &cmd.redacts {
        ctx.put(T_REDACT, target.as_bytes(), cmd.event_id.as_bytes());
    }

    for (id, group) in &cmd.new_groups {
        ctx.put(
            T_GROUP,
            &room_u64_key(&cmd.room_id, *id),
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
            // A locally created room's history is complete by construction.
            history_frontier: Vec::new(),
            next_history_idx: 1,
            gap_markers: Vec::new(),
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

fn apply_import(ctx: &mut ApplyCtx<'_>, cmd: &ImportRoom) -> StoreResult<RoomResponse> {
    // Re-applying the same join is a no-op. A *fresh* join into a known
    // room is a re-import: every local user left (so our fork went
    // stale), we re-joined through a resident, and its state dump
    // supersedes what we hold — existing events and history stay put.
    let existing_meta: Option<RoomMeta> =
        get_typed(ctx, "room meta decode", T_ROOM, cmd.room_id.as_bytes())?;
    if existing_meta.is_some()
        && get_typed::<StoredEvent>(ctx, "event decode", T_EVENT, cmd.join_event_id.as_bytes())?
            .is_some_and(|s| s.seq > 0)
    {
        return Ok(RoomResponse::Duplicate {
            event_id: cmd.join_event_id.clone(),
        });
    }

    // Supporting events (create + auth chain + current state): stored so
    // resolution and later sends can reach them, but kept out of the
    // timeline (seq 0), like rejected events.
    for ev in &cmd.events {
        if ctx.get(T_EVENT, ev.event_id.as_bytes())?.is_some() {
            continue;
        }
        let stored = StoredEvent {
            raw: ev.raw.clone(),
            seq: 0,
            state_group_after: 0,
            depth: ev.depth,
            rejected: None,
            history_idx: None,
            imported: true,
            relay: false,
        };
        ctx.put(
            T_EVENT,
            ev.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
    }

    // The state-group snapshot: the room's resolved state after the join.
    // Group ids start at 1; a re-import allocates the next one.
    let group_id = existing_meta.as_ref().map(|m| m.next_group).unwrap_or(1);
    let group = StateGroup {
        parent: None,
        chain_len: 0,
        entries: cmd.state.clone(),
    };
    ctx.put(
        T_GROUP,
        &room_u64_key(&cmd.room_id, group_id),
        enc("state group encode", &group)?,
    );

    // The membership event is the one timeline entry — emitted so `/sync`
    // and the membership projection see the join.
    let seq = ctx.emit(enc(
        "change payload encode",
        &ChangePayload::Event {
            room_id: cmd.room_id.clone(),
            event_id: cmd.join_event_id.clone(),
        },
    )?);
    let join_stored = StoredEvent {
        raw: cmd.join_raw.clone(),
        seq,
        state_group_after: group_id,
        depth: cmd.join_depth,
        rejected: None,
        history_idx: None,
        imported: true,
        relay: false,
    };
    ctx.put(
        T_EVENT,
        cmd.join_event_id.as_bytes(),
        enc("event encode", &join_stored)?,
    );
    ctx.put(
        T_SEQ,
        &seq.to_be_bytes(),
        enc(
            "seq entry encode",
            &SeqEntry::Event {
                room_id: cmd.room_id.clone(),
                event_id: cmd.join_event_id.clone(),
            },
        )?,
    );
    ctx.put(
        T_ROOM_SEQ,
        &room_u64_key(&cmd.room_id, seq),
        cmd.join_event_id.as_bytes(),
    );

    // Frontier: the join's unheld prevs (an already-visible event needs no
    // backfill); a re-import unions with whatever was already open.
    let mut frontier: std::collections::BTreeSet<String> = existing_meta
        .as_ref()
        .map(|m| m.history_frontier.iter().cloned().collect())
        .unwrap_or_default();
    for id in &cmd.history_frontier {
        let visible = get_typed::<StoredEvent>(ctx, "event decode", T_EVENT, id.as_bytes())?
            .is_some_and(|s| s.seq > 0 || s.history_idx.is_some());
        if !visible {
            frontier.insert(id.clone());
        }
    }
    let meta = RoomMeta {
        version: cmd.version.clone(),
        create_event_id: cmd.create_event_id.clone(),
        current_group: group_id,
        next_group: group_id + 1,
        extremities: vec![cmd.join_event_id.clone()],
        history_frontier: frontier.into_iter().collect(),
        next_history_idx: existing_meta
            .as_ref()
            .map(|m| m.next_history_idx)
            .unwrap_or(1),
        gap_markers: existing_meta
            .as_ref()
            .map(|m| m.gap_markers.clone())
            .unwrap_or_default(),
    };
    ctx.put(
        T_ROOM,
        cmd.room_id.as_bytes(),
        enc("room meta encode", &meta)?,
    );

    Ok(RoomResponse::Accepted {
        event_id: cmd.join_event_id.clone(),
        seq,
    })
}

fn apply_import_segment(ctx: &mut ApplyCtx<'_>, cmd: &ImportSegment) -> StoreResult<RoomResponse> {
    let Some(b) = ctx.get(T_ROOM, cmd.room_id.as_bytes())? else {
        return Err(StoreError::Engine(format!(
            "segment import to unknown room {}",
            cmd.room_id
        )));
    };
    let mut meta: RoomMeta = dec("room meta decode", &b)?;

    // Supporting events (anchor state + auth chain), off-timeline.
    for ev in &cmd.events {
        if ctx.get(T_EVENT, ev.event_id.as_bytes())?.is_some() {
            continue;
        }
        let stored = StoredEvent {
            raw: ev.raw.clone(),
            seq: 0,
            state_group_after: 0,
            depth: ev.depth,
            rejected: None,
            history_idx: None,
            imported: true,
            relay: false,
        };
        ctx.put(
            T_EVENT,
            ev.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
    }

    // The anchor snapshot every segment event resolves against.
    let group_id = meta.next_group;
    let group = StateGroup {
        parent: None,
        chain_len: 0,
        entries: cmd.state.clone(),
    };
    ctx.put(
        T_GROUP,
        &room_u64_key(&cmd.room_id, group_id),
        enc("state group encode", &group)?,
    );
    meta.next_group = group_id + 1;

    // The recovered chain joins the timeline, oldest first.
    let mut appended = 0u64;
    let mut first_seq = None;
    let mut last_id = None;
    for ev in &cmd.timeline {
        if get_typed::<StoredEvent>(ctx, "event decode", T_EVENT, ev.event_id.as_bytes())?
            .is_some_and(|s| s.seq > 0)
        {
            continue;
        }
        let seq = ctx.emit(enc(
            "change payload encode",
            &ChangePayload::Event {
                room_id: cmd.room_id.clone(),
                event_id: ev.event_id.clone(),
            },
        )?);
        let stored = StoredEvent {
            raw: ev.raw.clone(),
            seq,
            state_group_after: group_id,
            depth: ev.depth,
            rejected: None,
            history_idx: None,
            imported: false,
            relay: false,
        };
        ctx.put(
            T_EVENT,
            ev.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
        ctx.put(
            T_SEQ,
            &seq.to_be_bytes(),
            enc(
                "seq entry encode",
                &SeqEntry::Event {
                    room_id: cmd.room_id.clone(),
                    event_id: ev.event_id.clone(),
                },
            )?,
        );
        ctx.put(
            T_ROOM_SEQ,
            &room_u64_key(&cmd.room_id, seq),
            ev.event_id.as_bytes().to_vec(),
        );
        first_seq.get_or_insert(seq);
        last_id = Some(ev.event_id.clone());
        appended += 1;
    }

    if let Some(first) = first_seq {
        // The timeline is not contiguous below this point.
        meta.gap_markers.push(first);
        // Only markers above a client's `since` matter for sync-window
        // truncation, and `since` is always recent — so cap the retained
        // set to the newest few. Unbounded, a room that is repeatedly
        // gap-filled would grow RoomMeta without limit and, since the whole
        // record is rewritten per event, make every later append cost O(n).
        const MAX_GAP_MARKERS: usize = 1024;
        if meta.gap_markers.len() > MAX_GAP_MARKERS {
            let drop = meta.gap_markers.len() - MAX_GAP_MARKERS;
            meta.gap_markers.drain(..drop);
        }
    }
    if let Some(last) = last_id {
        // The chain's newest event is a genuine forward extremity until
        // the PDU that triggered the gap-fill consumes it.
        if !meta.extremities.contains(&last) {
            meta.extremities.push(last);
        }
    }
    for id in &cmd.frontier_add {
        let visible = get_typed::<StoredEvent>(ctx, "event decode", T_EVENT, id.as_bytes())?
            .is_some_and(|s| s.seq > 0 || s.history_idx.is_some());
        if !visible && !meta.history_frontier.contains(id) {
            meta.history_frontier.push(id.clone());
        }
    }
    ctx.put(
        T_ROOM,
        cmd.room_id.as_bytes(),
        enc("room meta encode", &meta)?,
    );

    Ok(RoomResponse::Segment { appended })
}

fn apply_import_history(ctx: &mut ApplyCtx<'_>, cmd: &ImportHistory) -> StoreResult<RoomResponse> {
    let Some(b) = ctx.get(T_ROOM, cmd.room_id.as_bytes())? else {
        return Err(StoreError::Engine(format!(
            "history import to unknown room {}",
            cmd.room_id
        )));
    };
    let mut meta: RoomMeta = dec("room meta decode", &b)?;

    // Ids made visible in this batch: `ctx.get` may not see this apply's
    // own staged puts, so track them explicitly.
    let mut batch_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut new_prevs: Vec<String> = Vec::new();
    let mut idx = meta.next_history_idx;
    let mut indexed = 0u64;
    for ev in &cmd.events {
        let existing: Option<StoredEvent> =
            get_typed(ctx, "event decode", T_EVENT, ev.event_id.as_bytes())?;
        let stored = match existing {
            // Already on the timeline or already in history: nothing to do
            // (also the idempotence path for a re-applied batch).
            Some(s) if s.seq > 0 || s.history_idx.is_some() => {
                batch_ids.insert(ev.event_id.clone());
                continue;
            }
            // Held off-timeline (import support event): joins the history
            // order, keeps its stored body.
            Some(mut s) => {
                s.history_idx = Some(idx);
                s
            }
            None => StoredEvent {
                raw: ev.raw.clone(),
                seq: 0,
                state_group_after: 0,
                depth: ev.depth,
                rejected: None,
                history_idx: Some(idx),
                imported: true,
                relay: false,
            },
        };
        let raw: CanonicalJsonObject =
            serde_json::from_slice(&stored.raw).map_err(|e| codec_err("history event parse", e))?;
        ctx.put(
            T_EVENT,
            ev.event_id.as_bytes(),
            enc("event encode", &stored)?,
        );
        ctx.put(
            T_HISTORY,
            &room_u64_key(&cmd.room_id, idx),
            ev.event_id.as_bytes().to_vec(),
        );
        batch_ids.insert(ev.event_id.clone());
        new_prevs.extend(crate::prev_event_ids(&raw));
        idx += 1;
        indexed += 1;
    }

    // Recompute the frontier: everything referenced at the historical edge
    // that is still not visible (neither timeline-stored, history-indexed,
    // nor part of this batch).
    let mut frontier: std::collections::BTreeSet<String> =
        meta.history_frontier.iter().cloned().collect();
    frontier.extend(new_prevs);
    let mut still_missing = Vec::new();
    for id in frontier {
        if batch_ids.contains(&id) {
            continue;
        }
        let visible = get_typed::<StoredEvent>(ctx, "event decode", T_EVENT, id.as_bytes())?
            .is_some_and(|s| s.seq > 0 || s.history_idx.is_some());
        if !visible {
            still_missing.push(id);
        }
    }
    meta.history_frontier = still_missing;
    meta.next_history_idx = idx;
    let complete = meta.history_frontier.is_empty();
    ctx.put(
        T_ROOM,
        cmd.room_id.as_bytes(),
        enc("room meta encode", &meta)?,
    );

    Ok(RoomResponse::History { indexed, complete })
}

// ---------------------------------------------------------------------------
// Typed reads
// ---------------------------------------------------------------------------

/// Typed read access to a room shard's applied state — local (this
/// node hosts the shard) or remote (served by a hosting replica over
/// the Read RPC). Every read
/// method is async for the remote case; the local case resolves
/// immediately.
#[derive(Clone)]
pub struct RoomStore {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Local(ReadCtx),
    Remote(std::sync::Arc<dyn saltator_shard::read::RemoteReader>),
}

fn remote_err(e: saltator_shard::ShardError) -> StoreError {
    StoreError::Engine(format!("remote read: {e}"))
}

impl RoomStore {
    pub fn new(read: ReadCtx) -> Self {
        Self {
            backend: Backend::Local(read),
        }
    }

    /// A store served by a remote replica of the shard.
    pub fn remote(reader: std::sync::Arc<dyn saltator_shard::read::RemoteReader>) -> Self {
        Self {
            backend: Backend::Remote(reader),
        }
    }

    /// Synchronous point read of a stored event — for the event
    /// pipeline's state-resolution callback, whose saltator-core API is
    /// deliberately sync and I/O-free. The pipeline only runs where the
    /// shard is hosted (spec.md §5.2: at the room-shard leader), so a
    /// remote store refuses.
    pub fn event_sync(&self, event_id: &str) -> StoreResult<Option<StoredEvent>> {
        match &self.backend {
            Backend::Local(ctx) => match ctx.get(T_EVENT, event_id.as_bytes())? {
                Some(b) => Ok(Some(dec("event decode", &b)?)),
                None => Ok(None),
            },
            Backend::Remote(_) => Err(StoreError::Engine(
                "event pipeline requires a hosted shard (sync read on remote store)".into(),
            )),
        }
    }

    // -- storage primitives, dispatched by backend --------------------

    async fn kv_get(&self, table: u8, key: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        match &self.backend {
            Backend::Local(ctx) => ctx.get(table, key),
            Backend::Remote(r) => match r
                .read(saltator_shard::ReadOp::Get {
                    table,
                    key: key.to_vec(),
                })
                .await
                .map_err(remote_err)?
            {
                saltator_shard::ReadValue::Value(v) => Ok(v),
                other => Err(StoreError::Engine(format!("get returned {other:?}"))),
            },
        }
    }

    async fn kv_scan(
        &self,
        table: u8,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> StoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        match &self.backend {
            Backend::Local(ctx) => ctx.scan(table, start, end, limit, reverse),
            Backend::Remote(r) => match r
                .read(saltator_shard::ReadOp::Scan {
                    table,
                    start: start.to_vec(),
                    end: end.to_vec(),
                    limit: limit.min(u32::MAX as usize) as u32,
                    reverse,
                })
                .await
                .map_err(remote_err)?
            {
                saltator_shard::ReadValue::Entries(e) => Ok(e),
                other => Err(StoreError::Engine(format!("scan returned {other:?}"))),
            },
        }
    }

    async fn kv_range(
        &self,
        table: u8,
        start: &[u8],
        end: &[u8],
    ) -> StoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        match &self.backend {
            Backend::Local(ctx) => ctx.range(table, start, end),
            Backend::Remote(r) => match r
                .read(saltator_shard::ReadOp::Range {
                    table,
                    start: start.to_vec(),
                    end: end.to_vec(),
                })
                .await
                .map_err(remote_err)?
            {
                saltator_shard::ReadValue::Entries(e) => Ok(e),
                other => Err(StoreError::Engine(format!("range returned {other:?}"))),
            },
        }
    }

    pub async fn event(&self, event_id: &str) -> StoreResult<Option<StoredEvent>> {
        match self.kv_get(T_EVENT, event_id.as_bytes()).await? {
            Some(b) => Ok(Some(dec("event decode", &b)?)),
            None => Ok(None),
        }
    }

    pub async fn meta(&self, room_id: &str) -> StoreResult<Option<RoomMeta>> {
        match self.kv_get(T_ROOM, room_id.as_bytes()).await? {
            Some(b) => Ok(Some(dec("room meta decode", &b)?)),
            None => Ok(None),
        }
    }

    /// One page of hosted rooms in room-id order, starting at `from`
    /// (inclusive) — for the admin room list. Bounded by construction, for
    /// the same reason [`UserStore::accounts`] is: enumeration is not a
    /// whole-table materialization.
    ///
    /// [`UserStore::accounts`]: saltator_userserver::UserStore::accounts
    pub async fn rooms(&self, from: Option<&str>, limit: usize) -> StoreResult<RoomPage> {
        // The extra row is the next page's start key, not a result.
        let rows = self
            .kv_scan(
                T_ROOM,
                from.unwrap_or("").as_bytes(),
                &[],
                limit.saturating_add(1),
                false,
            )
            .await?;
        let mut out = Vec::with_capacity(rows.len().min(limit));
        let mut next = None;
        for (i, (k, v)) in rows.into_iter().enumerate() {
            let room_id =
                String::from_utf8(k).map_err(|_| StoreError::Engine("room id not UTF-8".into()))?;
            if i == limit {
                next = Some(room_id);
                break;
            }
            out.push((room_id, dec("room meta decode", &v)?));
        }
        Ok((out, next))
    }

    pub async fn group(&self, room_id: &str, group: u64) -> StoreResult<Option<StateGroup>> {
        match self.kv_get(T_GROUP, &room_u64_key(room_id, group)).await? {
            Some(b) => Ok(Some(dec("state group decode", &b)?)),
            None => Ok(None),
        }
    }

    /// Materialize a state group into a full `(type, state_key) →
    /// event_id` map by walking the delta chain.
    pub async fn resolve_group(
        &self,
        room_id: &str,
        group: u64,
    ) -> StoreResult<std::collections::BTreeMap<(String, String), String>> {
        let mut chain = Vec::new();
        let mut cursor = Some(group);
        while let Some(id) = cursor {
            let g = self.group(room_id, id).await?.ok_or_else(|| {
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
    pub async fn timeline(&self, from: u64, limit: usize) -> StoreResult<Vec<(u64, SeqEntry)>> {
        let start = (from + 1).to_be_bytes();
        let mut out = Vec::new();
        for (k, v) in self.kv_scan(T_SEQ, &start, &[], limit, false).await? {
            let seq = u64::from_be_bytes(
                k.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("seq key width".into()))?,
            );
            out.push((seq, dec("seq entry decode", &v)?));
        }
        Ok(out)
    }

    /// One room's accepted events with shard seq in `(after, until]`
    /// (`until` = end of time when `None`): at most `limit` of them,
    /// oldest-first — or newest-first from the top of the window when
    /// `newest_first` (backwards `/messages` pagination).
    pub async fn room_timeline(
        &self,
        room_id: &str,
        after: u64,
        until: Option<u64>,
        limit: usize,
        newest_first: bool,
    ) -> StoreResult<Vec<(u64, String)>> {
        let start = room_u64_key(room_id, after.saturating_add(1));
        let end = match until {
            Some(u) if u == u64::MAX => room_u64_end(room_id),
            Some(u) => room_u64_key(room_id, u + 1),
            None => room_u64_end(room_id),
        };
        let mut out = Vec::new();
        for (k, v) in self
            .kv_scan(T_ROOM_SEQ, &start, &end, limit, newest_first)
            .await?
        {
            let seq = u64::from_be_bytes(
                k[k.len() - 8..]
                    .try_into()
                    .map_err(|_| StoreError::Engine("room seq key width".into()))?,
            );
            let event_id = String::from_utf8(v)
                .map_err(|_| StoreError::Engine("room seq value not UTF-8".into()))?;
            out.push((seq, event_id));
        }
        Ok(out)
    }

    /// One room's backfilled history with index in `(after, until]`
    /// (`until` = no bound when `None`): at most `limit` entries. History
    /// indexes grow *older* (idx 1 is the newest pre-timeline event), so
    /// `oldest_first: false` reads ascending idx (newer→older — the
    /// natural order for backwards `/messages` pagination continuing past
    /// the timeline floor) and `oldest_first: true` reads descending idx
    /// from the top of the window (older→newer, forwards pagination).
    pub async fn room_history(
        &self,
        room_id: &str,
        after: u64,
        until: Option<u64>,
        limit: usize,
        oldest_first: bool,
    ) -> StoreResult<Vec<(u64, String)>> {
        let start = room_u64_key(room_id, after.saturating_add(1));
        let end = match until {
            Some(u) if u == u64::MAX => room_u64_end(room_id),
            Some(u) => room_u64_key(room_id, u + 1),
            None => room_u64_end(room_id),
        };
        let mut out = Vec::new();
        for (k, v) in self
            .kv_scan(T_HISTORY, &start, &end, limit, oldest_first)
            .await?
        {
            let idx = u64::from_be_bytes(
                k[k.len() - 8..]
                    .try_into()
                    .map_err(|_| StoreError::Engine("history key width".into()))?,
            );
            let event_id = String::from_utf8(v)
                .map_err(|_| StoreError::Engine("history value not UTF-8".into()))?;
            out.push((idx, event_id));
        }
        Ok(out)
    }

    /// All receipts of a room: `(user_id, receipt_type, record)`.
    pub async fn receipts(
        &self,
        room_id: &str,
    ) -> StoreResult<Vec<(String, String, ReceiptRecord)>> {
        let mut start = room_id.as_bytes().to_vec();
        start.push(0);
        let end = room_u64_end(room_id);
        let mut out = Vec::new();
        for (k, v) in self.kv_range(T_RECEIPT, &start, &end).await? {
            let rest = &k[start.len()..];
            let sep = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| StoreError::Engine("receipt key shape".into()))?;
            let user_id = String::from_utf8(rest[..sep].to_vec())
                .map_err(|_| StoreError::Engine("receipt user not UTF-8".into()))?;
            // The type runs to the next separator; the trailing thread
            // component is carried in the record itself.
            let type_and_thread = &rest[sep + 1..];
            let type_end = type_and_thread
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(type_and_thread.len());
            let receipt_type = String::from_utf8(type_and_thread[..type_end].to_vec())
                .map_err(|_| StoreError::Engine("receipt type not UTF-8".into()))?;
            out.push((user_id, receipt_type, dec("receipt decode", &v)?));
        }
        Ok(out)
    }

    /// The event that redacted `event_id`, if any.
    pub async fn redacted_by(&self, event_id: &str) -> StoreResult<Option<String>> {
        Ok(match self.kv_get(T_REDACT, event_id.as_bytes()).await? {
            Some(v) => Some(
                String::from_utf8(v)
                    .map_err(|_| StoreError::Engine("redact value not UTF-8".into()))?,
            ),
            None => None,
        })
    }

    /// An event in its servable form: the stored canonical JSON, with the
    /// room version's redaction algorithm applied (and
    /// `unsigned.redacted_because` set) if the event has been redacted.
    /// Rejected events are not served.
    pub async fn served_event(
        &self,
        event_id: &str,
        version: RoomVersion,
    ) -> StoreResult<Option<CanonicalJsonObject>> {
        let Some(stored) = self.event(event_id).await? else {
            return Ok(None);
        };
        if stored.rejected.is_some() {
            return Ok(None);
        }
        let mut raw = parse_raw(&stored.raw)?;
        if let Some(redactor_id) = self.redacted_by(event_id).await? {
            if let Some(redactor) = self.event(&redactor_id).await? {
                raw = validation::redact(&raw, version)
                    .map_err(|e| StoreError::Engine(format!("redact: {e}")))?;
                let because = parse_raw(&redactor.raw)?;
                let unsigned = match raw.get_mut("unsigned") {
                    Some(CanonicalJsonValue::Object(o)) => o,
                    _ => {
                        raw.insert(
                            "unsigned".into(),
                            CanonicalJsonValue::Object(CanonicalJsonObject::new()),
                        );
                        match raw.get_mut("unsigned") {
                            Some(CanonicalJsonValue::Object(o)) => o,
                            _ => unreachable!("just inserted"),
                        }
                    }
                };
                unsigned.insert(
                    "redacted_because".into(),
                    CanonicalJsonValue::Object(because),
                );
            }
        }
        Ok(Some(raw))
    }
}

fn parse_raw(raw: &[u8]) -> StoreResult<CanonicalJsonObject> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| StoreError::Engine(format!("event json: {e}")))?;
    match CanonicalJsonValue::try_from(value) {
        Ok(CanonicalJsonValue::Object(o)) => Ok(o),
        Ok(_) => Err(StoreError::Engine("stored event not an object".into())),
        Err(e) => Err(StoreError::Engine(format!("stored event: {e}"))),
    }
}
