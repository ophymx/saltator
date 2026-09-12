//! Appservice transaction push (docs/design-appservices.md): tail the
//! room timeline and PUT every interesting event to each registered
//! appservice as `/_matrix/app/v1/transactions/{txnId}`.
//!
//! Ownership and durability follow federation delivery, not the push
//! gateway: an AS transaction is a promise ("what have I promised to
//! deliver to whom"), so progress lives in the fed-out shard
//! (`T_AS_CURSOR`, per appservice × room shard) and the single worker
//! runs wherever the fed-out shard leads, failing over with it. On
//! failure the cursor stays put and the appservice backs off — a bridge
//! restarting after an hour gets the hour, in order.
//!
//! Interest per event (Matrix v1.19 §AS API): the sender is the AS's
//! sender or in its `users` namespaces; a membership event's state_key
//! is; the room id is in `rooms`; one of the room's aliases is in
//! `aliases`; or a local joined member matches `users`. The member-list
//! and alias terms are cached per pass.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use saltator_appservice::{AppServiceClient, AppServiceRegistration};
use saltator_roomserver::SeqEntry;

use crate::{room_util, CsState};

/// Timeline rows scanned per iteration (events + receipts; only events
/// are pushed).
const SCAN_BATCH: usize = 256;
/// Events per transaction (Synapse's ceiling; large enough that a busy
/// bridge catches up quickly, small enough to bound request size).
const MAX_EVENTS_PER_TXN: usize = 100;
/// Idle wake-up, mirroring federation delivery: leadership changes have
/// no event, so the loop must poll its gate.
const IDLE_TICK: Duration = Duration::from_secs(1);
/// Per-appservice backoff bounds. Bridges go down for real stretches;
/// the cursor is durable, so patience costs nothing but latency.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Register metric descriptions — called once at startup from `main`,
/// never at a measurement site (the describe macros take the recorder
/// lock).
pub fn describe() {
    metrics::describe_counter!(
        "saltator_appservice_transactions_total",
        "Appservice transactions pushed, by appservice id and outcome (wire attempts: a retried transaction counts each attempt)"
    );
    metrics::describe_counter!(
        "saltator_appservice_events_pushed_total",
        "Events delivered to appservices, by appservice id (counted on accepted transactions only)"
    );
    metrics::describe_histogram!(
        "saltator_appservice_transaction_seconds",
        metrics::Unit::Seconds,
        "Round trip of one appservice transaction PUT"
    );
}

/// Spawn the push worker. `None` (no task) when nothing could ever be
/// delivered: no appservices with a `url`, or no fed-out shard to own
/// the cursors.
pub fn spawn_appservice_push(state: Arc<CsState>) -> Option<tokio::task::JoinHandle<()>> {
    if !state.appservices.services.iter().any(|a| a.url.is_some()) {
        return None;
    }
    if state.fedout.is_none() {
        tracing::warn!(
            "appservices with a url are registered but no fed-out shard is attached; event push disabled"
        );
        return None;
    }
    Some(tokio::spawn(async move {
        if let Err(e) = run(state).await {
            tracing::error!(error = %e, "appservice push stopped");
        }
    }))
}

async fn run(state: Arc<CsState>) -> Result<(), String> {
    let fedout = state.fedout.clone().expect("spawn checked fedout");
    let client = AppServiceClient::new();
    // In-memory by design, like federation's DeliveryBackoff: a failover
    // retries immediately once, then re-learns the backoff.
    let mut backoff: HashMap<String, (Instant, Duration)> = HashMap::new();
    let mut changes: Vec<_> = state.rooms.iter().map(|(_, s)| s.subscribe()).collect();

    loop {
        if fedout.shard_handle().is_leader() {
            for reg in &state.appservices.services {
                if reg.url.is_none() {
                    continue;
                }
                if let Some((until, _)) = backoff.get(&reg.id) {
                    if Instant::now() < *until {
                        continue;
                    }
                }
                // Per-shard cursors, one delivery sweep across all: the
                // first failed transaction backs the AS off as a whole
                // (its endpoint is down for every shard equally).
                let mut outcome = Ok(());
                for (idx, shard) in state.rooms.iter() {
                    outcome = deliver_to(&state, &fedout, &client, reg, idx, shard).await;
                    if outcome.is_err() {
                        break;
                    }
                }
                match outcome {
                    Ok(()) => {
                        backoff.remove(&reg.id);
                    }
                    Err(e) => {
                        let next = backoff
                            .get(&reg.id)
                            .map(|(_, d)| (*d * 2).min(BACKOFF_MAX))
                            .unwrap_or(BACKOFF_MIN);
                        tracing::warn!(id = %reg.id, error = %e, backoff_s = next.as_secs(),
                            "appservice transaction failed; backing off");
                        backoff.insert(reg.id.clone(), (Instant::now() + next, next));
                    }
                }
            }
        }
        let any_change =
            futures_util::future::select_all(changes.iter_mut().map(|rx| Box::pin(rx.recv())));
        tokio::select! {
            _ = tokio::time::sleep(IDLE_TICK) => {}
            _ = any_change => {}
        }
    }
}

/// Drain everything currently pending for one appservice. Returns at the
/// tip, or errs on the first failed transaction (the cursor then holds
/// the retry position).
#[allow(clippy::too_many_arguments)]
async fn deliver_to(
    state: &CsState,
    fedout: &saltator_fedout::FedOutServer,
    client: &AppServiceClient,
    reg: &Arc<AppServiceRegistration>,
    room_shard: u16,
    rooms: &Arc<saltator_roomserver::RoomServer>,
) -> Result<(), String> {
    let store = fedout.store();
    let mut cursor = match store
        .as_cursor(&reg.id, room_shard)
        .map_err(|e| e.to_string())?
    {
        Some(c) => c,
        None => {
            // First contact: seed at the current tip. History predating
            // the registration is not replayed at a bridge.
            let tip = rooms.shard_handle().seq().map_err(|e| e.to_string())?;
            fedout
                .advance_as_cursor(&reg.id, room_shard, tip)
                .await
                .map_err(|e| e.to_string())?;
            tip
        }
    };

    // Per-pass caches: whether a room interests this AS via its member
    // list, and the room→aliases reverse map (one alias-table scan,
    // built lazily on the first event that needs it).
    let mut member_interest: HashMap<String, bool> = HashMap::new();
    let mut room_aliases: Option<HashMap<String, Vec<String>>> = None;

    loop {
        let batch = rooms
            .store()
            .timeline(cursor, SCAN_BATCH)
            .await
            .map_err(|e| e.to_string())?;
        if batch.is_empty() {
            return Ok(());
        }
        let mut events: Vec<serde_json::Value> = Vec::new();
        let mut first = 0u64;
        let mut last = 0u64;
        let mut scanned_to = cursor;
        for (seq, entry) in &batch {
            scanned_to = *seq;
            let SeqEntry::Event { room_id, event_id } = entry else {
                continue;
            };
            // A membership event invalidates the member-list cache for
            // its room — the join that makes the AS interested must make
            // this very event interesting.
            let raw = match room_util::raw_event_shard(rooms, event_id).await {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(e) => return Err(e.message),
            };
            if raw_type(&raw) == Some("m.room.member") {
                member_interest.remove(room_id);
            }
            if !interested(
                state,
                reg,
                room_id,
                &raw,
                &mut member_interest,
                &mut room_aliases,
            )
            .await?
            {
                continue;
            }
            let meta = room_util::room_meta(&state.rooms, room_id)
                .await
                .map_err(|e| e.message)?;
            let version = room_util::room_version(&meta).map_err(|e| e.message)?;
            let sender = reg.sender_user(state.config.server_name.as_str());
            let Some(ev) =
                room_util::client_event(&state.rooms, version, room_id, event_id, &sender)
                    .await
                    .map_err(|e| e.message)?
            else {
                continue;
            };
            if events.is_empty() {
                first = *seq;
            }
            last = *seq;
            events.push(ev);
            if events.len() >= MAX_EVENTS_PER_TXN {
                break;
            }
        }

        if events.is_empty() {
            // A boring span still advances the cursor, or an idle server
            // would rescan it forever.
            fedout
                .advance_as_cursor(&reg.id, room_shard, scanned_to)
                .await
                .map_err(|e| e.to_string())?;
            cursor = scanned_to;
            continue;
        }

        // Deterministic from (cursor, timeline): a straight retry
        // recomputes the identical id and the AS dedupes on it. If the
        // batch composition shifts between attempts (events appended
        // past a short scan, interest-relevant state changed), the id
        // shifts with it — the residual corner is documented in
        // docs/design-appservices.md.
        let txn_id = format!("s{room_shard}_{first}_{last}_{}", events.len());
        let started = Instant::now();
        let outcome = client.push_transaction(reg, &txn_id, &events).await;
        metrics::histogram!("saltator_appservice_transaction_seconds", "appservice" => reg.id.clone())
            .record(started.elapsed().as_secs_f64());
        match outcome {
            Ok(()) => {
                metrics::counter!("saltator_appservice_transactions_total",
                    "appservice" => reg.id.clone(), "outcome" => "ok")
                .increment(1);
                metrics::counter!("saltator_appservice_events_pushed_total",
                    "appservice" => reg.id.clone())
                .increment(events.len() as u64);
                fedout
                    .advance_as_cursor(&reg.id, room_shard, scanned_to)
                    .await
                    .map_err(|e| e.to_string())?;
                cursor = scanned_to;
            }
            Err(e) => {
                metrics::counter!("saltator_appservice_transactions_total",
                    "appservice" => reg.id.clone(), "outcome" => "error")
                .increment(1);
                return Err(e.to_string());
            }
        }
    }
}

fn raw_type(raw: &ruma::CanonicalJsonObject) -> Option<&str> {
    match raw.get("type") {
        Some(ruma::CanonicalJsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn raw_str<'a>(raw: &'a ruma::CanonicalJsonObject, key: &str) -> Option<&'a str> {
    match raw.get(key) {
        Some(ruma::CanonicalJsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// The spec's interest predicate, cheap terms first.
async fn interested(
    state: &CsState,
    reg: &AppServiceRegistration,
    room_id: &str,
    raw: &ruma::CanonicalJsonObject,
    member_interest: &mut HashMap<String, bool>,
    room_aliases: &mut Option<HashMap<String, Vec<String>>>,
) -> Result<bool, String> {
    let server_name = state.config.server_name.as_str();
    if reg.is_interested_in_room_id(room_id) {
        return Ok(true);
    }
    if let Some(sender) = raw_str(raw, "sender") {
        if reg.is_interested_in_user(sender, server_name) {
            return Ok(true);
        }
    }
    if raw_type(raw) == Some("m.room.member") {
        if let Some(state_key) = raw_str(raw, "state_key") {
            if reg.is_interested_in_user(state_key, server_name) {
                return Ok(true);
            }
        }
    }
    if !reg.namespaces.aliases.is_empty() {
        let map = match room_aliases {
            Some(m) => m,
            None => {
                let mut m: HashMap<String, Vec<String>> = HashMap::new();
                for (alias, entry) in state.users.store().aliases().map_err(|e| e.to_string())? {
                    m.entry(entry.room_id).or_default().push(alias);
                }
                room_aliases.insert(m)
            }
        };
        if map
            .get(room_id)
            .is_some_and(|aliases| aliases.iter().any(|a| reg.is_interested_in_alias(a)))
        {
            return Ok(true);
        }
    }
    // Last resort: a local joined member in the `users` namespaces — or
    // the AS's own sender, which counts even with no namespaces at all
    // (is_interested_in_user covers both).
    if let Some(cached) = member_interest.get(room_id) {
        return Ok(*cached);
    }
    let members = room_util::joined_member_ids(&state.rooms, room_id)
        .await
        .map_err(|e| e.message)?;
    let local_suffix = format!(":{server_name}");
    let hit = members
        .iter()
        .any(|m| m.ends_with(&local_suffix) && reg.is_interested_in_user(m, server_name));
    member_interest.insert(room_id.to_owned(), hit);
    Ok(hit)
}
