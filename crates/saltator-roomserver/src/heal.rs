//! Inbound-PDU healing: when an event arrives citing prev/auth events we
//! don't hold, fetch what's missing from the origin, retry, and settle
//! permanent holes as rejections. The room server owns the *policy* —
//! what to fetch when, how retries bound, when a hole becomes a
//! rejection — and stays free of I/O: transport is injected through
//! [`EventFetcher`], implemented by the federation layer over its HTTP
//! client (and by in-process mocks in tests).

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use crate::{Outcome, RoomError, RoomServer};

type Result<T> = std::result::Result<T, RoomError>;

/// Delivery-side fetch budget per healing pass: bounds the ancestor walk
/// (a cycle or an uncooperative origin just exhausts it) and the
/// `/get_missing_events` request limit.
const GAP_FILL_LIMIT: usize = 50;

/// Transport for fetching missing events from a remote origin. Pure
/// transport: implementations translate these calls to federation HTTP
/// (percent-encoding, response envelopes) and manage key trust; the
/// healing sequences live in [`RoomServer`].
pub trait EventFetcher: Send + Sync {
    /// `POST /get_missing_events`: the timeline events between
    /// `earliest` (our extremities) and `latest` (the arriving PDU),
    /// oldest first.
    fn get_missing_events(
        &self,
        origin: &str,
        room_id: &str,
        earliest: Vec<String>,
        latest: &str,
        limit: usize,
    ) -> impl std::future::Future<Output = std::result::Result<Vec<CanonicalJsonObject>, String>> + Send;

    /// `GET /state_ids?event_id=`: the state of the room *before* the
    /// event, as `(pdu_ids, auth_chain_ids)`.
    fn state_ids(
        &self,
        origin: &str,
        room_id: &str,
        event_id: &str,
    ) -> impl std::future::Future<Output = std::result::Result<(Vec<String>, Vec<String>), String>> + Send;

    /// `GET /state?event_id=`: the whole-state legacy variant, as
    /// `(pdus, auth_chain)`.
    fn state(
        &self,
        origin: &str,
        room_id: &str,
        event_id: &str,
    ) -> impl std::future::Future<
        Output = std::result::Result<(Vec<CanonicalJsonObject>, Vec<CanonicalJsonObject>), String>,
    > + Send;

    /// `GET /event/{id}`: one event by ID; `Ok(None)` when the origin
    /// won't serve it (the deliberate 404 healing must tolerate).
    fn event(
        &self,
        origin: &str,
        event_id: &str,
    ) -> impl std::future::Future<Output = std::result::Result<Option<CanonicalJsonObject>, String>> + Send;

    /// Load `origin`'s signing keys into the room server's trusted set so
    /// fetched events verify. Best-effort.
    fn trust_origin_keys(&self, origin: &str) -> impl std::future::Future<Output = ()> + Send;

    /// Trust the signing keys of every server that authored one of
    /// `events` (a snapshot spans many origins). Best-effort.
    fn trust_event_servers(
        &self,
        events: &[CanonicalJsonObject],
    ) -> impl std::future::Future<Output = ()> + Send;
}

impl RoomServer {
    /// [`Self::ingest_pdu`] plus healing: on missing *prevs*, walk the
    /// timeline gap back from the PDU (`/get_missing_events`, anchoring
    /// on a state snapshot when the origin truncates); on missing *auth*
    /// events, fetch the cited events directly as outliers (`/event` —
    /// never the timeline walk, which Complement's
    /// RejectsEventsWithRejectedAuthEvents forbids for auth-only misses);
    /// retry once per flavor; settle a still-unfetchable auth chain as a
    /// stored rejection so descendants resolve instead of erroring.
    ///
    /// Terminal errors surface as [`RoomError::MissingEvents`] /
    /// [`RoomError::MissingAuthEvents`] only after healing has been
    /// tried and failed.
    pub async fn ingest_pdu_healing<F: EventFetcher>(
        &self,
        fetcher: &F,
        origin: &str,
        raw: CanonicalJsonObject,
    ) -> Result<Outcome> {
        let mut tried_gap = false;
        let mut tried_auth = false;
        loop {
            return match self.ingest_pdu(raw.clone()).await {
                Err(RoomError::MissingEvents(missing)) if !tried_gap => {
                    tried_gap = true;
                    // Prev gap: fetch the events between what we have and
                    // this PDU, then retry. `/get_missing_events` walks
                    // back from this PDU, which only works once the origin
                    // has stored it — not the case for an invite
                    // mid-`/invite` handshake (the origin ingests it only
                    // after we co-sign), so fall back to fetching the
                    // named missing events directly via `/event`.
                    if self.heal_gap(fetcher, origin, &raw).await
                        || self
                            .fetch_missing_by_id(fetcher, origin, missing.clone())
                            .await
                    {
                        continue;
                    }
                    Err(RoomError::MissingEvents(missing))
                }
                Err(RoomError::MissingAuthEvents(missing)) if !tried_auth => {
                    tried_auth = true;
                    // Auth-only miss (prevs all resolve): outliers to
                    // fetch directly. Whether or not the fetch produced
                    // anything, retry: the arm below settles a
                    // still-unfetchable chain.
                    self.fetch_missing_by_id(fetcher, origin, missing).await;
                    continue;
                }
                Err(RoomError::MissingAuthEvents(_)) => {
                    // Fetch already tried: the auth chain is permanently
                    // unverifiable, so the event is stored rejected
                    // (Synapse parity — TestCorruptedAuthChain requires
                    // the transaction to carry no per-PDU error).
                    self.ingest_pdu_rejecting_missing_auth(raw).await
                }
                other => other,
            };
        }
    }

    /// Fetch the events between our known state and `pdu` from `origin`
    /// via the fetcher's timeline walk, and ingest them (oldest first).
    /// Returns whether any events were ingested (worth a retry).
    /// Best-effort: an unknown room or a failed fetch yields `false`.
    async fn heal_gap<F: EventFetcher>(
        &self,
        fetcher: &F,
        origin: &str,
        pdu: &CanonicalJsonObject,
    ) -> bool {
        let Some(pdu_id) = self.pdu_event_id(pdu) else {
            return false;
        };
        let Some(room_id) = pdu.get("room_id").and_then(|v| v.as_str()) else {
            return false;
        };
        // We must know the room to fill a gap in it (a wholly-unknown
        // room needs a join, not backfill).
        let earliest = match self.room_extremities(room_id) {
            Ok(e) if !e.is_empty() => e,
            _ => return false,
        };

        // Trust the origin's keys so the fetched events verify.
        fetcher.trust_origin_keys(origin).await;

        let chain = match fetcher
            .get_missing_events(origin, room_id, earliest, pdu_id.as_str(), GAP_FILL_LIMIT)
            .await
        {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(error = %e, room_id, "gap fill: get_missing_events failed");
                return false;
            }
        };

        // Ingest oldest-first (the order the endpoint returns them).
        let mut ingested = 0usize;
        let mut still_missing = false;
        for obj in &chain {
            match self.ingest_pdu(obj.clone()).await {
                Ok(Outcome::Accepted { .. }) | Ok(Outcome::Duplicate { .. }) => ingested += 1,
                Err(RoomError::MissingEvents(_) | RoomError::MissingAuthEvents(_)) => {
                    still_missing = true
                }
                _ => {}
            }
        }
        if !still_missing {
            return ingested > 0;
        }

        // The origin truncated the response: the recovered events hang
        // off ancestors it did not return, so the pipeline cannot connect
        // them. Anchor them on a state snapshot at the chain's oldest
        // event instead and leave a marked gap (the sync `limited`
        // contract); the missing span joins the backfill frontier.
        let Some(anchor) = chain.first().and_then(|e| self.pdu_event_id(e)) else {
            return ingested > 0;
        };
        // Prefer `/state_ids` at the *prev* of the chain's oldest event
        // (the snapshot the chain then applies on top of), resolving
        // unknown IDs via `/event` and tolerating individual failures —
        // Synapse's healing sequence, and the only one Complement's
        // TestCorruptedAuthChain serves. Fall back to a whole-state
        // `/state` fetch at the oldest event itself.
        let anchor_prev = chain
            .first()
            .and_then(|e| e.get("prev_events"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let mut chain = chain;
        let mut snapshot = match &anchor_prev {
            Some(prev) => {
                self.fetch_state_by_ids(fetcher, origin, room_id, prev)
                    .await
            }
            None => None,
        };
        // `/state_ids` describes the state *before* `anchor_prev`, so
        // that event itself lands in neither the snapshot nor the chain —
        // yet the chain's oldest event cites it (prev and usually auth),
        // and leaving the one-event hole fails every later resolution
        // that walks through it (MSC4297's partial-sync tests). Synapse
        // fetches the breach event and inserts it as an outlier; mirror
        // that by prepending it to the chain, verified like everything
        // else we import.
        if snapshot.is_some() {
            if let Some(prev) = anchor_prev
                .as_deref()
                .filter(|p| !matches!(self.store().event(p), Ok(Some(_))))
            {
                match fetcher.event(origin, prev).await {
                    Ok(Some(obj)) => {
                        fetcher
                            .trust_event_servers(std::slice::from_ref(&obj))
                            .await;
                        if self.verify_pdu(room_id, &obj) {
                            chain.insert(0, obj);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, event_id = %prev, "gap anchor: breach-event fetch failed; leaving a hole");
                    }
                }
            }
        }
        if snapshot.is_none() {
            snapshot = match fetcher.state(origin, room_id, anchor.as_str()).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, room_id, "gap anchor: /state fetch failed");
                    return ingested > 0;
                }
            };
        }
        let (state_events, auth_chain) = snapshot.expect("set above");
        if state_events.is_empty() {
            return ingested > 0;
        }
        // The snapshot is imported wholesale, so a lying peer could
        // otherwise inject forged room state (fake power levels /
        // memberships) that we'd serve as authentic. Verify every event's
        // signature first, trusting the keys of each authoring server; if
        // anything fails to verify, abandon the gap-fill (the gap simply
        // stays, flagged limited in sync) rather than trust unverified
        // state.
        let all_events: Vec<CanonicalJsonObject> = state_events
            .iter()
            .chain(auth_chain.iter())
            .cloned()
            .collect();
        fetcher.trust_event_servers(&all_events).await;
        if !all_events.iter().all(|ev| self.verify_pdu(room_id, ev)) {
            tracing::warn!(
                room_id,
                "gap anchor: state snapshot failed signature verification; not importing"
            );
            return ingested > 0;
        }
        match self
            .import_segment(room_id, state_events, auth_chain, chain)
            .await
        {
            Ok(appended) => {
                tracing::info!(room_id, appended, "gap anchored on fetched state");
                appended > 0 || ingested > 0
            }
            Err(e) => {
                tracing::warn!(error = %e, room_id, "gap anchor: segment import failed");
                ingested > 0
            }
        }
    }

    /// Fetch a state snapshot as ID lists and resolve each ID to an event
    /// — from our store when we already hold it, else via the fetcher.
    /// Individual fetch failures leave a hole rather than sinking the
    /// snapshot: the auth information that *is* reachable still gets
    /// persisted (TestCorruptedAuthChain deliberately 404s one auth
    /// ancestor). `None` when the `/state_ids` request itself fails or
    /// yields no state.
    async fn fetch_state_by_ids<F: EventFetcher>(
        &self,
        fetcher: &F,
        origin: &str,
        room_id: &str,
        event_id: &str,
    ) -> Option<(Vec<CanonicalJsonObject>, Vec<CanonicalJsonObject>)> {
        let (pdu_ids, auth_chain_ids) = match fetcher.state_ids(origin, room_id, event_id).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::debug!(error = %e, room_id, "gap anchor: /state_ids fetch failed");
                return None;
            }
        };
        if pdu_ids.is_empty() {
            return None;
        }
        let resolve = |ids: Vec<String>| async move {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                if let Ok(Some(stored)) = self.store().event(&id) {
                    if let Ok(CanonicalJsonValue::Object(obj)) = serde_json::from_slice::<
                        serde_json::Value,
                    >(&stored.raw)
                    .map_err(|e| e.to_string())
                    .and_then(|v| CanonicalJsonValue::try_from(v).map_err(|e| e.to_string()))
                    {
                        out.push(obj);
                        continue;
                    }
                }
                match fetcher.event(origin, &id).await {
                    Ok(Some(obj)) => out.push(obj),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(error = %e, event_id = %id, "gap anchor: /event fetch failed; leaving a hole");
                    }
                }
            }
            out
        };
        let state_events = resolve(pdu_ids).await;
        let auth_chain = resolve(auth_chain_ids).await;
        if state_events.is_empty() {
            return None;
        }
        Some((state_events, auth_chain))
    }

    /// Fetch specifically-named missing events from `origin` by ID and
    /// ingest them, walking further missing references up to
    /// [`GAP_FILL_LIMIT`] fetches. This covers the case the timeline walk
    /// structurally cannot: a PDU handed to us before the origin has
    /// stored it (an invite mid-`/invite` handshake), where the origin
    /// cannot walk back from the PDU but can serve its prev/auth events
    /// by ID. Returns whether anything was ingested (worth a retry).
    async fn fetch_missing_by_id<F: EventFetcher>(
        &self,
        fetcher: &F,
        origin: &str,
        missing: Vec<String>,
    ) -> bool {
        fetcher.trust_origin_keys(origin).await;

        let mut ingested = false;
        let mut fetches = 0usize;
        // Depth-first: an event whose own prevs are missing goes back on
        // the queue behind them, so ancestors ingest first.
        let mut queue = missing;
        let mut retried: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Some(id) = queue.pop() {
            if fetches >= GAP_FILL_LIMIT {
                break;
            }
            fetches += 1;
            let obj = match fetcher.event(origin, &id).await {
                Ok(Some(o)) => o,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, event_id = %id, "gap fill: /event fetch failed");
                    continue;
                }
            };
            match self.ingest_pdu(obj.clone()).await {
                // A *rejected* ingest is still progress: the event is
                // stored and may satisfy someone's prev/auth reference (a
                // chain of rejected events in front of a valid one must
                // not strand the valid one —
                // RejectsEventsWithRejectedAuthEvents' sentinel).
                Ok(_) => ingested = true,
                Err(RoomError::MissingEvents(more) | RoomError::MissingAuthEvents(more))
                    if retried.insert(id.clone()) =>
                {
                    // Ancestors first, then this event again — once.
                    queue.push(id);
                    queue.extend(more);
                }
                // Second attempt and its auth ancestors are still absent:
                // they are unfetchable (the walk above already tried), so
                // store this event rejected — the settled rejection is
                // what lets descendants citing it resolve (as rejected)
                // instead of erroring (TestCorruptedAuthChain's 404'd
                // ancestor).
                Err(RoomError::MissingAuthEvents(_))
                    if self.ingest_pdu_rejecting_missing_auth(obj).await.is_ok() =>
                {
                    ingested = true;
                }
                _ => {}
            }
        }
        ingested
    }
}
