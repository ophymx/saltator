//! State resolution v2 (rooms v2–v11) and v2.1 (rooms v12+), per the
//! room-version specs at Matrix v1.19 (spec.md §5.2 step 4).
//!
//! v2.1 differs from v2 in exactly two ways, both gated by
//! [`StateResVersion`]: the iterative auth checks start from an *empty*
//! state map instead of the unconflicted map, and the full conflicted set
//! additionally includes the *conflicted state subgraph*.
//!
//! Pure: the caller supplies every event through `fetch`. Events rejected
//! for failing auth against their own auth chain must not be returned by
//! `fetch` — per the spec they never participate in resolution. (Events
//! rejected only against the state at the event DO participate; return
//! them normally.) All containers are ordered, so resolution is fully
//! deterministic.

use std::collections::{BTreeMap, BTreeSet};

use ruma::{EventId, OwnedEventId, OwnedUserId, UserId};

use crate::auth::{self, StateView};
use crate::event::Event;
use crate::power_levels::PowerLevel;
use crate::room_version::{RoomVersion, StateResVersion};

/// A state map key: `(event type, state key)`.
pub type Key = (String, String);
/// A state snapshot as resolved ids.
pub type StateIds = BTreeMap<Key, OwnedEventId>;

#[derive(Debug, thiserror::Error)]
pub enum StateResError {
    #[error("event {0} required for resolution but not available")]
    MissingEvent(OwnedEventId),
    #[error("no m.room.create event reachable from the state sets")]
    MissingCreate,
}

/// Resolve a set of conflicting state snapshots into one.
///
/// `state_sets` are the states after each fork (e.g. `S'(E_i)` for the
/// `prev_events` of a new event). `fetch` must return every event named in
/// the sets and their full auth chains.
pub fn resolve<E, F>(
    version: RoomVersion,
    state_sets: &[StateIds],
    fetch: &F,
) -> Result<StateIds, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    if state_sets.is_empty() {
        return Ok(StateIds::new());
    }

    // Definitions: unconflicted state map / conflicted state set.
    let (unconflicted, conflicted) = partition(state_sets);
    if conflicted.is_empty() {
        return Ok(unconflicted);
    }

    // Auth difference: ∪ C_i − ∩ C_i over the sets' full auth chains.
    let mut chains: Vec<BTreeSet<OwnedEventId>> = Vec::with_capacity(state_sets.len());
    let mut chain_cache: BTreeMap<OwnedEventId, BTreeSet<OwnedEventId>> = BTreeMap::new();
    for set in state_sets {
        let mut chain = BTreeSet::new();
        for id in set.values() {
            chain.extend(auth_chain(id, fetch, &mut chain_cache)?);
        }
        chains.push(chain);
    }
    let union: BTreeSet<_> = chains.iter().flatten().cloned().collect();
    let auth_difference: BTreeSet<OwnedEventId> = union
        .into_iter()
        .filter(|id| !chains.iter().all(|c| c.contains(id)))
        .collect();

    // Full conflicted set: conflicted ∪ auth difference (v2), additionally
    // ∪ conflicted state subgraph (v2.1).
    let mut full_conflicted: BTreeSet<OwnedEventId> = conflicted.clone();
    full_conflicted.extend(auth_difference);
    if version.state_res() == StateResVersion::V2_1 {
        full_conflicted.extend(conflicted_subgraph(&conflicted, fetch)?);
    }

    // The create event anchors creator lookups for the power ordering.
    let create_key = ("m.room.create".to_owned(), String::new());
    let create_id = unconflicted
        .get(&create_key)
        .or_else(|| state_sets.iter().find_map(|s| s.get(&create_key)))
        .ok_or(StateResError::MissingCreate)?;
    let create = fetch(create_id).ok_or_else(|| StateResError::MissingEvent(create_id.clone()))?;
    let creators = crate::power_levels::creators(version, &create);

    // Step 1: X = power events in the full conflicted set, plus their
    // auth-chain events inside it, in reverse topological power ordering.
    let mut power_set: BTreeSet<OwnedEventId> = BTreeSet::new();
    for id in &full_conflicted {
        let event = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        if is_power_event(&event) {
            power_set.insert(id.clone());
            for a in auth_chain(id, fetch, &mut chain_cache)? {
                if full_conflicted.contains(&a) {
                    power_set.insert(a);
                }
            }
        }
    }
    let sorted_power =
        reverse_topological_power_order(version, &power_set, fetch, &creators, &mut chain_cache)?;

    // Step 2: iterative auth checks over the power events. v2 starts from
    // the unconflicted map; v2.1 from an empty map.
    let initial = match version.state_res() {
        StateResVersion::V2 => unconflicted.clone(),
        StateResVersion::V2_1 => StateIds::new(),
    };
    let partial = iterative_auth_checks(version, &sorted_power, initial, fetch)?;

    // Step 3: mainline ordering of the remaining events, based on the
    // power-levels event in the partially resolved state.
    let remaining: Vec<OwnedEventId> = full_conflicted
        .iter()
        .filter(|id| !power_set.contains(*id))
        .cloned()
        .collect();
    let pl_key = ("m.room.power_levels".to_owned(), String::new());
    let mainline = build_mainline(partial.get(&pl_key), fetch)?;
    let mut ordered: Vec<(usize, u64, OwnedEventId)> = Vec::with_capacity(remaining.len());
    let mut position_cache: BTreeMap<OwnedEventId, usize> = BTreeMap::new();
    for id in remaining {
        let event = fetch(&id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        let pos = mainline_position(&event, &mainline, fetch, &mut position_cache)?;
        ordered.push((pos, u64::from(event.origin_server_ts().0), id));
    }
    // x < y if x's mainline position is GREATER; then smaller ts; then
    // smaller event id.
    ordered.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let sorted_remaining: Vec<OwnedEventId> = ordered.into_iter().map(|(_, _, id)| id).collect();

    // Step 4: iterative auth checks over the remainder.
    let mut resolved = iterative_auth_checks(version, &sorted_remaining, partial, fetch)?;

    // Step 5: the unconflicted state map always wins.
    for (k, v) in unconflicted {
        resolved.insert(k, v);
    }
    Ok(resolved)
}

/// Split state sets into the unconflicted map (same value in *every* set)
/// and the conflicted set (all other values, including keys missing from
/// some sets).
fn partition(state_sets: &[StateIds]) -> (StateIds, BTreeSet<OwnedEventId>) {
    let mut keys: BTreeSet<&Key> = BTreeSet::new();
    for set in state_sets {
        keys.extend(set.keys());
    }

    let mut unconflicted = StateIds::new();
    let mut conflicted = BTreeSet::new();
    for key in keys {
        let first = state_sets[0].get(key);
        if let (Some(value), true) = (first, state_sets.iter().all(|s| s.get(key) == first)) {
            unconflicted.insert(key.clone(), value.clone());
        } else {
            for set in state_sets {
                if let Some(id) = set.get(key) {
                    conflicted.insert(id.clone());
                }
            }
        }
    }
    (unconflicted, conflicted)
}

/// The auth chain of an event: its auth events, theirs, and so on — not
/// including the event itself.
fn auth_chain<E, F>(
    id: &EventId,
    fetch: &F,
    cache: &mut BTreeMap<OwnedEventId, BTreeSet<OwnedEventId>>,
) -> Result<BTreeSet<OwnedEventId>, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    if let Some(chain) = cache.get(id) {
        return Ok(chain.clone());
    }
    let event = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.to_owned()))?;
    let mut chain = BTreeSet::new();
    for a in event.auth_events() {
        if chain.insert(a.clone()) {
            chain.extend(auth_chain(a, fetch, cache)?);
        }
    }
    cache.insert(id.to_owned(), chain.clone());
    Ok(chain)
}

/// v2.1: the conflicted state subgraph — every event lying on an
/// `auth_events` path between two events of the conflicted state set
/// (endpoints included).
fn conflicted_subgraph<E, F>(
    conflicted: &BTreeSet<OwnedEventId>,
    fetch: &F,
) -> Result<BTreeSet<OwnedEventId>, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    // Forward-reachable set from the conflicted events (following
    // auth_events edges), with each node's outgoing edges.
    let mut edges: BTreeMap<OwnedEventId, Vec<OwnedEventId>> = BTreeMap::new();
    let mut stack: Vec<OwnedEventId> = conflicted.iter().cloned().collect();
    while let Some(id) = stack.pop() {
        if edges.contains_key(&id) {
            continue;
        }
        let event = fetch(&id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        let auth: Vec<OwnedEventId> = event.auth_events().to_vec();
        stack.extend(auth.iter().cloned());
        edges.insert(id, auth);
    }

    // reaches[n]: n has a path (length ≥ 0 for conflicted nodes) to a
    // conflicted event. Process in reverse topological order by iterating
    // until fixpoint (the graph is small and acyclic).
    let mut reaches: BTreeMap<&OwnedEventId, bool> =
        edges.keys().map(|k| (k, conflicted.contains(k))).collect();
    loop {
        let mut changed = false;
        for (node, auth) in &edges {
            if !reaches[node]
                && auth
                    .iter()
                    .any(|a| reaches.get(a).copied().unwrap_or(false))
            {
                reaches.insert(node, true);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // A node is in the subgraph if it is forward-reachable from a
    // conflicted event (all of `edges` is, by construction) AND it can
    // reach a conflicted event through its own auth edges — i.e. it is an
    // interior node or endpoint of a conflicted→conflicted path.
    Ok(edges
        .keys()
        .filter(|id| {
            conflicted.contains(*id)
                || edges[*id]
                    .iter()
                    .any(|a| reaches.get(a).copied().unwrap_or(false))
        })
        .cloned()
        .collect())
}

/// A *power event*: power_levels, join_rules, or a kick/ban.
fn is_power_event<E: Event>(event: &E) -> bool {
    match event.event_type() {
        "m.room.power_levels" | "m.room.join_rules" => event.state_key() == Some(""),
        "m.room.member" => {
            let membership = match event.content().get("membership") {
                Some(ruma::CanonicalJsonValue::String(s)) => s.as_str(),
                _ => return false,
            };
            matches!(membership, "leave" | "ban")
                && event.state_key() != Some(event.sender().as_str())
        }
        _ => false,
    }
}

/// The sender's power level "when looking at their respective auth_events":
/// from the power-levels event among the event's own auth events, with
/// creator fallbacks.
fn sender_power_at<E, F>(
    version: RoomVersion,
    event: &E,
    creators: &BTreeSet<OwnedUserId>,
    fetch: &F,
) -> Result<PowerLevel, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    if version.privileged_creators() && creators.contains(event.sender()) {
        return Ok(PowerLevel::Infinite);
    }
    for id in event.auth_events() {
        let auth = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        if auth.event_type() == "m.room.power_levels" && auth.state_key() == Some("") {
            return Ok(PowerLevel::Int(user_level_in(
                auth.content(),
                event.sender(),
            )));
        }
    }
    // No power-levels event in the auth chain: creators are at 100
    // (pre-v12), everyone else at 0.
    if creators.contains(event.sender()) {
        Ok(PowerLevel::Int(100))
    } else {
        Ok(PowerLevel::Int(0))
    }
}

fn user_level_in(pl_content: &ruma::CanonicalJsonObject, user: &UserId) -> i64 {
    use ruma::CanonicalJsonValue as V;
    let users = match pl_content.get("users") {
        Some(V::Object(o)) => o,
        _ => return default_user_level(pl_content),
    };
    match users.get(user.as_str()) {
        Some(V::Integer(i)) => i64::from(*i),
        _ => default_user_level(pl_content),
    }
}

fn default_user_level(pl_content: &ruma::CanonicalJsonObject) -> i64 {
    match pl_content.get("users_default") {
        Some(ruma::CanonicalJsonValue::Integer(i)) => i64::from(*i),
        _ => 0,
    }
}

/// Kahn's algorithm, selecting at each step the smallest candidate under
/// the power ordering: greater sender power first, then smaller
/// origin_server_ts, then smaller event id.
fn reverse_topological_power_order<E, F>(
    version: RoomVersion,
    events: &BTreeSet<OwnedEventId>,
    fetch: &F,
    creators: &BTreeSet<OwnedUserId>,
    chain_cache: &mut BTreeMap<OwnedEventId, BTreeSet<OwnedEventId>>,
) -> Result<Vec<OwnedEventId>, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    // Sort key per event.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct SortKey(std::cmp::Reverse<PowerLevel>, u64, OwnedEventId);

    let mut keys: BTreeMap<OwnedEventId, SortKey> = BTreeMap::new();
    // dependencies[e] = auth ancestors of e within the set (must sort
    // before e); dependents is the reverse relation.
    let mut pending: BTreeMap<OwnedEventId, BTreeSet<OwnedEventId>> = BTreeMap::new();
    let mut dependents: BTreeMap<OwnedEventId, Vec<OwnedEventId>> = BTreeMap::new();

    for id in events {
        let event = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        let power = sender_power_at(version, &event, creators, fetch)?;
        keys.insert(
            id.clone(),
            SortKey(
                std::cmp::Reverse(power),
                u64::from(event.origin_server_ts().0),
                id.clone(),
            ),
        );
        let deps: BTreeSet<OwnedEventId> = auth_chain(id, fetch, chain_cache)?
            .intersection(events)
            .cloned()
            .collect();
        for d in &deps {
            dependents.entry(d.clone()).or_default().push(id.clone());
        }
        pending.insert(id.clone(), deps);
    }

    let mut ready: BTreeSet<(&SortKey, OwnedEventId)> = pending
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(id, _)| (&keys[id], id.clone()))
        .collect();
    let mut out = Vec::with_capacity(events.len());
    while let Some((_, id)) = ready.pop_first() {
        out.push(id.clone());
        for dependent in dependents.remove(&id).unwrap_or_default() {
            let deps = pending.get_mut(&dependent).expect("known event");
            deps.remove(&id);
            if deps.is_empty() {
                ready.insert((&keys[&dependent], dependent));
            }
        }
    }
    debug_assert_eq!(out.len(), events.len(), "auth DAG must be acyclic");
    Ok(out)
}

/// State view backing the iterative auth checks: the working map, with
/// per-event fallback to the event's own auth events.
struct EffectiveState<E> {
    events: BTreeMap<Key, E>,
}

impl<E: Event> StateView<E> for EffectiveState<E> {
    fn get(&self, event_type: &str, state_key: &str) -> Option<&E> {
        self.events
            .get(&(event_type.to_owned(), state_key.to_owned()))
    }
}

/// The iterative auth checks algorithm: apply each event to the working
/// state if the auth rules allow it under that state; ignore it otherwise.
fn iterative_auth_checks<E, F>(
    version: RoomVersion,
    order: &[OwnedEventId],
    initial: StateIds,
    fetch: &F,
) -> Result<StateIds, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    let mut state = initial;
    for id in order {
        let event = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;

        // Keys the auth rules may consult: the selection set, plus the
        // create event (needed by the v12 room_id rule and m.federate).
        let mut needed = auth::auth_types_for_event(
            version,
            event.event_type(),
            event.sender(),
            event.state_key(),
            event.content(),
        );
        needed.insert(("m.room.create".to_owned(), String::new()));

        let mut effective = EffectiveState {
            events: BTreeMap::new(),
        };
        for key in needed {
            if let Some(existing) = state.get(&key) {
                let e =
                    fetch(existing).ok_or_else(|| StateResError::MissingEvent(existing.clone()))?;
                effective.events.insert(key, e);
                continue;
            }
            // v12+: the create event is never in auth_events — its ID is
            // the room_id with the sigil swapped.
            if key.0 == "m.room.create" && version.room_id_is_create_event_id() {
                if let Some(room_id) = event.room_id() {
                    let create_id = format!("${}", &room_id.as_str()[1..]);
                    if let Ok(create_id) = OwnedEventId::try_from(create_id) {
                        if let Some(create) = fetch(&create_id) {
                            effective.events.insert(key, create);
                        }
                    }
                }
                continue;
            }
            // Fall back to the event's own auth events (never rejected —
            // `fetch` does not return auth-chain-rejected events).
            for a in event.auth_events() {
                if let Some(auth_event) = fetch(a) {
                    let a_key = (
                        auth_event.event_type().to_owned(),
                        auth_event.state_key().unwrap_or_default().to_owned(),
                    );
                    if a_key == key {
                        effective.events.insert(a_key, auth_event);
                        break;
                    }
                }
            }
        }

        if auth::check_state_dependent(version, &event, &effective).is_ok() {
            let key = (
                event.event_type().to_owned(),
                event.state_key().unwrap_or_default().to_owned(),
            );
            state.insert(key, id.clone());
        }
    }
    Ok(state)
}

/// The mainline of a power-levels event: `[P0, P1, …]` where each `P_{i+1}`
/// is the power-levels event in `P_i`'s auth events.
fn build_mainline<E, F>(
    start: Option<&OwnedEventId>,
    fetch: &F,
) -> Result<BTreeMap<OwnedEventId, usize>, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    let mut mainline = BTreeMap::new();
    let mut current = start.cloned();
    let mut index = 0;
    while let Some(id) = current {
        let event = fetch(&id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        mainline.insert(id, index);
        index += 1;
        current = pl_in_auth_events(&event, fetch)?;
    }
    Ok(mainline)
}

fn pl_in_auth_events<E, F>(event: &E, fetch: &F) -> Result<Option<OwnedEventId>, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    for id in event.auth_events() {
        let auth = fetch(id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
        if auth.event_type() == "m.room.power_levels" && auth.state_key() == Some("") {
            return Ok(Some(id.clone()));
        }
    }
    Ok(None)
}

/// The mainline position of an event: the index of the first mainline
/// event reachable through its power-levels auth chain, or `usize::MAX`.
fn mainline_position<E, F>(
    event: &E,
    mainline: &BTreeMap<OwnedEventId, usize>,
    fetch: &F,
    cache: &mut BTreeMap<OwnedEventId, usize>,
) -> Result<usize, StateResError>
where
    E: Event,
    F: Fn(&EventId) -> Option<E>,
{
    if let Some(&pos) = cache.get(event.event_id()) {
        return Ok(pos);
    }
    let mut current = pl_in_auth_events(event, fetch)?;
    let mut walked: Vec<OwnedEventId> = vec![event.event_id().to_owned()];
    let pos = loop {
        match current {
            None => break usize::MAX,
            Some(id) => {
                if let Some(&i) = mainline.get(&id) {
                    break i;
                }
                if let Some(&i) = cache.get(&id) {
                    break i;
                }
                let e = fetch(&id).ok_or_else(|| StateResError::MissingEvent(id.clone()))?;
                walked.push(id);
                current = pl_in_auth_events(&e, fetch)?;
            }
        }
    };
    for id in walked {
        cache.insert(id, pos);
    }
    Ok(pos)
}
