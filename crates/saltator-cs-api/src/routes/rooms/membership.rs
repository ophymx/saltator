//! Membership: join/knock/leave/forget/invite/kick/ban, their
//! remote (federated) variants, and `joined_rooms`.

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Jb, Ra};
use crate::room_util::{accepted_event_id, current_state, raw_event};
use crate::CsState;
use axum::extract::{Path, State};
use ruma::api::client::knock::knock_room;
use ruma::api::client::membership::{
    ban_user, forget_room, invite_user, join_room_by_id, join_room_by_id_or_alias, joined_rooms,
    kick_user, leave_room, unban_user,
};
use ruma::{OwnedRoomId, RoomId, UserId};
use std::sync::Arc;

use super::*;

/// How long a restricted join waits for in-flight room state (e.g. a
/// power-levels grant crossing federation) before conceding that no local
/// member can authorise it and falling back to a remote join. Long enough
/// to cover a delivery retry cycle (backoff floor 500ms), short against
/// client join timeouts.
const RESTRICTED_AUTH_RECHECK: std::time::Duration = std::time::Duration::from_secs(1);

// -- membership ---------------------------------------------------------------

/// Shared body handling for the two join endpoints: `reason` is spec'd,
/// everything else rides along as custom member-event content. A room we
/// don't host is joined over federation.
/// Whether we can service a membership change from our own copy of the
/// room (vs. having to go through a resident over federation). Returns
/// `(hosted, meta_exists)`. A room we know (`meta_exists`) is only "hosted"
/// while we still participate — once every local user has left, our fork of
/// the DAG is stale and a rejoin/knock must go through a resident.
fn room_hosted_locally(state: &CsState, room_id: &RoomId) -> Result<(bool, bool)> {
    let meta_exists = state
        .rooms
        .for_room(room_id.as_str())
        .store()
        .meta(room_id.as_str())
        .map_err(internal)?
        .is_some();
    let hosted = meta_exists && {
        let our_name = state.config.server_name.as_str();
        let locally_joined = crate::room_util::joined_member_ids(&state.rooms, room_id.as_str())?
            .iter()
            .any(|u| u.ends_with(&format!(":{our_name}")));
        locally_joined || {
            let we_created = saltator_federation::resident_of_room(room_id.as_str()).as_deref()
                == Some(our_name);
            let no_remote_route = state
                .rooms
                .remote_servers_in_room(room_id.as_str(), our_name)
                .map(|s| s.is_empty())
                .unwrap_or(true);
            state.federation.is_none() || we_created || no_remote_route
        }
    };
    Ok((hosted, meta_exists))
}

async fn join_with_body(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    via: &[String],
    mut body: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    // Before anything else, including the remote handshake: an
    // administrator has closed this room.
    state.room_admin().ensure_joinable(room_id.as_str())?;
    let reason = body
        .remove("reason")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));
    body.remove("third_party_signed");

    // Local room: the normal pipeline. Knowing the room isn't enough —
    // once every local user has left, our fork of the DAG is stale (we
    // stopped receiving events), so a rejoin goes back through a resident
    // like a fresh remote join; the handshake re-imports current state and
    // seeds the backfill frontier with what we missed. Local-pipeline
    // rejoin remains for rooms we still participate in and rooms with no
    // other server to join through.
    let (hosted, meta_exists) = room_hosted_locally(state, room_id)?;
    if hosted {
        // A restricted / knock_restricted room needs an authorising local
        // user stamped on the join. If we hold the room but can't authorise
        // (no eligible local member, or we can't verify the allow
        // conditions), another resident might — fall back to a remote join.
        let mut verdict = state
            .rooms
            .restricted_join_authoriser(room_id, &auth.user_id)
            .map_err(internal)?;
        if matches!(verdict, saltator_roomserver::RestrictedAuth::CannotGrant) {
            // "No local member has invite power" is often only TRANSIENTLY
            // true mid-churn: the power-levels grant that empowers one may
            // be in flight from the room's origin (created milliseconds
            // ago on another server). Falling back to a remote join here
            // is not just slower — it changes semantics (the join gets
            // authorised by a remote user instead of the intended local
            // one). Wait briefly, re-evaluating as room state lands,
            // before conceding; a genuine CannotGrant pays this window
            // once and then fails over exactly as before.
            let mut changes = state.rooms.for_room(room_id.as_str()).subscribe();
            let deadline = tokio::time::Instant::now() + RESTRICTED_AUTH_RECHECK;
            loop {
                match tokio::time::timeout_at(deadline, changes.recv()).await {
                    Err(_) => break, // window closed; concede
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                    // A room-shard change (or a lagged stream — state moved
                    // even faster): re-evaluate.
                    Ok(_) => {
                        verdict = state
                            .rooms
                            .restricted_join_authoriser(room_id, &auth.user_id)
                            .map_err(internal)?;
                        if !matches!(verdict, saltator_roomserver::RestrictedAuth::CannotGrant) {
                            break;
                        }
                    }
                }
            }
        }
        match verdict {
            saltator_roomserver::RestrictedAuth::NotNeeded => {
                local_pipeline_join(state, auth, room_id, reason, body, None).await?;
            }
            saltator_roomserver::RestrictedAuth::Authorised(authoriser) => {
                local_pipeline_join(state, auth, room_id, reason, body, Some(authoriser)).await?;
            }
            saltator_roomserver::RestrictedAuth::FailsConditions => {
                return Err(ApiError::forbidden(
                    "You are not permitted to join this room",
                ));
            }
            saltator_roomserver::RestrictedAuth::CannotValidate
            | saltator_roomserver::RestrictedAuth::CannotGrant => {
                join_remote(state, auth, room_id, via).await?;
            }
        }
    } else {
        match join_remote(state, auth, room_id, via).await {
            Ok(()) => {}
            // No route to a resident (e.g. a v12 room we created whose
            // id names no server): rejoin our own copy rather than fail.
            Err(e) if meta_exists && e.status == axum::http::StatusCode::NOT_FOUND => {
                local_pipeline_join(state, auth, room_id, reason, body, None).await?;
            }
            Err(e) => return Err(e),
        }
    }

    // Joining an upgraded room carries the old room's push rules over.
    crate::routes::push::copy_rules_from_predecessor(state, &auth.user_id, room_id.as_str())
        .await?;

    // On-join device-list announce (spec "Device Management") — policy
    // and replay marking live in the e2ee service.
    state
        .e2ee()
        .announce_on_join(auth.user_id.as_str(), room_id.as_str());
    Ok(())
}

/// The local half of a join: no-op when already joined, else the normal
/// pipeline membership send.
async fn local_pipeline_join(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    reason: Option<String>,
    body: serde_json::Map<String, serde_json::Value>,
    authoriser: Option<ruma::OwnedUserId>,
) -> Result<()> {
    // Joining twice is a no-op: the existing membership event stands
    // (a fresh identical join would mint a new event ID).
    let current = current_state(&state.rooms, room_id.as_str())?;
    if crate::room_util::membership_in(
        &state.rooms,
        room_id.as_str(),
        &current,
        auth.user_id.as_str(),
    )? == "join"
    {
        return Ok(());
    }
    send_membership_with(
        state,
        room_id,
        &auth.user_id,
        &auth.user_id,
        "join",
        reason,
        body,
        authoriser.as_deref().map(|u| u.as_str()),
    )
    .await?;
    Ok(())
}

/// Join a room hosted on another server: run the make_join/send_join
/// handshake against a resident and import the returned state.
/// Event IDs referenced under an event's `auth_events` (v3+ list-of-strings).
fn auth_event_ids(ev: &ruma::CanonicalJsonObject) -> Vec<String> {
    match ev.get("auth_events") {
        Some(ruma::CanonicalJsonValue::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                ruma::CanonicalJsonValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The transitive `auth_events` closure of `join` over `events` — the set
/// that must verify for the join to be trustworthy. Events reachable only
/// from *other* returned events (not from the join) are not included, so an
/// unverifiable event dragged into the resident's auth chain by an unrelated
/// membership doesn't block the join.
fn join_auth_closure(
    join: &ruma::CanonicalJsonObject,
    events: &[ruma::CanonicalJsonObject],
    version: saltator_core::RoomVersion,
) -> std::collections::BTreeSet<String> {
    let mut auth_of: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for ev in events {
        if let Ok(id) = saltator_core::event::event_id(ev, version) {
            auth_of.insert(id.to_string(), auth_event_ids(ev));
        }
    }
    let mut closure = std::collections::BTreeSet::new();
    let mut stack = auth_event_ids(join);
    while let Some(id) = stack.pop() {
        if closure.insert(id.clone()) {
            if let Some(parents) = auth_of.get(&id) {
                stack.extend(parents.iter().cloned());
            }
        }
    }
    closure
}

async fn join_remote(state: &CsState, auth: &Auth, room_id: &RoomId, via: &[String]) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::not_found("Unknown room"));
    };
    // Candidate residents. When the client names *remote* servers
    // (`?server_name=` / `via`), those are the WHOLE list — Synapse only
    // ever augments with the inviter's domain, never the room-id server or
    // its own state, and TestRestrictedRoomsRemoteJoinFailOver depends on
    // that: a join routed `via=[hs2]` must fail outright when hs2 cannot
    // authorise it, not quietly fail over to a server the client never
    // named. A hint naming *us* is not a remote route (it means "your
    // call" — e.g. a local restricted join failing over to remote,
    // TestRestrictedRoomsRemoteJoinLocalUser routes `via=[hs1]` from an
    // hs1 user), so when no remote hint survives we fall back to the
    // server in the room id (pre-v12) and then any server in our
    // (possibly stale) copy.
    let our_name = state.config.server_name.as_str();
    let mut candidates: Vec<String> = Vec::new();
    let push = |server: String, candidates: &mut Vec<String>| {
        if server != our_name && !candidates.contains(&server) {
            candidates.push(server);
        }
    };
    for hint in via {
        push(hint.clone(), &mut candidates);
    }
    if candidates.is_empty() {
        if let Some(resident) = saltator_federation::resident_of_room(room_id.as_str()) {
            push(resident, &mut candidates);
        }
        if let Ok(servers) = state
            .rooms
            .remote_servers_in_room(room_id.as_str(), our_name)
        {
            for server in servers {
                push(server, &mut candidates);
            }
        }
    }
    if candidates.is_empty() {
        return Err(ApiError::not_found(
            "Cannot determine a server to join through",
        ));
    }

    let mut resp = None;
    let mut last_err = String::new();
    let mut forbidden: Option<String> = None;
    for destination in &candidates {
        match saltator_federation::join_remote_room(
            &fed.client,
            &fed.signer,
            destination,
            room_id.as_str(),
            auth.user_id.as_str(),
        )
        .await
        {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(e) => {
                // A 403 is the resident's definitive verdict (not invited to
                // a restricted/invite room, banned, …): propagate it rather
                // than falling through to another candidate — otherwise a
                // fake or unrelated server that 404s would mask the real
                // reason (Complement TestKnockingInMSC3787Room's federated
                // "join without invite should fail" wants the 403).
                if e.remote_status() == Some(403) {
                    forbidden = Some(e.to_string());
                    break;
                }
                last_err = e.to_string();
            }
        }
    }
    let Some(resp) = resp else {
        if let Some(reason) = forbidden {
            return Err(ApiError::forbidden(reason));
        }
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote join failed: {last_err}"),
        ));
    };

    // The resident's state dump is not trusted for authenticity. The events
    // that authorise *our* join — its transitive auth chain (create, power
    // levels, join rules, the sender's prior membership) — MUST verify, or a
    // lying resident could seed forged critical state (fake power levels,
    // memberships) that we'd serve as authentic. Other returned events (a
    // room name, an unrelated membership, an event pulled into the auth
    // chain only by something else) may legitimately be unverifiable —
    // signed by a key we can't fetch, say — and per the spec are dropped,
    // not grounds to refuse the join (Complement
    // TestJoinFederatedRoomWithUnverifiableEvents).
    let all_events: Vec<ruma::CanonicalJsonObject> = resp
        .state
        .iter()
        .chain(resp.auth_chain.iter())
        .cloned()
        .collect();
    saltator_federation::trust_event_servers(&fed.key_cache, &state.rooms, &all_events).await;

    let critical = join_auth_closure(&resp.event, &all_events, resp.room_version);
    for ev in &all_events {
        let id = saltator_core::event::event_id(ev, resp.room_version)
            .map(|i| i.to_string())
            .unwrap_or_default();
        if critical.contains(&id)
            && !state
                .rooms
                .for_room(room_id.as_str())
                .verify_pdu_at(resp.room_version, ev)
        {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "remote join returned auth-chain state that failed signature verification",
            ));
        }
    }
    // Keep the verifiable events; drop unverifiable non-critical ones.
    let kept_state: Vec<_> = resp
        .state
        .into_iter()
        .filter(|e| {
            state
                .rooms
                .for_room(room_id.as_str())
                .verify_pdu_at(resp.room_version, e)
        })
        .collect();
    let kept_auth: Vec<_> = resp
        .auth_chain
        .into_iter()
        .filter(|e| {
            state
                .rooms
                .for_room(room_id.as_str())
                .verify_pdu_at(resp.room_version, e)
        })
        .collect();

    let outcome = state
        .rooms
        .import_room(resp.room_version, resp.event, kept_state, kept_auth)
        .await
        .map_err(internal)?;
    accepted_event_id(outcome)?;

    // Read-your-writes: block until the membership projection sees the join
    // so the immediately following /sync shows the room.
    let seq = state
        .rooms
        .for_room(room_id.as_str())
        .shard_handle()
        .seq()
        .map_err(internal)?;
    let _ = saltator_userserver::wait_for_projection(
        &state.users,
        state.rooms.index_of(room_id.as_str()),
        seq,
        std::time::Duration::from_secs(5),
    )
    .await;
    project_imported_members(state, room_id.as_str(), seq).await?;
    Ok(())
}

/// Seed the membership projection with an imported room's current members:
/// the import stores them off-timeline (seq 0), where the change-stream
/// projection never sees them, yet device-list and presence visibility
/// ("do they share a room?") depend on their rows existing.
async fn project_imported_members(state: &CsState, room_id: &str, upto: u64) -> Result<()> {
    let current = crate::room_util::current_state(&state.rooms, room_id)?;
    let mut changes = Vec::new();
    for ((event_type, state_key), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(raw) = crate::room_util::raw_event(&state.rooms, room_id, event_id)? else {
            continue;
        };
        let membership = match raw.get("content") {
            Some(ruma::CanonicalJsonValue::Object(c)) => match c.get("membership") {
                Some(ruma::CanonicalJsonValue::String(m)) => m.clone(),
                _ => continue,
            },
            _ => continue,
        };
        let sender = match raw.get("sender") {
            Some(ruma::CanonicalJsonValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        changes.push(saltator_userserver::MembershipChange {
            user_id: state_key.clone(),
            room_id: room_id.to_owned(),
            membership,
            event_id: event_id.clone(),
            sender,
            room_seq: upto,
        });
    }
    state
        .users
        .apply_room_changes(&format!("import/{room_id}"), upto, changes)
        .await?;
    Ok(())
}

pub async fn join_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Jb(body): Jb,
) -> Result<Ra<join_room_by_id::v3::Response>> {
    let room_id = OwnedRoomId::try_from(room_id)
        .map_err(|e| ApiError::invalid_param(format!("room_id: {e}")))?;
    let via = join_via_hints(query.as_deref());
    join_with_body(&state, &auth, &room_id, &via, body).await?;
    Ok(Ra(join_room_by_id::v3::Response::new(room_id)))
}

pub async fn join_by_id_or_alias(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id_or_alias): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Jb(body): Jb,
) -> Result<Ra<join_room_by_id_or_alias::v3::Response>> {
    let id_or_alias = ruma::OwnedRoomOrAliasId::try_from(room_id_or_alias)
        .map_err(|e| ApiError::invalid_param(format!("room_id_or_alias: {e}")))?;
    let via = join_via_hints(query.as_deref());
    let room_id: OwnedRoomId = match id_or_alias.try_into() {
        Ok(room_id) => room_id,
        // A remote alias is resolved through the aliasing server's
        // directory (the resulting room ID names the resident to join
        // through); a local alias resolves from our own table.
        Err(alias) if alias.server_name() != state.config.server_name => {
            resolve_remote_alias(&state, alias.as_str()).await?.0
        }
        Err(alias) => resolve_alias(&state, alias.as_str()).await?,
    };
    join_with_body(&state, &auth, &room_id, &via, body).await?;
    Ok(Ra(join_room_by_id_or_alias::v3::Response::new(room_id)))
}

/// `POST /_matrix/client/v3/knock/{roomIdOrAlias}`: request permission to
/// join a room whose join rule is `knock`/`knock_restricted`. A local room
/// sends the knock membership directly; a remote room goes through the
/// make_knock/send_knock handshake.
pub async fn knock_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id_or_alias): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Jb(body): Jb,
) -> Result<Ra<knock_room::v3::Response>> {
    let id_or_alias = ruma::OwnedRoomOrAliasId::try_from(room_id_or_alias)
        .map_err(|e| ApiError::invalid_param(format!("room_id_or_alias: {e}")))?;
    let via = join_via_hints(query.as_deref());
    let room_id: OwnedRoomId = match id_or_alias.try_into() {
        Ok(room_id) => room_id,
        Err(alias) if alias.server_name() != state.config.server_name => {
            resolve_remote_alias(&state, alias.as_str()).await?.0
        }
        Err(alias) => resolve_alias(&state, alias.as_str()).await?,
    };
    // A knock is a request to join, so it is closed off by the same block.
    state.room_admin().ensure_joinable(room_id.as_str())?;
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));

    let (hosted, _) = room_hosted_locally(&state, &room_id)?;
    if hosted {
        send_membership(
            &state,
            &room_id,
            &auth.user_id,
            &auth.user_id,
            "knock",
            reason,
        )
        .await?;
    } else {
        knock_remote(&state, &auth, &room_id, &via, reason).await?;
    }
    Ok(Ra(knock_room::v3::Response::new(room_id)))
}

/// The remote half of a knock: run the make_knock/send_knock handshake
/// through a resident, then record the pending knock (with its stripped
/// `knock_room_state`) so it surfaces in the knocker's `/sync`.
async fn knock_remote(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    via: &[String],
    reason: Option<String>,
) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::not_found("Unknown room"));
    };
    let our_name = state.config.server_name.as_str();
    let mut candidates: Vec<String> = Vec::new();
    let push = |server: String, candidates: &mut Vec<String>| {
        if server != our_name && !candidates.contains(&server) {
            candidates.push(server);
        }
    };
    for hint in via {
        push(hint.clone(), &mut candidates);
    }
    // Client-named remote servers are the whole list (Synapse parity —
    // see the join candidate selection above); fall back to derived
    // servers only when no remote hint survives.
    if candidates.is_empty() {
        if let Some(resident) = saltator_federation::resident_of_room(room_id.as_str()) {
            push(resident, &mut candidates);
        }
        if let Ok(servers) = state
            .rooms
            .remote_servers_in_room(room_id.as_str(), our_name)
        {
            for server in servers {
                push(server, &mut candidates);
            }
        }
    }
    if candidates.is_empty() {
        return Err(ApiError::not_found(
            "Cannot determine a server to knock through",
        ));
    }

    let mut resp = None;
    let mut last_status = None;
    let mut last_err = String::new();
    for destination in &candidates {
        match saltator_federation::knock_remote_room(
            &fed.client,
            &fed.signer,
            destination,
            room_id.as_str(),
            auth.user_id.as_str(),
            reason.as_deref(),
        )
        .await
        {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(e) => {
                // A 403 is the resident's definitive verdict (banned,
                // already joined/invited, or the room doesn't accept
                // knocks): propagate it immediately. Falling through to
                // another candidate would let an unrelated server that 404s
                // (e.g. a Complement test server also in the room, which has
                // no /make_knock) mask the real 403 —
                // TestKnockingInMSC3787Room's federated "banned cannot
                // knock" wants the 403.
                if e.remote_status() == Some(403) {
                    last_status = Some(403);
                    last_err = e.to_string();
                    break;
                }
                last_status = e.remote_status();
                last_err = e.to_string();
            }
        }
    }
    let Some(resp) = resp else {
        // Surface the resident's own verdict where it is meaningful: a 403
        // (banned, already joined/invited, or the room doesn't accept
        // knocks) and 404 (unknown room) are the errors a client acts on.
        return Err(match last_status {
            Some(403) => ApiError::forbidden(format!("knock rejected: {last_err}")),
            Some(404) => ApiError::not_found("Unknown room"),
            _ => ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("remote knock failed: {last_err}"),
            ),
        });
    };

    let event_id = saltator_core::event::event_id(&resp.event, resp.room_version)
        .map(|i| i.to_string())
        .unwrap_or_default();
    let mut stripped: Vec<Vec<u8>> = Vec::new();
    for item in &resp.knock_room_state {
        if let Ok(bytes) = serde_json::to_vec(item) {
            stripped.push(bytes);
        }
    }
    // Ensure the knocker's own (stripped) knock member event is present —
    // a resident that curated it out of knock_room_state would otherwise
    // leave the knocker's /sync without their membership event.
    let member_stripped = serde_json::json!({
        "type": "m.room.member",
        "state_key": auth.user_id.as_str(),
        "sender": auth.user_id.as_str(),
        "content": resp.event.get("content").map(|c| serde_json::Value::from(c.clone())),
    });
    if let Ok(bytes) = serde_json::to_vec(&member_stripped) {
        stripped.push(bytes);
    }
    state
        .users
        .record_remote_knock(
            auth.user_id.as_str(),
            room_id.as_str(),
            auth.user_id.as_str(),
            &event_id,
            stripped,
        )
        .await
        .map_err(internal)?;
    Ok(())
}

/// The server-routing hints on a join request: `?server_name=` (and the
/// newer `?via=`) values, percent-decoded, in order, deduplicated.
fn join_via_hints(query: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pair in query.unwrap_or_default().split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == "server_name" || k == "via" {
            let server = percent_decode(v);
            if !server.is_empty() && !out.contains(&server) {
                out.push(server);
            }
        }
    }
    out
}

/// Minimal percent-decoding for a query value (`host%3A1045` -> `host:1045`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn leave_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<leave_room::v3::Request>,
) -> Result<Ra<leave_room::v3::Response>> {
    // A room we don't host that the user has a pending invite to: rejecting
    // it is a leave over federation (make_leave/send_leave).
    let hosted = state
        .rooms
        .for_room(req.room_id.as_str())
        .store()
        .meta(req.room_id.as_str())
        .map_err(internal)?
        .is_some();
    if !hosted {
        if let Some(entry) = state
            .users
            .store()
            .membership(auth.user_id.as_str(), req.room_id.as_str())
            .map_err(internal)?
        {
            if entry.membership == "invite" {
                leave_remote(&state, &auth, &req.room_id, &entry.sender).await?;
                return Ok(Ra(leave_room::v3::Response::new()));
            }
        }
    }
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &auth.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(leave_room::v3::Response::new()))
}

/// Reject a pending remote invite by running the make_leave/send_leave
/// handshake against the inviting server, then clearing the local invite.
async fn leave_remote(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    invite_sender: &str,
) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::forbidden("Federation is not configured"));
    };
    // The resident to leave through: the inviting user's server, falling
    // back to the room ID's server.
    let destination = ruma::UserId::parse(invite_sender)
        .ok()
        .map(|u| u.server_name().as_str().to_owned())
        .or_else(|| saltator_federation::resident_of_room(room_id.as_str()))
        .ok_or_else(|| ApiError::not_found("Cannot determine a server to leave through"))?;

    saltator_federation::leave_remote_room(
        &fed.client,
        &fed.signer,
        &destination,
        room_id.as_str(),
        auth.user_id.as_str(),
    )
    .await
    .map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote leave failed: {e}"),
        )
    })?;

    state
        .users
        .record_remote_leave(auth.user_id.as_str(), room_id.as_str())
        .await
        .map_err(internal)?;
    Ok(())
}

pub async fn forget_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<forget_room::v3::Request>,
) -> Result<Ra<forget_room::v3::Response>> {
    let membership = state
        .users
        .store()
        .membership(auth.user_id.as_str(), req.room_id.as_str())
        .map_err(internal)?;
    if membership.as_ref().is_some_and(|m| m.membership == "join") {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "You must leave the room before forgetting it",
        ));
    }
    state
        .users
        .forget_room(auth.user_id.as_str(), req.room_id.as_str())
        .await
        .map_err(internal)?;
    Ok(Ra(forget_room::v3::Response::new()))
}

pub async fn invite_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<invite_user::v3::Request>,
) -> Result<Ra<invite_user::v3::Response>> {
    let invite_user::v3::InvitationRecipient::UserId(invite) = &req.recipient else {
        return Err(ApiError::invalid_param("Third-party invites not supported"));
    };
    // A user on another server must co-sign their own invite over
    // federation before we can put it in the room.
    if invite.user_id.server_name() != state.config.server_name {
        invite_remote(
            &state,
            &auth,
            &req.room_id,
            &invite.user_id,
            serde_json::Map::new(),
        )
        .await?;
    } else {
        send_membership(
            &state,
            &req.room_id,
            &auth.user_id,
            &invite.user_id,
            "invite",
            invite.reason.clone(),
        )
        .await?;
    }
    Ok(Ra(invite_user::v3::Response::new()))
}

/// Stripped current-room state to accompany a federated invite
/// (`invite_room_state`): the create event plus the identifying state
/// clients render on an invite.
fn invite_room_state(state: &CsState, room_id: &str) -> Result<Vec<serde_json::Value>> {
    const TYPES: &[&str] = &[
        "m.room.create",
        "m.room.join_rules",
        "m.room.canonical_alias",
        "m.room.name",
        "m.room.avatar",
        "m.room.topic",
        "m.room.encryption",
    ];
    let current = current_state(&state.rooms, room_id)?;
    let mut out = Vec::new();
    for t in TYPES {
        if let Some(event_id) = current.get(&((*t).to_owned(), String::new())) {
            if let Some(raw) = raw_event(&state.rooms, room_id, event_id)? {
                out.push(crate::room_util::stripped_event(&raw));
            }
        }
    }
    Ok(out)
}

/// Invite a user on another server: build and sign the `m.room.member`
/// invite, have the target's server co-sign it (`PUT /invite`), then
/// ingest the co-signed event into the room.
pub(super) async fn invite_remote(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    invitee: &UserId,
    content: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::forbidden("Federation is not configured"));
    };
    let (version, event) = state
        .rooms
        .build_invite(room_id, &auth.user_id, invitee, content)
        .await
        .map_err(internal)?;
    let event_id = saltator_core::event::event_id(&event, version).map_err(internal)?;

    let body = serde_json::json!({
        "room_version": version.as_str(),
        "event": ruma::CanonicalJsonValue::Object(event),
        "invite_room_state": invite_room_state(state, room_id.as_str())?,
    });
    let path = format!(
        "/_matrix/federation/v2/invite/{}/{}",
        encode_segment(room_id.as_str()),
        encode_segment(event_id.as_str()),
    );
    let resp = fed
        .client
        .put(invitee.server_name().as_str(), &path, &body)
        .await
        .map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("remote invite failed: {e}"),
            )
        })?;

    // Ingest the doubly-signed event into the room (distributes to any
    // other resident servers via the outbound sender).
    let signed = match resp
        .get("event")
        .cloned()
        .map(ruma::CanonicalJsonValue::try_from)
    {
        Some(Ok(ruma::CanonicalJsonValue::Object(o))) => o,
        _ => {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "invite response missing signed event",
            ))
        }
    };
    let outcome = state.rooms.ingest_pdu(signed).await.map_err(internal)?;
    accepted_event_id(outcome)?;
    Ok(())
}

pub async fn kick_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<kick_user::v3::Request>,
) -> Result<Ra<kick_user::v3::Response>> {
    // Auth rules alone would accept a redundant leave; the CS contract is
    // that kicking someone who is not in the room (never present, or
    // already left) is forbidden.
    let current = current_state(&state.rooms, req.room_id.as_str())?;
    let target_membership = crate::room_util::membership_in(
        &state.rooms,
        req.room_id.as_str(),
        &current,
        req.user_id.as_str(),
    )?;
    if !matches!(target_membership.as_str(), "join" | "invite" | "knock") {
        return Err(ApiError::forbidden(
            "Cannot kick a user who is not in the room",
        ));
    }
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(kick_user::v3::Response::new()))
}

pub async fn ban_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<ban_user::v3::Request>,
) -> Result<Ra<ban_user::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "ban",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(ban_user::v3::Response::new()))
}

pub async fn unban_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<unban_user::v3::Request>,
) -> Result<Ra<unban_user::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(unban_user::v3::Response::new()))
}

pub async fn joined_rooms(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<joined_rooms::v3::Request>,
) -> Result<Ra<joined_rooms::v3::Response>> {
    let rooms = state
        .users
        .store()
        .memberships(auth.user_id.as_str())
        .map_err(internal)?
        .into_iter()
        .filter(|(_, m)| m.membership == "join")
        .filter_map(|(room_id, _)| OwnedRoomId::try_from(room_id).ok())
        .collect();
    Ok(Ra(joined_rooms::v3::Response::new(rooms)))
}

#[cfg(test)]
mod tests {
    use super::join_via_hints;

    #[test]
    fn join_via_hints_parses_server_name_and_via() {
        assert_eq!(join_via_hints(Some("server_name=hs1")), vec!["hs1"]);
        // The newer `via` alias, a percent-decoded ported name, and dedup
        // across repeats.
        assert_eq!(
            join_via_hints(Some(
                "server_name=host.docker.internal%3A1045&via=hs2&server_name=hs2"
            )),
            vec!["host.docker.internal:1045".to_owned(), "hs2".to_owned()]
        );
        assert!(join_via_hints(None).is_empty());
        assert!(join_via_hints(Some("foo=bar")).is_empty());
    }
}
