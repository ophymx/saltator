//! Remote room joins, resident side (spec "Joining Rooms"): a remote
//! server calls `GET /make_join` for a template, fills and signs it, then
//! `PUT /send_join` to have us apply it and return the room state.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use crate::inbound::Authenticated;
use crate::FedState;

/// A federation error body with the given errcode/status.
fn err(
    status: StatusCode,
    errcode: &str,
    msg: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({ "errcode": errcode, "error": msg })),
    )
}

type FedResult = Result<axum::Json<serde_json::Value>, (StatusCode, axum::Json<serde_json::Value>)>;

/// Refuse an inbound membership handshake into a room an administrator has
/// closed (docs/design-admin-identity.md slice 5).
///
/// The resident side has to enforce this, not just the client API: a block
/// that only stopped our own users would leave the room reachable through
/// us by every other server on the federation. The state lives in the user
/// shard so both surfaces can read it without either owning the other.
///
/// No user shard wired (key-only deployments) means no blocks exist to
/// enforce.
///
/// Fails CLOSED on a store error: a block that a transient read failure
/// could lift is not a block. This matches the client-side `ensure_joinable`
/// (security review 2026-08-13, Low #6).
fn refuse_if_blocked(
    state: &FedState,
    room_id: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let Some(users) = state.users.as_ref() else {
        return Ok(());
    };
    let refuse = |msg: &str| Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", msg));
    match users.store().blocked_room(room_id) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => refuse("This room has been blocked by a server administrator"),
        Err(_) => refuse("Could not verify the room's block status"),
    }
}

/// The `room_id` of a membership event body, for the block check.
fn event_room_id(raw: &CanonicalJsonObject) -> Option<&str> {
    match raw.get("room_id") {
        Some(CanonicalJsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// A `send_join`/`send_leave` body must be an `m.room.member` event with
/// the expected membership and `state_key == sender`; anything else is
/// rejected with 400 (spec: these endpoints only accept the corresponding
/// membership transition, so a non-join can't be smuggled through
/// `send_join`).
fn require_membership_event(
    raw: &CanonicalJsonObject,
    expected: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let str_of = |k: &str| match raw.get(k) {
        Some(CanonicalJsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    };
    let is_member = str_of("type") == Some("m.room.member");
    let membership = match raw.get("content") {
        Some(CanonicalJsonValue::Object(c)) => match c.get("membership") {
            Some(CanonicalJsonValue::String(m)) => Some(m.as_str()),
            _ => None,
        },
        _ => None,
    };
    let state_key = str_of("state_key");
    if is_member
        && membership == Some(expected)
        && state_key.is_some()
        && state_key == str_of("sender")
    {
        Ok(())
    } else {
        Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            &format!(
                "event must be an m.room.member with membership={expected} and state_key==sender"
            ),
        ))
    }
}

/// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}`. Returns an
/// unsigned knock template; the knocking server fills, signs, and submits it
/// via `/send_knock` (spec "Knocking Rooms").
pub async fn make_knock(
    State(state): State<Arc<FedState>>,
    Path((room_id, user_id)): Path<(String, String)>,
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let rooms = rooms.for_room(&room_id).clone();
    let room = ruma::RoomId::parse(&room_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad room id"))?;
    let user = ruma::UserId::parse(&user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad user id"))?;
    refuse_if_blocked(&state, room.as_str())?;

    match rooms.make_knock_template(&room, &user) {
        Ok((version, template)) => Ok(axum::Json(serde_json::json!({
            "room_version": version.as_str(),
            "event": CanonicalJsonValue::Object(template),
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )),
    }
}

/// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`: apply a
/// remote server's signed knock and return the stripped room state.
pub async fn send_knock(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    // BODY-ROUTED: resolved (and keys trusted) after the event parses.
    let shards = rooms;

    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "knock event is not valid JSON",
        )
    })?;
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "knock event is not an object",
            ))
        }
    };
    // spec: /send_knock accepts only an m.room.member knock with
    // state_key == sender; anything else is a 400.
    require_membership_event(&raw, "knock")?;
    let Some(CanonicalJsonValue::String(event_room)) = raw.get("room_id").cloned() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "event has no room_id",
        ));
    };
    // Route by the EVENT's room — the path is advisory, and applying to
    // the wrong shard on a lying path must be impossible.
    let rooms = shards.for_room(&event_room).clone();
    let now = crate::now_ms();
    if let Ok(keys) = state.key_cache.keys_for(&auth.origin, now).await {
        if let Some(set) = keys.get(&auth.origin) {
            rooms.trust_keys(&auth.origin, set.clone());
        }
    }
    // Unconditional: an event with no `room_id` must be refused, not have
    // the block silently skipped (security review 2026-08-13, Vuln 2).
    let room_id = event_room_id(&raw).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "event has no room_id",
        )
    })?;
    refuse_if_blocked(&state, room_id)?;

    match rooms.send_knock(raw).await {
        Ok(result) => Ok(axum::Json(serde_json::json!({
            "knock_room_state": result.knock_room_state,
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &e.to_string())),
    }
}

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`.
pub async fn make_join(
    State(state): State<Arc<FedState>>,
    Path((room_id, user_id)): Path<(String, String)>,
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let rooms = rooms.for_room(&room_id).clone();
    let room = ruma::RoomId::parse(&room_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad room id"))?;
    let user = ruma::UserId::parse(&user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad user id"))?;
    refuse_if_blocked(&state, room.as_str())?;

    match rooms.make_join_template(&room, &user) {
        Ok((version, template)) => Ok(axum::Json(serde_json::json!({
            "room_version": version.as_str(),
            "event": CanonicalJsonValue::Object(template),
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(saltator_roomserver::RoomError::CannotAuthoriseJoin(denial)) => {
            Err(restricted_denial(denial))
        }
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )),
    }
}

/// Map a restricted-join denial to its spec error (MSC3083 "Restricted
/// rooms"). The 400s tell the requesting server to fail over to another
/// resident; the 403 is a definitive rejection.
fn restricted_denial(
    denial: saltator_roomserver::RestrictedDenial,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    use saltator_roomserver::RestrictedDenial::*;
    match denial {
        Forbidden => err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "You are not permitted to join this room",
        ),
        CannotValidate => err(
            StatusCode::BAD_REQUEST,
            "M_UNABLE_TO_AUTHORISE_JOIN",
            "This server cannot validate any of the join conditions",
        ),
        CannotGrant => err(
            StatusCode::BAD_REQUEST,
            "M_UNABLE_TO_GRANT_JOIN",
            "This server cannot grant the join; try another server",
        ),
    }
}

/// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`.
pub async fn send_join(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    Ok(axum::Json(send_join_apply(state, auth).await?))
}

/// `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}`: the legacy
/// send_join. Identical validation and application to v2, but the body is
/// returned in the historical `[200, body]` envelope (spec "Joining Rooms",
/// deprecated v1 response shape).
pub async fn send_join_v1(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let body = send_join_apply(state, auth).await?;
    Ok(axum::Json(serde_json::json!([200, body])))
}

/// Shared send_join core: trust the origin's keys, validate the membership,
/// apply the join, and return the v2 response body object.
async fn send_join_apply(
    state: Arc<FedState>,
    auth: Authenticated,
) -> Result<serde_json::Value, (StatusCode, axum::Json<serde_json::Value>)> {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    // BODY-ROUTED: resolved (and keys trusted) after the event parses.
    let shards = rooms;

    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "join event is not valid JSON",
        )
    })?;
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "join event is not an object",
            ))
        }
    };
    require_membership_event(&raw, "join")?;
    let Some(CanonicalJsonValue::String(event_room)) = raw.get("room_id").cloned() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "event has no room_id",
        ));
    };
    // Route by the EVENT's room — the path is advisory, and applying to
    // the wrong shard on a lying path must be impossible.
    let rooms = shards.for_room(&event_room).clone();
    let now = crate::now_ms();
    if let Ok(keys) = state.key_cache.keys_for(&auth.origin, now).await {
        if let Some(set) = keys.get(&auth.origin) {
            rooms.trust_keys(&auth.origin, set.clone());
        }
    }
    // From the event, because the event is what gets applied. Unconditional:
    // a missing `room_id` is refused, not a silently skipped block
    // (security review 2026-08-13, Vuln 2).
    let room_id = event_room_id(&raw).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "event has no room_id",
        )
    })?;
    refuse_if_blocked(&state, room_id)?;

    match rooms.send_join(raw).await {
        Ok(result) => Ok(serde_json::json!({
            "event": CanonicalJsonValue::Object(result.event),
            "state": to_array(result.state),
            "auth_chain": to_array(result.auth_chain),
            "origin": state.server_name.as_str(),
        })),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &e.to_string())),
    }
}

fn to_array(events: Vec<CanonicalJsonObject>) -> serde_json::Value {
    serde_json::Value::Array(
        events
            .into_iter()
            .map(|e| serde_json::Value::from(CanonicalJsonValue::Object(e)))
            .collect(),
    )
}

/// `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`: the auth
/// chain of an event (spec "Retrieving events").
pub async fn event_auth(
    State(state): State<Arc<FedState>>,
    Path((room_id, event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let rooms = rooms.for_room(&room_id).clone();
    // Requester's server must be in the room (Synapse parity) — the auth
    // chain names members, power levels and the room's whole authority
    // structure. And the event must actually belong to the path's room,
    // or the room check authorizes a cross-room probe.
    if !rooms
        .server_in_room(&room_id, &auth.origin)
        .unwrap_or(false)
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Requesting server is not in the room",
        ));
    }
    let in_this_room = rooms
        .store()
        .event(&event_id)
        .ok()
        .flatten()
        .and_then(|stored| serde_json::from_slice::<serde_json::Value>(&stored.raw).ok())
        .is_some_and(|pdu| match pdu.get("room_id") {
            Some(serde_json::Value::String(r)) => *r == room_id,
            // v12 create events carry no room_id; their auth chain is
            // empty, so serving it discloses nothing.
            None => true,
            _ => false,
        });
    if !in_this_room {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown event"));
    }
    match rooms.event_auth_chain(&event_id) {
        Ok(Some(chain)) => Ok(axum::Json(serde_json::json!({
            "auth_chain": to_array(chain),
        }))),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown event")),
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )),
    }
}

/// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`: template for
/// a remote user to leave/reject.
pub async fn make_leave(
    State(state): State<Arc<FedState>>,
    Path((room_id, user_id)): Path<(String, String)>,
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let rooms = rooms.for_room(&room_id).clone();
    let room = ruma::RoomId::parse(&room_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad room id"))?;
    let user = ruma::UserId::parse(&user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad user id"))?;
    match rooms.make_leave_template(&room, &user) {
        Ok((version, template)) => Ok(axum::Json(serde_json::json!({
            "room_version": version.as_str(),
            "event": CanonicalJsonValue::Object(template),
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )),
    }
}

/// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`: apply a
/// remote signed leave/reject.
pub async fn send_leave(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    send_leave_apply(state, auth).await?;
    Ok(axum::Json(serde_json::json!({})))
}

/// `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}`: the legacy
/// send_leave, returning the historical `[200, {}]` envelope.
pub async fn send_leave_v1(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    send_leave_apply(state, auth).await?;
    Ok(axum::Json(serde_json::json!([200, {}])))
}

/// Shared send_leave core: trust the origin's keys, validate the membership,
/// and apply the leave/reject.
async fn send_leave_apply(
    state: Arc<FedState>,
    auth: Authenticated,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    // BODY-ROUTED: resolved (and keys trusted) after the event parses.
    let shards = rooms;
    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "leave event is not valid JSON",
        )
    })?;
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "leave event is not an object",
            ))
        }
    };
    require_membership_event(&raw, "leave")?;
    let Some(CanonicalJsonValue::String(event_room)) = raw.get("room_id").cloned() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "event has no room_id",
        ));
    };
    // Route by the EVENT's room — the path is advisory, and applying to
    // the wrong shard on a lying path must be impossible.
    let rooms = shards.for_room(&event_room).clone();
    let now = crate::now_ms();
    if let Ok(keys) = state.key_cache.keys_for(&auth.origin, now).await {
        if let Some(set) = keys.get(&auth.origin) {
            rooms.trust_keys(&auth.origin, set.clone());
        }
    }
    match rooms.send_leave(raw).await {
        Ok(saltator_roomserver::Outcome::Rejected { reason, .. }) => {
            Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &reason))
        }
        Ok(_) => Ok(()),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &e.to_string())),
    }
}

/// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}` (spec "Inviting
/// to a room"): a remote server asks us to co-sign an `m.room.member`
/// invite for one of our users. We validate it, add our signature, record
/// it as a pending invite so the user sees it in `/sync`, and return the
/// doubly-signed event.
pub async fn invite(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "invite body is not valid JSON",
        )
    })?;
    let room_version = body
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "missing room_version",
            )
        })?;
    let version = saltator_core::RoomVersion::parse(room_version).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_INCOMPATIBLE_ROOM_VERSION",
            "bad room_version",
        )
    })?;
    let event: CanonicalJsonObject =
        match body.get("event").cloned().map(CanonicalJsonValue::try_from) {
            Some(Ok(CanonicalJsonValue::Object(o))) => o,
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "missing event",
                ))
            }
        };

    // Structural validation (spec: sign only genuine invites for our users).
    let invalid = |m: &str| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", m);
    if event.get("type").and_then(|v| v.as_str()) != Some("m.room.member") {
        return Err(invalid("event type is not m.room.member"));
    }
    let membership = event
        .get("content")
        .and_then(|c| c.as_object())
        .and_then(|c| c.get("membership"))
        .and_then(|m| m.as_str());
    if membership != Some("invite") {
        return Err(invalid("membership is not invite"));
    }
    let sender = event
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let sender_ok = ruma::UserId::parse(&sender)
        .map(|u| u.server_name().as_str() == auth.origin)
        .unwrap_or(false);
    if !sender_ok {
        return Err(invalid("sender is not on the origin server"));
    }
    let state_key = event
        .get("state_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let invitee = ruma::OwnedUserId::try_from(state_key.clone())
        .map_err(|_| invalid("state_key is not a user id"))?;
    if invitee.server_name() != state.server_name {
        return Err(invalid("invited user is not on this server"));
    }
    // An invite is the other way into a room. Refusing joins but signing
    // invites would leave the block one click from useless.
    //
    // Check the block against the PATH room — that is the room we record
    // the pending invite for and, when we host it, ingest into. Reading
    // the block from the event body while acting on the path let a
    // mismatched or absent event `room_id` slip a pending invite (with
    // attacker-controlled stripped state) into a blocked room (security
    // review 2026-08-13, Vuln 2). Require the two to agree.
    let room_id = ruma::RoomId::parse(&_room_id).map_err(|_| invalid("bad room id"))?;
    if event_room_id(&event) != Some(room_id.as_str()) {
        return Err(invalid("event room_id does not match the invite path"));
    }
    refuse_if_blocked(&state, room_id.as_str())?;

    // Verify the origin's signature on the event.
    let now = crate::now_ms();
    let origin_keys = state
        .key_cache
        .keys_for(&auth.origin, now)
        .await
        .map_err(|e| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("origin keys: {e}"),
            )
        })?;
    if ruma::signatures::verify_event(&origin_keys, &event, &version.rules()).is_err() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_INVALID_PARAM",
            "invite event signature verification failed",
        ));
    }

    // Add our signature.
    let mut signed = event;
    if let Err(e) = state.signer.hash_and_sign_event(&mut signed, version) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        ));
    }

    // If we already host this room (the invitee was a member before), the
    // invite belongs in the room's DAG: its `prev_events` order it after any
    // prior membership — e.g. an unban that reached us as a room event — so the
    // invitee's /sync stays consistent with the room. Ingest it through the
    // normal PDU path (fetching missing prev events from the origin). Only a
    // room we don't host is recorded as an out-of-band pending invite, whose
    // stripped state `build_invited_room` reads from the user shard.
    let hosted = state
        .rooms
        .as_ref()
        .and_then(|r| {
            r.for_room(_room_id.as_str())
                .store()
                .meta(_room_id.as_str())
                .ok()
                .flatten()
        })
        .is_some();
    let mut ingested = false;
    if hosted {
        let value = serde_json::Value::from(CanonicalJsonValue::Object(signed.clone()));
        let (_, result) = crate::transactions::process_pdu(&state, &auth.origin, value).await;
        ingested = result.get("error").is_none();
        if !ingested {
            tracing::warn!(room_id = %_room_id, ?result,
                "invite: could not ingest into hosted room; recording out-of-band");
        }
    }

    // Record the pending invite (with its stripped state) so the invited
    // user sees it in /sync. The invite member event itself is included.
    if !ingested {
        if let Some(users) = &state.users {
            let mut stripped: Vec<Vec<u8>> = Vec::new();
            if let Some(serde_json::Value::Array(items)) = body.get("invite_room_state") {
                for item in items {
                    if let Ok(bytes) = serde_json::to_vec(item) {
                        stripped.push(bytes);
                    }
                }
            }
            // Include the (stripped) invite membership event.
            let member_stripped = serde_json::json!({
                "type": "m.room.member",
                "state_key": state_key.as_str(),
                "sender": sender.as_str(),
                "content": signed.get("content").map(|c| serde_json::Value::from(c.clone())),
            });
            if let Ok(bytes) = serde_json::to_vec(&member_stripped) {
                stripped.push(bytes);
            }
            let event_id = saltator_core::event::event_id(&signed, version)
                .map(|id| id.to_string())
                .unwrap_or_default();
            if let Err(e) = users
                .record_remote_invite(
                    invitee.as_str(),
                    _room_id.as_str(),
                    &sender,
                    &event_id,
                    stripped,
                )
                .await
            {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "M_UNKNOWN",
                    &e.to_string(),
                ));
            }
        }
    }

    Ok(axum::Json(serde_json::json!({
        "event": CanonicalJsonValue::Object(signed),
    })))
}

#[cfg(test)]
mod tests {
    use super::require_membership_event;
    use ruma::{CanonicalJsonObject, CanonicalJsonValue};

    fn obj(v: serde_json::Value) -> CanonicalJsonObject {
        match CanonicalJsonValue::try_from(v).unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn membership_event_validation() {
        let join = obj(serde_json::json!({
            "type": "m.room.member",
            "sender": "@bob:b.test",
            "state_key": "@bob:b.test",
            "content": {"membership": "join"},
        }));
        assert!(require_membership_event(&join, "join").is_ok());
        // send_leave must reject a join event, and vice versa.
        assert!(require_membership_event(&join, "leave").is_err());

        // A non-membership event can't be smuggled through send_join.
        let message = obj(serde_json::json!({
            "type": "m.room.message",
            "sender": "@bob:b.test",
            "content": {"body": "hi"},
        }));
        assert!(require_membership_event(&message, "join").is_err());

        // state_key must equal sender.
        let mismatched = obj(serde_json::json!({
            "type": "m.room.member",
            "sender": "@bob:b.test",
            "state_key": "@carol:b.test",
            "content": {"membership": "join"},
        }));
        assert!(require_membership_event(&mismatched, "join").is_err());
    }
}
