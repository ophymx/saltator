//! Authorization rules for room versions 11 and 12 (spec.md §5.2 step 3).
//!
//! Implements the "Authorisation rules" of the room-version specs at Matrix
//! v1.19. Comments cite v12 rule numbers; v11 differences are gated via
//! [`RoomVersion`]. Rejection tags are version-agnostic strings (the two
//! versions number the same rules differently).
//!
//! Split, mirroring how the rules are consumed:
//!
//! - [`check_auth_events`] — structural checks of the event's own
//!   `auth_events` list (v11 rule 2 / v12 rule 3). Run once, on receipt.
//! - [`check_state_dependent`] — everything evaluated against a state
//!   snapshot: the state before the event during normal processing, or a
//!   candidate map during state resolution.
//!
//! Two rules are *not* here because they need key material rather than
//! state: "events must be signed by the sender's server" and the
//! `join_authorised_via_users_server` signature check (v12 rule 5.2.1) —
//! both are receipt-time checks in [`crate::validation`] / the federation
//! layer. Callers of [`check_state_dependent`] assert they already passed.

use std::collections::{BTreeMap, BTreeSet};

use ruma::signatures::{to_canonical_json_string_for_signing, verify_canonical_json_bytes};
use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedUserId, SigningKeyAlgorithm, UserId};

use crate::event::Event;
use crate::power_levels::{PowerLevel, RoomPowerLevels};
use crate::room_version::RoomVersion;

/// Why an event failed authorization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("auth: {rule}: {reason}")]
pub struct Rejection {
    /// Version-agnostic tag identifying the failed rule.
    pub rule: &'static str,
    pub reason: String,
}

pub type AuthResult = Result<(), Rejection>;

fn reject(rule: &'static str, reason: impl Into<String>) -> AuthResult {
    Err(Rejection {
        rule,
        reason: reason.into(),
    })
}

/// Read access to a room-state snapshot keyed by `(type, state_key)`.
/// Events in the snapshot are accepted (not rejected) by contract.
pub trait StateView<E: Event> {
    fn get(&self, event_type: &str, state_key: &str) -> Option<&E>;
}

/// The concrete map used in tests and simple callers.
pub type StateMap<E> = BTreeMap<(String, String), E>;

impl<E: Event> StateView<E> for StateMap<E> {
    fn get(&self, event_type: &str, state_key: &str) -> Option<&E> {
        BTreeMap::get(self, &(event_type.to_owned(), state_key.to_owned()))
    }
}

fn str_prop<'a>(obj: &'a CanonicalJsonObject, key: &str) -> Option<&'a str> {
    match obj.get(key) {
        Some(CanonicalJsonValue::String(s)) => Some(s),
        _ => None,
    }
}

fn obj_prop<'a>(obj: &'a CanonicalJsonObject, key: &str) -> Option<&'a CanonicalJsonObject> {
    match obj.get(key) {
        Some(CanonicalJsonValue::Object(o)) => Some(o),
        _ => None,
    }
}

/// A user's current membership in a state snapshot (`leave` when absent).
fn membership<'a, E: Event + 'a>(state: &'a impl StateView<E>, user: &str) -> &'a str {
    state
        .get("m.room.member", user)
        .and_then(|e| str_prop(e.content(), "membership"))
        .unwrap_or("leave")
}

/// The `(type, state_key)` pairs the auth-events selection algorithm
/// permits for an event (server-server spec, "Auth events selection").
/// This is also exactly the set to fetch from current state when *building*
/// `auth_events` for a locally-created event.
pub fn auth_types_for_event(
    version: RoomVersion,
    event_type: &str,
    sender: &UserId,
    state_key: Option<&str>,
    content: &CanonicalJsonObject,
) -> BTreeSet<(String, String)> {
    let mut set = BTreeSet::new();
    if event_type == "m.room.create" {
        return set;
    }

    if version.create_event_in_auth_events() {
        set.insert(("m.room.create".to_owned(), String::new()));
    }
    set.insert(("m.room.power_levels".to_owned(), String::new()));
    set.insert(("m.room.member".to_owned(), sender.as_str().to_owned()));

    if event_type == "m.room.member" {
        if let Some(target) = state_key {
            set.insert(("m.room.member".to_owned(), target.to_owned()));
        }
        let mem = str_prop(content, "membership").unwrap_or_default();
        if matches!(mem, "join" | "invite" | "knock") {
            set.insert(("m.room.join_rules".to_owned(), String::new()));
        }
        if mem == "invite" {
            if let Some(token) = obj_prop(content, "third_party_invite")
                .and_then(|tpi| obj_prop(tpi, "signed"))
                .and_then(|signed| str_prop(signed, "token"))
            {
                set.insert(("m.room.third_party_invite".to_owned(), token.to_owned()));
            }
        }
        if mem == "join" {
            if let Some(authoriser) = str_prop(content, "join_authorised_via_users_server") {
                set.insert(("m.room.member".to_owned(), authoriser.to_owned()));
            }
        }
    }
    set
}

/// An entry of an event's `auth_events`, resolved to the event plus its
/// local rejection status.
pub struct AuthEntry<'a, E> {
    pub event: &'a E,
    pub rejected: bool,
}

/// Structural checks of the event's own `auth_events` (v11 rule 2 / v12
/// rule 3): no duplicate `(type, state_key)`, every entry permitted by the
/// selection algorithm, no rejected entries, `room_id` agreement, and (v11)
/// the create event present.
pub fn check_auth_events<E: Event>(
    version: RoomVersion,
    event: &E,
    entries: &[AuthEntry<'_, E>],
) -> AuthResult {
    // Rule 1 precedes the auth_events rules: m.room.create is
    // self-authorising and carries no auth_events. Any entry it does carry
    // still fails 3.2 below (the selection set is empty), but the
    // create-entry-required rule (v11 2.4) must not apply to it.
    let is_create = event.event_type() == "m.room.create";

    let allowed = auth_types_for_event(
        version,
        event.event_type(),
        event.sender(),
        event.state_key(),
        event.content(),
    );

    let mut seen = BTreeSet::new();
    let mut have_create = false;
    for entry in entries {
        let e = entry.event;
        let key = (
            e.event_type().to_owned(),
            e.state_key().unwrap_or_default().to_owned(),
        );
        // 3.1: duplicate (type, state_key) entries.
        if !seen.insert(key.clone()) {
            return reject(
                "auth_events.duplicate",
                format!("duplicate auth entry for {key:?}"),
            );
        }
        // 3.2: entries outside the selection set. (v12: this also enforces
        // that the create event MUST NOT be listed.)
        if !allowed.contains(&key) {
            return reject(
                "auth_events.selection",
                format!("{key:?} is not a permitted auth event for this event"),
            );
        }
        // 3.3: rejected entries.
        if entry.rejected {
            return reject(
                "auth_events.rejected",
                format!("auth event {} was rejected", e.event_id()),
            );
        }
        // 3.5: room_id must match.
        if e.room_id() != event.room_id()
            && !(version.room_id_is_create_event_id() && key.0 == "m.room.create")
        {
            return reject(
                "auth_events.room_id",
                format!("auth event {} belongs to another room", e.event_id()),
            );
        }
        have_create |= key.0 == "m.room.create";
    }

    // v11 2.4: an m.room.create entry is required (except on the create
    // event itself).
    if version.create_event_in_auth_events() && !have_create && !is_create {
        return reject("auth_events.create", "no m.room.create in auth_events");
    }
    Ok(())
}

/// The state-dependent authorisation rules, evaluated against `state` —
/// the room state before the event, or a candidate map during state
/// resolution.
pub fn check_state_dependent<E: Event>(
    version: RoomVersion,
    event: &E,
    state: &impl StateView<E>,
) -> AuthResult {
    // Rule 1: m.room.create is self-authorising.
    if event.event_type() == "m.room.create" {
        return check_create(version, event);
    }

    // Everything else needs the create event in state.
    let Some(create) = state.get("m.room.create", "") else {
        return reject("state.create", "no m.room.create in state");
    };

    // v12 rule 2: the event's room_id must be the (accepted) create
    // event's ID with the `!` sigil. Events in `state` are accepted by
    // contract, so acceptance is implied by `create` being present.
    if version.room_id_is_create_event_id() {
        let expected = &create.event_id().as_str()[1..];
        match event.room_id() {
            Some(rid) if &rid.as_str()[1..] == expected => {}
            _ => {
                return reject(
                    "room_id.create",
                    "room_id does not match the create event's ID",
                )
            }
        }
    }

    // Rule 4 (v11 rule 3): m.federate.
    if let Some(CanonicalJsonValue::Bool(false)) = create.content().get("m.federate") {
        if event.sender().server_name() != create.sender().server_name() {
            return reject("federate", "room does not federate and sender is remote");
        }
    }

    let power = RoomPowerLevels::resolve(version, create, state.get("m.room.power_levels", ""))
        .map_err(|e| Rejection {
            rule: "state.power_levels",
            reason: e.to_string(),
        })?;
    let sender_pl = power.user(event.sender());

    // Rule 5 (v11 rule 4): m.room.member.
    if event.event_type() == "m.room.member" {
        return check_member(event, create, state, &power, sender_pl);
    }

    // Rule 6 (v11 rule 5): sender must be joined.
    if membership(state, event.sender().as_str()) != "join" {
        return reject("sender.membership", "sender is not joined");
    }

    // Rule 7 (v11 rule 6): m.room.third_party_invite needs invite level.
    if event.event_type() == "m.room.third_party_invite" {
        return if sender_pl.satisfies(power.invite) {
            Ok(())
        } else {
            reject("third_party_invite.level", "sender below invite level")
        };
    }

    // Rule 8 (v11 rule 7): required power level for the event type.
    let required = power.required_for(event.event_type(), event.is_state());
    if !sender_pl.satisfies(required) {
        return reject(
            "event.level",
            format!("sender below required level {required} for this event type"),
        );
    }

    // Rule 9 (v11 rule 8): user-keyed state must be keyed by the sender.
    if let Some(sk) = event.state_key() {
        if sk.starts_with('@') && sk != event.sender().as_str() {
            return reject("state_key.user", "user-keyed state_key is not the sender");
        }
    }

    // Rule 10 (v11 rule 9): m.room.power_levels.
    if event.event_type() == "m.room.power_levels" {
        return check_power_levels(version, event, state, &power, sender_pl);
    }

    // Rule 11 (v11 rule 10): otherwise, allow.
    Ok(())
}

/// Rule 1: checks on `m.room.create` itself.
fn check_create<E: Event>(version: RoomVersion, event: &E) -> AuthResult {
    // 1.1: no prev_events.
    if !event.prev_events().is_empty() {
        return reject("create.prev_events", "create event has prev_events");
    }

    if version.room_id_is_create_event_id() {
        // v12 1.2: no room_id property at all.
        if event.room_id().is_some() {
            return reject("create.room_id", "v12 create event carries a room_id");
        }
    } else {
        // v11 1.2: room_id domain must match sender domain.
        match event.room_id() {
            Some(rid) if rid.server_name() == Some(event.sender().server_name()) => {}
            _ => {
                return reject(
                    "create.room_id",
                    "room_id domain does not match sender domain",
                )
            }
        }
    }

    // 1.3: room_version, if present, must be recognised. We recognise
    // exactly the versions we implement (spec.md §3).
    match event.content().get("room_version") {
        None => {}
        Some(CanonicalJsonValue::String(v)) if RoomVersion::parse(v).is_ok() => {}
        Some(_) => return reject("create.room_version", "unrecognised room_version"),
    }

    // v12 1.4: additional_creators must be an array of valid user IDs.
    if version.privileged_creators() {
        match event.content().get("additional_creators") {
            None => {}
            Some(CanonicalJsonValue::Array(arr)) => {
                for v in arr {
                    match v {
                        CanonicalJsonValue::String(s)
                            if OwnedUserId::try_from(s.as_str()).is_ok() => {}
                        _ => {
                            return reject(
                                "create.additional_creators",
                                "additional_creators entry is not a valid user ID",
                            )
                        }
                    }
                }
            }
            Some(_) => {
                return reject(
                    "create.additional_creators",
                    "additional_creators is not an array",
                )
            }
        }
    }

    // 1.5 (v11 1.4): otherwise, allow.
    Ok(())
}

/// Rule 5 (v11 rule 4): `m.room.member` events.
///
/// Note the v12 additional-creators list deliberately does NOT extend the
/// first-join shortcut (5.3.1) — the spec names only the create `sender`.
fn check_member<E: Event>(
    event: &E,
    create: &E,
    state: &impl StateView<E>,
    power: &RoomPowerLevels,
    sender_pl: PowerLevel,
) -> AuthResult {
    // 5.1: state_key and content.membership are required.
    let Some(target) = event.state_key() else {
        return reject("member.state_key", "member event without state_key");
    };
    let Some(new_membership) = str_prop(event.content(), "membership") else {
        return reject("member.membership", "member event without membership");
    };

    // 5.2 (join_authorised_via_users_server signature validity) is a
    // receipt-time check; see module docs.

    let sender = event.sender();
    let sender_mem = membership(state, sender.as_str());
    let target_mem = membership(state, target);
    let join_rule = state
        .get("m.room.join_rules", "")
        .and_then(|e| str_prop(e.content(), "join_rule"))
        .unwrap_or("invite");

    match new_membership {
        // 5.3: join.
        "join" => {
            // 5.3.1: the room's very first join — sole prev event is the
            // create and the joiner is the create's sender.
            if event.prev_events().len() == 1
                && event.prev_events()[0] == *create.event_id()
                && target == create.sender().as_str()
            {
                return Ok(());
            }
            // 5.3.2: only self-joins beyond this point.
            if sender.as_str() != target {
                return reject("member.join.sender", "join sender differs from state_key");
            }
            // 5.3.3: banned users cannot join.
            if sender_mem == "ban" {
                return reject("member.join.ban", "sender is banned");
            }
            match join_rule {
                // 5.3.4.
                "invite" | "knock" => {
                    if matches!(sender_mem, "invite" | "join") {
                        Ok(())
                    } else {
                        reject("member.join.rule", "not invited to invite/knock room")
                    }
                }
                // 5.3.5.
                "restricted" | "knock_restricted" => {
                    // 5.3.5.1.
                    if matches!(sender_mem, "join" | "invite") {
                        return Ok(());
                    }
                    // 5.3.5.2: the authorising user must be joined and able
                    // to invite.
                    let Some(authoriser) =
                        str_prop(event.content(), "join_authorised_via_users_server")
                    else {
                        return reject(
                            "member.join.restricted",
                            "restricted join without authorising user",
                        );
                    };
                    let Ok(authoriser) = OwnedUserId::try_from(authoriser) else {
                        return reject(
                            "member.join.restricted",
                            "authorising user is not a valid user ID",
                        );
                    };
                    if membership(state, authoriser.as_str()) != "join" {
                        return reject(
                            "member.join.restricted",
                            "authorising user is not in the room",
                        );
                    }
                    if !power.user(&authoriser).satisfies(power.invite) {
                        return reject("member.join.restricted", "authorising user cannot invite");
                    }
                    // 5.3.5.3.
                    Ok(())
                }
                // 5.3.6.
                "public" => Ok(()),
                // 5.3.7.
                _ => reject("member.join.rule", format!("join_rule {join_rule:?}")),
            }
        }

        // 5.4: invite.
        "invite" => {
            // 5.4.1: third-party invites.
            if let Some(tpi) = obj_prop(event.content(), "third_party_invite") {
                return check_third_party_invite(event, tpi, target, target_mem, state);
            }
            // 5.4.2.
            if sender_mem != "join" {
                return reject("member.invite.sender", "inviter is not joined");
            }
            // 5.4.3.
            if matches!(target_mem, "join" | "ban") {
                return reject("member.invite.target", "target is joined or banned");
            }
            // 5.4.4 / 5.4.5.
            if sender_pl.satisfies(power.invite) {
                Ok(())
            } else {
                reject("member.invite.level", "sender below invite level")
            }
        }

        // 5.5: leave.
        "leave" => {
            // 5.5.1: self-leave (reject an invite, retract a knock, leave).
            if sender.as_str() == target {
                return if matches!(sender_mem, "invite" | "join" | "knock") {
                    Ok(())
                } else {
                    reject(
                        "member.leave.self",
                        "cannot leave without being in the room",
                    )
                };
            }
            // 5.5.2.
            if sender_mem != "join" {
                return reject("member.leave.sender", "kicker is not joined");
            }
            // 5.5.3: unbanning needs the ban level.
            if target_mem == "ban" && !sender_pl.satisfies(power.ban) {
                return reject("member.leave.unban", "sender below ban level");
            }
            // 5.5.4 / 5.5.5: kicking needs the kick level and seniority.
            if sender_pl.satisfies(power.kick) && power.user_from_str(target) < sender_pl {
                Ok(())
            } else {
                reject("member.leave.kick", "sender cannot kick target")
            }
        }

        // 5.6: ban.
        "ban" => {
            // 5.6.1.
            if sender_mem != "join" {
                return reject("member.ban.sender", "banner is not joined");
            }
            // 5.6.2 / 5.6.3.
            if sender_pl.satisfies(power.ban) && power.user_from_str(target) < sender_pl {
                Ok(())
            } else {
                reject("member.ban.level", "sender cannot ban target")
            }
        }

        // 5.7: knock.
        "knock" => {
            // 5.7.1.
            if !matches!(join_rule, "knock" | "knock_restricted") {
                return reject("member.knock.rule", "room does not accept knocks");
            }
            // 5.7.2.
            if sender.as_str() != target {
                return reject("member.knock.sender", "knock sender differs from state_key");
            }
            // 5.7.3 / 5.7.4.
            if !matches!(sender_mem, "ban" | "invite" | "join") {
                Ok(())
            } else {
                reject(
                    "member.knock.membership",
                    "sender is banned, invited or joined",
                )
            }
        }

        // 5.8: unknown membership.
        other => reject("member.unknown", format!("unknown membership {other:?}")),
    }
}

/// Rule 5.4.1: invites carrying a `third_party_invite` block.
fn check_third_party_invite<E: Event>(
    event: &E,
    tpi: &CanonicalJsonObject,
    target: &str,
    target_mem: &str,
    state: &impl StateView<E>,
) -> AuthResult {
    // 5.4.1.1.
    if target_mem == "ban" {
        return reject("member.3pi.ban", "target is banned");
    }
    // 5.4.1.2.
    let Some(signed) = obj_prop(tpi, "signed") else {
        return reject("member.3pi.signed", "third_party_invite without signed");
    };
    // 5.4.1.3.
    let (Some(mxid), Some(token)) = (str_prop(signed, "mxid"), str_prop(signed, "token")) else {
        return reject("member.3pi.signed", "signed without mxid/token");
    };
    // 5.4.1.4.
    if mxid != target {
        return reject("member.3pi.mxid", "signed mxid does not match state_key");
    }
    // 5.4.1.5.
    let Some(tpi_event) = state.get("m.room.third_party_invite", token) else {
        return reject("member.3pi.token", "no matching m.room.third_party_invite");
    };
    // 5.4.1.6.
    if event.sender() != tpi_event.sender() {
        return reject(
            "member.3pi.sender",
            "sender differs from third_party_invite sender",
        );
    }
    // 5.4.1.7 / 5.4.1.8: any signature in `signed` matches any public key
    // in the third_party_invite event.
    let mut candidate_keys: Vec<&str> = Vec::new();
    if let Some(k) = str_prop(tpi_event.content(), "public_key") {
        candidate_keys.push(k);
    }
    if let Some(CanonicalJsonValue::Array(arr)) = tpi_event.content().get("public_keys") {
        for v in arr {
            if let CanonicalJsonValue::Object(o) = v {
                if let Some(k) = str_prop(o, "public_key") {
                    candidate_keys.push(k);
                }
            }
        }
    }
    if signed_by_any_key(signed, &candidate_keys) {
        Ok(())
    } else {
        reject("member.3pi.signature", "no signature matches a public key")
    }
}

/// Whether any signature in `signed.signatures` verifies against any of
/// the base64-encoded ed25519 `candidate_keys`.
fn signed_by_any_key(signed: &CanonicalJsonObject, candidate_keys: &[&str]) -> bool {
    let Ok(message) = to_canonical_json_string_for_signing(signed) else {
        return false;
    };
    let Some(sig_map) = obj_prop(signed, "signatures") else {
        return false;
    };

    let decode = |s: &str| ruma::serde::Base64::<ruma::serde::base64::Standard>::parse(s).ok();

    for key_b64 in candidate_keys {
        let Some(key) = decode(key_b64) else { continue };
        for sigs in sig_map.values() {
            let CanonicalJsonValue::Object(sigs) = sigs else {
                continue;
            };
            for (key_id, sig) in sigs {
                if !key_id.starts_with("ed25519:") {
                    continue;
                }
                let CanonicalJsonValue::String(sig_b64) = sig else {
                    continue;
                };
                let Some(sig) = decode(sig_b64) else { continue };
                if verify_canonical_json_bytes(
                    &SigningKeyAlgorithm::Ed25519,
                    key.as_bytes(),
                    sig.as_bytes(),
                    message.as_bytes(),
                )
                .is_ok()
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Rule 10 (v11 rule 9): `m.room.power_levels` events.
fn check_power_levels<E: Event>(
    version: RoomVersion,
    event: &E,
    state: &impl StateView<E>,
    power: &RoomPowerLevels,
    sender_pl: PowerLevel,
) -> AuthResult {
    let content = event.content();

    // 10.1: scalar level properties must be integers.
    for key in [
        "users_default",
        "events_default",
        "state_default",
        "ban",
        "redact",
        "kick",
        "invite",
    ] {
        match content.get(key) {
            None | Some(CanonicalJsonValue::Integer(_)) => {}
            Some(_) => return reject("power_levels.int", format!("{key} is not an integer")),
        }
    }
    // 10.2: events/notifications must be objects of integers.
    for key in ["events", "notifications"] {
        match content.get(key) {
            None => {}
            Some(CanonicalJsonValue::Object(map))
                if map
                    .values()
                    .all(|v| matches!(v, CanonicalJsonValue::Integer(_))) => {}
            Some(CanonicalJsonValue::Object(_)) => {
                return reject(
                    "power_levels.int",
                    format!("{key} contains a non-integer value"),
                )
            }
            Some(_) => return reject("power_levels.int", format!("{key} is not an object")),
        }
    }
    // 10.3: users must map valid user IDs to integers.
    match content.get("users") {
        None => {}
        Some(CanonicalJsonValue::Object(map)) => {
            for (k, v) in map {
                if OwnedUserId::try_from(k.as_str()).is_err() {
                    return reject("power_levels.users", format!("{k:?} is not a user ID"));
                }
                if !matches!(v, CanonicalJsonValue::Integer(_)) {
                    return reject("power_levels.int", format!("users.{k} is not an integer"));
                }
            }
        }
        Some(_) => return reject("power_levels.users", "users is not an object"),
    }

    // v12 10.4: room creators must not appear in `users`.
    if version.privileged_creators() {
        if let Some(CanonicalJsonValue::Object(users)) = content.get("users") {
            for creator in power.creators() {
                if users.contains_key(creator.as_str()) {
                    return reject(
                        "power_levels.creator",
                        format!("creator {creator} listed in users"),
                    );
                }
            }
        }
    }

    // 10.5: the room's first power-levels event is allowed as-is.
    let Some(previous) = state.get("m.room.power_levels", "") else {
        return Ok(());
    };
    let old = previous.content();

    let get_int = |obj: &CanonicalJsonObject, key: &str| -> Option<i64> {
        match obj.get(key) {
            Some(CanonicalJsonValue::Integer(i)) => Some(i64::from(*i)),
            _ => None,
        }
    };

    // 10.6: scalar alterations — both old and new value must not exceed
    // the sender's level.
    for key in [
        "users_default",
        "events_default",
        "state_default",
        "ban",
        "redact",
        "kick",
        "invite",
    ] {
        let old_v = get_int(old, key);
        let new_v = get_int(content, key);
        if old_v != new_v {
            if let Some(v) = old_v {
                if !sender_pl.satisfies(v) {
                    return reject(
                        "power_levels.alter",
                        format!("cannot change {key} from level {v} above own"),
                    );
                }
            }
            if let Some(v) = new_v {
                if !sender_pl.satisfies(v) {
                    return reject(
                        "power_levels.alter",
                        format!("cannot set {key} to level {v} above own"),
                    );
                }
            }
        }
    }

    // 10.7–10.10: per-entry alterations in events/notifications/users.
    let entry_map = |obj: &CanonicalJsonObject, key: &str| -> BTreeMap<String, i64> {
        match obj.get(key) {
            Some(CanonicalJsonValue::Object(map)) => map
                .iter()
                .filter_map(|(k, v)| match v {
                    CanonicalJsonValue::Integer(i) => Some((k.clone(), i64::from(*i))),
                    _ => None,
                })
                .collect(),
            _ => BTreeMap::new(),
        }
    };

    for key in ["events", "notifications", "users"] {
        let old_map = entry_map(old, key);
        let new_map = entry_map(content, key);
        let is_users = key == "users";

        for (k, old_v) in &old_map {
            let changed_or_removed = new_map.get(k) != Some(old_v);
            if !changed_or_removed {
                continue;
            }
            if is_users {
                // 10.9: strictly-greater-or-equal check, sparing the
                // sender's own entry.
                if k != event.sender().as_str() && PowerLevel::Int(*old_v) >= sender_pl {
                    return reject(
                        "power_levels.demote",
                        format!("cannot alter {k} at level {old_v} at/above own"),
                    );
                }
            } else {
                // 10.7.
                if !sender_pl.satisfies(*old_v) {
                    return reject(
                        "power_levels.alter",
                        format!("cannot alter {key}.{k} from level {old_v} above own"),
                    );
                }
            }
        }
        for (k, new_v) in &new_map {
            let added_or_changed = old_map.get(k) != Some(new_v);
            if !added_or_changed {
                continue;
            }
            // 10.8 / 10.10.
            if !sender_pl.satisfies(*new_v) {
                return reject(
                    "power_levels.grant",
                    format!("cannot set {key}.{k} to level {new_v} above own"),
                );
            }
        }
    }

    // 10.11 (v11 9.10): otherwise, allow.
    Ok(())
}

/// Helper: power level for a possibly-invalid user-ID string (targets come
/// from `state_key`). Invalid IDs get the default level.
trait PowerFromStr {
    fn user_from_str(&self, user: &str) -> PowerLevel;
}

impl PowerFromStr for RoomPowerLevels {
    fn user_from_str(&self, user: &str) -> PowerLevel {
        match <&UserId>::try_from(user) {
            Ok(uid) => self.user(uid),
            Err(_) => PowerLevel::Int(self.users_default),
        }
    }
}
