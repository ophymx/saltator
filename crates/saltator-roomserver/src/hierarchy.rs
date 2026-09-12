//! Space-summary building shared by the client-server `GET /hierarchy`
//! endpoint and the federation `GET /hierarchy/{roomId}` endpoint (spec
//! "Spaces" / MSC2946).
//!
//! Reads a room's resolved current state and produces its summary chunk
//! (name, topic, join rule, member count, `room_type`, …) plus the ordered,
//! valid `m.space.child` links. Visibility and traversal live in the callers;
//! this is the pure state-to-summary projection both sides agree on.

use serde_json::{json, Value};

use saltator_store::{Result as StoreResult, StoreError};

use crate::RoomServer;

/// A valid `m.space.child` link out of a space.
pub struct ChildLink {
    /// Target room ID (the child event's `state_key`).
    pub target: String,
    /// A valid `order` key if present; drives child ordering.
    pub order: Option<String>,
    /// `origin_server_ts` of the `m.space.child` event; fallback sort key.
    pub ts: i64,
    /// `content.suggested == true`.
    pub suggested: bool,
    /// The link as a stripped state event (`type`, `state_key`, `content`,
    /// `sender`, `origin_server_ts`) for `children_state`.
    pub stripped: Value,
}

/// A room's summary chunk (without `children_state`, which callers render to
/// honour `suggested_only`) together with the fields callers need for
/// visibility and traversal decisions.
pub struct RoomSummary {
    /// The summary object: `room_id`, `num_joined_members`, `world_readable`,
    /// `guest_can_join`, `join_rule`, and the optional `name`, `topic`,
    /// `canonical_alias`, `avatar_url`, `room_type`, `allowed_room_ids`.
    pub summary: Value,
    /// Valid child links (via present), unordered.
    pub children: Vec<ChildLink>,
    /// Whether `m.room.create` `type` is `m.space`.
    pub is_space: bool,
    /// Effective `m.room.join_rules` `join_rule` (`invite` if unset).
    pub join_rule: String,
    /// Whether history visibility is `world_readable`.
    pub world_readable: bool,
    /// `allow` room IDs for a `restricted` join rule.
    pub allowed_room_ids: Vec<String>,
}

fn codec(e: impl std::fmt::Display) -> StoreError {
    StoreError::Engine(format!("hierarchy summary: {e}"))
}

/// A valid `order` key: a string of at most 50 printable-ASCII (`\x20..=\x7E`)
/// characters (spec "Ordering of children"); anything else is treated as
/// absent.
fn valid_order(content: &Value) -> Option<String> {
    let s = content.get("order")?.as_str()?;
    (s.len() <= 50 && s.bytes().all(|b| (0x20..=0x7E).contains(&b))).then(|| s.to_owned())
}

/// Build the summary of a locally-hosted room, or `None` if this server does
/// not host it.
pub async fn room_summary(rooms: &RoomServer, room_id: &str) -> StoreResult<Option<RoomSummary>> {
    let store = rooms.store();
    let Some(meta) = store.meta(room_id).await? else {
        return Ok(None);
    };
    let current = store.resolve_group(room_id, meta.current_group).await?;

    // Content of the `(event_type, "")` state event, as JSON.
    async fn content_of(
        store: &crate::RoomStore,
        current: &std::collections::BTreeMap<(String, String), String>,
        event_type: &str,
    ) -> StoreResult<Option<Value>> {
        let Some(event_id) = current.get(&(event_type.to_owned(), String::new())) else {
            return Ok(None);
        };
        let Some(stored) = store.event(event_id).await? else {
            return Ok(None);
        };
        let v: Value = serde_json::from_slice(&stored.raw).map_err(codec)?;
        Ok(v.get("content").cloned())
    }
    async fn str_field(
        store: &crate::RoomStore,
        current: &std::collections::BTreeMap<(String, String), String>,
        event_type: &str,
        key: &str,
    ) -> StoreResult<Option<String>> {
        Ok(content_of(store, current, event_type)
            .await?
            .as_ref()
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned))
    }

    let mut joined: u64 = 0;
    let mut children: Vec<ChildLink> = Vec::new();
    for ((event_type, state_key), event_id) in &current {
        if event_type == "m.room.member" {
            let Some(stored) = store.event(event_id).await? else {
                continue;
            };
            let v: Value = serde_json::from_slice(&stored.raw).map_err(codec)?;
            if v.get("content")
                .and_then(|c| c.get("membership"))
                .and_then(Value::as_str)
                == Some("join")
            {
                joined += 1;
            }
            continue;
        }
        if event_type != "m.space.child" {
            continue;
        }
        let Some(stored) = store.event(event_id).await? else {
            continue;
        };
        let ev: Value = serde_json::from_slice(&stored.raw).map_err(codec)?;
        let content = ev.get("content").cloned().unwrap_or(Value::Null);
        // A link is valid iff `content.via` is present as an array; a link is
        // removed by omitting `via`.
        if !content.get("via").map(Value::is_array).unwrap_or(false) {
            continue;
        }
        let ts = ev
            .get("origin_server_ts")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        children.push(ChildLink {
            target: state_key.clone(),
            order: valid_order(&content),
            ts,
            suggested: content
                .get("suggested")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            stripped: json!({
                "type": "m.space.child",
                "state_key": state_key,
                "content": content,
                "sender": ev.get("sender").cloned().unwrap_or(Value::Null),
                "origin_server_ts": ts,
            }),
        });
    }

    let room_type = content_of(&store, &current, "m.room.create")
        .await?
        .as_ref()
        .and_then(|c| c.get("type"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let is_space = room_type.as_deref() == Some("m.space");

    let join_rules = content_of(&store, &current, "m.room.join_rules").await?;
    let join_rule = join_rules
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(Value::as_str)
        .unwrap_or("invite")
        .to_owned();
    let allowed_room_ids: Vec<String> = join_rules
        .as_ref()
        .and_then(|c| c.get("allow"))
        .and_then(Value::as_array)
        .map(|allow| {
            allow
                .iter()
                .filter(|a| a.get("type").and_then(Value::as_str) == Some("m.room_membership"))
                .filter_map(|a| a.get("room_id").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let world_readable = str_field(
        &store,
        &current,
        "m.room.history_visibility",
        "history_visibility",
    )
    .await?
    .as_deref()
        == Some("world_readable");
    let guest_can_join = str_field(&store, &current, "m.room.guest_access", "guest_access")
        .await?
        .as_deref()
        == Some("can_join");

    let mut summary = json!({
        "room_id": room_id,
        "num_joined_members": joined,
        "world_readable": world_readable,
        "guest_can_join": guest_can_join,
        "join_rule": join_rule,
    });
    let obj = summary.as_object_mut().expect("summary is an object");
    if let Some(name) = str_field(&store, &current, "m.room.name", "name").await? {
        obj.insert("name".into(), name.into());
    }
    if let Some(topic) = str_field(&store, &current, "m.room.topic", "topic").await? {
        obj.insert("topic".into(), topic.into());
    }
    if let Some(alias) = str_field(&store, &current, "m.room.canonical_alias", "alias").await? {
        obj.insert("canonical_alias".into(), alias.into());
    }
    if let Some(avatar) = str_field(&store, &current, "m.room.avatar", "url").await? {
        obj.insert("avatar_url".into(), avatar.into());
    }
    if let Some(rt) = &room_type {
        obj.insert("room_type".into(), rt.clone().into());
    }
    if !allowed_room_ids.is_empty() {
        obj.insert("allowed_room_ids".into(), json!(allowed_room_ids));
    }

    Ok(Some(RoomSummary {
        summary,
        children,
        is_space,
        join_rule,
        world_readable,
        allowed_room_ids,
    }))
}

/// Parse a stripped `m.space.child` state event (as carried in a
/// `children_state` array, e.g. from a federation `/hierarchy` response) back
/// into a [`ChildLink`], or `None` if it is not a valid link (`via` absent).
pub fn child_link_from_stripped(stripped: &Value) -> Option<ChildLink> {
    let target = stripped.get("state_key")?.as_str()?.to_owned();
    let content = stripped.get("content").cloned().unwrap_or(Value::Null);
    if !content.get("via").map(Value::is_array).unwrap_or(false) {
        return None;
    }
    let ts = stripped
        .get("origin_server_ts")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Some(ChildLink {
        target,
        order: valid_order(&content),
        ts,
        suggested: content
            .get("suggested")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stripped: stripped.clone(),
    })
}

/// The child links in spec order: children with a valid `order` key sorted
/// lexicographically first, then the rest by `origin_server_ts` ascending,
/// ties broken by target room ID. When `suggested_only`, non-suggested links
/// are dropped.
pub fn ordered_children(children: &[ChildLink], suggested_only: bool) -> Vec<&ChildLink> {
    let mut v: Vec<&ChildLink> = children
        .iter()
        .filter(|c| !suggested_only || c.suggested)
        .collect();
    v.sort_by(|a, b| match (&a.order, &b.order) {
        (Some(x), Some(y)) => x.cmp(y).then(a.ts.cmp(&b.ts)).then(a.target.cmp(&b.target)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.ts.cmp(&b.ts).then(a.target.cmp(&b.target)),
    });
    v
}
