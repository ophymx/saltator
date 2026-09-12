//! Push rules and pushers (spec.md §5.5). Rules are stored as the user's
//! `m.push_rules` account data (content `{"global": <ruleset>}`), so every
//! mutation bumps the user-shard seq — incremental syncs wake and re-emit
//! the rules like any other account-data change. Rule *evaluation* (HTTP
//! pushes to gateways) is a later brick; pushers are stored and listed.

use std::sync::Arc;

use axum::extract::{Path, State};
use serde_json::{json, Value};

use ruma::push::{
    Action, NewConditionalPushRule, NewPatternedPushRule, NewPushRule, NewSimplePushRule, RuleKind,
    Ruleset,
};
use ruma::UserId;

use crate::error::ApiError;
use crate::extract::{Auth, Jb};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;
type JsonResp = Result<axum::Json<Value>>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// The user's rules: their stored customization, or the server defaults.
pub(crate) fn load_ruleset(state: &CsState, user_id: &UserId) -> Result<Ruleset> {
    if let Some(entry) = state
        .users
        .store()
        .account_data(user_id.as_str(), "", "m.push_rules")
        .map_err(internal)?
    {
        if let Some(global) = serde_json::from_slice::<Value>(&entry.json)
            .ok()
            .and_then(|mut c| c.get_mut("global").map(Value::take))
        {
            if let Ok(ruleset) = serde_json::from_value(global) {
                return Ok(ruleset);
            }
        }
    }
    Ok(Ruleset::server_default(user_id))
}

async fn save_ruleset(state: &CsState, user_id: &UserId, ruleset: &Ruleset) -> Result<()> {
    let content = serde_json::to_vec(&json!({ "global": ruleset })).map_err(internal)?;
    state
        .users
        .put_account_data(user_id, "", "m.push_rules", content)
        .await?;
    Ok(())
}

/// Serialize this user's rule mutations: every load→mutate→save must hold
/// this, or concurrent writers (e.g. two parallel joins copying upgrade
/// rules) lose updates.
async fn lock_rules(state: &CsState, user_id: &UserId) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut map = state.push_rule_locks.lock().await;
        map.entry(user_id.to_string()).or_default().clone()
    };
    lock.lock_owned().await
}

/// `GET /pushrules/`: the full ruleset.
pub async fn get_pushrules(State(state): State<Arc<CsState>>, auth: Auth) -> JsonResp {
    let ruleset = load_ruleset(&state, &auth.user_id)?;
    Ok(axum::Json(json!({ "global": ruleset })))
}

/// The serialized form of one rule, looked up by kind + id (string-level:
/// the stored shape is what clients must see back).
fn find_rule(ruleset: &Ruleset, kind: &str, rule_id: &str) -> Result<Value> {
    let global = serde_json::to_value(ruleset).map_err(internal)?;
    global
        .get(kind)
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|r| r.get("rule_id").and_then(|i| i.as_str()) == Some(rule_id))
        })
        .cloned()
        .ok_or_else(|| ApiError::not_found("No such push rule"))
}

/// `GET /pushrules/global/{kind}/{ruleId}`: one rule, 404 when absent.
pub async fn get_pushrule(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((kind, rule_id)): Path<(String, String)>,
) -> JsonResp {
    let ruleset = load_ruleset(&state, &auth.user_id)?;
    Ok(axum::Json(find_rule(&ruleset, &kind, &rule_id)?))
}

/// `GET /pushrules/global/{kind}/{ruleId}/{enabled|actions}`.
pub async fn get_pushrule_attr(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((kind, rule_id, attr)): Path<(String, String, String)>,
) -> JsonResp {
    let ruleset = load_ruleset(&state, &auth.user_id)?;
    let rule = find_rule(&ruleset, &kind, &rule_id)?;
    match attr.as_str() {
        "enabled" | "actions" => Ok(axum::Json(json!({ &attr: rule[&attr] }))),
        _ => Err(ApiError::invalid_param("Unknown rule attribute")),
    }
}

/// `DELETE /pushrules/global/{kind}/{ruleId}`.
pub async fn delete_pushrule(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((kind, rule_id)): Path<(String, String)>,
) -> JsonResp {
    let _guard = lock_rules(&state, &auth.user_id).await;
    let mut ruleset = load_ruleset(&state, &auth.user_id)?;
    ruleset
        .remove(RuleKind::from(kind.as_str()), &rule_id)
        .map_err(|_| ApiError::not_found("No such push rule"))?;
    save_ruleset(&state, &auth.user_id, &ruleset).await?;
    Ok(axum::Json(json!({})))
}

/// `PUT /pushrules/global/{kind}/{ruleId}`: create or replace a rule.
pub async fn put_pushrule(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((kind, rule_id)): Path<(String, String)>,
    Jb(body): Jb,
) -> JsonResp {
    let actions: Vec<Action> = match body.get("actions") {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| ApiError::invalid_param(format!("actions: {e}")))?,
        None => return Err(ApiError::invalid_param("Missing actions")),
    };
    let rule = match kind.as_str() {
        "room" => {
            let room_id = rule_id
                .parse()
                .map_err(|_| ApiError::invalid_param("room rule ID must be a room ID"))?;
            NewPushRule::Room(NewSimplePushRule::new(room_id, actions))
        }
        "sender" => {
            let user_id = rule_id
                .parse()
                .map_err(|_| ApiError::invalid_param("sender rule ID must be a user ID"))?;
            NewPushRule::Sender(NewSimplePushRule::new(user_id, actions))
        }
        "content" => {
            let pattern = body
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::invalid_param("Missing pattern"))?;
            NewPushRule::Content(NewPatternedPushRule::new(
                rule_id.clone(),
                pattern.to_owned(),
                actions,
            ))
        }
        "override" | "underride" => {
            let conditions = match body.get("conditions") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| ApiError::invalid_param(format!("conditions: {e}")))?,
                None => Vec::new(),
            };
            let rule = NewConditionalPushRule::new(rule_id.clone(), conditions, actions);
            if kind == "override" {
                NewPushRule::Override(rule)
            } else {
                NewPushRule::Underride(rule)
            }
        }
        _ => return Err(ApiError::invalid_param("Unknown rule kind")),
    };

    let _guard = lock_rules(&state, &auth.user_id).await;
    let mut ruleset = load_ruleset(&state, &auth.user_id)?;
    ruleset
        .insert(rule, None, None)
        .map_err(|e| ApiError::invalid_param(e.to_string()))?;
    save_ruleset(&state, &auth.user_id, &ruleset).await?;
    Ok(axum::Json(json!({})))
}

/// `PUT /pushrules/global/{kind}/{ruleId}/{enabled|actions}`.
pub async fn put_pushrule_attr(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((kind, rule_id, attr)): Path<(String, String, String)>,
    Jb(body): Jb,
) -> JsonResp {
    let kind = RuleKind::from(kind.as_str());
    let _guard = lock_rules(&state, &auth.user_id).await;
    let mut ruleset = load_ruleset(&state, &auth.user_id)?;
    match attr.as_str() {
        "enabled" => {
            let enabled = body
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| ApiError::invalid_param("Missing enabled"))?;
            ruleset
                .set_enabled(kind, &rule_id, enabled)
                .map_err(|_| ApiError::not_found("No such push rule"))?;
        }
        "actions" => {
            let actions: Vec<Action> = match body.get("actions") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| ApiError::invalid_param(format!("actions: {e}")))?,
                None => return Err(ApiError::invalid_param("Missing actions")),
            };
            ruleset
                .set_actions(kind, &rule_id, actions)
                .map_err(|_| ApiError::not_found("No such push rule"))?;
        }
        _ => return Err(ApiError::invalid_param("Unknown rule attribute")),
    }
    save_ruleset(&state, &auth.user_id, &ruleset).await?;
    Ok(axum::Json(json!({})))
}

/// `GET /pushers`: every pusher of the user.
pub async fn get_pushers(State(state): State<Arc<CsState>>, auth: Auth) -> JsonResp {
    let pushers: Vec<Value> = state
        .users
        .store()
        .pushers(auth.user_id.as_str())
        .map_err(internal)?
        .iter()
        .filter_map(|b| serde_json::from_slice(b).ok())
        .collect();
    Ok(axum::Json(json!({ "pushers": pushers })))
}

/// `POST /pushers/set`: create/replace a pusher, or delete it when `kind`
/// is null.
pub async fn set_pushers(State(state): State<Arc<CsState>>, auth: Auth, Jb(body): Jb) -> JsonResp {
    let app_id = body
        .get("app_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::invalid_param("Missing app_id"))?
        .to_owned();
    let pushkey = body
        .get("pushkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::invalid_param("Missing pushkey"))?
        .to_owned();
    let delete = body.get("kind").is_none_or(|k| k.is_null());
    // http pushers must name a gateway, and the spec fixes its path.
    if !delete && body.get("kind").and_then(|k| k.as_str()) == Some("http") {
        let url = body
            .get("data")
            .and_then(|d| d.get("url"))
            .and_then(|u| u.as_str())
            .ok_or_else(|| ApiError::invalid_param("http pushers require data.url"))?;
        if !url.ends_with("/_matrix/push/v1/notify") {
            return Err(ApiError::invalid_param(
                "data.url must end with /_matrix/push/v1/notify",
            ));
        }
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| ApiError::invalid_param("data.url is not a valid URL"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ApiError::invalid_param("data.url must be http(s)"));
        }
        // Reject a gateway pointed at an internal literal up front; hostname
        // targets are re-vetted at delivery by the guarded client.
        saltator_federation::ssrf::check_url(&parsed, state.config.allow_internal_fetch)
            .map_err(ApiError::forbidden)?;
    }
    let json = if delete {
        None
    } else {
        let mut obj = body.clone();
        obj.remove("append");
        Some(serde_json::to_vec(&Value::Object(obj)).map_err(internal)?)
    };
    state
        .users
        .set_pusher(&auth.user_id, &auth.device_id, &app_id, &pushkey, json)
        .await?;
    Ok(axum::Json(json!({})))
}

/// Room-upgrade carry-over (Synapse-compatible behavior, not spec'd):
/// when a local user joins a room that declares a predecessor, copies of
/// their push rules referencing the old room are re-pointed at the new
/// one. The old rules stay — they still apply to the tombstoned room.
pub(crate) async fn copy_rules_from_predecessor(
    state: &CsState,
    user_id: &UserId,
    room_id: &str,
) -> Result<()> {
    // Nothing stored means nothing can reference the old room.
    if state
        .users
        .store()
        .account_data(user_id.as_str(), "", "m.push_rules")
        .map_err(internal)?
        .is_none()
    {
        return Ok(());
    }
    let Some(predecessor) = crate::room_util::predecessor_of(&state.rooms, room_id).await? else {
        return Ok(());
    };
    let Ok(new_room_id) = ruma::OwnedRoomId::try_from(room_id.to_owned()) else {
        return Ok(());
    };
    let _guard = lock_rules(state, user_id).await;
    let mut ruleset = load_ruleset(state, user_id)?;
    let copied: Vec<NewPushRule> = ruleset
        .room
        .iter()
        .filter(|r| r.rule_id.as_str() == predecessor)
        .map(|r| {
            NewPushRule::Room(NewSimplePushRule::new(
                new_room_id.clone(),
                r.actions.clone(),
            ))
        })
        .collect();
    if copied.is_empty() {
        return Ok(());
    }
    for rule in copied {
        let _ = ruleset.insert(rule, None, None);
    }
    save_ruleset(state, user_id, &ruleset).await
}
