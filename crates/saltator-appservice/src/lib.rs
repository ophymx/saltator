//! Application service registrations: the model, the YAML loading, and
//! the namespace predicates (docs/design-appservices.md).
//!
//! This crate is deliberately a leaf shared by `saltator-cs-api` (auth,
//! masquerading, the outbound push worker) and `saltator-federation`
//! (query-on-miss for aliases and profiles): both need to answer "which
//! appservice, if any, owns this entity", and the answer must not fork.

mod client;

pub use client::{AppServiceClient, AppServiceQuerier, PingError, PushError};

use regex::Regex;
use serde::Deserialize;

/// One application service, as registered by its YAML file.
#[derive(Debug)]
pub struct AppServiceRegistration {
    /// Unique, admin-chosen, stable identifier. Uniqueness is enforced at
    /// load (the spec MUSTs it; both `id` and `as_token` identify the AS).
    pub id: String,
    /// Base URL for the homeserver→AS direction. `None` means the AS
    /// wants no traffic at all: no push, no queries, no ping.
    pub url: Option<String>,
    /// The token the AS authenticates to us with.
    pub as_token: String,
    /// The token we authenticate to the AS with (Bearer, every request).
    pub hs_token: String,
    /// Localpart of the AS's own user (`@{sender_localpart}:{server}`).
    pub sender_localpart: String,
    pub namespaces: Namespaces,
    /// Whether *masqueraded* users are rate-limited. The sender never is.
    pub rate_limited: bool,
    /// Whether the AS wants typing/receipt/presence data in its
    /// transactions. Parsed, currently logged-and-ignored (deferred —
    /// docs/design-appservices.md).
    pub receive_ephemeral: bool,
    /// Third-party protocol ids the AS bridges (informational for now;
    /// `/thirdparty` proxying is deferred).
    pub protocols: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Namespaces {
    pub users: Vec<Namespace>,
    pub aliases: Vec<Namespace>,
    pub rooms: Vec<Namespace>,
}

#[derive(Debug)]
pub struct Namespace {
    pub exclusive: bool,
    /// Compiled wrapped as `^(?:…)` — Synapse parity: Python's
    /// `re.match` anchors the start and only the start, and every
    /// registration file in the wild was written against that.
    pub regex: Regex,
}

impl Namespace {
    fn matches(&self, s: &str) -> bool {
        self.regex.is_match(s)
    }
}

fn ns_matches<'a>(list: &'a [Namespace], s: &str) -> Option<&'a Namespace> {
    list.iter().find(|n| n.matches(s))
}

impl AppServiceRegistration {
    /// The AS's own full user id on this server.
    pub fn sender_user(&self, server_name: &str) -> String {
        format!("@{}:{}", self.sender_localpart, server_name)
    }

    /// Whether the AS may act as / is interested in this user: its own
    /// sender, or a `users` namespace match.
    pub fn is_interested_in_user(&self, user_id: &str, server_name: &str) -> bool {
        self.sender_user(server_name) == user_id
            || ns_matches(&self.namespaces.users, user_id).is_some()
    }

    pub fn is_interested_in_room_id(&self, room_id: &str) -> bool {
        ns_matches(&self.namespaces.rooms, room_id).is_some()
    }

    pub fn is_interested_in_alias(&self, alias: &str) -> bool {
        ns_matches(&self.namespaces.aliases, alias).is_some()
    }

    /// Whether this AS claims the user exclusively (its sender always is:
    /// nobody else may register it).
    pub fn is_exclusive_user(&self, user_id: &str, server_name: &str) -> bool {
        self.sender_user(server_name) == user_id
            || ns_matches(&self.namespaces.users, user_id).is_some_and(|n| n.exclusive)
    }

    pub fn is_exclusive_alias(&self, alias: &str) -> bool {
        ns_matches(&self.namespaces.aliases, alias).is_some_and(|n| n.exclusive)
    }
}

/// All registered application services, in file order. Registrations
/// are `Arc`ed so an authenticated request can carry a handle to the
/// one that authenticated it without cloning the compiled regexes.
#[derive(Debug, Default)]
pub struct AppServices {
    pub services: Vec<std::sync::Arc<AppServiceRegistration>>,
}

impl AppServices {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    pub fn by_token(&self, as_token: &str) -> Option<&std::sync::Arc<AppServiceRegistration>> {
        self.services.iter().find(|a| a.as_token == as_token)
    }

    pub fn by_id(&self, id: &str) -> Option<&std::sync::Arc<AppServiceRegistration>> {
        self.services.iter().find(|a| a.id == id)
    }

    /// Whether a *non-appservice* actor may claim this user id: some AS
    /// holds it exclusively → `false`.
    pub fn user_claimable_by_others(&self, user_id: &str, server_name: &str) -> bool {
        !self
            .services
            .iter()
            .any(|a| a.is_exclusive_user(user_id, server_name))
    }

    /// Same question for a room alias.
    pub fn alias_claimable_by_others(&self, alias: &str) -> bool {
        !self.services.iter().any(|a| a.is_exclusive_alias(alias))
    }

    /// The appservices whose alias namespaces cover `alias` and which can
    /// be asked about it (non-null `url`).
    pub fn alias_query_candidates(
        &self,
        alias: &str,
    ) -> Vec<std::sync::Arc<AppServiceRegistration>> {
        self.services
            .iter()
            .filter(|a| a.url.is_some() && a.is_interested_in_alias(alias))
            .cloned()
            .collect()
    }

    /// The appservices whose user namespaces cover `user_id` and which
    /// can be asked about it (non-null `url`).
    pub fn user_query_candidates(
        &self,
        user_id: &str,
        server_name: &str,
    ) -> Vec<std::sync::Arc<AppServiceRegistration>> {
        self.services
            .iter()
            .filter(|a| a.url.is_some() && a.is_interested_in_user(user_id, server_name))
            .cloned()
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("{file}: {source}")]
    Yaml {
        file: String,
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("{file}: invalid {ns} namespace regex `{regex}`: {source}")]
    BadRegex {
        file: String,
        ns: &'static str,
        regex: String,
        #[source]
        source: regex::Error,
    },
    #[error("{file}: `{field}` must not be empty")]
    EmptyField { file: String, field: &'static str },
    #[error("duplicate appservice {what} `{value}` ({file_a} and {file_b}); each registration must be unique")]
    Duplicate {
        what: &'static str,
        value: String,
        file_a: String,
        file_b: String,
    },
    #[error("appservice registration dir {dir}: {source}")]
    Dir {
        dir: String,
        #[source]
        source: std::io::Error,
    },
}

/// The raw file shape. `deny_unknown_fields` is deliberately absent:
/// registration files are written by bridge software and routinely carry
/// extra keys (`de.sorunome.msc2409.push_ephemeral`, comments-as-keys…).
#[derive(Deserialize)]
struct RawRegistration {
    id: String,
    #[serde(default)]
    url: Option<String>,
    as_token: String,
    hs_token: String,
    sender_localpart: String,
    #[serde(default)]
    namespaces: RawNamespaces,
    #[serde(default = "default_true")]
    rate_limited: bool,
    #[serde(default)]
    receive_ephemeral: bool,
    #[serde(default)]
    protocols: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, Default)]
struct RawNamespaces {
    #[serde(default)]
    users: Vec<RawNamespace>,
    #[serde(default)]
    aliases: Vec<RawNamespace>,
    #[serde(default)]
    rooms: Vec<RawNamespace>,
}

#[derive(Deserialize)]
struct RawNamespace {
    #[serde(default)]
    exclusive: bool,
    regex: String,
}

fn compile_ns(
    file: &str,
    ns: &'static str,
    raw: Vec<RawNamespace>,
) -> Result<Vec<Namespace>, RegistrationError> {
    raw.into_iter()
        .map(|r| {
            // `^(?:…)`: anchor the start, group so alternation in the raw
            // pattern cannot escape the anchor.
            Regex::new(&format!("^(?:{})", r.regex))
                .map(|regex| Namespace {
                    exclusive: r.exclusive,
                    regex,
                })
                .map_err(|source| RegistrationError::BadRegex {
                    file: file.to_owned(),
                    ns,
                    regex: r.regex,
                    source,
                })
        })
        .collect()
}

/// Parse one registration file's contents.
pub fn parse_registration(
    file: &str,
    text: &str,
) -> Result<AppServiceRegistration, RegistrationError> {
    let raw: RawRegistration =
        serde_yaml_ng::from_str(text).map_err(|source| RegistrationError::Yaml {
            file: file.to_owned(),
            source,
        })?;
    for (field, value) in [
        ("id", &raw.id),
        ("as_token", &raw.as_token),
        ("hs_token", &raw.hs_token),
        ("sender_localpart", &raw.sender_localpart),
    ] {
        if value.is_empty() {
            return Err(RegistrationError::EmptyField {
                file: file.to_owned(),
                field,
            });
        }
    }
    let url = match raw.url {
        // `url: null` and a missing key both mean "no outbound traffic";
        // an empty string is treated the same (Synapse parity).
        Some(u) if !u.is_empty() => Some(u.trim_end_matches('/').to_owned()),
        _ => None,
    };
    Ok(AppServiceRegistration {
        id: raw.id,
        url,
        as_token: raw.as_token,
        hs_token: raw.hs_token,
        sender_localpart: raw.sender_localpart,
        namespaces: Namespaces {
            users: compile_ns(file, "users", raw.namespaces.users)?,
            aliases: compile_ns(file, "aliases", raw.namespaces.aliases)?,
            rooms: compile_ns(file, "rooms", raw.namespaces.rooms)?,
        },
        rate_limited: raw.rate_limited,
        receive_ephemeral: raw.receive_ephemeral,
        protocols: raw.protocols,
    })
}

/// Load every `*.yaml` in a directory. Any invalid file is a hard error —
/// a silently dropped bridge is worse than a refused boot — as is a
/// duplicate `id` or `as_token` across files (spec MUST).
pub fn load_dir(dir: &str) -> Result<AppServices, RegistrationError> {
    let entries = std::fs::read_dir(dir).map_err(|source| RegistrationError::Dir {
        dir: dir.to_owned(),
        source,
    })?;
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yaml"))
        .collect();
    // Deterministic load order, so "first file wins" arguments never
    // depend on the filesystem.
    paths.sort();

    let mut services: Vec<std::sync::Arc<AppServiceRegistration>> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    for path in paths {
        let file = path.display().to_string();
        let text = std::fs::read_to_string(&path).map_err(|source| RegistrationError::Dir {
            dir: file.clone(),
            source,
        })?;
        let reg = parse_registration(&file, &text)?;
        for (prev, prev_file) in services.iter().zip(&sources) {
            let dup = if prev.id == reg.id {
                Some(("id", reg.id.clone()))
            } else if prev.as_token == reg.as_token {
                Some(("as_token", "<redacted>".to_owned()))
            } else {
                None
            };
            if let Some((what, value)) = dup {
                return Err(RegistrationError::Duplicate {
                    what,
                    value,
                    file_a: prev_file.clone(),
                    file_b: file,
                });
            }
        }
        tracing::info!(file = %file, id = %reg.id, sender = %reg.sender_localpart,
            url = reg.url.as_deref().unwrap_or("<none>"),
            "loaded appservice registration");
        if reg.receive_ephemeral {
            tracing::warn!(id = %reg.id,
                "receive_ephemeral is not implemented; the appservice will not get typing/receipt data");
        }
        services.push(std::sync::Arc::new(reg));
        sources.push(file);
    }
    Ok(AppServices { services })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAUTRIX_STYLE: &str = r#"
id: telegram
url: http://localhost:29317/
as_token: as_secret
hs_token: hs_secret
sender_localpart: telegrambot
rate_limited: false
namespaces:
    users:
    - exclusive: true
      regex: '@telegram_.*:example\.com'
    aliases:
    - exclusive: true
      regex: '#telegram_.*:example\.com'
de.sorunome.msc2409.push_ephemeral: true
"#;

    #[test]
    fn parses_a_real_registration() {
        let reg = parse_registration("t.yaml", MAUTRIX_STYLE).unwrap();
        assert_eq!(reg.id, "telegram");
        // Trailing slash trimmed so path joins can't double it.
        assert_eq!(reg.url.as_deref(), Some("http://localhost:29317"));
        assert!(!reg.rate_limited);
        assert!(!reg.receive_ephemeral);
        assert!(reg.is_interested_in_user("@telegram_12345:example.com", "example.com"));
        assert!(reg.is_exclusive_user("@telegram_12345:example.com", "example.com"));
        assert!(reg.is_interested_in_user("@telegrambot:example.com", "example.com"));
        assert!(!reg.is_interested_in_user("@alice:example.com", "example.com"));
        assert!(reg.is_interested_in_alias("#telegram_chat:example.com"));
    }

    #[test]
    fn regexes_anchor_start_only() {
        // Synapse parity: `re.match` semantics. `@p_.*` written without a
        // trailing anchor matches any longer string, but never mid-string.
        let reg = parse_registration(
            "t.yaml",
            r#"
id: x
url: null
as_token: a
hs_token: h
sender_localpart: bot
namespaces:
  users:
  - regex: '@p_[0-9]+'
"#,
        )
        .unwrap();
        assert!(reg.is_interested_in_user("@p_123:anything.also.after", "s"));
        assert!(!reg.is_interested_in_user("x@p_123", "s"));
        // Alternation cannot escape the anchor: `a|b` compiles as ^(?:a|b).
        let reg2 = parse_registration(
            "t.yaml",
            "id: y\nurl:\nas_token: a\nhs_token: h\nsender_localpart: b\nnamespaces:\n  users:\n  - regex: '@a.*|@b.*'\n",
        )
        .unwrap();
        assert!(!reg2.is_interested_in_user("zzz@b_1", "s"));
        assert!(reg2.is_interested_in_user("@b_1", "s"));
    }

    #[test]
    fn null_and_missing_url_disable_traffic() {
        for url_line in ["url: null", "url:", ""] {
            let text =
                format!("id: x\n{url_line}\nas_token: a\nhs_token: h\nsender_localpart: bot\n");
            let reg = parse_registration("t.yaml", &text).unwrap();
            assert!(reg.url.is_none(), "case {url_line:?}");
        }
    }

    #[test]
    fn defaults_and_missing_namespaces() {
        let reg = parse_registration(
            "t.yaml",
            "id: x\nurl: http://x\nas_token: a\nhs_token: h\nsender_localpart: bot\n",
        )
        .unwrap();
        assert!(reg.rate_limited, "rate_limited defaults to true");
        assert!(reg.namespaces.users.is_empty());
        // Only the sender is claimable.
        assert!(reg.is_interested_in_user("@bot:s", "s"));
        assert!(!reg.is_interested_in_user("@other:s", "s"));
    }

    #[test]
    fn bad_regex_is_an_error_not_a_skip() {
        let err = parse_registration(
            "t.yaml",
            "id: x\nurl:\nas_token: a\nhs_token: h\nsender_localpart: b\nnamespaces:\n  users:\n  - regex: '@[unclosed'\n",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::BadRegex { ns: "users", .. }
        ));
    }

    #[test]
    fn exclusivity_across_services() {
        let a = parse_registration(
            "a.yaml",
            "id: a\nurl:\nas_token: ta\nhs_token: h\nsender_localpart: abot\nnamespaces:\n  users:\n  - {exclusive: true, regex: '@irc_.*'}\n  aliases:\n  - {exclusive: false, regex: '#log_.*'}\n",
        )
        .unwrap();
        let svcs = AppServices {
            services: vec![std::sync::Arc::new(a)],
        };
        assert!(!svcs.user_claimable_by_others("@irc_bob:s", "s"));
        assert!(
            !svcs.user_claimable_by_others("@abot:s", "s"),
            "sender is always exclusive"
        );
        assert!(svcs.user_claimable_by_others("@alice:s", "s"));
        // Non-exclusive alias namespace: others may still create there.
        assert!(svcs.alias_claimable_by_others("#log_x:s"));
    }

    #[test]
    fn duplicate_tokens_refuse_to_load() {
        let dir = std::env::temp_dir().join(format!("as-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["one.yaml", "two.yaml"] {
            std::fs::write(
                dir.join(name),
                "id: same\nurl:\nas_token: tok\nhs_token: h\nsender_localpart: b\n",
            )
            .unwrap();
        }
        let err = load_dir(dir.to_str().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::Duplicate { what: "id", .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
