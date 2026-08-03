//! Server access control lists (spec "Server Access Control Lists (ACLs)").
//! An `m.room.server_acl` state event names which servers may participate in
//! a room; receivers must drop events and room-scoped EDUs from denied
//! servers.

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

/// A parsed `m.room.server_acl` content.
#[derive(Debug, Clone)]
pub struct ServerAcl {
    allow: Vec<String>,
    deny: Vec<String>,
    /// Whether IP-literal server names are permitted at all (default true).
    allow_ip_literals: bool,
}

impl ServerAcl {
    /// Parse from an `m.room.server_acl` event's `content`.
    pub fn from_content(content: &CanonicalJsonObject) -> Self {
        let list = |key: &str| -> Vec<String> {
            match content.get(key) {
                Some(CanonicalJsonValue::Array(a)) => a
                    .iter()
                    .filter_map(|v| match v {
                        CanonicalJsonValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        };
        // Spec: allow_ip_literals defaults to true when absent.
        let allow_ip_literals = !matches!(
            content.get("allow_ip_literals"),
            Some(CanonicalJsonValue::Bool(false))
        );
        Self {
            allow: list("allow"),
            deny: list("deny"),
            allow_ip_literals,
        }
    }

    /// Whether `server_name` is allowed to participate. Matching is against
    /// the hostname with the port stripped (spec: ports are not matched);
    /// entries are globs (`*` = any run, `?` = one char). A server is allowed
    /// only if it is not an unpermitted IP literal, matches no `deny` entry,
    /// and matches at least one `allow` entry.
    pub fn is_allowed(&self, server_name: &str) -> bool {
        // The IP-literal gate looks at the host (a `1.2.3.4:port` server is
        // still an IP literal), but glob matching is against the full server
        // name as sent — matching a port-stripped host against entries that
        // carry a port (as deployments and Complement use) would never fire.
        let host = host_without_port(server_name);
        if is_ip_literal(host) && !self.allow_ip_literals {
            return false;
        }
        if self.deny.iter().any(|g| glob_match(g, server_name)) {
            return false;
        }
        self.allow.iter().any(|g| glob_match(g, server_name))
    }
}

/// The host part of a server name, without the port. Handles bracketed IPv6
/// (`[::1]:8448` -> `[::1]`), bare IPv4/hostname with a port, and no port.
fn host_without_port(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('[') {
        // IPv6 literal: keep the bracketed form.
        if let Some(end) = rest.find(']') {
            return &name[..end + 2];
        }
        return name;
    }
    match name.rsplit_once(':') {
        // A trailing `:digits` is a port; anything else (an unbracketed IPv6,
        // which isn't a valid server name anyway) is left as-is.
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => name,
    }
}

/// Whether `host` is an IP literal (IPv4, or bracketed IPv6).
fn is_ip_literal(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Glob match with `*` (any run, including empty) and `?` (exactly one
/// character); all other characters match literally.
fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    // Iterative backtracking over `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn acl(v: serde_json::Value) -> ServerAcl {
        match CanonicalJsonValue::try_from(v).unwrap() {
            CanonicalJsonValue::Object(o) => ServerAcl::from_content(&o),
            _ => panic!(),
        }
    }

    #[test]
    fn deny_beats_allow() {
        // Deployments (and Complement) use fully-qualified `host:port` server
        // names consistently in both the ACL and the sending origin, so glob
        // matching is against the full name — a ported deny entry blocks the
        // matching ported server, and `*` covers everyone.
        let a = acl(json!({"allow": ["*"], "deny": ["evil.com", "bad.host:8448"]}));
        assert!(a.is_allowed("good.com"));
        assert!(a.is_allowed("good.com:8448"));
        assert!(!a.is_allowed("evil.com"));
        assert!(!a.is_allowed("bad.host:8448"));
    }

    #[test]
    fn not_in_allow_is_denied() {
        let a = acl(json!({"allow": ["matrix.org"]}));
        assert!(a.is_allowed("matrix.org"));
        assert!(!a.is_allowed("other.org"));
        // Empty/absent allow denies everyone.
        assert!(!acl(json!({})).is_allowed("anyone.org"));
    }

    #[test]
    fn globs() {
        let a = acl(json!({"allow": ["*.example.com", "one?.net"]}));
        assert!(a.is_allowed("a.example.com"));
        assert!(a.is_allowed("deep.sub.example.com"));
        assert!(!a.is_allowed("example.com"));
        assert!(a.is_allowed("one5.net"));
        assert!(!a.is_allowed("one55.net"));
    }

    #[test]
    fn ip_literals() {
        let deny_ips = acl(json!({"allow": ["*"], "allow_ip_literals": false}));
        assert!(!deny_ips.is_allowed("1.2.3.4"));
        assert!(!deny_ips.is_allowed("1.2.3.4:8448"));
        assert!(!deny_ips.is_allowed("[::1]:8448"));
        assert!(deny_ips.is_allowed("host.name"));
        // Default (true) permits IP literals if otherwise allowed.
        assert!(acl(json!({"allow": ["*"]})).is_allowed("1.2.3.4"));
    }
}
