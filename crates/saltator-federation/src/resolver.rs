//! Server-name resolution (spec "Resolving server names"): turn a Matrix
//! server name into a concrete base URL and `Host` header for federation
//! requests.
//!
//! Implemented: IP literals, explicit ports, `.well-known/matrix/server`
//! delegation, SRV records (`_matrix-fed._tcp` and the deprecated
//! `_matrix._tcp`), and the default federation port 8448. An SRV target is
//! dialed directly while TLS/`Host` keep the delegated name, applied as a
//! per-client DNS override (see [`ResolvedServer::connect_addr`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The default Matrix federation port.
const DEFAULT_FED_PORT: u16 = 8448;
/// well-known cache lifetime (spec recommends 24h; errors shorter).
const WELL_KNOWN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const WELL_KNOWN_ERR_TTL: Duration = Duration::from_secs(60 * 60);

/// Where and how to reach a server: the request base (`scheme://authority`)
/// and the `Host` header to present. `connect_addr`, when set, is the
/// concrete socket to dial (an SRV result) while TLS/`Host` still use
/// `host_header` — the client applies it as a DNS override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServer {
    pub base_url: String,
    pub host_header: String,
    pub connect_addr: Option<std::net::SocketAddr>,
}

/// Resolves server names, caching well-known lookups.
pub struct ServerResolver {
    http: reqwest::Client,
    cache: Mutex<HashMap<String, (ResolvedServer, Instant)>>,
    dns: std::sync::OnceLock<Option<hickory_resolver::TokioResolver>>,
    allow_private_ips: bool,
}

impl ServerResolver {
    pub fn new(http: reqwest::Client, allow_private_ips: bool) -> Self {
        Self {
            http,
            cache: Mutex::new(HashMap::new()),
            dns: std::sync::OnceLock::new(),
            allow_private_ips,
        }
    }

    /// Refuse a resolution that would dial a private/loopback/link-local
    /// address, unless `allow_private_ips` was set for a trusted harness
    /// (security review 2026-08-13, Vuln 5 / M2). This covers the two
    /// targets the guarded DNS resolver cannot see: an IP-literal
    /// `base_url` (reqwest connects to it without a DNS lookup) and an SRV
    /// `connect_addr` (applied as a fixed `resolve` override that bypasses
    /// the resolver). Hostname `base_url`s with no override are vetted by
    /// the guarded client at connect time.
    pub fn ensure_allowed(&self, resolved: &ResolvedServer) -> Result<(), &'static str> {
        if self.allow_private_ips {
            return Ok(());
        }
        if let Some(addr) = resolved.connect_addr {
            if crate::ssrf::is_blocked_ip(&addr.ip()) {
                return Err("server resolves to a disallowed (internal) address");
            }
        }
        // The base_url authority may itself be an IP literal (an IP-literal
        // server name, or a well-known/SRV delegation to one).
        if let Ok(url) = reqwest::Url::parse(&resolved.base_url) {
            if let Some(host) = url.host_str() {
                if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                    if crate::ssrf::is_blocked_ip(&ip) {
                        return Err("server resolves to a disallowed (internal) address");
                    }
                }
            }
        }
        Ok(())
    }

    /// The DNS resolver, built from system config on first use. `None` if
    /// it can't be initialized (SRV lookups then fall back to the default
    /// port).
    fn dns(&self) -> Option<&hickory_resolver::TokioResolver> {
        self.dns
            .get_or_init(|| {
                hickory_resolver::TokioResolver::builder_tokio()
                    .map(|b| b.build())
                    .map_err(|e| tracing::warn!(error = %e, "DNS resolver init failed"))
                    .ok()
            })
            .as_ref()
    }

    /// Resolve `server_name` per the spec algorithm: IP literals, explicit
    /// ports, well-known delegation, SRV records, and the default port.
    pub async fn resolve(&self, server_name: &str) -> ResolvedServer {
        if let Some(hit) = self.cached(server_name) {
            return hit;
        }
        let (host, port, is_ip) = split_host_port(server_name);

        // Steps 1 & 2: IP literal, or a hostname with an explicit port —
        // no well-known / SRV, connect directly.
        if is_ip || port.is_some() {
            let resolved = plan_direct(server_name, &host, port, is_ip);
            self.store(server_name, resolved.clone(), WELL_KNOWN_TTL);
            return resolved;
        }

        // Step 3: bare hostname — well-known delegation, else SRV, else
        // the default port on the name itself.
        let (resolved, ttl) = match self.fetch_well_known(&host).await {
            Some(m_server) => (self.resolve_delegated(&m_server).await, WELL_KNOWN_TTL),
            None => (self.resolve_srv_or_default(&host).await, WELL_KNOWN_ERR_TTL),
        };
        self.store(server_name, resolved.clone(), ttl);
        resolved
    }

    /// A well-known `m.server` value: an explicit port connects directly;
    /// otherwise SRV, then the default port.
    async fn resolve_delegated(&self, m_server: &str) -> ResolvedServer {
        let (host, port, is_ip) = split_host_port(m_server);
        if is_ip || port.is_some() {
            return plan_delegated(m_server);
        }
        self.resolve_srv_or_default(&host).await
    }

    /// Try `_matrix-fed._tcp.{host}` then the deprecated `_matrix._tcp`,
    /// falling back to the default federation port on `host`.
    async fn resolve_srv_or_default(&self, host: &str) -> ResolvedServer {
        // Both lookups run concurrently — the common case is that neither
        // record exists, and doing them in series pays two full DNS timeouts
        // on the latency path of the first request to a server. Preference
        // still goes to `_matrix-fed._tcp` when both answer.
        let fed_name = format!("_matrix-fed._tcp.{host}");
        let deprecated_name = format!("_matrix._tcp.{host}");
        let (fed, deprecated) = tokio::join!(
            self.lookup_srv(&fed_name),
            self.lookup_srv(&deprecated_name),
        );
        match fed.or(deprecated) {
            Some(addr) => plan_srv(host, addr),
            None => plan_default(host),
        }
    }

    /// Look up an SRV record and resolve its target to a socket address.
    async fn lookup_srv(&self, name: &str) -> Option<std::net::SocketAddr> {
        let dns = self.dns()?;
        let srv = dns.srv_lookup(name).await.ok()?.into_iter().next()?;
        let target = srv.target().to_utf8();
        let ip = dns.lookup_ip(target).await.ok()?.into_iter().next()?;
        Some(std::net::SocketAddr::new(ip, srv.port()))
    }

    fn cached(&self, name: &str) -> Option<ResolvedServer> {
        let cache = self.cache.lock().expect("resolver cache poisoned");
        cache
            .get(name)
            .and_then(|(r, expiry)| (*expiry > Instant::now()).then(|| r.clone()))
    }

    fn store(&self, name: &str, resolved: ResolvedServer, ttl: Duration) {
        if let Some(expiry) = Instant::now().checked_add(ttl) {
            self.cache
                .lock()
                .expect("resolver cache poisoned")
                .insert(name.to_owned(), (resolved, expiry));
        }
    }

    /// Fetch `https://{host}/.well-known/matrix/server` and return a valid
    /// `m.server` value, or `None` on any error/invalid response.
    async fn fetch_well_known(&self, host: &str) -> Option<String> {
        let url = format!("https://{host}/.well-known/matrix/server");
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        body.get("m.server")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
    }
}

/// Split a server name into `(host, port, is_ip_literal)`, handling
/// bracketed IPv6 (`[::1]:8448`), bare IPv4 (`1.2.3.4:8448`), and hostnames.
fn split_host_port(name: &str) -> (String, Option<u16>, bool) {
    if let Some(rest) = name.strip_prefix('[') {
        // IPv6 literal: `[addr]` optionally followed by `:port`.
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (addr.to_owned(), port, true);
        }
        return (name.to_owned(), None, false);
    }
    // Non-bracketed: an explicit port is a trailing `:digits`.
    if let Some((host, maybe_port)) = name.rsplit_once(':') {
        if let Ok(port) = maybe_port.parse::<u16>() {
            let is_ip = host.parse::<std::net::Ipv4Addr>().is_ok();
            return (host.to_owned(), Some(port), is_ip);
        }
    }
    let is_ip = name.parse::<std::net::Ipv4Addr>().is_ok();
    (name.to_owned(), None, is_ip)
}

/// Bracket an IPv6 literal for use in a URL authority.
fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Steps 1–2: direct connection to an IP literal or explicit host:port.
/// The `Host` header is the original server name.
fn plan_direct(server_name: &str, host: &str, port: Option<u16>, _is_ip: bool) -> ResolvedServer {
    let port = port.unwrap_or(DEFAULT_FED_PORT);
    ResolvedServer {
        base_url: format!("https://{}:{port}", url_host(host)),
        host_header: server_name.to_owned(),
        connect_addr: None,
    }
}

/// Delegated `m.server` = `host[:port]` with a direct connection. A no-port
/// delegation only reaches here as a fallback (the resolver tries SRV
/// first); the port defaults to 8448 and the `Host` header omits it.
fn plan_delegated(m_server: &str) -> ResolvedServer {
    let (host, port, _is_ip) = split_host_port(m_server);
    match port {
        Some(p) => ResolvedServer {
            base_url: format!("https://{}:{p}", url_host(&host)),
            host_header: format!("{host}:{p}"),
            connect_addr: None,
        },
        None => ResolvedServer {
            base_url: format!("https://{}:{DEFAULT_FED_PORT}", url_host(&host)),
            host_header: host,
            connect_addr: None,
        },
    }
}

/// SRV result: connect to `addr`, but TLS/`Host` use `host` (the name the
/// cert must be valid for). The base URL omits the port so the resolve
/// override's port is used.
fn plan_srv(host: &str, addr: std::net::SocketAddr) -> ResolvedServer {
    ResolvedServer {
        base_url: format!("https://{}", url_host(host)),
        host_header: host.to_owned(),
        connect_addr: Some(addr),
    }
}

/// Step 5 fallback: no delegation, default port, Host = hostname.
fn plan_default(host: &str) -> ResolvedServer {
    ResolvedServer {
        base_url: format!("https://{}:{DEFAULT_FED_PORT}", url_host(host)),
        host_header: host.to_owned(),
        connect_addr: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(allow_private_ips: bool) -> ServerResolver {
        ServerResolver::new(reqwest::Client::new(), allow_private_ips)
    }

    fn resolved(base_url: &str, connect_addr: Option<&str>) -> ResolvedServer {
        ResolvedServer {
            base_url: base_url.to_owned(),
            host_header: "example.org".to_owned(),
            connect_addr: connect_addr.map(|a| a.parse().unwrap()),
        }
    }

    /// The pre-auth SSRF guard (Vuln 5 / M2): an IP-literal base_url or an
    /// SRV connect address in a private range is refused, a public one
    /// passes, and a hostname base_url is left to the guarded client.
    #[test]
    fn ensure_allowed_blocks_private_targets() {
        let r = resolver(false);
        // IP-literal base_url in a private/loopback/link-local range.
        for base in [
            "https://127.0.0.1:8448",
            "https://10.1.2.3:8448",
            "https://192.168.0.5:8448",
            "https://169.254.169.254:80", // cloud metadata
            "https://[::1]:8448",
        ] {
            assert!(
                r.ensure_allowed(&resolved(base, None)).is_err(),
                "{base} must be refused"
            );
        }
        // An SRV connect_addr pointing at a private IP, even with a public
        // base_url authority.
        assert!(r
            .ensure_allowed(&resolved("https://example.org:8448", Some("10.0.0.9:8448")))
            .is_err());

        // Public targets pass.
        assert!(r
            .ensure_allowed(&resolved("https://1.1.1.1:8448", None))
            .is_ok());
        assert!(r
            .ensure_allowed(&resolved(
                "https://example.org:8448",
                Some("93.184.216.34:8448")
            ))
            .is_ok());
        // A hostname base_url with no override is vetted later, at connect.
        assert!(r
            .ensure_allowed(&resolved("https://example.org:8448", None))
            .is_ok());
    }

    /// A trusted harness (allow_private_ips) skips the guard entirely.
    #[test]
    fn ensure_allowed_permits_private_when_allowed() {
        let r = resolver(true);
        assert!(r
            .ensure_allowed(&resolved("https://127.0.0.1:8448", None))
            .is_ok());
        assert!(r
            .ensure_allowed(&resolved("https://example.org:8448", Some("10.0.0.9:8448")))
            .is_ok());
    }

    #[test]
    fn ipv4_literal_default_port() {
        let (h, p, ip) = split_host_port("1.2.3.4");
        assert!(ip && p.is_none() && h == "1.2.3.4");
        let r = plan_direct("1.2.3.4", &h, p, ip);
        assert_eq!(r.base_url, "https://1.2.3.4:8448");
        assert_eq!(r.host_header, "1.2.3.4");
    }

    #[test]
    fn ipv4_literal_with_port() {
        let (h, p, ip) = split_host_port("1.2.3.4:9000");
        assert_eq!((h.as_str(), p, ip), ("1.2.3.4", Some(9000), true));
        let r = plan_direct("1.2.3.4:9000", &h, p, ip);
        assert_eq!(r.base_url, "https://1.2.3.4:9000");
        assert_eq!(r.host_header, "1.2.3.4:9000");
    }

    #[test]
    fn ipv6_literal_with_port() {
        let (h, p, ip) = split_host_port("[2001:db8::1]:8448");
        assert_eq!((h.as_str(), p, ip), ("2001:db8::1", Some(8448), true));
        let r = plan_direct("[2001:db8::1]:8448", &h, p, ip);
        assert_eq!(r.base_url, "https://[2001:db8::1]:8448");
        assert_eq!(r.host_header, "[2001:db8::1]:8448");
    }

    #[test]
    fn hostname_with_explicit_port_skips_wellknown() {
        let (h, p, ip) = split_host_port("matrix.example.com:8449");
        assert_eq!(
            (h.as_str(), p, ip),
            ("matrix.example.com", Some(8449), false)
        );
        let r = plan_direct("matrix.example.com:8449", &h, p, ip);
        assert_eq!(r.base_url, "https://matrix.example.com:8449");
        assert_eq!(r.host_header, "matrix.example.com:8449");
    }

    #[test]
    fn bare_hostname_no_wellknown_defaults_8448() {
        // Complement's model: server name resolves directly on :8448.
        let r = plan_default("hs1");
        assert_eq!(r.base_url, "https://hs1:8448");
        assert_eq!(r.host_header, "hs1");
    }

    #[test]
    fn delegation_with_port() {
        // matrix.org-style: m.server carries an explicit port.
        let r = plan_delegated("matrix-federation.matrix.org:443");
        assert_eq!(r.base_url, "https://matrix-federation.matrix.org:443");
        assert_eq!(r.host_header, "matrix-federation.matrix.org:443");
    }

    #[test]
    fn delegation_without_port_defaults_8448() {
        let r = plan_delegated("delegated.example.com");
        assert_eq!(r.base_url, "https://delegated.example.com:8448");
        assert_eq!(r.host_header, "delegated.example.com");
    }

    #[test]
    fn delegation_to_ip_literal_with_port() {
        let r = plan_delegated("10.0.0.5:8448");
        assert_eq!(r.base_url, "https://10.0.0.5:8448");
        assert_eq!(r.host_header, "10.0.0.5:8448");
    }

    #[test]
    fn srv_connects_to_target_but_tls_uses_the_name() {
        let addr = "10.1.2.3:8500".parse().unwrap();
        let r = plan_srv("matrix.example.com", addr);
        // Base URL omits the port so the resolve override's port is used;
        // TLS/Host validate against the delegated name, not the SRV target.
        assert_eq!(r.base_url, "https://matrix.example.com");
        assert_eq!(r.host_header, "matrix.example.com");
        assert_eq!(r.connect_addr, Some(addr));
    }
}
