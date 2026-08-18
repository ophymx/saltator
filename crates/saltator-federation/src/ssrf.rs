//! SSRF protection for server-initiated HTTP fetches (URL previews, push
//! gateway delivery, and — opt-in — federation).
//!
//! Two layers, because reqwest connects to IP-literal URLs without ever
//! consulting a custom resolver:
//!   1. [`is_blocked_ip`] / [`check_url`] reject IP-literal targets up front
//!      and on every redirect hop.
//!   2. [`guarded_client`] installs a DNS resolver that filters blocked
//!      addresses out of every hostname resolution — so redirects and
//!      DNS-rebinding (a name that resolves public once, private next) are
//!      caught at connect time too.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// True if `ip` is loopback, private, link-local, CGNAT, multicast, or any
/// other range an outbound server fetch has no legitimate reason to reach.
/// IPv4-mapped IPv6 addresses are unwrapped and checked as IPv4.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(&mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()          // 0.0.0.0/8
        || ip.is_loopback()      // 127.0.0.0/8
        || ip.is_private()       // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()    // 169.254.0.0/16 (incl. cloud metadata)
        || ip.is_broadcast()     // 255.255.255.255
        || ip.is_multicast()     // 224.0.0.0/4
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 100 && (o[1] & 0xc0) == 64   // 100.64.0.0/10 CGNAT
        || o[0] == 198 && (o[1] & 0xfe) == 18   // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // 240.0.0.0/4 reserved
}

fn is_blocked_v6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    ip.is_unspecified()               // ::
        || ip.is_loopback()           // ::1
        || ip.is_multicast()          // ff00::/8
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 documentation
}

/// Reject a URL whose host is an IP literal in a blocked range. Hostnames
/// pass here and are vetted at resolution time by [`guarded_client`].
/// `allow_internal` (trusted test harnesses only) skips the check.
pub fn check_url(url: &reqwest::Url, allow_internal: bool) -> Result<(), &'static str> {
    if allow_internal {
        return Ok(());
    }
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if is_blocked_ip(&ip) {
                return Err("URL resolves to a disallowed (internal) address");
            }
        }
    }
    Ok(())
}

/// A reqwest DNS resolver that drops blocked addresses from every
/// resolution and fails when a name resolves only to blocked ones.
struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = addrs.filter(|a| !is_blocked_ip(&a.ip())).collect();
            if allowed.is_empty() {
                return Err::<Addrs, _>(
                    "host resolves only to disallowed (internal) addresses".into(),
                );
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// A reqwest client builder wired with the SSRF guard: private-IP-filtering
/// DNS plus a redirect policy that re-checks each hop's IP literal and caps
/// the chain. Callers add their own timeout and then `.build()`.
/// `allow_internal` (trusted test harnesses only) returns a plain builder
/// with just a redirect cap.
pub fn guarded_client(allow_internal: bool) -> reqwest::ClientBuilder {
    if allow_internal {
        return reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(5));
    }
    apply_guard(reqwest::Client::builder())
}

/// Add the SSRF guard — private-IP-filtering DNS plus a redirect policy
/// that re-checks each hop's IP literal and caps the chain — to an
/// existing builder, so callers that need their own TLS/timeout/`resolve`
/// options (federation) can still opt into the guard without discarding
/// them.
pub fn apply_guard(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .dns_resolver(std::sync::Arc::new(GuardedResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if let Some(host) = attempt.url().host_str() {
                if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                    if is_blocked_ip(&ip) {
                        return attempt.error("redirect to a disallowed (internal) address");
                    }
                }
            }
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            attempt.follow()
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_internal_ranges() {
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:10.0.0.1",
        ] {
            assert!(is_blocked_ip(&ip(s)), "should block {s}");
        }
    }

    #[test]
    fn allows_public() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(!is_blocked_ip(&ip(s)), "should allow {s}");
        }
    }

    #[test]
    fn check_url_rejects_literal_and_passes_hostnames() {
        assert!(check_url(
            &reqwest::Url::parse("http://169.254.169.254/x").unwrap(),
            false
        )
        .is_err());
        assert!(check_url(&reqwest::Url::parse("http://[::1]:8080/x").unwrap(), false).is_err());
        assert!(check_url(
            &reqwest::Url::parse("https://example.com/x").unwrap(),
            false
        )
        .is_ok());
        assert!(check_url(&reqwest::Url::parse("https://8.8.8.8/x").unwrap(), false).is_ok());
        // allow_internal bypasses the check.
        assert!(check_url(&reqwest::Url::parse("http://127.0.0.1/x").unwrap(), true).is_ok());
    }
}
