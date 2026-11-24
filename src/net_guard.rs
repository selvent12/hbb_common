//! Local-only network guard.
//!
//! This build must never talk to the internet. Every outgoing connection made through
//! hbb_common (TCP, UDP, WebSocket) is checked here first: the destination has to be an IP
//! literal in a private, loopback or link-local range. Host names are refused before any
//! lookup, so no DNS query is sent either.
//!
//! The same predicate is meant to be reused by the incoming-connection filter.

use crate::ResultType;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Whether `ip` belongs to a network that is not routed on the public internet.
///
/// IPv4: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 and the limited broadcast
/// 255.255.255.255. (100.64/10 carrier-grade NAT is deliberately not included.)
/// IPv6: ::1, fc00::/7 (unique local), fe80::/10 (link-local), and IPv4-mapped forms of
/// the IPv4 ranges above.
pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_ipv4(v4),
        IpAddr::V6(v6) => is_local_ipv6(v6),
    }
}

fn is_local_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast()
}

fn is_local_ipv6(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_local_ipv4(&v4);
    }
    let s = ip.segments();
    ip.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
}

/// Fails unless `addr` is a local destination.
pub fn check_addr(addr: &SocketAddr) -> ResultType<()> {
    if is_local_ip(&addr.ip()) {
        Ok(())
    } else {
        log::warn!("net_guard: blocked outgoing connection to {}", addr);
        crate::bail!("Blocked: {} is not a local address (local-only build)", addr)
    }
}

/// Parses `target` ("ip:port" or "[ipv6]:port") and fails unless it is a local IP literal.
/// Host names are rejected without being resolved.
pub fn check_target(target: &str) -> ResultType<SocketAddr> {
    match target.trim().parse::<SocketAddr>() {
        Ok(addr) => {
            check_addr(&addr)?;
            Ok(addr)
        }
        Err(_) => {
            log::warn!("net_guard: blocked outgoing connection to host name {}", target);
            crate::bail!(
                "Blocked: {} is not a local IP address; host names are not resolved (local-only build)",
                target
            )
        }
    }
}

/// Fails unless the host part of `url` is a local IP literal.
pub fn check_url(url: &str) -> ResultType<()> {
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL {}: {}", url, e))?;
    let ip = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => {
            log::warn!("net_guard: blocked request to {}", url);
            crate::bail!("Blocked: {} has no local IP host (local-only build)", url)
        }
    };
    check_addr(&SocketAddr::new(ip, parsed.port_or_known_default().unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ranges() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "127.0.0.1",
            "169.254.1.1",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_local_ip(&ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "2001:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_local_ip(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn targets() {
        assert!(check_target("192.168.1.5:21118").is_ok());
        assert!(check_target("[fe80::1]:21118").is_ok());
        assert!(check_target("8.8.8.8:53").is_err());
        assert!(check_target("rs-ny.rustdesk.com:21116").is_err());
        assert!(check_target("localhost:21118").is_err());
        assert!(check_url("ws://192.168.1.5:21118").is_ok());
        assert!(check_url("https://api.rustdesk.com").is_err());
        assert!(check_url("https://8.8.8.8/").is_err());
    }
}
