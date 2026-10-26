//! Outgoing connections that users configure (0.7 phase 5a): identity
//! providers of teams' SSO, audit webhooks and syslog sinks. They must not
//! make the server reach its own network: `https://` (or TLS) to public
//! addresses only, unless the administrator allowed a prefix in the config.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::push::is_public_ip;

/// What may be reached.
#[derive(Debug, Clone, Default)]
pub struct Egress {
    prefixes: Vec<String>,
    hosts: HashSet<String>,
}

impl Egress {
    /// From the allowed prefixes of the config (`http://127.0.0.1:8080/`,
    /// `syslog://10.0.0.5:514`).
    pub fn new(prefixes: &[String]) -> Self {
        let mut out = Self::default();
        for p in prefixes {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            if let Ok(u) = url::Url::parse(p)
                && let Some(h) = u.host_str()
            {
                out.hosts
                    .insert(h.trim_matches(['[', ']']).to_ascii_lowercase());
            }
            out.prefixes.push(p.to_string());
        }
        out
    }

    fn allowed_prefix(&self, s: &str) -> bool {
        self.prefixes.iter().any(|p| s.starts_with(p.as_str()))
    }

    fn private_host(host: &url::Host<&str>) -> bool {
        match host {
            url::Host::Ipv4(ip) => !is_public_ip(IpAddr::V4(*ip)),
            url::Host::Ipv6(ip) => !is_public_ip(IpAddr::V6(*ip)),
            url::Host::Domain(d) => {
                let d = d.to_ascii_lowercase();
                d == "localhost"
                    || d.ends_with(".localhost")
                    || d.ends_with(".local")
                    || d.ends_with(".internal")
                    || !d.contains('.')
            }
        }
    }

    /// Checks an `https://` URL (an issuer, a webhook).
    pub fn check_url(&self, url: &str) -> Result<url::Url, String> {
        let u = url::Url::parse(url.trim()).map_err(|_| "not a URL".to_string())?;
        if !matches!(u.scheme(), "https" | "http") {
            return Err("must be an https URL".into());
        }
        if !u.username().is_empty() || u.password().is_some() {
            return Err("cannot carry a user or password".into());
        }
        let host = u.host().ok_or_else(|| "has no host".to_string())?;
        if self.allowed_prefix(u.as_str()) {
            return Ok(u);
        }
        if u.scheme() != "https" {
            return Err("must be an https URL (or allowed by the administrator)".into());
        }
        if Self::private_host(&host) {
            return Err("is on a private address (the administrator can allow it)".into());
        }
        Ok(u)
    }

    /// Checks a syslog target (`host`, `port`).
    pub fn check_syslog(&self, host: &str, port: u16, tls: bool) -> Result<(), String> {
        let host = host.trim().trim_matches(['[', ']']);
        if host.is_empty() || port == 0 {
            return Err("needs a host and a port".into());
        }
        if self.allowed_prefix(&format!("syslog://{host}:{port}")) {
            return Ok(());
        }
        if !tls {
            return Err("plain TCP is only allowed for targets the administrator allowed".into());
        }
        let h = url::Host::parse(host).map_err(|_| "bad host".to_string())?;
        let h = match &h {
            url::Host::Domain(d) => url::Host::Domain(d.as_str()),
            url::Host::Ipv4(i) => url::Host::Ipv4(*i),
            url::Host::Ipv6(i) => url::Host::Ipv6(*i),
        };
        if Self::private_host(&h) {
            return Err("is on a private address (the administrator can allow it)".into());
        }
        Ok(())
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.hosts.contains(&host.to_ascii_lowercase())
    }

    /// An HTTP client whose names only resolve to public addresses (except
    /// the hosts of allowed prefixes); no redirects.
    pub fn http_client(&self, timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Termoak-Server/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(Resolver(self.clone())))
            .build()
            .unwrap_or_default()
    }

    /// Resolves a syslog host to the addresses it may use.
    pub async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let any = self.host_allowed(host.trim_matches(['[', ']']))
            || self.allowed_prefix(&format!("syslog://{host}:{port}"));
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
            .await?
            .filter(|a| any || is_public_ip(a.ip()))
            .collect();
        if addrs.is_empty() {
            return Err(std::io::Error::other("the target has no public address"));
        }
        Ok(addrs)
    }
}

struct Resolver(Egress);

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let any = self.0.host_allowed(&host);
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| any || is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("the host has no public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_targets() {
        let e = Egress::new(&[
            "http://127.0.0.1:5556/".into(),
            "syslog://10.0.0.5:514".into(),
        ]);
        assert!(e.check_url("https://accounts.google.com").is_ok());
        assert!(e.check_url("http://127.0.0.1:5556/dex").is_ok());
        assert!(e.check_url("http://127.0.0.1:9999/").is_err());
        assert!(e.check_url("https://10.1.2.3/").is_err());
        assert!(e.check_url("https://intranet/").is_err());
        assert!(e.check_url("https://u:p@x.example/").is_err());
        assert!(e.check_syslog("siem.example.com", 6514, true).is_ok());
        assert!(e.check_syslog("siem.example.com", 514, false).is_err());
        assert!(e.check_syslog("10.0.0.5", 514, false).is_ok());
        assert!(e.check_syslog("192.168.1.2", 6514, true).is_err());
    }
}
