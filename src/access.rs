use crate::geoip::GeoLocation;
use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Open,
    #[default]
    Whitelist,
    Blacklist,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegionMode {
    #[default]
    Any,
    Allow,
    Block,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegionRule {
    pub country: String,
    pub province: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessSettings {
    pub mode: AccessMode,
    pub cidrs: Vec<String>,
    pub region_mode: RegionMode,
    pub regions: Vec<RegionRule>,
    // Unknown covers private/reserved addresses and missing XDB results.
    pub allow_unknown: bool,
    pub trusted_proxies: Vec<String>,
}

impl Default for AccessSettings {
    fn default() -> Self {
        Self {
            mode: AccessMode::default(),
            cidrs: Vec::new(),
            region_mode: RegionMode::default(),
            regions: Vec::new(),
            allow_unknown: false,
            trusted_proxies: vec!["127.0.0.1/32".into(), "::1/128".into()],
        }
    }
}

pub struct AccessPolicy {
    pub settings: AccessSettings,
    networks: Vec<IpNet>,
    proxies: Vec<IpNet>,
}

impl AccessPolicy {
    pub fn compile(mut settings: AccessSettings) -> Result<Self> {
        ensure!(
            settings.cidrs.len() <= 1000 && settings.trusted_proxies.len() <= 100,
            "too many CIDRs"
        );
        let networks = parse_networks(&settings.cidrs)?;
        let proxies = parse_networks(&settings.trusted_proxies)?;
        ensure!(
            settings.mode != AccessMode::Whitelist || !networks.is_empty(),
            "白名单模式至少需要一个网段"
        );
        ensure!(settings.regions.len() <= 500, "too many region rules");
        for rule in &mut settings.regions {
            rule.country = rule.country.trim().to_string();
            rule.province = rule.province.trim().to_string();
            ensure!(
                !rule.country.is_empty() && rule.country.len() <= 100 && rule.province.len() <= 100,
                "地区规则必须指定国家/地区；省级行政区可留空"
            );
        }
        ensure!(
            settings.region_mode != RegionMode::Allow || !settings.regions.is_empty(),
            "地区白名单至少需要一个地区"
        );
        settings.cidrs = networks.iter().map(ToString::to_string).collect();
        settings.trusted_proxies = proxies.iter().map(ToString::to_string).collect();
        Ok(Self {
            settings,
            networks,
            proxies,
        })
    }

    pub fn decide(&self, ip: IpAddr, location: &GeoLocation) -> Result<(), &'static str> {
        let ip = canonical_ip(ip);
        let listed = self.networks.iter().any(|net| net.contains(&ip));
        match self.settings.mode {
            AccessMode::Whitelist if !listed => return Err("client_whitelist"),
            AccessMode::Blacklist if listed => return Err("client_blacklist"),
            _ => {}
        }
        if self.settings.region_mode == RegionMode::Any {
            return Ok(());
        }
        if location.country.is_none() && location.country_code.is_none() {
            return if self.settings.allow_unknown {
                Ok(())
            } else {
                Err("region_unknown")
            };
        }
        let matched = self.settings.regions.iter().any(|rule| {
            let country = location
                .country
                .as_ref()
                .is_some_and(|v| v.eq_ignore_ascii_case(&rule.country))
                || location
                    .country_code
                    .as_ref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(&rule.country));
            country
                && (rule.province.is_empty()
                    || location
                        .province
                        .as_ref()
                        .is_some_and(|v| v == &rule.province))
        });
        match self.settings.region_mode {
            RegionMode::Allow if !matched => Err("region_whitelist"),
            RegionMode::Block if matched => Err("region_blacklist"),
            _ => Ok(()),
        }
    }

    pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        let trusted = |ip: IpAddr| self.proxies.iter().any(|net| net.contains(&ip));
        let mut ip = canonical_ip(peer);
        let Some(value) = forwarded_for else {
            return ip;
        };
        for previous in value.rsplit(',') {
            if !trusted(ip) {
                break;
            }
            let Ok(previous) = previous.trim().parse() else {
                break;
            };
            ip = canonical_ip(previous);
        }
        ip
    }
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn parse_networks(values: &[String]) -> Result<Vec<IpNet>> {
    values
        .iter()
        .map(|s| Ok(s.parse::<IpNet>()?.trunc()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_proxy_defaults_and_explicit_configuration() -> Result<()> {
        let mut settings: AccessSettings = serde_json::from_str(r#"{"mode":"open"}"#)?;
        assert_eq!(settings.trusted_proxies, ["127.0.0.1/32", "::1/128"]);
        let policy = AccessPolicy::compile(settings.clone())?;
        let client: IpAddr = "198.51.100.42".parse()?;
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(
                policy.client_ip(peer.parse()?, Some("invalid-prefix, 198.51.100.42")),
                client
            );
        }
        let untrusted = "127.0.0.2".parse()?;
        assert_eq!(
            policy.client_ip(untrusted, Some("198.51.100.42")),
            untrusted
        );

        settings.trusted_proxies.push("192.0.2.0/24".into());
        let policy = AccessPolicy::compile(settings)?;
        assert_eq!(
            policy.client_ip("127.0.0.1".parse()?, Some("198.51.100.42, 192.0.2.4")),
            client
        );
        let settings: AccessSettings =
            serde_json::from_str(r#"{"mode":"open","trusted_proxies":[]}"#)?;
        let policy = AccessPolicy::compile(settings)?;
        for peer in ["127.0.0.1", "::1"] {
            let peer = peer.parse()?;
            assert_eq!(policy.client_ip(peer, Some("198.51.100.42")), peer);
        }
        Ok(())
    }

    #[test]
    fn modes_regions_unknown_and_proxy_trust() -> Result<()> {
        let mut settings = AccessSettings {
            mode: AccessMode::Open,
            ..Default::default()
        };
        let unknown = GeoLocation::default();
        assert!(
            AccessPolicy::compile(settings.clone())?
                .decide("8.8.8.8".parse()?, &unknown)
                .is_ok()
        );
        settings.mode = AccessMode::Blacklist;
        settings.cidrs = vec!["8.8.8.0/24".into(), "2001:db8::/32".into()];
        let policy = AccessPolicy::compile(settings.clone())?;
        for ip in ["8.8.8.8", "::ffff:8.8.8.8", "2001:db8::1"] {
            assert_eq!(
                policy.decide(ip.parse()?, &unknown),
                Err("client_blacklist")
            );
        }
        settings.mode = AccessMode::Whitelist;
        settings.region_mode = RegionMode::Allow;
        settings.regions = vec![RegionRule {
            country: "CN".into(),
            province: "广东省".into(),
        }];
        settings.trusted_proxies = vec!["127.0.0.0/8".into()];
        let policy = AccessPolicy::compile(settings)?;
        let location = GeoLocation::from_xdb("中国|广东省|深圳市|电信|CN");
        assert!(policy.decide("8.8.8.8".parse()?, &location).is_ok());
        assert_eq!(
            policy.decide("8.8.8.8".parse()?, &unknown),
            Err("region_unknown")
        );
        assert_eq!(
            policy.decide("1.1.1.1".parse()?, &location),
            Err("client_whitelist")
        );
        assert_eq!(
            policy.client_ip("8.8.8.8".parse()?, Some("1.1.1.1")),
            "8.8.8.8".parse::<IpAddr>()?
        );
        assert_eq!(
            policy.client_ip("127.0.0.1".parse()?, Some("9.9.9.9, 8.8.8.8")),
            "8.8.8.8".parse::<IpAddr>()?
        );
        Ok(())
    }
}
