use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: PathBuf,
    pub dns_udp: SocketAddr,
    pub dns_tcp: SocketAddr,
    pub doh: SocketAddr,
    pub dot: SocketAddr,
    pub doq: SocketAddr,
    pub admin: SocketAddr,
    pub allowed_clients: Vec<IpNet>,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub subscription_ca: Option<PathBuf>,
    pub root_hints: Option<PathBuf>,
    #[serde(default = "default_log_days")]
    pub query_log_days: i64,
}

fn default_log_days() -> i64 {
    7
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Self = toml::from_str(&raw).context("parsing configuration")?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for value in [
            &mut config.database,
            &mut config.certificate,
            &mut config.private_key,
        ] {
            if value.is_relative() {
                *value = base.join(&*value);
            }
        }
        if let Some(value) = &mut config.subscription_ca
            && value.is_relative()
        {
            *value = base.join(&*value);
        }
        if let Some(value) = &mut config.root_hints
            && value.is_relative()
        {
            *value = base.join(&*value);
        }
        anyhow::ensure!(
            !config.allowed_clients.is_empty(),
            "allowed_clients must not be empty"
        );
        anyhow::ensure!(
            (1..=90).contains(&config.query_log_days),
            "query_log_days must be 1..90"
        );
        anyhow::ensure!(
            config.admin.ip().is_loopback(),
            "admin HTTP must bind to loopback; use an authenticated TLS reverse proxy for remote management"
        );
        Ok(config)
    }
}
