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
    #[serde(default)]
    #[serde(rename = "warmup")]
    _legacy_warmup: Option<toml::Value>,
    pub database: PathBuf,
    pub dns_udp: Option<SocketAddr>,
    pub dns_tcp: Option<SocketAddr>,
    pub doh: Option<SocketAddr>,
    #[serde(default)]
    pub doh_http: bool,
    #[serde(default)]
    pub doh_on_admin: bool,
    pub dot: Option<SocketAddr>,
    pub doq: Option<SocketAddr>,
    pub admin: SocketAddr,
    #[serde(default)]
    pub allow_remote_admin: bool,
    pub allowed_clients: Vec<IpNet>,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
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
        let absolute = std::env::current_dir()?.join(path);
        let base = absolute.parent().unwrap_or_else(|| Path::new("."));
        if config.database.is_relative() {
            config.database = base.join(&config.database);
        }
        for value in [&mut config.certificate, &mut config.private_key] {
            if let Some(path) = value
                && path.is_relative()
            {
                *path = base.join(&*path);
            }
        }
        anyhow::ensure!(
            config.certificate.is_some() == config.private_key.is_some(),
            "certificate and private_key must be configured together"
        );
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
            config.admin.ip().is_loopback() || config.allow_remote_admin,
            "non-loopback admin HTTP requires allow_remote_admin=true"
        );
        anyhow::ensure!(
            !config.doh_on_admin || (config.admin.ip().is_loopback() && config.doh.is_none()),
            "doh_on_admin requires a loopback admin address and no separate doh address"
        );
        Ok(config)
    }
}
