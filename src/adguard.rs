use crate::{
    resolver::{matches_domain, normalize_domain},
    upstream,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    #[serde(skip_serializing)]
    pub use_proxy: bool,
    pub urls: [String; 2],
    pub update_hours: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            use_proxy: false,
            urls: [1, 2].map(|n| {
                format!("https://adguardteam.github.io/HostlistsRegistry/assets/filter_{n}.txt")
            }),
            update_hours: 24,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        for url in &self.urls {
            upstream::validate_https(url)?;
        }
        ensure!(
            (1..=720).contains(&self.update_hours),
            "AdGuard 更新周期需为 1..720 小时"
        );
        Ok(())
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Rules {
    blocked: HashSet<String>,
    except: HashSet<String>,
}
impl Rules {
    pub fn add(&mut self, bytes: &[u8]) -> Result<()> {
        let mut count = 0;
        for line in std::str::from_utf8(bytes)?.lines().map(str::trim) {
            let (rule, exception) = line.strip_prefix("@@").map_or((line, false), |s| (s, true));
            let domain = rule
                .strip_prefix("||")
                .and_then(|s| s.strip_suffix('^'))
                .or_else(|| {
                    let mut fields = rule.split_ascii_whitespace();
                    matches!(fields.next()?, "0.0.0.0" | "127.0.0.1" | "::1")
                        .then(|| fields.next())
                        .flatten()
                });
            if let Some(name) = domain.filter(|s| {
                s.contains('.')
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            }) && let Ok(name) = normalize_domain(name)
            {
                if exception {
                    self.except.insert(name);
                } else {
                    self.blocked.insert(name);
                }
                count += 1;
            }
        }
        ensure!(count > 0, "AdGuard 来源没有可用域名");
        Ok(())
    }
    pub fn blocks(&self, name: &str) -> bool {
        matches_domain(&self.blocked, name) && !matches_domain(&self.except, name)
    }
    pub fn count(&self) -> usize {
        self.blocked.len()
    }
}
