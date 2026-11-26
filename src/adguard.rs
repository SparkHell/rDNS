use crate::{
    resolver::{domain_glob, domain_regex, matches_domain, normalize_domain},
    upstream,
};
use anyhow::{Result, ensure};
use regex::{RegexSet, RegexSetBuilder};
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
    #[serde(default)]
    skipped: usize,
    #[serde(default)]
    block_patterns: HashSet<String>,
    #[serde(default)]
    except_patterns: HashSet<String>,
    #[serde(skip)]
    compiled_blocks: RegexSet,
    #[serde(skip)]
    compiled_exceptions: RegexSet,
}
impl Rules {
    pub fn add(&mut self, bytes: &[u8]) -> Result<()> {
        let mut count = 0;
        for line in std::str::from_utf8(bytes)?
            .trim_start_matches('\u{feff}')
            .lines()
            .map(str::trim)
        {
            if line.is_empty() || line.starts_with(['!', '#', '[']) {
                continue;
            }
            let (rule, exception) = line.strip_prefix("@@").map_or((line, false), |s| (s, true));
            if let Some(expression) = adguard_expression(rule) {
                if domain_regex(&expression).is_ok() {
                    if exception {
                        self.except_patterns.insert(expression);
                    } else {
                        self.block_patterns.insert(expression);
                    }
                    count += 1;
                } else {
                    self.skipped += 1;
                }
                continue;
            }
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
            } else {
                self.skipped += 1;
            }
        }
        ensure!(count > 0, "AdGuard 来源没有可用规则");
        Ok(())
    }

    pub fn compile(&mut self) -> Result<()> {
        self.compiled_blocks = RegexSetBuilder::new(&self.block_patterns)
            .case_insensitive(true)
            .build()?;
        self.compiled_exceptions = RegexSetBuilder::new(&self.except_patterns)
            .case_insensitive(true)
            .build()?;
        Ok(())
    }

    pub fn blocks(&self, name: &str) -> bool {
        (matches_domain(&self.blocked, name) || self.compiled_blocks.is_match(name))
            && !matches_domain(&self.except, name)
            && !self.compiled_exceptions.is_match(name)
    }
    pub fn count(&self) -> usize {
        self.blocked.len() + self.block_patterns.len()
    }

    pub fn exception_count(&self) -> usize {
        self.except.len() + self.except_patterns.len()
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }
}

fn adguard_expression(rule: &str) -> Option<String> {
    if let Some(regex) = rule
        .strip_prefix('/')
        .and_then(|body| body.strip_suffix('/'))
    {
        // A slash inside a DNS name can never match. Excluding it also prevents
        // rules with modifiers from being misread as delimiter-only expressions.
        return (!regex.is_empty() && !regex.contains('/')).then(|| regex.to_owned());
    }
    let glob = rule.strip_prefix("||")?.strip_suffix('^')?;
    if glob.contains('*')
        && glob.contains('.')
        && glob
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-*".contains(&byte))
    {
        return Some(format!(r"(?:\A|\.){}\z", domain_glob(glob)));
    }
    None
}
