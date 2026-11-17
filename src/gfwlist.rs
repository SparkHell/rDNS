use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GfwSettings {
    pub enabled: bool,
    pub url: String,
    pub update_hours: u64,
    pub group: String,
}
impl Default for GfwSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt".into(),
            update_hours: 6,
            group: "default".into(),
        }
    }
}

#[derive(Default)]
struct Rules {
    domains: HashSet<String>,
    wildcards: Vec<Regex>,
    expressions: Vec<Regex>,
}
impl Rules {
    fn matches(&self, domain: &str) -> bool {
        let mut suffix = domain;
        loop {
            if self.domains.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, next)) => suffix = next,
                None => break,
            }
        }
        self.wildcards.iter().any(|r| r.is_match(domain))
            || self.expressions.iter().any(|r| {
                r.is_match(&format!("https://{domain}/"))
                    || r.is_match(&format!("http://{domain}/"))
            })
    }
}

pub struct GfwList {
    include: Rules,
    exclude: Rules,
    pub count: usize,
    pub skipped: usize,
}
impl GfwList {
    pub fn parse(data: &str) -> Result<Self> {
        ensure!(data.len() <= 10 * 1024 * 1024, "GFWList exceeds 10 MiB");
        let decoded;
        let text = if data.trim_start().starts_with("[AutoProxy") {
            data
        } else {
            let compact: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            decoded = String::from_utf8(
                STANDARD
                    .decode(compact)
                    .context("GFWList is neither AutoProxy text nor valid Base64")?,
            )?;
            &decoded
        };
        ensure!(
            text.trim_start().starts_with("[AutoProxy"),
            "AutoProxy header required"
        );
        let mut list = Self {
            include: Rules::default(),
            exclude: Rules::default(),
            count: 0,
            skipped: 0,
        };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                continue;
            }
            let (exception, rule) = line
                .strip_prefix("@@")
                .map(|s| (true, s))
                .unwrap_or((false, line));
            let rules = if exception {
                &mut list.exclude
            } else {
                &mut list.include
            };
            if rule.starts_with('/') && rule.ends_with('/') {
                match Regex::new(&rule[1..rule.len() - 1]) {
                    Ok(regex) => {
                        rules.expressions.push(regex);
                        list.count += 1;
                    }
                    Err(_) => list.skipped += 1,
                }
                continue;
            }
            // DNS has no URL path. Positive URL rules route the entire hostname.
            // Path-specific exceptions cannot safely exempt the entire hostname.
            let rule = rule.trim_start_matches('|').trim_start_matches('.');
            let rule = rule
                .strip_prefix("https://")
                .or_else(|| rule.strip_prefix("http://"))
                .unwrap_or(rule);
            let host = rule
                .split(['/', '^', '|', '$', '?', '#'])
                .next()
                .unwrap_or("");
            let rest = &rule[host.len()..];
            if exception && !rest.trim_matches(['/', '^', '|']).is_empty() {
                list.skipped += 1;
                continue;
            }
            if host.len() > 253
                || !host.contains('.')
                || !host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_*".contains(&c))
            {
                list.skipped += 1;
                continue;
            }
            let host = host.to_ascii_lowercase();
            if host.contains('*') {
                let expression =
                    format!("(?:^|\\.){}$", regex::escape(&host).replace("\\*", "[^.]*"));
                match Regex::new(&expression) {
                    Ok(regex) => rules.wildcards.push(regex),
                    Err(_) => {
                        list.skipped += 1;
                        continue;
                    }
                }
            } else {
                rules.domains.insert(host);
            }
            list.count += 1;
        }
        ensure!(list.count > 0, "GFWList contains no supported rules");
        Ok(list)
    }
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.include.matches(&domain) && !self.exclude.matches(&domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_and_autoproxy_rules() -> Result<()> {
        let built_in = GfwList::parse(include_str!("../resources/gfwlist.txt"))?;
        assert!(built_in.count > 1000);
        let data = "[AutoProxy 0.2.9]\n||example.com\n@@||safe.example.com\n||cdn*.other.com\n|https://path.example.org/somewhere\n@@|https://path.example.org/safe\n";
        for text in [data.to_owned(), STANDARD.encode(data)] {
            let list = GfwList::parse(&text)?;
            assert!(list.matches("www.example.com"));
            assert!(!list.matches("safe.example.com"));
            assert!(!list.matches("notexample.com"));
            assert!(list.matches("cdn12.other.com"));
            assert!(list.matches("path.example.org"));
            assert!(!list.matches("other.com"));
            assert_eq!(list.skipped, 1);
        }
        assert!(GfwList::parse("<html>error</html>").is_err());
        Ok(())
    }
}
