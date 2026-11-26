use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GfwSettings {
    pub enabled: bool,
    #[serde(skip_serializing)]
    pub use_proxy: bool,
    pub url: String,
    pub update_hours: u64,
    pub group: String,
    #[serde(skip_serializing)]
    pub proxy: String,
}
impl Default for GfwSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            use_proxy: false,
            url: "https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt".into(),
            update_hours: 6,
            group: "default".into(),
            proxy: String::new(),
        }
    }
}

#[derive(Default)]
struct RulesBuilder {
    domains: HashSet<String>,
    wildcards: Vec<String>,
    expressions: Vec<String>,
}

impl RulesBuilder {
    fn build(self) -> Rules {
        let compile = |patterns: Vec<String>| -> (RegexSet, Vec<Regex>) {
            if patterns.is_empty() {
                return (RegexSet::empty(), Vec::new());
            }
            match RegexSetBuilder::new(&patterns)
                .size_limit(32 * 1024 * 1024)
                .dfa_size_limit(32 * 1024 * 1024)
                .build()
            {
                Ok(set) => (set, Vec::new()),
                Err(_) => (
                    RegexSet::empty(),
                    patterns
                        .into_iter()
                        .filter_map(|p| Regex::new(&p).ok())
                        .collect(),
                ),
            }
        };
        let (wildcard_set, wildcards) = compile(self.wildcards);
        let (expression_set, expressions) = compile(self.expressions);
        Rules {
            domains: self.domains,
            wildcard_set,
            wildcards,
            expression_set,
            expressions,
        }
    }
}

#[derive(Default)]
struct Rules {
    domains: HashSet<String>,
    wildcard_set: RegexSet,
    wildcards: Vec<Regex>,
    expression_set: RegexSet,
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
        if self.wildcard_set.is_match(domain) || self.wildcards.iter().any(|r| r.is_match(domain)) {
            return true;
        }
        if !self.expression_set.is_empty() || !self.expressions.is_empty() {
            let https = format!("https://{domain}/");
            let http = format!("http://{domain}/");
            return self.expression_set.is_match(&https)
                || self.expression_set.is_match(&http)
                || self
                    .expressions
                    .iter()
                    .any(|r| r.is_match(&https) || r.is_match(&http));
        }
        false
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
        let mut include = RulesBuilder::default();
        let mut exclude = RulesBuilder::default();
        let mut count = 0usize;
        let mut skipped = 0usize;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                continue;
            }
            let (exception, rule) = line
                .strip_prefix("@@")
                .map(|s| (true, s))
                .unwrap_or((false, line));
            let rules = if exception {
                &mut exclude
            } else {
                &mut include
            };
            if let Some(rest) = rule.strip_prefix('/') {
                let Some(pattern) = rest.strip_suffix('/').filter(|s| !s.is_empty()) else {
                    skipped += 1;
                    continue;
                };
                if Regex::new(pattern).is_ok() {
                    rules.expressions.push(pattern.to_owned());
                    count += 1;
                } else {
                    skipped += 1;
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
                skipped += 1;
                continue;
            }
            if host.len() > 253
                || !host.contains('.')
                || !host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_*".contains(&c))
            {
                skipped += 1;
                continue;
            }
            let host = host.to_ascii_lowercase();
            if host.contains('*') {
                let expression =
                    format!("(?:^|\\.){}$", regex::escape(&host).replace("\\*", "[^.]*"));
                if Regex::new(&expression).is_ok() {
                    rules.wildcards.push(expression);
                } else {
                    skipped += 1;
                    continue;
                }
            } else {
                rules.domains.insert(host);
            }
            count += 1;
        }
        ensure!(count > 0, "GFWList contains no supported rules");
        Ok(Self {
            include: include.build(),
            exclude: exclude.build(),
            count,
            skipped,
        })
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
    fn malformed_regex_delimiters_are_skipped() {
        for rule in ["/", "//", "/[/", "@@/"] {
            let text = format!("[AutoProxy]\n{rule}\n||example.test");
            let rules = GfwList::parse(&text).unwrap();
            assert_eq!(rules.skipped, 1);
            assert!(rules.matches("example.test"));
        }
        assert!(GfwList::parse("[AutoProxy]\n/").is_err());
    }

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
