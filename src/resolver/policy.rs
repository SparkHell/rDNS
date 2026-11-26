use crate::store::{Rule, RuleInput};
use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, TXT},
    },
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Default)]
pub(super) struct DomainFilter {
    suffixes: HashSet<String>,
    wildcards: HashSet<String>,
}

impl DomainFilter {
    fn insert(&mut self, name: String) {
        if let Some(suffix) = name.strip_prefix("*.") {
            self.wildcards.insert(suffix.to_owned());
        } else {
            self.suffixes.insert(name);
        }
    }

    fn matches(&self, domain: &str) -> bool {
        matches_domain(&self.suffixes, domain)
            || (!self.wildcards.is_empty()
                && domain
                    .split_once('.')
                    .is_some_and(|(_, suffix)| matches_domain(&self.wildcards, suffix)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FilterDecision {
    Allow,
    Block(&'static str),
}

#[derive(Default)]
pub(super) struct Policy {
    local: HashMap<String, Vec<Rule>>,
    wild_local: HashMap<String, Vec<Rule>>,
    allow: DomainFilter,
    block: DomainFilter,
    subscription_blocks: HashSet<String>,
    imported_exact: HashMap<String, (i64, bool)>,
    imported_suffix: HashMap<String, (i64, bool)>,
    imported_patterns: Vec<(i64, bool, regex::Regex)>,
    forward: Vec<(String, SocketAddr)>,
}

impl Policy {
    pub(super) fn compile(rules: Vec<Rule>, domains: Vec<String>) -> Result<Self> {
        let mut policy = Self::default();
        for rule in rules {
            if let Some(match_type) = rule.filter_match.as_deref() {
                let block = rule.kind == "block";
                match match_type {
                    "DOMAIN" => {
                        policy.imported_exact.insert(rule.domain, (rule.id, block));
                    }
                    "DOMAIN-SUFFIX" => {
                        policy.imported_suffix.insert(rule.domain, (rule.id, block));
                    }
                    _ => {
                        let pattern = imported_domain_pattern(match_type, &rule.domain)?;
                        policy.imported_patterns.push((rule.id, block, pattern));
                    }
                }
                continue;
            }
            match rule.kind.as_str() {
                "local" => {
                    if let Some(suffix) = rule.domain.strip_prefix("*.") {
                        policy
                            .wild_local
                            .entry(suffix.to_owned())
                            .or_default()
                            .push(rule);
                    } else {
                        policy
                            .local
                            .entry(rule.domain.clone())
                            .or_default()
                            .push(rule);
                    }
                }
                "allow" => {
                    policy.allow.insert(rule.domain);
                }
                "block" => {
                    policy.block.insert(rule.domain);
                }
                "forward" => {
                    if let Some(value) = &rule.value {
                        policy.forward.push((rule.domain, value.parse()?));
                    }
                }
                _ => {}
            }
        }
        policy.subscription_blocks.extend(domains);
        policy
            .imported_patterns
            .sort_unstable_by_key(|rule| std::cmp::Reverse(rule.0));
        policy.forward.sort_by_key(|(domain, _)| {
            let wildcard = domain.strip_prefix("*.");
            std::cmp::Reverse((wildcard.unwrap_or(domain).len(), wildcard.is_some()))
        });
        Ok(policy)
    }

    pub(super) fn local_records(&self, domain: &str) -> Option<&[Rule]> {
        if let Some(records) = self.local.get(domain) {
            return Some(records);
        }
        let mut name = domain;
        while let Some((_, suffix)) = name.split_once('.') {
            if let Some(records) = self.wild_local.get(suffix) {
                return Some(records);
            }
            name = suffix;
        }
        None
    }

    pub(super) fn forward_target(&self, domain: &str) -> Option<SocketAddr> {
        self.forward.iter().find_map(|(pattern, target)| {
            let wildcard = pattern.strip_prefix("*.");
            let suffix = wildcard.unwrap_or(pattern);
            let subdomain = domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'));
            (subdomain || (wildcard.is_none() && domain == suffix)).then_some(*target)
        })
    }

    pub(super) fn filter(&self, domain: &str) -> Option<FilterDecision> {
        let mut latest = self.imported_exact.get(domain).copied();
        if !self.imported_suffix.is_empty() {
            let mut suffix = domain;
            loop {
                if let Some(&rule) = self.imported_suffix.get(suffix)
                    && latest.is_none_or(|current| current.0 < rule.0)
                {
                    latest = Some(rule);
                }
                let Some((_, parent)) = suffix.split_once('.') else {
                    break;
                };
                suffix = parent;
            }
        }
        for (id, block, pattern) in &self.imported_patterns {
            if latest.is_some_and(|current| current.0 >= *id) {
                break;
            }
            if pattern.is_match(domain) {
                latest = Some((*id, *block));
                break;
            }
        }
        if let Some((_, block)) = latest {
            return Some(if block {
                FilterDecision::Block("imported_rule")
            } else {
                FilterDecision::Allow
            });
        }
        if self.allow.matches(domain) {
            Some(FilterDecision::Allow)
        } else if self.block.matches(domain) {
            Some(FilterDecision::Block("blacklist"))
        } else {
            matches_domain(&self.subscription_blocks, domain)
                .then_some(FilterDecision::Block("subscription"))
        }
    }
}

pub(super) fn validate_rule(input: &RuleInput) -> Result<RuleInput> {
    let domain = input.domain.trim();
    let normalized = match domain.strip_prefix("*.") {
        Some(suffix) if !suffix.starts_with(char::is_whitespace) => {
            normalize_domain(suffix).map(|suffix| format!("*.{suffix}"))
        }
        _ => normalize_domain(domain),
    }
    .map_err(|_| anyhow::anyhow!("请填写有效域名，通配符只支持 *.example.com 这种格式"))?;
    anyhow::ensure!(normalized.len() <= 253, "规则域名过长");
    anyhow::ensure!(
        ["local", "allow", "block", "forward"].contains(&input.kind.as_str()),
        "invalid rule kind"
    );
    let mut result = input.clone();
    result.domain = normalized;
    match input.kind.as_str() {
        "local" => {
            let kind = input
                .record_type
                .as_deref()
                .context("record_type required")?
                .to_uppercase();
            anyhow::ensure!(
                ["A", "AAAA", "CNAME", "TXT"].contains(&kind.as_str()),
                "record_type must be A, AAAA, CNAME or TXT"
            );
            let value = input.value.as_deref().context("value required")?;
            parse_rdata(&kind, value)?;
            anyhow::ensure!(
                (1..=86400).contains(&input.ttl.unwrap_or(300)),
                "TTL must be 1..86400"
            );
            result.record_type = Some(kind);
            result.ttl = Some(input.ttl.unwrap_or(300));
        }
        "forward" => {
            let addr: SocketAddr = input
                .value
                .as_deref()
                .context("upstream socket address required")?
                .parse()?;
            anyhow::ensure!(
                !addr.ip().is_unspecified(),
                "upstream cannot be unspecified"
            );
            result.record_type = None;
            result.ttl = None;
        }
        _ => {
            result.record_type = None;
            result.value = None;
            result.ttl = None;
        }
    }
    Ok(result)
}

pub(crate) fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(
        !domain.is_empty() && domain.len() <= 253 && !domain.contains('*'),
        "invalid domain"
    );
    Name::from_ascii(format!("{domain}."))?;
    Ok(domain)
}

pub(crate) fn matches_domain(set: &HashSet<String>, domain: &str) -> bool {
    let mut remaining = domain;
    loop {
        if set.contains(remaining) {
            return true;
        }
        let Some((_, suffix)) = remaining.split_once('.') else {
            return false;
        };
        remaining = suffix;
    }
}

pub(super) fn answer_local<'a>(
    response: &mut Message,
    query: &Query,
    kind: &str,
    records: impl Iterator<Item = (&'a str, &'a str, u32)>,
) -> Result<()> {
    for (record_type, value, ttl) in records {
        if record_type == "CNAME" || query.query_type() == RecordType::ANY || record_type == kind {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                ttl,
                parse_rdata(record_type, value)?,
            ));
        }
    }
    response.metadata.authoritative = true;
    Ok(())
}

fn parse_rdata(kind: &str, value: &str) -> Result<RData> {
    Ok(match kind {
        "A" => RData::A(A(value.parse()?)),
        "AAAA" => RData::AAAA(AAAA(value.parse()?)),
        "CNAME" => RData::CNAME(CNAME(Name::from_ascii(format!(
            "{}.",
            normalize_domain(value)?
        ))?)),
        "TXT" => {
            anyhow::ensure!(value.len() <= 255, "TXT exceeds 255 bytes");
            RData::TXT(TXT::new(vec![value.to_string()]))
        }
        _ => anyhow::bail!("unsupported record type"),
    })
}

pub(super) async fn forward(wire: &[u8], query: &Message, upstream: SocketAddr) -> Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(wire).await?;
    let mut udp_buf = [0u8; 4096];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut udp_buf)).await??;
    let reply = Message::from_vec(&udp_buf[..length])?;
    anyhow::ensure!(
        reply.metadata.id == query.metadata.id && reply.queries == query.queries,
        "upstream response mismatch"
    );
    if !reply.metadata.truncation {
        return Ok(udp_buf[..length].to_vec());
    }
    let mut stream =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(upstream)).await??;
    stream.write_all(&(wire.len() as u16).to_be_bytes()).await?;
    stream.write_all(wire).await?;
    let length = stream.read_u16().await? as usize;
    anyhow::ensure!(length <= 65535, "upstream response too large");
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer).await?;
    let reply = Message::from_vec(&buffer)?;
    anyhow::ensure!(
        reply.metadata.id == query.metadata.id && reply.queries == query.queries,
        "upstream response mismatch"
    );
    Ok(buffer)
}

pub struct ImportedFilter {
    pub domain: String,
    pub match_type: &'static str,
    pub block: bool,
}

pub(crate) fn domain_glob(pattern: &str) -> String {
    regex::escape(pattern)
        .replace("\\*", ".*")
        .replace("\\?", ".")
}

pub(crate) fn domain_regex(expression: &str) -> Result<regex::Regex> {
    Ok(regex::RegexBuilder::new(expression)
        .case_insensitive(true)
        .size_limit(1024 * 1024)
        .build()?)
}

fn imported_domain_pattern(kind: &str, pattern: &str) -> Result<regex::Regex> {
    anyhow::ensure!(!pattern.is_empty(), "请填写匹配表达式");
    match kind {
        "DOMAIN-WILDCARD" => {
            anyhow::ensure!(
                pattern.len() <= 253
                    && pattern
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".-*?".contains(&byte)),
                "通配符域名只支持字母、数字、点、连字符、* 和 ?"
            );
            domain_regex(&format!(r"\A(?:{})\z", domain_glob(pattern)))
        }
        "DOMAIN-REGEX" => domain_regex(pattern).context("域名正则无效或超出编译限制"),
        _ => anyhow::bail!("未知的域名匹配类型"),
    }
}

pub fn parse_imported_filters(text: &str) -> Result<Vec<ImportedFilter>> {
    let mut rules = Vec::new();
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with([';', '!', '#'])
            || line.starts_with("//")
            || line.eq_ignore_ascii_case("[Rule]")
            || line.eq_ignore_ascii_case("rules:")
        {
            continue;
        }
        let rule = parse_imported_filter(line)
            .with_context(|| format!("第 {} 行", index + 1))
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
        rules.push(rule);
    }
    anyhow::ensure!(!rules.is_empty(), "请至少输入一条过滤规则");
    let mut seen = HashSet::new();
    rules.reverse();
    rules.retain(|rule| seen.insert((rule.match_type, rule.domain.clone())));
    rules.reverse();
    Ok(rules)
}

fn parse_imported_filter(line: &str) -> Result<ImportedFilter> {
    let line = line
        .find(" #")
        .map_or(line, |index| &line[..index])
        .trim_end();
    let entry = line.strip_prefix('-').unwrap_or(line).trim();
    let entry = ['\'', '"']
        .into_iter()
        .find_map(|quote| entry.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(entry);
    let (kind, fields) = entry
        .split_once(',')
        .context("请使用 匹配类型,匹配值,策略")?;
    let (hostname, action) = fields
        .rsplit_once(',')
        .context("请使用 匹配类型,匹配值,策略")?;
    let hostname = hostname.trim();
    let match_type = match kind.trim().to_ascii_uppercase().as_str() {
        "DOMAIN" => "DOMAIN",
        "DOMAIN-SUFFIX" => "DOMAIN-SUFFIX",
        "DOMAIN-WILDCARD" => "DOMAIN-WILDCARD",
        "DOMAIN-REGEX" => "DOMAIN-REGEX",
        _ => anyhow::bail!("匹配类型只支持 DOMAIN、DOMAIN-SUFFIX、DOMAIN-WILDCARD 和 DOMAIN-REGEX"),
    };
    let block = match action.trim().to_ascii_uppercase().as_str() {
        "REJECT" => true,
        "DIRECT" => false,
        _ => anyhow::bail!("策略只支持 REJECT 和 DIRECT"),
    };
    if matches!(match_type, "DOMAIN-WILDCARD" | "DOMAIN-REGEX") {
        let domain = if match_type == "DOMAIN-WILDCARD" {
            hostname.trim_end_matches('.').to_ascii_lowercase()
        } else {
            hostname.to_owned()
        };
        imported_domain_pattern(match_type, &domain)?;
        return Ok(ImportedFilter {
            domain,
            match_type,
            block,
        });
    }
    anyhow::ensure!(
        hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
            && hostname.parse::<IpAddr>().is_err(),
        "请填写有效域名"
    );
    let domain = normalize_domain(hostname).context("请填写有效域名")?;
    anyhow::ensure!(
        domain.parse::<IpAddr>().is_err()
            && domain
                .split('.')
                .all(|label| !label.starts_with('-') && !label.ends_with('-')),
        "请填写有效域名"
    );
    Ok(ImportedFilter {
        domain,
        match_type,
        block,
    })
}

pub fn parse_filter_list(text: &str) -> Result<Vec<String>> {
    let mut domains = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("@@")
        {
            continue;
        }
        let candidate = if let Some(rest) = line.strip_prefix("||") {
            rest.split('^').next().unwrap_or("")
        } else if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
            line.split_whitespace().nth(1).unwrap_or("")
        } else if line.contains('/')
            || line.contains('$')
            || line.contains('*')
            || line.contains(' ')
        {
            continue;
        } else {
            line
        };
        if let Ok(domain) = normalize_domain(candidate) {
            domains.insert(domain);
        }
        anyhow::ensure!(domains.len() <= 1_000_000, "filter list too large");
    }
    let mut result: Vec<_> = domains.into_iter().collect();
    result.sort();
    Ok(result)
}
