mod prefetch;
mod umbrella;
mod warmup;
use crate::{
    cache::{CacheSettings, CachedProvider, PersistentCache},
    config::Config,
    features::Features,
    store::{Rule, RuleInput, Store},
    upstream::{DohGroup, ResolveMode},
};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record,
        rdata::{A, AAAA, CNAME, TXT},
    },
};
use hickory_resolver::{
    TtlConfig,
    config::ResolverOpts,
    recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
pub use warmup::CacheJobInput;

#[derive(Default)]
struct DomainFilter {
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

#[derive(Default)]
struct Policy {
    local: HashMap<String, Vec<Rule>>,
    wild_local: HashMap<String, Vec<Rule>>,
    allow: DomainFilter,
    block: DomainFilter,
    forward: Vec<(String, SocketAddr)>,
}

impl Policy {
    fn local_records(&self, domain: &str) -> Option<&[Rule]> {
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

    fn forward_target(&self, domain: &str) -> Option<SocketAddr> {
        self.forward.iter().find_map(|(pattern, target)| {
            let wildcard = pattern.strip_prefix("*.");
            let suffix = wildcard.unwrap_or(pattern);
            let subdomain = domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'));
            (subdomain || (wildcard.is_none() && domain == suffix)).then_some(*target)
        })
    }
}

pub struct Engine {
    pub config: Config,
    pub store: Store,
    policy: ArcSwap<Policy>,
    policy_reload: tokio::sync::Mutex<()>,
    pub features: Arc<Features>,
    recursor: ArcSwap<Recursor<CachedProvider>>,
    prefetch: prefetch::Prefetch,
    cache: Arc<PersistentCache>,
    roots: Vec<IpAddr>,
    jobs: tokio::sync::Mutex<warmup::Jobs>,
    warm_candidates: ArcSwap<serde_json::Value>,
}

impl Engine {
    pub async fn new(
        config: Config,
        store: Store,
        cache: Arc<PersistentCache>,
    ) -> Result<Arc<Self>> {
        // Root addresses bootstrap iterative lookups; the recursor follows referrals with RD=0.
        let mut roots = if let Some(path) = &config.root_hints {
            parse_root_hints(
                &std::fs::read_to_string(path)
                    .with_context(|| format!("reading root hints {}", path.display()))?,
            )?
        } else {
            parse_root_hints(include_str!("../resources/named.root"))?
        };
        let ipv4_route = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| socket.connect("198.41.0.4:53"))
            .is_ok();
        let ipv6_route = std::net::UdpSocket::bind("[::]:0")
            .and_then(|socket| socket.connect("[2001:503:ba3e::2:30]:53"))
            .is_ok();
        if ipv4_route && roots.iter().any(IpAddr::is_ipv4) {
            roots.retain(IpAddr::is_ipv4);
        } else if ipv6_route && roots.iter().any(IpAddr::is_ipv6) {
            roots.retain(IpAddr::is_ipv6);
        }
        anyhow::ensure!(
            !roots.is_empty(),
            "no root hints match the available IP family"
        );
        let recursor = build_recursor(&roots, &cache)?;
        if store.client_networks().await?.is_empty() {
            store
                .replace_client_networks(
                    &config
                        .allowed_clients
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                )
                .await?;
        }
        let features = Features::new(config.clone(), store.clone(), cache.clone()).await?;
        let engine = Arc::new(Self {
            config,
            store,
            policy_reload: Default::default(),
            policy: ArcSwap::from_pointee(Policy::default()),
            features,
            recursor: ArcSwap::from_pointee(recursor),
            prefetch: prefetch::Prefetch::new(&cache.settings()),
            cache,
            roots,
            jobs: Default::default(),
            warm_candidates: Default::default(),
        });
        engine.reload_policy().await?;
        Ok(engine)
    }

    pub async fn cache_stats(&self) -> serde_json::Value {
        let mut stats = self.cache.stats().await;
        let (entries, bytes) = self.prefetch.stats();
        stats["memory_entries"] = (stats["memory_entries"].as_u64().unwrap_or(0) + entries).into();
        stats["memory_bytes"] = (stats["memory_bytes"].as_u64().unwrap_or(0) + bytes).into();
        stats["memory_hits"] = (stats["memory_hits"].as_u64().unwrap_or(0)
            + self
                .prefetch
                .hits
                .load(std::sync::atomic::Ordering::Relaxed))
        .into();
        stats["background_active"] = self.cache.background_active().into();
        stats["background_recommended"] = crate::cache::recommended_background_concurrency().into();
        stats["automation"] = self.job_status().await;
        stats
    }

    pub async fn update_cache_settings(&self, settings: CacheSettings) -> Result<()> {
        let _guard = self.jobs.lock().await;
        settings.validate()?;
        let recursor = settings
            .requires_reset(&self.cache.settings())
            .then(|| build_recursor_with_settings(&self.roots, &self.cache, &settings))
            .transpose()?;
        self.cache
            .set_settings(settings.clone(), || {
                if let Some(recursor) = recursor {
                    self.recursor.store(Arc::new(recursor));
                    self.prefetch.reset(&settings);
                }
            })
            .await?;
        Ok(())
    }

    pub async fn reload_clients(&self) -> Result<()> {
        let mut settings = self.features.current.load().settings.clone();
        settings.access.mode = crate::access::AccessMode::Whitelist;
        settings.access.cidrs = self.store.client_networks().await?;
        self.features.apply(settings).await
    }

    pub async fn reload_policy(&self) -> Result<()> {
        let _guard = self.policy_reload.lock().await;
        let (rules, domains) = self.store.policy_snapshot().await?;
        let mut policy = Policy::default();
        for rule in rules {
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
        policy.block.suffixes.extend(domains);
        policy.forward.sort_by_key(|(domain, _)| {
            let wildcard = domain.strip_prefix("*.");
            std::cmp::Reverse((wildcard.unwrap_or(domain).len(), wildcard.is_some()))
        });
        self.policy.store(Arc::new(policy));
        Ok(())
    }

    pub fn validate_rule(input: &RuleInput) -> Result<RuleInput> {
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

    pub async fn answer(
        self: &Arc<Self>,
        wire: &[u8],
        peer: SocketAddr,
        protocol: &str,
    ) -> Result<Vec<u8>> {
        self.answer_for(wire, peer, protocol, None).await
    }

    pub async fn answer_for(
        self: &Arc<Self>,
        wire: &[u8],
        peer: SocketAddr,
        protocol: &str,
        user_id: Option<i64>,
    ) -> Result<Vec<u8>> {
        let started = Instant::now();
        let request = Message::from_vec(wire).context("invalid DNS message")?;
        let mut response = response(&request, ResponseCode::NoError);
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
        {
            response.metadata.response_code = ResponseCode::FormErr;
            return Ok(response.to_vec()?);
        }
        let query = request.queries[0].clone();
        if query.query_class() != DNSClass::IN {
            response.metadata.response_code = ResponseCode::Refused;
            return Ok(response.to_vec()?);
        }
        let domain = if query.name().is_root() {
            ".".to_owned()
        } else {
            query
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        };
        let kind = query.query_type().to_string();
        let policy = self.policy.load_full();
        let runtime = self.features.current.load_full();
        let location = runtime.geo.lookup(crate::access::canonical_ip(peer.ip()));
        let mut selected_upstream = None;
        let outcome;
        if let Err(reason) = runtime.access.decide(peer.ip(), &location) {
            response.metadata.response_code = ResponseCode::Refused;
            outcome = reason;
        } else if let Some(records) = policy.local_records(&domain) {
            for record in records.iter().filter(|record| {
                matches!(record.record_type.as_deref(), Some("CNAME"))
                    || record.record_type.as_deref() == Some(kind.as_str())
            }) {
                if let (Some(rt), Some(value)) = (&record.record_type, &record.value) {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        record.ttl.unwrap_or(300) as u32,
                        parse_rdata(rt, value)?,
                    ));
                }
            }
            response.metadata.authoritative = true;
            outcome = "local";
        } else if self.is_blocked(&policy, &runtime, &domain) {
            response.metadata.response_code = ResponseCode::NXDomain;
            outcome = "blocked";
        } else if let Some(upstream) = policy.forward_target(&domain) {
            let _foreground = self.begin_foreground(true);
            let budget = Duration::from_millis(runtime.settings.resolution.timeout_ms);
            match tokio::time::timeout(budget, forward(wire, upstream)).await {
                Err(_) => {
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = "timeout";
                }
                Ok(Ok(bytes)) => {
                    let mut forwarded = Message::from_vec(&bytes)?;
                    forwarded.metadata.id = request.metadata.id;
                    forwarded.metadata.authentic_data = false;
                    response = forwarded;
                    outcome = "forward";
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, %upstream, "conditional forward failed");
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = "error";
                }
            }
        } else {
            match self
                .cache_lookup(&runtime, &request, &domain, true)
                .await
                .as_ref()
            {
                Ok(Ok(answer)) => {
                    let mut answer = answer.clone();
                    selected_upstream = answer.upstream.clone();
                    let do_bit = request
                        .edns
                        .as_ref()
                        .is_some_and(|edns| edns.flags().dnssec_ok);
                    answer.message.metadata.id = request.metadata.id;
                    answer.message.metadata.recursion_desired = request.metadata.recursion_desired;
                    answer.message.metadata.recursion_available = true;
                    answer.message.queries = request.queries.clone();
                    response = answer.message.maybe_strip_dnssec_records(do_bit);
                    response.edns = request.edns.as_ref().map(|_| {
                        let mut edns = Edns::new();
                        edns.set_max_payload(request.max_payload())
                            .set_dnssec_ok(do_bit);
                        edns
                    });
                    outcome = answer.outcome;
                }
                Ok(Err(error)) => {
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = if *error == LookupFailure::Bogus {
                        "dnssec_bogus"
                    } else {
                        "error"
                    };
                }
                Err(_) => {
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = "timeout";
                }
            }
        }
        let wire = response.to_vec()?;
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        if let Err(error) = self
            .store
            .query_log
            .push(crate::query_log::QueryLogEntry {
                at: chrono::Utc::now().to_rfc3339(),
                user_id,
                client: peer.ip().to_string(),
                domain,
                qtype: kind,
                outcome: outcome.into(),
                protocol: protocol.into(),
                duration_ms,
                country: location.country,
                province: location.province,
                city: location.city,
                upstream: selected_upstream,
            })
            .await
        {
            tracing::warn!(%error, "query log write failed");
        }
        Ok(wire)
    }
    fn is_blocked(
        &self,
        policy: &Policy,
        runtime: &crate::features::FeatureRuntime,
        domain: &str,
    ) -> bool {
        !policy.allow.matches(domain)
            && (policy.block.matches(domain)
                || (runtime.settings.adguard.enabled && self.features.ads.load().blocks(domain)))
    }

    async fn routed_lookup(
        &self,
        runtime: &crate::features::FeatureRuntime,
        request: &Message,
        gfw: bool,
    ) -> Result<Result<Resolved, LookupFailure>, tokio::time::error::Elapsed> {
        let settings = &runtime.settings;
        let group_name = if gfw {
            &settings.gfwlist.group
        } else {
            &settings.resolution.group
        };
        let group = runtime.groups.get(group_name).cloned();
        let mode = if gfw {
            ResolveMode::Doh
        } else {
            settings.resolution.mode.clone()
        };
        let lookup = async {
            match mode {
                ResolveMode::Recursive => self.recursive_lookup(request).await,
                ResolveMode::Doh => {
                    let primary = group
                        .context("missing upstream group")
                        .map_err(|_| LookupFailure::Unavailable)?;
                    let reserve_fallback = gfw && group_name != &settings.resolution.group;
                    let budget = if reserve_fallback {
                        primary
                            .timeout()
                            .min(Duration::from_millis(settings.resolution.timeout_ms / 2))
                    } else {
                        primary.timeout()
                    };
                    let result = tokio::time::timeout(
                        budget,
                        doh_lookup(
                            primary,
                            request.clone(),
                            settings.resolution.validate_dnssec,
                        ),
                    )
                    .await
                    .unwrap_or(Err(LookupFailure::Unavailable));
                    if gfw
                        && matches!(result, Err(LookupFailure::Unavailable))
                        && group_name != &settings.resolution.group
                    {
                        let fallback = runtime
                            .groups
                            .get(&settings.resolution.group)
                            .cloned()
                            .ok_or(LookupFailure::Unavailable)?;
                        let mut answer = doh_lookup(
                            fallback,
                            request.clone(),
                            settings.resolution.validate_dnssec,
                        )
                        .await?;
                        answer.outcome = "gfw_fallback_doh";
                        Ok(answer)
                    } else {
                        result
                    }
                }
                ResolveMode::Parallel => {
                    let doh = group
                        .context("missing upstream group")
                        .map_err(|_| LookupFailure::Unavailable)?;
                    prefer_recursive(
                        self.recursive_lookup(request),
                        doh_lookup(doh, request.clone(), settings.resolution.validate_dnssec),
                        Duration::from_millis(settings.resolution.priority_ms),
                    )
                    .await
                }
            }
        };
        let mut result = tokio::time::timeout(
            Duration::from_millis(settings.resolution.timeout_ms),
            lookup,
        )
        .await?;
        if let Ok(answer) = &mut result
            && gfw
            && answer.outcome == "doh"
        {
            answer.outcome = "gfw_doh";
        }
        Ok(result)
    }
    async fn recursive_lookup(&self, request: &Message) -> Result<Resolved, LookupFailure> {
        let query = request.queries[0].clone();
        let do_bit = request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        let recursor = if crate::cache::bypass_cache(request) {
            match build_recursor(&self.roots, &self.cache) {
                Ok(recursor) => Arc::new(recursor),
                Err(error) => {
                    tracing::debug!(%error, "could not prepare recursive refresh");
                    return Err(LookupFailure::Unavailable);
                }
            }
        } else {
            self.recursor.load_full()
        };
        match recursor
            .resolve(query.clone(), Instant::now(), do_bit)
            .await
        {
            Ok(mut message) => {
                let secure = validated_answer_is_secure(&message).ok_or(LookupFailure::Bogus)?;
                if !matches!(
                    message.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) {
                    return Err(LookupFailure::Unavailable);
                }
                message.metadata.authentic_data = secure;
                Ok(Resolved {
                    message,
                    outcome: "recursive",
                    upstream: None,
                })
            }
            Err(error) if error.is_nx_domain() || error.is_no_records_found() => {
                let nx = error.is_nx_domain();
                let mut message = response(
                    request,
                    if nx {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NoError
                    },
                );
                if let Some(soa) = error.into_soa() {
                    message.add_authority(Record::from_rdata(
                        soa.name,
                        soa.ttl,
                        RData::SOA(soa.data),
                    ));
                }
                Ok(Resolved {
                    message,
                    outcome: if nx { "nxdomain" } else { "nodata" },
                    upstream: None,
                })
            }
            Err(error) => {
                tracing::debug!(%error, "recursive lookup failed");
                if matches!(&error, hickory_resolver::recursor::RecursorError::Net(error) if crate::upstream::dnssec_error(error))
                {
                    Err(LookupFailure::Bogus)
                } else {
                    Err(LookupFailure::Unavailable)
                }
            }
        }
    }
}

#[derive(Clone)]
struct Resolved {
    message: Message,
    outcome: &'static str,
    upstream: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LookupFailure {
    Unavailable,
    Bogus,
}

async fn doh_lookup(
    group: Arc<DohGroup>,
    request: Message,
    validate: bool,
) -> Result<Resolved, LookupFailure> {
    match group.resolve(request, validate).await {
        Ok(mut message) => {
            if validate {
                let secure = validated_answer_is_secure(&message).ok_or(LookupFailure::Bogus)?;
                // Negative answers have no answer RRsets; the validator sets AD from the NSEC proof.
                message.metadata.authentic_data =
                    secure || (message.answers.is_empty() && message.metadata.authentic_data);
            } else {
                message.metadata.authentic_data = false;
            }
            Ok(Resolved {
                message,
                outcome: "doh",
                upstream: Some(group.name.clone()),
            })
        }
        Err(error) => {
            tracing::debug!(group = %group.name, %error, "DoH lookup failed");
            if error
                .downcast_ref::<hickory_resolver::net::NetError>()
                .is_some_and(crate::upstream::dnssec_error)
            {
                Err(LookupFailure::Bogus)
            } else {
                Err(LookupFailure::Unavailable)
            }
        }
    }
}

async fn prefer_recursive<R, D>(
    recursive: R,
    doh: D,
    priority: Duration,
) -> Result<Resolved, LookupFailure>
where
    R: std::future::Future<Output = Result<Resolved, LookupFailure>>,
    D: std::future::Future<Output = Result<Resolved, LookupFailure>>,
{
    tokio::pin!(recursive, doh);
    let deadline = tokio::time::sleep(priority);
    tokio::pin!(deadline);
    let mut rec_pending = true;
    let mut doh_pending = true;
    let mut elapsed = false;
    let mut ready = None;
    loop {
        tokio::select! {
            biased;
            result = &mut recursive, if rec_pending => {
                rec_pending = false;
                match result { Ok(answer) => return Ok(answer), Err(LookupFailure::Bogus) => return Err(LookupFailure::Bogus), Err(_) => {} }
                if let Some(answer) = ready.take() { return Ok(answer); }
                if !doh_pending { return Err(LookupFailure::Unavailable); }
            }
            result = &mut doh, if doh_pending => {
                doh_pending = false;
                match result {
                    Ok(answer) if !rec_pending || elapsed => return Ok(answer),
                    Ok(answer) => ready = Some(answer),
                    Err(LookupFailure::Bogus) => return Err(LookupFailure::Bogus),
                    Err(_) if !rec_pending => return Err(LookupFailure::Unavailable),
                    Err(_) => {}
                }
            }
            _ = &mut deadline, if !elapsed => {
                elapsed = true;
                if let Some(answer) = ready.take() { return Ok(answer); }
            }
        }
    }
}

fn build_recursor(
    roots: &[IpAddr],
    cache: &Arc<PersistentCache>,
) -> Result<Recursor<CachedProvider>> {
    build_recursor_with_settings(roots, cache, &cache.settings())
}

fn build_recursor_with_settings(
    roots: &[IpAddr],
    cache: &Arc<PersistentCache>,
    settings: &CacheSettings,
) -> Result<Recursor<CachedProvider>> {
    let mut resolver_options = ResolverOpts::default();
    resolver_options.positive_max_ttl = Some(Duration::from_secs(u64::from(
        settings.ns_max_ttl.min(settings.answer_max_ttl),
    )));
    resolver_options.negative_max_ttl =
        Some(Duration::from_secs(u64::from(settings.negative_max_ttl)));
    // Hickory counts cached responses, not bytes. Keep this small; the byte-bounded cache is below.
    let options = RecursorOptions {
        response_cache_size: 2_048,
        cache_policy: TtlConfig::from_opts(&resolver_options),
        ..RecursorOptions::default()
    };
    Recursor::new(
        roots,
        DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
        None,
        options,
        CachedProvider::new(cache.clone(), roots),
    )
    .context("starting validating recursor")
}

fn response(request: &Message, code: ResponseCode) -> Message {
    let mut message = Message::response(request.metadata.id, request.metadata.op_code);
    message.metadata.recursion_desired = request.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    message.metadata.response_code = code;
    if let Some(edns) = &request.edns {
        message.edns = Some(edns.clone());
    }
    for query in &request.queries {
        message.add_query(query.clone());
    }
    message
}

fn validated_answer_is_secure(message: &Message) -> Option<bool> {
    if message
        .answers
        .iter()
        .any(|record| record.proof.is_bogus() || record.proof.is_indeterminate())
    {
        None
    } else {
        Some(
            !message.answers.is_empty()
                && message
                    .answers
                    .iter()
                    .all(|record| record.proof.is_secure()),
        )
    }
}

fn parse_root_hints(text: &str) -> Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 4
            || !fields[0]
                .to_ascii_uppercase()
                .ends_with(".ROOT-SERVERS.NET.")
        {
            continue;
        }
        if fields[2] == "A" || fields[2] == "AAAA" {
            addresses.push(fields[3].parse()?);
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    anyhow::ensure!(
        addresses.len() >= 2,
        "root hints must contain at least two valid addresses"
    );
    Ok(addresses)
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

async fn forward(wire: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(wire).await?;
    let mut buffer = vec![0u8; 65535];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer)).await??;
    buffer.truncate(length);
    let reply = Message::from_vec(&buffer)?;
    let query = Message::from_vec(wire)?;
    anyhow::ensure!(
        reply.metadata.id == query.metadata.id && reply.queries == query.queries,
        "upstream response mismatch"
    );
    if !reply.metadata.truncation {
        return Ok(buffer);
    }
    let mut stream =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(upstream)).await??;
    stream.write_all(&(wire.len() as u16).to_be_bytes()).await?;
    stream.write_all(wire).await?;
    let length = stream.read_u16().await? as usize;
    anyhow::ensure!(length <= 65535, "upstream response too large");
    buffer.resize(length, 0);
    stream.read_exact(&mut buffer).await?;
    let reply = Message::from_vec(&buffer)?;
    anyhow::ensure!(
        reply.metadata.id == query.metadata.id && reply.queries == query.queries,
        "upstream response mismatch"
    );
    Ok(buffer)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Proof;

    fn ready(outcome: &'static str) -> Result<Resolved, LookupFailure> {
        Ok(Resolved {
            message: Message::query(),
            outcome,
            upstream: None,
        })
    }

    #[tokio::test]
    async fn recursive_priority_window_and_failure_semantics() {
        let result = prefer_recursive(
            async { ready("recursive") },
            async { ready("doh") },
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "recursive");
        let started = Instant::now();
        let result = prefer_recursive(
            std::future::pending(),
            async { ready("doh") },
            Duration::from_millis(30),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "doh");
        assert!(started.elapsed() >= Duration::from_millis(25));
        let result = prefer_recursive(
            async { Err(LookupFailure::Unavailable) },
            async { ready("doh") },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "doh");
        let result = prefer_recursive(
            async { Err(LookupFailure::Bogus) },
            async { ready("doh") },
            Duration::from_millis(0),
        )
        .await;
        assert!(matches!(result, Err(LookupFailure::Bogus)));
        let result = prefer_recursive(
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ready("recursive")
            },
            async { Err(LookupFailure::Unavailable) },
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "recursive");
    }
    #[test]
    fn filtering_parses_hosts_and_adblock_domains() {
        let domains = parse_filter_list(
            "! comment\n0.0.0.0 ads.example\n||track.example^\n@@||allowed.example^\n",
        )
        .unwrap();
        assert_eq!(domains, ["ads.example", "track.example"]);
    }
    #[test]
    fn suffix_match_respects_label_boundary() {
        let set = HashSet::from(["example.com".to_string()]);
        assert!(matches_domain(&set, "ads.example.com"));
        assert!(!matches_domain(&set, "notexample.com"));
    }

    #[test]
    fn invalid_local_data_is_rejected_before_persistence() {
        let bad = RuleInput {
            kind: "local".into(),
            domain: "internal.example".into(),
            record_type: Some("A".into()),
            value: Some("not-an-ip".into()),
            ttl: Some(300),
        };
        assert!(Engine::validate_rule(&bad).is_err());
        let bad_forward = RuleInput {
            kind: "forward".into(),
            domain: "corp.example".into(),
            record_type: None,
            value: Some("0.0.0.0:53".into()),
            ttl: None,
        };
        assert!(Engine::validate_rule(&bad_forward).is_err());
    }

    #[test]
    fn bogus_dnssec_proof_never_becomes_a_successful_answer() {
        let name = Name::from_ascii("example.com.").unwrap();
        let mut answer = Message::response(0, OpCode::Query);
        let mut record = Record::from_rdata(name, 60, RData::A(A("192.0.2.1".parse().unwrap())));
        record.proof = Proof::Bogus;
        answer.add_answer(record.clone());
        assert_eq!(validated_answer_is_secure(&answer), None);
        record.proof = Proof::Indeterminate;
        answer.answers = vec![record.clone()];
        assert_eq!(validated_answer_is_secure(&answer), None);
        record.proof = Proof::Insecure;
        answer.answers = vec![record.clone()];
        assert_eq!(validated_answer_is_secure(&answer), Some(false));
        record.proof = Proof::Secure;
        answer.answers = vec![record];
        assert_eq!(validated_answer_is_secure(&answer), Some(true));
    }

    #[test]
    fn bundled_root_hints_include_current_ipv4_and_ipv6_addresses() {
        let roots = parse_root_hints(include_str!("../resources/named.root")).unwrap();
        assert!(roots.len() >= 20);
        assert!(roots.contains(&"170.247.170.2".parse().unwrap()));
        assert!(roots.contains(&"2801:1b8:10::b".parse().unwrap()));
    }
}
