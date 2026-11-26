mod policy;
mod prefetch;
mod umbrella;
mod warmup;
use crate::{
    cache::{CacheSettings, CachedProvider, PersistentCache},
    config::Config,
    features::Features,
    portal::{DnsPreferences, query_policy},
    store::{RuleInput, Store},
    upstream::{DohGroup, RecursionCompatibility, ResolveMode},
};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::opt::EdnsOption},
};
use hickory_resolver::{
    TtlConfig,
    config::ResolverOpts,
    net::{DnsError, NetError},
    recursor::{
        DnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorError, RecursorOptions,
    },
};
use policy::{FilterDecision, Policy, answer_local, forward};
pub use policy::{ImportedFilter, parse_filter_list, parse_imported_filters};
pub(crate) use policy::{domain_glob, domain_regex, matches_domain, normalize_domain};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
pub use warmup::CacheJobInput;

pub(crate) struct QueryAnswer {
    pub wire: Vec<u8>,
    pub block_reason: Option<&'static str>,
    pub duration_ms: f64,
}

pub(crate) fn record_type_label(kind: RecordType) -> String {
    match kind {
        RecordType::Unknown(code) => format!("TYPE{code}"),
        _ => kind.to_string(),
    }
}

pub struct Engine {
    pub config: Config,
    pub store: Store,
    policy: ArcSwap<Policy>,
    policy_reload: tokio::sync::Mutex<()>,
    pub features: Arc<Features>,
    recursor: ArcSwap<Recursors>,
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
        let policy = Policy::compile(rules, domains)?;
        self.policy.store(Arc::new(policy));
        Ok(())
    }

    pub fn validate_rule(input: &RuleInput) -> Result<RuleInput> {
        policy::validate_rule(input)
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
        Ok(self
            .answer_with_diagnostics(wire, peer, protocol, user_id, false)
            .await?
            .wire)
    }

    pub(crate) async fn answer_with_diagnostics(
        self: &Arc<Self>,
        wire: &[u8],
        peer: SocketAddr,
        protocol: &str,
        user_id: Option<i64>,
        test_adguard: bool,
    ) -> Result<QueryAnswer> {
        let started = Instant::now();
        let request = Message::from_vec(wire).context("invalid DNS message")?;
        let mut response = response(&request, ResponseCode::NoError);
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
        {
            response.metadata.response_code = ResponseCode::FormErr;
            return Ok(QueryAnswer {
                wire: response.to_vec()?,
                block_reason: None,
                duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            });
        }
        let query = request.queries[0].clone();
        if query.query_class() != DNSClass::IN {
            response.metadata.response_code = ResponseCode::Refused;
            return Ok(QueryAnswer {
                wire: response.to_vec()?,
                block_reason: None,
                duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            });
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
        let kind = record_type_label(query.query_type());
        let policy = self.policy.load_full();
        let runtime = self.features.current.load_full();
        let location = runtime.geo.lookup(crate::access::canonical_ip(peer.ip()));
        let access = runtime.access.decide(peer.ip(), &location);
        let personal = match user_id.filter(|_| access.is_ok()) {
            Some(user) => query_policy(&self.store, user, &domain).await?,
            None => Some((
                DnsPreferences {
                    adguard: test_adguard,
                    ..Default::default()
                },
                Vec::new(),
            )),
        };
        let inactive = personal.is_none();
        let (preferences, personal_records) = personal.unwrap_or_default();
        let forward_target = policy.forward_target(&domain);
        let filter = policy.filter(&domain);
        let mut selected_upstream = None;
        let outcome;
        let mut block_reason = None;
        if let Err(reason) = access {
            response.metadata.response_code = ResponseCode::Refused;
            outcome = reason;
            block_reason = Some(reason);
        } else if inactive {
            response.metadata.response_code = ResponseCode::Refused;
            outcome = "refused";
            block_reason = Some("inactive_account");
        } else if let Some(records) = policy.local_records(&domain) {
            answer_local(
                &mut response,
                &query,
                &kind,
                records.iter().filter_map(|record| {
                    Some((
                        record.record_type.as_deref()?,
                        record.value.as_deref()?,
                        record.ttl.unwrap_or(300) as u32,
                    ))
                }),
            )?;
            outcome = "local";
        } else if let Some(FilterDecision::Block(reason)) = filter {
            response.metadata.response_code = ResponseCode::NXDomain;
            outcome = "blocked";
            block_reason = Some(reason);
        } else if forward_target.is_none() && !personal_records.is_empty() {
            answer_local(
                &mut response,
                &query,
                &kind,
                personal_records.iter().map(|record| {
                    (
                        record.record_type.as_str(),
                        record.value.as_str(),
                        record.ttl,
                    )
                }),
            )?;
            outcome = "personal_local";
        } else if preferences.adguard
            && runtime.settings.adguard.enabled
            && filter != Some(FilterDecision::Allow)
            && self.features.ads.load().blocks(&domain)
        {
            response.metadata.response_code = ResponseCode::NXDomain;
            outcome = "blocked";
            block_reason = Some("adguard");
        } else if let Some(upstream) = forward_target {
            let _foreground = self.begin_foreground(true);
            let budget = Duration::from_millis(runtime.settings.resolution.timeout_ms);
            match tokio::time::timeout(budget, forward(wire, &request, upstream)).await {
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
            let gfw = preferences.gfwlist
                && runtime.settings.gfwlist.enabled
                && self.features.list.load().matches(&domain);
            match self
                .cache_lookup(&runtime, &request, gfw, true)
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
                        // RFC 8914 Extended DNS Error, when the client supports EDNS.
                        if let Some(warning) = answer.dnssec_warning {
                            edns.options_mut().insert(EdnsOption::Unknown(
                                15,
                                (warning as u16).to_be_bytes().to_vec(),
                            ));
                        }
                        edns
                    });
                    outcome = answer.outcome;
                }
                Ok(Err(error)) => {
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = if matches!(error, LookupFailure::Dnssec(_)) {
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
        if let Err(error) = self.store.query_log.push(crate::query_log::QueryLogEntry {
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
            rcode: Some(u16::from(response.metadata.response_code)),
            response_wire: user_id.map(|_| wire.clone()),
        }) {
            tracing::warn!(%error, "query log write failed");
        }
        Ok(QueryAnswer {
            wire,
            block_reason,
            duration_ms,
        })
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
        let strict = settings.resolution.recursion_compatibility == RecursionCompatibility::Strict;
        let qtype = request.queries[0].query_type();
        let lookup = async {
            match mode {
                ResolveMode::Recursive if strict => {
                    let doh = group
                        .context("missing upstream group")
                        .map_err(|_| LookupFailure::Unavailable)?;
                    let total = Duration::from_millis(settings.resolution.timeout_ms);
                    let reserve = doh.timeout().min(total / 2);
                    let recursive = tokio::time::timeout(
                        total - reserve,
                        self.recursive_lookup(request, false, true),
                    )
                    .await
                    .unwrap_or(Err(LookupFailure::Unavailable));
                    if recursive
                        .as_ref()
                        .is_ok_and(|answer| answer.has_answer(qtype))
                    {
                        return recursive;
                    }
                    let fallback = tokio::time::timeout(
                        reserve,
                        doh_lookup(doh, request.clone(), settings.resolution.validate_dnssec),
                    )
                    .await
                    .unwrap_or(Err(LookupFailure::Unavailable));
                    fallback_answer(recursive, fallback, qtype)
                }
                ResolveMode::Recursive => self.recursive_lookup(request, true, false).await,
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
                        self.recursive_lookup(request, false, strict),
                        doh_lookup(
                            doh,
                            request.clone(),
                            strict && settings.resolution.validate_dnssec,
                        ),
                        Duration::from_millis(settings.resolution.priority_ms),
                        strict.then_some(qtype),
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
    async fn recursive_lookup(
        &self,
        request: &Message,
        allow_unverified: bool,
        strict: bool,
    ) -> Result<Resolved, LookupFailure> {
        let recursors = self.recursor.load_full();
        let fresh = crate::cache::bypass_cache(request);
        let (validating, unverified) = match (fresh, strict) {
            (true, true) => (&recursors.fresh_strict, &recursors.fresh_unverified),
            (true, false) => (&recursors.fresh_relaxed, &recursors.fresh_unverified),
            (false, true) => (&recursors.strict, &recursors.unverified),
            (false, false) => (&recursors.relaxed, &recursors.unverified),
        };
        match Self::resolve_recursive(validating, request).await {
            Err(LookupFailure::Dnssec(code)) if allow_unverified => {
                let mut answer = Self::resolve_recursive(unverified, request)
                    .await
                    .map_err(|_| LookupFailure::Dnssec(code))?;
                answer.outcome = "recursive_dnssec_unverified";
                answer.dnssec_warning = Some(code);
                Ok(answer)
            }
            result => result,
        }
    }

    async fn resolve_recursive(
        recursor: &Recursor<CachedProvider>,
        request: &Message,
    ) -> Result<Resolved, LookupFailure> {
        let query = request.queries[0].clone();
        let do_bit = request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        match recursor.resolve(query, Instant::now(), do_bit).await {
            Ok(mut message) => {
                if !matches!(
                    message.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) {
                    return Err(LookupFailure::Unavailable);
                }
                message.metadata.authentic_data =
                    recursor.is_validating() && validated_answer_is_secure(&message)?;
                Ok(Resolved {
                    message,
                    outcome: "recursive",
                    upstream: None,
                    dnssec_warning: None,
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
                    dnssec_warning: None,
                })
            }
            Err(error) => {
                tracing::debug!(%error, "recursive lookup failed");
                Err(match error {
                    RecursorError::Net(error) => dnssec_failure(&error),
                    _ => LookupFailure::Unavailable,
                })
            }
        }
    }
}

#[derive(Clone)]
struct Resolved {
    message: Message,
    outcome: &'static str,
    upstream: Option<String>,
    dnssec_warning: Option<DnssecFailure>,
}

impl Resolved {
    fn has_answer(&self, qtype: RecordType) -> bool {
        self.message.metadata.response_code == ResponseCode::NoError
            && self
                .message
                .answers
                .iter()
                .any(|record| qtype == RecordType::ANY || record.record_type() == qtype)
    }
}

fn fallback_answer(
    recursive: Result<Resolved, LookupFailure>,
    doh: Result<Resolved, LookupFailure>,
    qtype: RecordType,
) -> Result<Resolved, LookupFailure> {
    match (recursive, doh) {
        (_, Ok(answer)) if answer.has_answer(qtype) => Ok(answer),
        (Ok(answer), _) | (Err(_), Ok(answer)) => Ok(answer),
        (Err(error), Err(_)) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LookupFailure {
    Unavailable,
    Dnssec(DnssecFailure),
}

// RFC 8914 Extended DNS Error information codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum DnssecFailure {
    Indeterminate = 5,
    Bogus = 6,
}

fn dnssec_failure(error: &NetError) -> LookupFailure {
    match error {
        NetError::Dns(DnsError::DnssecBogus) => LookupFailure::Dnssec(DnssecFailure::Bogus),
        NetError::Dns(DnsError::Nsec { proof, .. }) if proof.is_bogus() => {
            LookupFailure::Dnssec(DnssecFailure::Bogus)
        }
        NetError::Dns(DnsError::Nsec { proof, .. }) if proof.is_indeterminate() => {
            LookupFailure::Dnssec(DnssecFailure::Indeterminate)
        }
        _ => LookupFailure::Unavailable,
    }
}

async fn doh_lookup(
    group: Arc<DohGroup>,
    request: Message,
    validate: bool,
) -> Result<Resolved, LookupFailure> {
    match group.resolve(request, validate).await {
        Ok(mut message) => {
            if validate {
                let secure = validated_answer_is_secure(&message)?;
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
                dnssec_warning: None,
            })
        }
        Err(error) => {
            tracing::debug!(group = %group.name, %error, "DoH lookup failed");
            Err(error
                .downcast_ref::<NetError>()
                .map_or(LookupFailure::Unavailable, dnssec_failure))
        }
    }
}

async fn prefer_recursive<R, D>(
    recursive: R,
    doh: D,
    priority: Duration,
    fallback_for: Option<RecordType>,
) -> Result<Resolved, LookupFailure>
where
    R: std::future::Future<Output = Result<Resolved, LookupFailure>>,
    D: std::future::Future<Output = Result<Resolved, LookupFailure>>,
{
    tokio::pin!(recursive, doh);
    let deadline = tokio::time::sleep(priority);
    tokio::pin!(deadline);
    let mut recursive_result = None;
    let mut doh_result = None;
    let mut elapsed = false;
    let usable = |answer: &Resolved| fallback_for.is_none_or(|qtype| answer.has_answer(qtype));
    loop {
        tokio::select! {
            biased;
            result = &mut recursive, if recursive_result.is_none() => {
                if result.as_ref().is_ok_and(usable) {
                    return result;
                }
                recursive_result = Some(result);
            }
            result = &mut doh, if doh_result.is_none() => {
                doh_result = Some(result);
            }
            _ = &mut deadline, if !elapsed => elapsed = true,
        }

        match (&recursive_result, &doh_result) {
            (Some(_), Some(_)) => {
                let recursive = recursive_result.take().unwrap();
                let doh = doh_result.take().unwrap();
                return match fallback_for {
                    Some(qtype) => fallback_answer(recursive, doh, qtype),
                    None => doh.or(recursive),
                };
            }
            (None, Some(Ok(_))) if elapsed => {
                return doh_result.take().unwrap();
            }
            _ => {}
        }
    }
}

struct Recursors {
    relaxed: Recursor<CachedProvider>,
    strict: Recursor<CachedProvider>,
    unverified: Recursor<CachedProvider>,
    fresh_relaxed: Recursor<CachedProvider>,
    fresh_strict: Recursor<CachedProvider>,
    fresh_unverified: Recursor<CachedProvider>,
}

fn build_recursor(roots: &[IpAddr], cache: &Arc<PersistentCache>) -> Result<Recursors> {
    build_recursor_with_settings(roots, cache, &cache.settings())
}

fn build_recursor_with_settings(
    roots: &[IpAddr],
    cache: &Arc<PersistentCache>,
    settings: &CacheSettings,
) -> Result<Recursors> {
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
    let build = |policy, qname_minimization, response_cache_size| {
        Recursor::new(
            roots,
            policy,
            None,
            RecursorOptions {
                qname_minimization,
                response_cache_size,
                ..options.clone()
            },
            CachedProvider::new(cache.clone(), roots),
        )
        .context("starting recursor")
    };
    Ok(Recursors {
        relaxed: build(
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
            QNameMinimization::Relaxed,
            2_048,
        )?,
        strict: build(
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
            QNameMinimization::Strict,
            2_048,
        )?,
        unverified: build(
            DnssecPolicy::ValidationDisabled,
            QNameMinimization::Relaxed,
            2_048,
        )?,
        fresh_relaxed: build(
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
            QNameMinimization::Relaxed,
            0,
        )?,
        fresh_strict: build(
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
            QNameMinimization::Strict,
            0,
        )?,
        fresh_unverified: build(
            DnssecPolicy::ValidationDisabled,
            QNameMinimization::Relaxed,
            0,
        )?,
    })
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

fn validated_answer_is_secure(message: &Message) -> Result<bool, LookupFailure> {
    if message.answers.iter().any(|record| record.proof.is_bogus()) {
        Err(LookupFailure::Dnssec(DnssecFailure::Bogus))
    } else if message
        .answers
        .iter()
        .any(|record| record.proof.is_indeterminate())
    {
        Err(LookupFailure::Dnssec(DnssecFailure::Indeterminate))
    } else {
        Ok(!message.answers.is_empty()
            && message
                .answers
                .iter()
                .all(|record| record.proof.is_secure()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        dnssec::Proof,
        rr::rdata::{A, CNAME},
    };
    use std::collections::HashSet;

    fn ready(outcome: &'static str) -> Result<Resolved, LookupFailure> {
        Ok(Resolved {
            message: Message::query(),
            outcome,
            upstream: None,
            dnssec_warning: None,
        })
    }

    #[tokio::test]
    async fn recursive_priority_window_and_failure_semantics() {
        let result = prefer_recursive(
            async { ready("recursive") },
            async { ready("doh") },
            Duration::from_millis(20),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "recursive");
        let started = Instant::now();
        let result = prefer_recursive(
            std::future::pending(),
            async { ready("doh") },
            Duration::from_millis(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "doh");
        assert!(started.elapsed() >= Duration::from_millis(25));
        let result = prefer_recursive(
            async { Err(LookupFailure::Unavailable) },
            async { ready("doh") },
            Duration::from_secs(1),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "doh");
        for failure in [DnssecFailure::Bogus, DnssecFailure::Indeterminate] {
            let failure = LookupFailure::Dnssec(failure);
            let result = prefer_recursive(
                async { Err(failure) },
                async { ready("doh") },
                Duration::from_secs(1),
                None,
            )
            .await
            .unwrap();
            assert_eq!(result.outcome, "doh");

            let result = prefer_recursive(
                async { Err(failure) },
                async { Err(LookupFailure::Unavailable) },
                Duration::from_secs(1),
                None,
            )
            .await;
            assert!(matches!(result, Err(error) if error == failure));
        }
        let result = prefer_recursive(
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ready("recursive")
            },
            async { Err(LookupFailure::Unavailable) },
            Duration::from_millis(1),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.outcome, "recursive");
    }

    #[tokio::test]
    async fn strict_recursion_tries_doh_when_requested_records_are_missing() {
        let qtype = RecordType::A;
        let doh_answer = || {
            let mut answer = ready("doh").unwrap();
            answer.message.add_answer(Record::from_rdata(
                Name::from_ascii("resolved.test.").unwrap(),
                60,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            Ok(answer)
        };
        for rcode in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let recursive_negative = || {
                let mut answer = ready("recursive").unwrap();
                answer.message.metadata.response_code = rcode;
                answer.message.add_answer(Record::from_rdata(
                    Name::from_ascii("alias.test.").unwrap(),
                    60,
                    RData::CNAME(CNAME(Name::from_ascii("resolved.test.").unwrap())),
                ));
                Ok(answer)
            };
            let result = prefer_recursive(
                async { recursive_negative() },
                async { doh_answer() },
                Duration::from_secs(1),
                Some(qtype),
            )
            .await
            .unwrap();
            assert_eq!(result.outcome, "doh");
            let result =
                fallback_answer(recursive_negative(), Err(LookupFailure::Unavailable), qtype)
                    .unwrap();
            assert_eq!(result.message.metadata.response_code, rcode);
        }
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
    fn classifies_dnssec_proof() {
        let name = Name::from_ascii("example.com.").unwrap();
        let mut answer = Message::response(0, OpCode::Query);
        let mut record = Record::from_rdata(name, 60, RData::A(A("192.0.2.1".parse().unwrap())));
        record.proof = Proof::Bogus;
        answer.add_answer(record.clone());
        assert_eq!(
            validated_answer_is_secure(&answer),
            Err(LookupFailure::Dnssec(DnssecFailure::Bogus))
        );
        record.proof = Proof::Indeterminate;
        answer.answers = vec![record.clone()];
        assert_eq!(
            validated_answer_is_secure(&answer),
            Err(LookupFailure::Dnssec(DnssecFailure::Indeterminate))
        );
        record.proof = Proof::Insecure;
        answer.answers = vec![record.clone()];
        assert_eq!(validated_answer_is_secure(&answer), Ok(false));
        record.proof = Proof::Secure;
        answer.answers = vec![record];
        assert_eq!(validated_answer_is_secure(&answer), Ok(true));
    }

    #[test]
    fn bundled_root_hints_include_current_ipv4_and_ipv6_addresses() {
        let roots = parse_root_hints(include_str!("../resources/named.root")).unwrap();
        assert!(roots.len() >= 20);
        assert!(roots.contains(&"170.247.170.2".parse().unwrap()));
        assert!(roots.contains(&"2801:1b8:10::b".parse().unwrap()));
    }
}
