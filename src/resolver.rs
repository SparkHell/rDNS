use crate::{
    config::Config,
    store::{Rule, RuleInput, Store},
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
    net::runtime::TokioRuntimeProvider,
    recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Clone, Default)]
struct Policy {
    local: Vec<Rule>,
    allow: HashSet<String>,
    block: HashSet<String>,
    forward: Vec<(String, SocketAddr)>,
}

pub struct Engine {
    pub config: Config,
    pub store: Store,
    policy: ArcSwap<Policy>,
    clients: ArcSwap<Vec<ipnet::IpNet>>,
    recursor: Recursor<TokioRuntimeProvider>,
}

impl Engine {
    pub async fn new(config: Config, store: Store) -> Result<Arc<Self>> {
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
        let recursor = Recursor::new(
            &roots,
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
            None,
            RecursorOptions::default(),
            TokioRuntimeProvider::default(),
        )
        .context("starting validating recursor")?;
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
        let engine = Arc::new(Self {
            config,
            store,
            policy: ArcSwap::from_pointee(Policy::default()),
            clients: ArcSwap::from_pointee(Vec::new()),
            recursor,
        });
        engine.reload_policy().await?;
        engine.reload_clients().await?;
        Ok(engine)
    }

    pub async fn reload_clients(&self) -> Result<()> {
        let networks = self
            .store
            .client_networks()
            .await?
            .into_iter()
            .map(|cidr| cidr.parse())
            .collect::<std::result::Result<Vec<ipnet::IpNet>, _>>()?;
        anyhow::ensure!(!networks.is_empty(), "client allowlist cannot be empty");
        self.clients.store(Arc::new(networks));
        Ok(())
    }

    pub fn client_allowed(&self, peer: SocketAddr) -> bool {
        self.clients
            .load()
            .iter()
            .any(|network| network.contains(&peer.ip()))
    }

    pub async fn reload_policy(&self) -> Result<()> {
        let mut policy = Policy::default();
        for rule in self.store.rules().await? {
            match rule.kind.as_str() {
                "local" => policy.local.push(rule),
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
        policy
            .block
            .extend(self.store.subscription_domains().await?);
        policy
            .forward
            .sort_by_key(|(domain, _)| std::cmp::Reverse(domain.len()));
        self.policy.store(Arc::new(policy));
        Ok(())
    }

    pub fn validate_rule(input: &RuleInput) -> Result<RuleInput> {
        let domain = normalize_domain(&input.domain)?;
        anyhow::ensure!(
            ["local", "allow", "block", "forward"].contains(&input.kind.as_str()),
            "invalid rule kind"
        );
        let mut result = input.clone();
        result.domain = domain;
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

    pub async fn answer(&self, wire: &[u8], peer: SocketAddr, protocol: &str) -> Result<Vec<u8>> {
        let request = Message::from_vec(wire).context("invalid DNS message")?;
        let mut response = response(&request, ResponseCode::NoError);
        if !self.client_allowed(peer) {
            response.metadata.response_code = ResponseCode::Refused;
            return Ok(response.to_vec()?);
        }
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
        let domain = normalize_domain(&query.name().to_ascii())?;
        let kind = query.query_type().to_string();
        let policy = self.policy.load_full();
        let mut outcome = "recursive";
        if policy.local.iter().any(|r| r.domain == domain) {
            for record in policy.local.iter().filter(|r| {
                r.domain == domain
                    && (r.record_type.as_deref() == Some(kind.as_str())
                        || r.record_type.as_deref() == Some("CNAME"))
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
        } else if !matches_domain(&policy.allow, &domain) && matches_domain(&policy.block, &domain)
        {
            response.metadata.response_code = ResponseCode::NXDomain;
            outcome = "blocked";
        } else if let Some((_, upstream)) = policy
            .forward
            .iter()
            .find(|(suffix, _)| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
        {
            match forward(wire, *upstream).await {
                Ok(bytes) => {
                    let mut forwarded = Message::from_vec(&bytes)?;
                    forwarded.metadata.id = request.metadata.id;
                    forwarded.metadata.authentic_data = false;
                    response = forwarded;
                    outcome = "forward";
                }
                Err(error) => {
                    tracing::warn!(%error, %upstream, "conditional forward failed");
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = "error";
                }
            }
        } else {
            let do_bit = request
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok);
            match tokio::time::timeout(
                Duration::from_secs(15),
                self.recursor.resolve(query.clone(), Instant::now(), do_bit),
            )
            .await
            {
                Ok(Ok(mut resolved)) => {
                    tracing::debug!(%domain, ?resolved.metadata, proofs = ?resolved.all_sections().map(|r| (r.record_type(), r.proof)).collect::<Vec<_>>(), "recursor result");
                    if let Some(secure) = validated_answer_is_secure(&resolved) {
                        resolved.metadata.id = request.metadata.id;
                        resolved.metadata.recursion_desired = request.metadata.recursion_desired;
                        resolved.metadata.recursion_available = true;
                        resolved.metadata.authentic_data = secure;
                        resolved.queries = vec![query.clone()];
                        if request.edns.is_some() {
                            let mut edns = Edns::new();
                            edns.set_max_payload(request.max_payload())
                                .set_dnssec_ok(do_bit);
                            resolved.edns = Some(edns);
                        } else {
                            resolved.edns = None;
                        }
                        response = resolved;
                    } else {
                        response.metadata.response_code = ResponseCode::ServFail;
                        outcome = "dnssec_bogus";
                    }
                }
                Ok(Err(error)) => {
                    if error.is_nx_domain() {
                        response.metadata.response_code = ResponseCode::NXDomain;
                        outcome = "nxdomain";
                    } else if error.is_no_records_found() {
                        outcome = "nodata";
                    } else {
                        tracing::warn!(%error, %domain, "recursive lookup failed");
                        response.metadata.response_code = ResponseCode::ServFail;
                        outcome = "error";
                    }
                    if matches!(outcome, "nxdomain" | "nodata")
                        && let Some(soa) = error.into_soa()
                    {
                        response.add_authority(Record::from_rdata(
                            soa.name,
                            soa.ttl,
                            RData::SOA(soa.data),
                        ));
                    }
                }
                Err(_) => {
                    response.metadata.response_code = ResponseCode::ServFail;
                    outcome = "timeout";
                }
            }
        }
        if let Err(error) = self
            .store
            .log_query(&peer.ip().to_string(), &domain, &kind, outcome, protocol)
            .await
        {
            tracing::warn!(%error, "query log write failed");
        }
        Ok(response.to_vec()?)
    }
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

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(
        !domain.is_empty() && domain.len() <= 253 && !domain.contains('*'),
        "invalid domain"
    );
    Name::from_ascii(format!("{domain}."))?;
    Ok(domain)
}

fn matches_domain(set: &HashSet<String>, domain: &str) -> bool {
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
