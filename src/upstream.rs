use crate::{cache::PersistentCache, config::Config};
use anyhow::{Context, Result, ensure};
use futures::{StreamExt, stream::BoxStream};
use hickory_proto::op::{DnsRequest, DnsResponse, Message, MessageType, ResponseCode};
use hickory_resolver::net::{
    DnsError, NetError, dnssec::DnssecDnsHandle, runtime::TokioRuntimeProvider, xfer::DnsHandle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DohServer {
    pub url: String,
    pub bootstrap_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupSettings {
    pub name: String,
    pub servers: Vec<DohServer>,
    pub proxy: String,
    pub timeout_ms: u64,
}
impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            name: "default".into(),
            servers: vec![],
            proxy: String::new(),
            timeout_ms: 3000,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolveMode {
    #[default]
    Recursive,
    Doh,
    Parallel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResolutionSettings {
    pub mode: ResolveMode,
    pub group: String,
    pub priority_ms: u64,
    pub timeout_ms: u64,
    pub validate_dnssec: bool,
}
impl Default for ResolutionSettings {
    fn default() -> Self {
        Self {
            mode: ResolveMode::Recursive,
            group: "default".into(),
            priority_ms: 300,
            timeout_ms: 15000,
            validate_dnssec: true,
        }
    }
}

pub fn validate_https(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid HTTPS URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "HTTPS URL required; credentials and fragments are not allowed"
    );
    Ok(url)
}

pub fn http_client(config: &Config, proxy: &str) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5));
    if !proxy.is_empty() {
        let url = reqwest::Url::parse(proxy).context("invalid proxy URL")?;
        ensure!(
            ["http", "https", "socks5", "socks5h"].contains(&url.scheme())
                && url.host_str().is_some(),
            "proxy must use http, https, socks5 or socks5h"
        );
        // Proxy-side name resolution prevents the system resolver from handling DoH hostnames.
        let proxy = if url.scheme() == "socks5" {
            proxy.replacen("socks5://", "socks5h://", 1)
        } else {
            proxy.to_owned()
        };
        builder =
            builder.proxy(reqwest::Proxy::all(&proxy).context("invalid proxy configuration")?);
    }
    if let Some(path) = &config.subscription_ca {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    Ok(builder)
}

pub async fn download(config: &Config, url: &str, proxy: &str, limit: usize) -> Result<Vec<u8>> {
    validate_https(url)?;
    let response = http_client(config, proxy)?
        .timeout(Duration::from_secs(60))
        .build()?
        .get(url)
        .send()
        .await
        .context("source download failed")?
        .error_for_status()
        .context("source returned an HTTP error")?;
    bounded_body(response, limit).await
}

async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "response exceeds size limit"
    );
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            body.len() + chunk.len() <= limit,
            "response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

struct Endpoint {
    url: String,
    client: reqwest::Client,
    requests: AtomicU64,
    failures: AtomicU64,
    cooldown_until: AtomicU64,
}

pub struct DohGroup {
    pub name: String,
    endpoints: Vec<Endpoint>,
    next: AtomicU64,
    cache_namespace: String,
    cache: Arc<PersistentCache>,
    timeout: Duration,
}

impl DohGroup {
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    pub fn build(
        config: &Config,
        settings: &GroupSettings,
        cache: Arc<PersistentCache>,
    ) -> Result<Arc<Self>> {
        ensure!(
            !settings.name.trim().is_empty() && settings.name.len() <= 80,
            "upstream group needs a name"
        );
        ensure!(
            !settings.servers.is_empty() && settings.servers.len() <= 16,
            "provide 1..16 DoH servers per group"
        );
        ensure!(
            (100..=30000).contains(&settings.timeout_ms),
            "DoH timeout must be 100..30000 ms"
        );
        let mut endpoints = Vec::new();
        for server in &settings.servers {
            let url = validate_https(&server.url)?;
            ensure!(server.bootstrap_ips.len() <= 16, "too many bootstrap IPs");
            let mut builder = http_client(config, &settings.proxy)?
                .timeout(Duration::from_millis(settings.timeout_ms))
                .pool_idle_timeout(Duration::from_secs(90));
            if !server.bootstrap_ips.is_empty() {
                let port = url.port_or_known_default().unwrap_or(443);
                let addresses: Vec<_> = server
                    .bootstrap_ips
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect();
                builder = builder.resolve_to_addrs(url.host_str().unwrap(), &addresses);
            }
            endpoints.push(Endpoint {
                url: server.url.clone(),
                client: builder.build()?,
                requests: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                cooldown_until: AtomicU64::new(0),
            });
        }
        let cache_namespace = hex::encode(Sha256::digest(serde_json::to_vec(settings)?));
        Ok(Arc::new(Self {
            name: settings.name.clone(),
            endpoints,
            next: AtomicU64::new(0),
            cache_namespace,
            cache,
            timeout: Duration::from_millis(settings.timeout_ms),
        }))
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"name":self.name,"servers":self.endpoints.iter().map(|e| serde_json::json!({"url":e.url,"requests":e.requests.load(Ordering::Relaxed),"failures":e.failures.load(Ordering::Relaxed),"cooldown_until":e.cooldown_until.load(Ordering::Relaxed)})).collect::<Vec<_>>()})
    }

    async fn exchange(&self, request: DnsRequest) -> Result<DnsResponse> {
        let mut message = (*request).clone();
        message.metadata.recursion_desired = true;
        message.metadata.authentic_data = false;
        let question = message.queries.clone();
        let id = message.metadata.id;
        message.metadata.id = 0;
        let wire = message.to_vec()?;
        let key = format!(
            "doh:{}:{}",
            self.cache_namespace,
            hex::encode(Sha256::digest(&wire))
        );
        if let Some(answer) = self.cache.get(&key, id).await {
            return Ok(answer);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) as usize % self.endpoints.len();
        let now = chrono::Utc::now().timestamp() as u64;
        let mut candidates: Vec<_> = (0..self.endpoints.len())
            .map(|i| &self.endpoints[(start + i) % self.endpoints.len()])
            .collect();
        candidates.sort_by_key(|e| e.cooldown_until.load(Ordering::Relaxed) > now);
        let attempt_timeout =
            (self.timeout / candidates.len() as u32).max(Duration::from_millis(25));
        for endpoint in candidates {
            endpoint.requests.fetch_add(1, Ordering::Relaxed);
            let attempt = async {
                let response = endpoint
                    .client
                    .post(&endpoint.url)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .body(wire.clone())
                    .send()
                    .await?
                    .error_for_status()?;
                ensure!(
                    response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.split(';').next().unwrap_or("").trim()
                            == "application/dns-message"),
                    "upstream did not return a DNS message"
                );
                let age = response
                    .headers()
                    .get("age")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let bytes = bounded_body(response, 65535).await?;
                let mut answer = Message::from_vec(&bytes)?;
                for record in answer
                    .answers
                    .iter_mut()
                    .chain(answer.authorities.iter_mut())
                    .chain(answer.additionals.iter_mut())
                {
                    record.ttl = record.ttl.saturating_sub(age);
                }
                ensure!(
                    answer.metadata.message_type == MessageType::Response
                        && answer.metadata.op_code == message.metadata.op_code
                        && answer.metadata.id == 0
                        && answer.queries == question
                        && !answer.metadata.truncation,
                    "upstream DNS response mismatch"
                );
                ensure!(
                    matches!(
                        answer.metadata.response_code,
                        ResponseCode::NoError | ResponseCode::NXDomain
                    ),
                    "upstream DNS error"
                );
                answer.metadata.id = id;
                answer.metadata.authentic_data = false;
                Ok::<_, anyhow::Error>(DnsResponse::from_message(answer)?)
            };
            if let Ok(Ok(answer)) = tokio::time::timeout(attempt_timeout, attempt).await {
                endpoint.cooldown_until.store(0, Ordering::Relaxed);
                self.cache.insert(&key, &answer).await;
                return Ok(answer);
            }
            endpoint.failures.fetch_add(1, Ordering::Relaxed);
            endpoint.cooldown_until.store(now + 30, Ordering::Relaxed);
        }
        anyhow::bail!("all DoH servers in group '{}' failed", self.name)
    }

    pub async fn resolve(self: &Arc<Self>, request: Message, validate: bool) -> Result<Message> {
        tokio::time::timeout(self.timeout, self.resolve_inner(request, validate))
            .await
            .context("DoH group query timed out")?
    }

    async fn resolve_inner(self: &Arc<Self>, request: Message, validate: bool) -> Result<Message> {
        let handle = DohHandle(self.clone());
        let request = DnsRequest::new(request, Default::default());
        let answer = if validate {
            match DnssecDnsHandle::new(handle)
                .send(request)
                .next()
                .await
                .context("no validating DoH response")?
            {
                Ok(answer) => answer,
                Err(NetError::Dns(DnsError::Nsec {
                    response, proof, ..
                })) if proof.is_secure() || proof.is_insecure() => {
                    let mut message = response.into_message();
                    message.metadata.authentic_data = proof.is_secure();
                    return Ok(message);
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            handle
                .send(request)
                .next()
                .await
                .context("no DoH response")??
        };
        Ok(answer.into_message())
    }
}

pub fn dnssec_error(error: &NetError) -> bool {
    match error {
        NetError::Dns(DnsError::DnssecBogus) => true,
        NetError::Dns(DnsError::Nsec { proof, .. }) => proof.is_bogus() || proof.is_indeterminate(),
        _ => false,
    }
}

#[derive(Clone)]
struct DohHandle(Arc<DohGroup>);
impl DnsHandle for DohHandle {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;
    fn send(&self, request: DnsRequest) -> Self::Response {
        let group = self.0.clone();
        futures::stream::once(async move {
            group
                .exchange(request)
                .await
                .map_err(|e| NetError::from(e.to_string()))
        })
        .boxed()
    }
}
