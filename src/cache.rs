use crate::store::Store;
use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use chrono::Utc;
use futures::{StreamExt, stream::BoxStream};
use hickory_proto::{
    dnssec::rdata::DNSSECRData,
    op::{DnsRequest, DnsResponse, Message, ResponseCode},
    rr::{RData, RecordType},
};
use hickory_resolver::{
    ConnectionProvider, PoolContext,
    config::ConnectionConfig,
    net::{
        NetError,
        runtime::TokioRuntimeProvider,
        xfer::{DnsExchange, DnsHandle},
    },
};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

pub const MAX_BACKGROUND_CONCURRENCY: usize = 64;

pub fn recommended_background_concurrency() -> usize {
    (std::thread::available_parallelism().map_or(2, usize::from) * 4).clamp(2, 32)
}

fn default_refresh_min() -> u8 {
    80
}
fn default_refresh_max() -> u8 {
    90
}

pub fn answer_budget(mib: u32) -> u64 {
    u64::from(mib) * 1024 * 1024 / 8
}

tokio::task_local! {
    pub static FRESH_QUERY: hickory_proto::op::Query;
}

pub fn bypass_cache(request: &Message) -> bool {
    FRESH_QUERY
        .try_with(|query| request.queries.first() == Some(query))
        .unwrap_or(false)
}

pub fn age_records(message: &mut Message, elapsed: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = record.ttl.saturating_sub(elapsed);
    }
}

pub fn positive_ttl(message: &Message, settings: &CacheSettings) -> Option<u32> {
    if message.answers.is_empty() || message.metadata.response_code != ResponseCode::NoError {
        return None;
    }
    let response = DnsResponse::from_message(message.clone()).ok()?;
    cache_ttl(&response, settings, Utc::now().timestamp()).map(|(_, ttl)| ttl)
}

pub struct BackgroundPermit(Arc<PersistentCache>);
impl Drop for BackgroundPermit {
    fn drop(&mut self) {
        self.0.background.fetch_sub(1, Ordering::AcqRel);
        self.0.background_ready.notify_one();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheSettings {
    pub memory_mib: u32,
    #[serde(default = "recommended_background_concurrency")]
    pub background_concurrency: usize,
    #[serde(default = "default_refresh_min")]
    pub refresh_ttl_min_pct: u8,
    #[serde(default = "default_refresh_max")]
    pub refresh_ttl_max_pct: u8,
    pub ns_max_ttl: u32,
    pub answer_max_ttl: u32,
    pub negative_max_ttl: u32,
}
impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            memory_mib: 64,
            background_concurrency: recommended_background_concurrency(),
            refresh_ttl_min_pct: default_refresh_min(),
            refresh_ttl_max_pct: default_refresh_max(),
            ns_max_ttl: 86_400,
            answer_max_ttl: 86_400,
            negative_max_ttl: 3_600,
        }
    }
}
impl CacheSettings {
    pub fn requires_reset(&self, previous: &Self) -> bool {
        *self
            != Self {
                background_concurrency: self.background_concurrency,
                refresh_ttl_min_pct: self.refresh_ttl_min_pct,
                refresh_ttl_max_pct: self.refresh_ttl_max_pct,
                ..previous.clone()
            }
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=4096).contains(&self.memory_mib) {
            bail!("memory cache must be 1..4096 MiB");
        }
        if !(1..=MAX_BACKGROUND_CONCURRENCY).contains(&self.background_concurrency) {
            bail!("后台并发数须为 1..64");
        }
        if !(1..=99).contains(&self.refresh_ttl_min_pct)
            || !(self.refresh_ttl_min_pct..=99).contains(&self.refresh_ttl_max_pct)
        {
            bail!("TTL 刷新区间须在 1%–99% 内，起点不能大于终点");
        }
        for ttl in [self.ns_max_ttl, self.answer_max_ttl, self.negative_max_ttl] {
            if !(1..=604_800).contains(&ttl) {
                bail!("cache TTL limits must be 1..604800 seconds");
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CachedEntry {
    wire: Vec<u8>,
    inserted_at: i64,
    expires_at: i64,
}

pub struct PersistentCache {
    store: Store,
    pub root: crate::root_zone::RootDelegations,
    settings: ArcSwap<CacheSettings>,
    configuration: tokio::sync::RwLock<()>,
    memory: ArcSwap<Cache<String, Arc<CachedEntry>>>,
    stats_sequence: AtomicU64,
    background: AtomicUsize,
    pub background_ready: tokio::sync::Notify,
    memory_hits: AtomicU64,
    disk_hits: AtomicU64,
    misses: AtomicU64,
}

impl PersistentCache {
    pub async fn new(store: Store) -> Result<Arc<Self>> {
        let settings = store.cache_settings().await?.unwrap_or_default();
        settings.validate()?;
        Ok(Arc::new(Self {
            root: Default::default(),
            store,
            memory: ArcSwap::from_pointee(memory_cache(settings.memory_mib)),
            configuration: Default::default(),
            settings: ArcSwap::from_pointee(settings),
            stats_sequence: AtomicU64::new(0),
            background: AtomicUsize::new(0),
            background_ready: Default::default(),
            memory_hits: AtomicU64::new(0),
            disk_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }))
    }
    pub fn try_background(self: Arc<Self>) -> Option<BackgroundPermit> {
        let limit = self.settings.load().background_concurrency;
        self.background
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        Some(BackgroundPermit(self))
    }

    pub fn background_active(&self) -> usize {
        self.background.load(Ordering::Acquire)
    }

    pub fn settings(&self) -> CacheSettings {
        (*self.settings.load_full()).clone()
    }
    pub async fn set_settings(
        &self,
        settings: CacheSettings,
        publish: impl FnOnce(),
    ) -> Result<()> {
        settings.validate()?;
        let _guard = self.configuration.write().await;
        let reset = settings.requires_reset(&self.settings.load());
        self.store.set_cache_settings(&settings, reset).await?;
        if reset {
            self.memory
                .store(Arc::new(memory_cache(settings.memory_mib)));
        }
        self.settings.store(Arc::new(settings));
        self.background_ready.notify_waiters();
        publish();
        Ok(())
    }
    pub async fn stats(&self) -> serde_json::Value {
        let memory = self.memory.load();
        memory.run_pending_tasks();
        let (disk_entries, disk_bytes) = self.store.cache_stats().await.unwrap_or((0, 0));
        serde_json::json!({"sample_id":self.stats_sequence.fetch_add(1, Ordering::Relaxed) + 1,"settings":self.settings(), "memory_bytes":memory.weighted_size(), "memory_entries":memory.entry_count(), "disk_entries":disk_entries, "disk_bytes":disk_bytes, "process_rss_bytes":process_rss_bytes(), "memory_hits":self.memory_hits.load(Ordering::Relaxed), "disk_hits":self.disk_hits.load(Ordering::Relaxed), "misses":self.misses.load(Ordering::Relaxed)})
    }
    pub async fn get(&self, key: &str, request_id: u16) -> Option<DnsResponse> {
        let _guard = self.configuration.read().await;
        let now = Utc::now().timestamp();
        let (entry, from_disk) = match self.memory.load().get(key) {
            Some(entry) => (entry, false),
            None => {
                let Some(row) = self.store.cache_entry(key).await.ok().flatten() else {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                let entry = Arc::new(CachedEntry {
                    wire: row.0,
                    inserted_at: row.1,
                    expires_at: row.2,
                });
                self.memory.load().insert(key.to_owned(), entry.clone());
                (entry, true)
            }
        };
        if now < entry.inserted_at || now >= entry.expires_at {
            self.memory.load().invalidate(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut message = Message::from_vec(&entry.wire).ok()?;
        let elapsed = (now - entry.inserted_at) as u32;
        age_records(&mut message, elapsed);
        message.metadata.id = request_id;
        let response = DnsResponse::from_message(message).ok()?;
        if from_disk {
            self.disk_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.memory_hits.fetch_add(1, Ordering::Relaxed);
        }
        Some(response)
    }
    pub async fn insert(&self, key: &str, response: &DnsResponse) {
        let _guard = self.configuration.read().await;
        let settings = self.settings();
        let now = Utc::now().timestamp();
        let Some((kind, ttl)) = cache_ttl(response, &settings, now) else {
            return;
        };
        let entry = Arc::new(CachedEntry {
            wire: response.as_buffer().to_vec(),
            inserted_at: now,
            expires_at: now + i64::from(ttl),
        });
        if entry.wire.len() > 65_535 {
            return;
        }
        if let Err(error) = self
            .store
            .set_cache_entry(key, &entry.wire, entry.inserted_at, entry.expires_at, kind)
            .await
        {
            tracing::warn!(%error, "persistent DNS cache write failed");
        }
        self.memory.load().insert(key.to_owned(), entry);
    }
}

fn process_rss_bytes() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0)
        * 1024
}

fn memory_cache(mib: u32) -> Cache<String, Arc<CachedEntry>> {
    Cache::builder()
        .max_capacity(u64::from(mib) * 1024 * 1024 - answer_budget(mib))
        .weigher(|key: &String, entry: &Arc<CachedEntry>| {
            (key.len() + entry.wire.len() + 64).min(u32::MAX as usize) as u32
        })
        .build()
}

fn cache_ttl(
    response: &DnsResponse,
    settings: &CacheSettings,
    now: i64,
) -> Option<(&'static str, u32)> {
    let is_negative = response.metadata.response_code == ResponseCode::NXDomain
        || (response.answers.is_empty()
            && response
                .authorities
                .iter()
                .any(|record| record.record_type() == RecordType::SOA));
    let is_ns = response
        .queries
        .first()
        .is_some_and(|q| q.query_type() == RecordType::NS)
        || (response.answers.is_empty()
            && response
                .authorities
                .iter()
                .any(|record| record.record_type() == RecordType::NS));
    let (kind, cap) = if is_negative {
        ("negative", settings.negative_max_ttl)
    } else if is_ns {
        ("delegation", settings.ns_max_ttl)
    } else if !response.answers.is_empty() {
        ("answer", settings.answer_max_ttl)
    } else {
        return None;
    };
    let mut ttl = cap;
    if is_negative {
        ttl = ttl.min(response.negative_ttl()?);
    }
    for record in response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
    {
        ttl = ttl.min(record.ttl);
        if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &record.data {
            ttl = ttl.min(sig.input().sig_expiration.get().saturating_sub(now as u32));
        }
    }
    (ttl > 0).then_some((kind, ttl))
}

fn cache_key(ip: IpAddr, port: u16, request: &DnsRequest) -> Option<String> {
    let query = request.queries.first()?;
    (request.queries.len() == 1).then(|| {
        format!(
            "{ip}:{port}|{}|{}|{}|{}|{}",
            query.name().to_ascii().to_ascii_lowercase(),
            query.query_type(),
            query.query_class(),
            request.metadata.recursion_desired,
            request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
        )
    })
}

#[derive(Clone)]
pub struct CachedProvider {
    roots: Arc<[IpAddr]>,
    runtime: TokioRuntimeProvider,
    cache: Arc<PersistentCache>,
}
impl CachedProvider {
    pub fn new(cache: Arc<PersistentCache>, roots: &[IpAddr]) -> Self {
        Self {
            roots: roots.into(),
            runtime: TokioRuntimeProvider::default(),
            cache,
        }
    }
}

#[derive(Clone)]
pub struct CachedHandle {
    is_root: bool,
    inner: DnsExchange<TokioRuntimeProvider>,
    ip: IpAddr,
    port: u16,
    cache: Arc<PersistentCache>,
}
impl DnsHandle for CachedHandle {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;
    fn is_verifying_dnssec(&self) -> bool {
        self.inner.is_verifying_dnssec()
    }
    fn is_using_edns(&self) -> bool {
        self.inner.is_using_edns()
    }
    fn send(&self, request: DnsRequest) -> Self::Response {
        let this = self.clone();
        futures::stream::once(async move {
            if this.is_root
                && let Some(response) = this
                    .cache
                    .root
                    .referral(&request, this.cache.settings.load().ns_max_ttl)
            {
                return Some(Ok(response));
            }
            let key = if bypass_cache(&request) {
                None
            } else {
                cache_key(this.ip, this.port, &request)
            };
            if let Some(key) = &key
                && let Some(response) = this.cache.get(key, request.metadata.id).await
            {
                return Some(Ok(response));
            }
            let mut stream = this.inner.send(request);
            let result = stream.next().await;
            if let (Some(key), Some(Ok(response))) = (&key, &result) {
                this.cache.insert(key, response).await;
            }
            result
        })
        .filter_map(|result| async move { result })
        .boxed()
    }
}
impl ConnectionProvider for CachedProvider {
    type Conn = CachedHandle;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send + 'static>>;
    type RuntimeProvider = TokioRuntimeProvider;
    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let future = <TokioRuntimeProvider as ConnectionProvider>::new_connection(
            &self.runtime,
            ip,
            config,
            cx,
        )?;
        let port = config.port;
        let is_root = port == 53 && self.roots.contains(&ip);
        let cache = self.cache.clone();
        Ok(Box::pin(async move {
            Ok(CachedHandle {
                is_root,
                inner: future.await?,
                ip,
                port,
                cache,
            })
        }))
    }
    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use hickory_proto::{
        dnssec::{
            Algorithm,
            rdata::{RRSIG, SigInput},
        },
        rr::SerialNumber,
    };
    use hickory_proto::{
        op::{OpCode, Query},
        rr::{
            Name, Record,
            rdata::{A, NS},
        },
    };

    #[tokio::test]
    async fn sqlite_cache_survives_recreation_and_replays_with_new_id() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "rdns-cache-{}-{}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = Store::open(&path).await?;
        let cache = PersistentCache::new(store.clone()).await?;
        assert_eq!(cache.settings().memory_mib, 64);
        let name = Name::from_ascii("example.com.")?;
        let mut message = Message::response(10, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name.clone(),
            120,
            RData::A(A("192.0.2.1".parse()?)),
        ));
        let answer_response = DnsResponse::from_message(message)?;
        let now = Utc::now().timestamp();
        let mut signed_message = answer_response.clone().into_message();
        let signature = RRSIG::from_sig(
            SigInput {
                type_covered: RecordType::A,
                algorithm: Algorithm::ECDSAP256SHA256,
                num_labels: 2,
                original_ttl: 120,
                sig_expiration: SerialNumber::new((now + 30) as u32),
                sig_inception: SerialNumber::new((now - 30) as u32),
                key_tag: 1,
                signer_name: name.clone(),
            },
            vec![1],
        );
        signed_message.add_answer(Record::from_rdata(
            name.clone(),
            120,
            RData::DNSSEC(DNSSECRData::RRSIG(signature)),
        ));
        let signed_response = DnsResponse::from_message(signed_message)?;
        assert_eq!(
            cache_ttl(&signed_response, &CacheSettings::default(), now),
            Some(("answer", 30))
        );
        cache.insert("answer-key", &answer_response).await;
        let mut referral = Message::response(11, OpCode::Query);
        referral.add_query(Query::query(name.clone(), RecordType::NS));
        referral.add_authority(Record::from_rdata(
            name.clone(),
            120,
            RData::NS(NS(Name::from_ascii("ns.example.com.")?)),
        ));
        referral.add_additional(Record::from_rdata(
            Name::from_ascii("ns.example.com.")?,
            120,
            RData::A(A("192.0.2.2".parse()?)),
        ));
        let referral_response = DnsResponse::from_message(referral)?;
        let short_ns = CacheSettings {
            ns_max_ttl: 60,
            ..CacheSettings::default()
        };
        assert_eq!(
            cache_ttl(&referral_response, &short_ns, Utc::now().timestamp()),
            Some(("delegation", 60))
        );
        cache.insert("delegation-key", &referral_response).await;
        store
            .set_cache_entry(
                "answer-key",
                answer_response.as_buffer(),
                now - 30,
                now + 90,
                "answer",
            )
            .await?;
        drop(cache);
        let restored = PersistentCache::new(store.clone()).await?;
        let answer = restored
            .get("answer-key", 22)
            .await
            .context("answer missing from SQLite")?;
        assert_eq!(answer.metadata.id, 22);
        assert_eq!(answer.answers.len(), 1);
        assert!(answer.answers[0].ttl <= 90);
        assert!(restored.get("delegation-key", 23).await.is_some());
        assert_eq!(restored.stats().await["disk_hits"], 2);
        // Pause an old-generation insert in SQLite after it selected the old TTL.
        let blocker = store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let writer_cache = restored.clone();
        let original = answer_response.clone();
        let writer = tokio::spawn(async move { writer_cache.insert("race", &original).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while restored.configuration.try_write().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let reconfigure = restored.set_settings(
            CacheSettings {
                answer_max_ttl: 2,
                ..Default::default()
            },
            || {},
        );
        tokio::pin!(reconfigure);
        assert!(futures::poll!(&mut reconfigure).is_pending());
        blocker.rollback().await?;
        writer.await?;
        reconfigure.await?;
        assert!(restored.get("race", 1).await.is_none());
        assert!(
            PersistentCache::new(store.clone())
                .await?
                .get("race", 2)
                .await
                .is_none()
        );
        restored.insert("race", &answer_response).await;
        let (_, inserted, expires) = store.cache_entry("race").await?.unwrap();
        assert_eq!(expires - inserted, 2);
        store.pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }
}
