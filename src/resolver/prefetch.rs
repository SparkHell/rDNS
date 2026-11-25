use super::*;
use crate::{
    cache::{BackgroundPermit, age_records, positive_ttl},
    features::FeatureRuntime,
};
use arc_swap::ArcSwap;
use hickory_proto::op::Query;
use moka::sync::Cache;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::OnceCell;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Key {
    revision: u64,
    cache_version: u64,
    query: Query,
    gfw: bool,
    recursion_desired: bool,
    dnssec_ok: bool,
}

type Outcome = Result<Result<Resolved, LookupFailure>, tokio::time::error::Elapsed>;
type Flight = Arc<OnceCell<Arc<Outcome>>>;
type AnswerCache = Cache<Key, Arc<HotAnswer>>;

struct HotAnswer {
    answer: Resolved,
    inserted: Instant,
    ttl: u32,
    refresh_jitter: f64,
    attempted: AtomicBool,
}

pub(super) struct Prefetch {
    entries: ArcSwap<AnswerCache>,
    flights: Mutex<HashMap<Key, Flight>>,
    version: AtomicU64,
    foreground: AtomicUsize,
    pub hits: AtomicU64,
}

struct Lease<'a> {
    flights: &'a Mutex<HashMap<Key, Flight>>,
    key: Key,
    flight: Flight,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut flights = self.flights.lock().expect("DNS flight lock");
        if Arc::strong_count(&self.flight) == 2 {
            flights.remove(&self.key);
        }
    }
}

pub(super) struct Foreground<'a>(&'a Engine);
impl Drop for Foreground<'_> {
    fn drop(&mut self) {
        if self.0.prefetch.foreground.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.cache.background_ready.notify_waiters();
        }
    }
}

impl Prefetch {
    pub fn new(settings: &CacheSettings) -> Self {
        Self {
            entries: ArcSwap::from_pointee(entries(settings)),
            flights: Default::default(),
            version: Default::default(),
            foreground: Default::default(),
            hits: Default::default(),
        }
    }

    pub fn reset(&self, settings: &CacheSettings) {
        self.entries.store(Arc::new(entries(settings)));
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    pub fn stats(&self) -> (u64, u64) {
        let cache = self.entries.load();
        cache.run_pending_tasks();
        (cache.entry_count(), cache.weighted_size())
    }

    fn join(&self, key: &Key, only_vacant: bool) -> Option<Lease<'_>> {
        let mut flights = self.flights.lock().expect("DNS flight lock");
        if only_vacant && flights.contains_key(key) {
            return None;
        }
        let flight = flights.entry(key.clone()).or_default().clone();
        Some(Lease {
            flights: &self.flights,
            key: key.clone(),
            flight,
        })
    }
}

fn entries(settings: &CacheSettings) -> AnswerCache {
    Cache::builder()
        .max_capacity(crate::cache::answer_budget(settings.memory_mib))
        .time_to_live(Duration::from_secs(settings.answer_max_ttl.into()))
        .weigher(|key: &Key, entry: &Arc<HotAnswer>| {
            (key.query.name().len()
                + entry
                    .answer
                    .message
                    .to_vec()
                    .map_or(65535, |wire| wire.len())
                    * 2
                + 192)
                .min(u32::MAX as usize) as u32
        })
        .build()
}

impl Engine {
    pub(super) async fn cache_lookup(
        self: &Arc<Self>,
        runtime: &Arc<FeatureRuntime>,
        request: &Message,
        gfw: bool,
        foreground: bool,
    ) -> Arc<Outcome> {
        let edns = request.edns.as_ref();
        if edns.is_some_and(|edns| !edns.options().as_ref().is_empty())
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || request.metadata.checking_disabled
        {
            let _fg = self.begin_foreground(foreground);
            return Arc::new(self.routed_lookup(runtime, request, gfw).await);
        }
        let key = Key {
            revision: runtime.cache_revision,
            cache_version: self.prefetch.version.load(Ordering::Acquire),
            query: request.queries[0].clone(),
            gfw,
            recursion_desired: request.metadata.recursion_desired,
            dnssec_ok: edns.is_some_and(|edns| edns.flags().dnssec_ok),
        };
        let entries = self.prefetch.entries.load_full();
        if let Some(entry) = entries.get(&key)
            && let age = entry.inserted.elapsed()
            && age < Duration::from_secs(entry.ttl.into())
        {
            let settings = self.cache.settings();
            let fraction = (f64::from(settings.refresh_ttl_min_pct)
                + entry.refresh_jitter
                    * f64::from(settings.refresh_ttl_max_pct - settings.refresh_ttl_min_pct))
                / 100.0;
            let refresh_at = Duration::from_secs_f64(f64::from(entry.ttl) * fraction);
            if foreground
                && age >= refresh_at
                && !entry.attempted.load(Ordering::Acquire)
                && let Some(permit) = self.try_background()
                && !entry.attempted.swap(true, Ordering::AcqRel)
            {
                let engine = self.clone();
                let runtime = runtime.clone();
                let request = request.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(lease) = engine.prefetch.join(&key, true) {
                        lease
                            .flight
                            .get_or_init(|| async {
                                let result = crate::cache::FRESH_QUERY
                                    .scope(
                                        key.query.clone(),
                                        engine.routed_lookup(&runtime, &request, gfw),
                                    )
                                    .await;
                                engine.save_hot_answer(&entries, &key, &result);
                                Arc::new(result)
                            })
                            .await;
                    }
                });
            }
            if foreground {
                self.prefetch.hits.fetch_add(1, Ordering::Relaxed);
            }
            let mut answer = entry.answer.clone();
            age_records(&mut answer.message, age.as_secs() as u32);
            return Arc::new(Ok(Ok(answer)));
        }
        let _fg = self.begin_foreground(foreground);
        let lease = self.prefetch.join(&key, false).expect("join DNS flight");
        lease
            .flight
            .get_or_init(|| async {
                let result = self.routed_lookup(runtime, request, gfw).await;
                self.save_hot_answer(&entries, &key, &result);
                Arc::new(result)
            })
            .await
            .clone()
    }

    fn save_hot_answer(&self, entries: &AnswerCache, key: &Key, result: &Outcome) {
        if let Ok(Ok(answer)) = result
            && let Some(ttl) = positive_ttl(&answer.message, &self.cache.settings())
        {
            // Use actual cached lifetime, with a small independent offset per refresh.
            entries.insert(
                key.clone(),
                Arc::new(HotAnswer {
                    answer: answer.clone(),
                    inserted: Instant::now(),
                    ttl,
                    refresh_jitter: rand::random::<f64>(),
                    attempted: AtomicBool::new(false),
                }),
            );
        }
    }

    pub(super) fn begin_foreground(&self, foreground: bool) -> Option<Foreground<'_>> {
        foreground.then(|| {
            self.prefetch.foreground.fetch_add(1, Ordering::AcqRel);
            Foreground(self)
        })
    }

    pub(super) fn try_background(&self) -> Option<BackgroundPermit> {
        if self.prefetch.foreground.load(Ordering::Acquire) > 0 {
            return None;
        }
        let permit = self.cache.clone().try_background()?;
        (self.prefetch.foreground.load(Ordering::Acquire) == 0).then_some(permit)
    }
}
