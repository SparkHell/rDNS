use super::*;
use anyhow::{Context, ensure};
use chrono::Utc;
use futures::{StreamExt, stream};
use hickory_proto::{op::Query, rr::RecordType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::{sync::watch, task::JoinHandle};

const REGIONS: &str = include_str!("../../resources/regions.txt");
const RADAR: &str = "https://api.cloudflare.com/client/v4/radar/ranking/top";

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(default)]
struct Settings {
    ns: bool,
    radar: bool,
    #[serde(default)]
    global_top_1000: bool,
    local_hot_enabled: Option<bool>,
    warm_domain_limit: usize,
    local_window_hours: u32,
    local_min_queries: u32,
    regions: Vec<String>,
    token: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ns: false,
            radar: false,
            global_top_1000: false,
            local_hot_enabled: None,
            warm_domain_limit: 1000,
            local_window_hours: 24,
            local_min_queries: 3,
            regions: Vec::new(),
            token: String::new(),
        }
    }
}

impl Settings {
    fn local_hot(&self) -> bool {
        self.local_hot_enabled.unwrap_or(self.radar)
    }
    fn warm_enabled(&self) -> bool {
        self.local_hot() || self.radar
    }
}

#[derive(Debug, Clone)]
struct LocalHot {
    domain: String,
    count: i64,
    kinds: Vec<RecordType>,
}
type WarmQuestion = (String, RecordType);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheJobInput {
    ns: bool,
    radar: bool,
    #[serde(default)]
    global_top_1000: bool,
    local_hot_enabled: Option<bool>,
    warm_domain_limit: Option<usize>,
    local_window_hours: Option<u32>,
    local_min_queries: Option<u32>,
    regions: Vec<String>,
    token: Option<String>, // Omitted preserves the secret; an empty string clears it.
}

#[derive(Default)]
pub(super) struct Jobs {
    settings: Settings,
    ns: Option<JoinHandle<()>>,
    radar: Option<JoinHandle<()>>,
}

async fn stop(job: &mut Option<JoinHandle<()>>) {
    if let Some(task) = job.take() {
        task.abort();
        let _ = task.await;
    }
}

impl Engine {
    pub async fn start_cache_jobs(self: &Arc<Self>) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        jobs.settings = self.store.setting("cache_jobs").await?.unwrap_or_default();
        if jobs.settings.ns && self.config.root_hints.is_none() {
            self.cache.root.load(&self.store).await?;
            jobs.ns = Some(tokio::spawn(crate::root_zone::maintain(
                self.cache.clone(),
                self.store.clone(),
                false,
            )));
        }
        if jobs.settings.warm_enabled() {
            jobs.radar = Some(tokio::spawn(
                self.clone().radar_worker(jobs.settings.clone(), false),
            ));
        }
        Ok(())
    }

    pub async fn set_cache_jobs(self: &Arc<Self>, input: CacheJobInput) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        let mut regions = input.regions;
        for code in &mut regions {
            code.make_ascii_uppercase();
            ensure!(
                REGIONS.split_ascii_whitespace().any(|c| c == code),
                "无效的国家或地区代码"
            );
        }
        regions.sort();
        regions.dedup();
        let token = input
            .token
            .unwrap_or_else(|| jobs.settings.token.clone())
            .trim()
            .to_owned();
        ensure!(
            token.len() <= 4096 && token.bytes().all(|b| b.is_ascii_graphic()),
            "Token 格式无效"
        );
        ensure!(
            !input.radar || (!regions.is_empty() && !token.is_empty()),
            "请配置 Token 并选择地区"
        );
        ensure!(
            !input.ns || self.config.root_hints.is_none(),
            "自定义根服务器时无法启用公共根区快照"
        );
        let new = Settings {
            ns: input.ns,
            radar: input.radar,
            global_top_1000: input.global_top_1000,
            local_hot_enabled: input.local_hot_enabled.or(jobs.settings.local_hot_enabled),
            warm_domain_limit: input
                .warm_domain_limit
                .unwrap_or(jobs.settings.warm_domain_limit),
            local_window_hours: input
                .local_window_hours
                .unwrap_or(jobs.settings.local_window_hours),
            local_min_queries: input
                .local_min_queries
                .unwrap_or(jobs.settings.local_min_queries),
            regions,
            token,
        };
        ensure!(
            (1..=100_000).contains(&new.warm_domain_limit),
            "预热域名数须为 1–100000"
        );
        ensure!(
            (1..=168).contains(&new.local_window_hours),
            "本地统计窗口须为 1–168 小时"
        );
        ensure!(
            (1..=50000).contains(&new.local_min_queries),
            "高频门槛须为 1–50000 次"
        );
        let old = jobs.settings.clone();
        if new == old {
            return Ok(());
        }
        if new.ns && !old.ns {
            self.cache.root.load(&self.store).await?;
        }
        if let Err(e) = self.store.set_setting("cache_jobs", &new).await {
            if new.ns && !old.ns {
                self.cache.root.clear();
            }
            return Err(e);
        }
        if old.ns != new.ns {
            stop(&mut jobs.ns).await;
            if new.ns {
                jobs.ns = Some(tokio::spawn(crate::root_zone::maintain(
                    self.cache.clone(),
                    self.store.clone(),
                    false,
                )));
            } else {
                self.cache.root.clear();
                self.prefetch.reset(&self.cache.settings());
                self.recursor
                    .store(Arc::new(build_recursor(&self.roots, &self.cache)?));
            }
        }
        if new.global_top_1000 != old.global_top_1000
            || new.radar != old.radar
            || new.regions != old.regions
            || new.token != old.token
            || new.local_hot() != old.local_hot()
            || new.warm_domain_limit != old.warm_domain_limit
            || new.local_min_queries != old.local_min_queries
            || new.local_window_hours != old.local_window_hours
        {
            stop(&mut jobs.radar).await;
            self.warm_candidates.store(Arc::new(Value::Null));
            if new.warm_enabled() {
                jobs.radar = Some(tokio::spawn(
                    self.clone()
                        .radar_worker(new.clone(), new.token != old.token),
                ));
            }
        }
        jobs.settings = new;
        Ok(())
    }

    pub async fn refresh_cache_job(self: &Arc<Self>, kind: &str) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        match kind {
            "ns" if jobs.ns.is_some() => {
                stop(&mut jobs.ns).await;
                jobs.ns = Some(tokio::spawn(crate::root_zone::maintain(
                    self.cache.clone(),
                    self.store.clone(),
                    true,
                )));
            }
            "radar" if jobs.settings.warm_enabled() => {
                stop(&mut jobs.radar).await;
                jobs.radar = Some(tokio::spawn(
                    self.clone().radar_worker(jobs.settings.clone(), true),
                ));
            }
            _ => anyhow::bail!("请先启用对应缓存"),
        }
        Ok(())
    }

    pub(super) async fn job_status(&self) -> Value {
        let settings = self.jobs.lock().await.settings.clone();
        let rows = sqlx::query_as::<_,(String,i64,Option<String>,Option<i64>,Option<String>)>(
            "SELECT region,json_array_length(domains),ranking_date,updated_at,error FROM radar_rankings ORDER BY region"
        ).fetch_all(&self.store.pool).await.unwrap_or_default();
        let regions:Vec<_> = rows.into_iter().filter(|r|settings.regions.contains(&r.0) || (settings.global_top_1000 && r.0=="GLOBAL")).map(|(region,count,date,updated_at,error)| json!({ "region":region,"count":count,"date":date,"updated_at":updated_at,"error":error })).collect();
        json!({"settings":{"ns":settings.ns && self.config.root_hints.is_none(),"radar":settings.radar,"global_top_1000":settings.global_top_1000,"regions":settings.regions,"local_hot_enabled":settings.local_hot(),"warm_domain_limit":settings.warm_domain_limit,"local_window_hours":settings.local_window_hours,"local_min_queries":settings.local_min_queries},
        "token_configured":!settings.token.is_empty(),"custom_roots":self.config.root_hints.is_some(),"root":self.cache.root.status(),
        "umbrella":self.store.setting::<Value>("umbrella_status").await.ok().flatten(),
        "warm_candidates":self.warm_candidates.load_full().as_ref(),
        "root_error":self.store.setting::<Value>("root_update_error").await.ok().flatten(),"rankings":regions})
    }

    async fn radar_worker(self: Arc<Self>, settings: Settings, force: bool) {
        let (public, mut public_rx) = watch::channel(Vec::new());
        let (selected, questions) = watch::channel(Vec::new());
        let fetch = async {
            if !settings.radar {
                std::future::pending::<()>().await;
            }
            let mut force = force;
            loop {
                let result = self.refresh_rankings(&settings, force, &public).await;
                force = false;
                let delay = result.unwrap_or_else(|error| {
                    tracing::warn!(%error, "could not refresh Radar rankings");
                    900
                });
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        };
        let select = async {
            let mut local = Vec::new();
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        if settings.local_hot() {
                            match self.local_hot(&settings).await {
                                Ok(latest) => local = latest,
                                Err(error) => tracing::warn!(%error,"could not rank local DNS queries"),
                            }
                        }
                    }
                    result = public_rx.changed() => { if result.is_err() {return;} },
                }
                let public_names = public_rx.borrow_and_update();
                let (names, fallback) =
                    select_warm_questions(&local, &public_names, settings.warm_domain_limit);
                let changed = selected.send_if_modified(|old| {
                    if *old == names {
                        false
                    } else {
                        *old = names;
                        true
                    }
                });
                if changed {
                    tracing::info!(
                        local_domains = local.len(),
                        public_domains = fallback,
                        limit = settings.warm_domain_limit,
                        "DNS warmup list updated"
                    );
                }
                self.warm_candidates.store(Arc::new(json!({
                    "local_domains":local.len(),"public_domains":fallback,
                    "local_preview":local.iter().take(20).map(|entry|json!({
                        "domain":entry.domain,"count":entry.count,
                        "kinds":entry.kinds.iter().map(ToString::to_string).collect::<Vec<_>>()
                    })).collect::<Vec<_>>()
                })));
            }
        };
        tokio::select! { _ = fetch => {}, () = select => {}, () = self.warm_rankings(questions) => {} }
    }

    async fn local_hot(&self, settings: &Settings) -> Result<Vec<LocalHot>> {
        let since = Utc::now() - chrono::Duration::hours(settings.local_window_hours.into());
        let rows = sqlx::query_as::<_,(String,i64,String)>(
            "WITH sample AS (
                SELECT at,domain,qtype,outcome FROM query_log ORDER BY id DESC LIMIT 50000
             ), counts AS (
                SELECT domain,qtype,COUNT(*) AS hits FROM sample
                WHERE at >= ? AND outcome IN ('recursive','doh','gfw_doh','gfw_fallback_doh')
                  AND qtype IN ('A','AAAA','HTTPS','SVCB')
                GROUP BY domain,qtype
             ), parents AS (
                SELECT domain,SUM(hits) AS hits FROM counts GROUP BY domain
                HAVING SUM(hits)>=? ORDER BY hits DESC,domain LIMIT ?
             )
             SELECT parents.domain,parents.hits,counts.qtype
             FROM parents JOIN counts USING(domain) ORDER BY parents.hits DESC,parents.domain,counts.qtype"
        ).bind(since.to_rfc3339()).bind(i64::from(settings.local_min_queries)).bind(settings.warm_domain_limit as i64)
            .fetch_all(&self.store.pool).await?;
        let runtime = self.features.current.load_full();
        let policy = self.policy.load_full();
        let mut local = Vec::<LocalHot>::new();
        for (domain, count, kind) in rows {
            let Ok(kind) = kind.parse() else {
                continue;
            };
            if let Some(entry) = local.last_mut()
                && entry.domain == domain
            {
                entry.kinds.push(kind);
            } else if self.warm_allowed(&policy, &runtime, &domain) {
                local.push(LocalHot {
                    domain,
                    count,
                    kinds: vec![kind],
                });
            }
        }
        Ok(local)
    }

    async fn refresh_rankings(
        &self,
        settings: &Settings,
        force: bool,
        tx: &watch::Sender<Vec<String>>,
    ) -> Result<u64> {
        let client = crate::upstream::http_client(&self.config, "")?
            .timeout(Duration::from_secs(30))
            .build()?;
        let now = Utc::now().timestamp();
        let mut lists = HashMap::new();
        let mut due = Vec::new();
        let mut next = now + 86400;
        let mut sources = settings.regions.clone();
        if settings.global_top_1000 {
            sources.push("GLOBAL".to_owned());
        }
        let mut umbrella = self
            .store
            .setting::<umbrella::Snapshot>("umbrella_hosts")
            .await?
            .unwrap_or_default();
        for region in &sources {
            let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
                "SELECT domains,attempted_at,error FROM radar_rankings WHERE region=?",
            )
            .bind(region)
            .fetch_optional(&self.store.pool)
            .await?;
            if let Some((domains, at, error)) = row {
                lists.insert(
                    region.clone(),
                    serde_json::from_str::<HashSet<String>>(&domains)?,
                );
                let deadline = at
                    + if error.is_some() {
                        900
                    } else if region == "GLOBAL" {
                        604800
                    } else {
                        86400
                    };
                if !force && at <= now && deadline > now {
                    next = next.min(deadline);
                    continue;
                }
            }
            due.push(region);
        }
        let publish = |lists: &HashMap<String, HashSet<String>>, snapshot: &umbrella::Snapshot| {
            let names = public_candidates(lists, snapshot, settings.warm_domain_limit);
            tx.send_if_modified(|old| {
                if *old == names {
                    return false;
                }
                *old = names;
                true
            });
        };
        publish(&lists, &umbrella);
        for region in due {
            match update_region(&self.store, &client, RADAR, &settings.token, region).await? {
                Some(domains) => {
                    lists.insert(region.clone(), domains);
                    publish(&lists, &umbrella);
                }
                None => next = next.min(Utc::now().timestamp() + 900),
            }
        }
        let parents: HashSet<_> = lists.values().flatten().cloned().collect();
        if !parents.is_empty() {
            let changed = umbrella.version != umbrella::SNAPSHOT_VERSION
                || parents.len() != umbrella.hosts.len()
                || parents.iter().any(|p| !umbrella.hosts.contains_key(p));
            let deadline = if umbrella.error.is_some() {
                umbrella.attempted_at + 900
            } else if changed {
                0
            } else {
                umbrella.updated_at + 86400
            };
            if force || deadline <= now {
                let download = async {
                    let bytes = crate::upstream::download_with_timeout(
                        &self.config,
                        umbrella::URL,
                        "",
                        32 * 1024 * 1024,
                        Duration::from_secs(180),
                    )
                    .await?;
                    tokio::task::spawn_blocking(move || umbrella::extract(bytes, parents)).await?
                }
                .await;
                umbrella.attempted_at = Utc::now().timestamp();
                match download {
                    Ok(hosts) => {
                        umbrella.hosts = hosts;
                        umbrella.version = umbrella::SNAPSHOT_VERSION;
                        umbrella.updated_at = umbrella.attempted_at;
                        umbrella.error = None;
                    }
                    Err(_) => {
                        umbrella.error = Some("Umbrella 下载或校验失败".into());
                        next = next.min(umbrella.attempted_at + 900);
                    }
                }
                self.store.set_setting("umbrella_hosts", &umbrella).await?;
                self.store.set_setting("umbrella_status",&json!({"updated_at":umbrella.updated_at,"error":umbrella.error,"count":umbrella.hosts.values().flatten().collect::<HashSet<_>>().len()})).await?;
                publish(&lists, &umbrella);
            } else {
                next = next.min(deadline);
            }
        }
        Ok((next - Utc::now().timestamp()).max(1) as u64)
    }

    async fn warm_rankings(self: &Arc<Self>, mut rx: watch::Receiver<Vec<WarmQuestion>>) {
        let mut schedule = HashMap::new();
        loop {
            let now = tokio::time::Instant::now();
            let due: Vec<_> = {
                let ordered = rx.borrow_and_update();
                let allowed: HashSet<_> = ordered.iter().collect();
                schedule.retain(|question, _| allowed.contains(question));
                ordered
                    .iter()
                    .filter(|question| *schedule.entry((*question).clone()).or_insert(now) <= now)
                    .cloned()
                    .collect()
            };
            let mut work = stream::iter(due)
                .map(|(domain, kind)| async move {
                    let permit = loop {
                        let ready = self.cache.background_ready.notified();
                        if let Some(permit) = self.try_background() {
                            break permit;
                        }
                        ready.await;
                    };
                    let ttl = self.warm_question(&domain, kind).await;
                    drop(permit);
                    (
                        (domain, kind),
                        tokio::time::Instant::now() + Duration::from_secs(u64::from(ttl)),
                    )
                })
                .buffer_unordered(crate::cache::MAX_BACKGROUND_CONCURRENCY);
            loop {
                tokio::select! {
                    changed=rx.changed()=>{if changed.is_err(){return;} break;},
                    item=work.next()=>match item {
                        Some((q,at))=>{schedule.insert(q,at);}
                        None=>{
                            let until=schedule.values().copied().min().unwrap_or(now+Duration::from_secs(86400));
                            tokio::select! { _=tokio::time::sleep_until(until)=>{}, changed=rx.changed()=>if changed.is_err(){return;} }
                            break;
                        }
                    }
                }
            }
        }
    }

    fn warm_allowed(
        &self,
        policy: &Policy,
        runtime: &crate::features::FeatureRuntime,
        domain: &str,
    ) -> bool {
        policy.local_records(domain).is_none()
            && !self.is_blocked(policy, runtime, domain)
            && policy.forward_target(domain).is_none()
    }

    async fn warm_question(self: &Arc<Self>, domain: &str, kind: RecordType) -> u32 {
        let runtime = self.features.current.load_full();
        let policy = self.policy.load_full();
        if !self.warm_allowed(&policy, &runtime, domain) {
            return 300;
        }
        let Ok(name) = Name::from_ascii(format!("{domain}.")) else {
            return 300;
        };
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, kind));
        if let Ok(Ok(answer)) = self
            .cache_lookup(&runtime, &request, domain, false)
            .await
            .as_ref()
            && let Some(ttl) = answer
                .message
                .answers
                .iter()
                .map(|r| r.ttl)
                .min()
                .filter(|ttl| *ttl > 0)
        {
            return ttl.min(self.cache.settings().answer_max_ttl);
        }
        300
    }
}

fn select_warm_questions(
    local: &[LocalHot],
    public: &[String],
    limit: usize,
) -> (Vec<WarmQuestion>, usize) {
    let mut questions = Vec::new();
    let mut chosen = HashSet::new();
    for entry in local.iter().take(limit) {
        chosen.insert(entry.domain.as_str());
        questions.extend(entry.kinds.iter().map(|kind| (entry.domain.clone(), *kind)));
    }
    let local_count = chosen.len();
    for domain in public {
        if chosen.len() >= limit {
            break;
        }
        if chosen.insert(domain) {
            questions.extend([RecordType::A, RecordType::AAAA].map(|kind| (domain.clone(), kind)));
        }
    }
    (questions, chosen.len() - local_count)
}

fn public_candidates(
    lists: &HashMap<String, HashSet<String>>,
    snapshot: &umbrella::Snapshot,
    limit: usize,
) -> Vec<String> {
    let mut priority = HashMap::<&str, usize>::new();
    for (region, domains) in lists {
        for domain in domains {
            *priority.entry(domain).or_default() += usize::from(region != "GLOBAL");
        }
    }
    let mut parents: Vec<_> = priority.into_iter().collect();
    parents.sort_unstable_by_key(|(name, weight)| (std::cmp::Reverse(*weight), *name));
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    let mut sources = Vec::new();
    // Mix parents with their highest-ranked Umbrella match so a large global
    // parent list cannot consume every slot before the first subdomain.
    for (parent, _) in parents {
        if selected.len() >= limit {
            break;
        }
        if seen.insert(parent) {
            selected.push(parent.to_owned());
        }
        if let Some(hosts) = snapshot.hosts.get(parent) {
            let mut hosts = hosts.iter();
            if selected.len() < limit
                && let Some(name) = hosts.by_ref().find(|host| seen.insert(host.as_str()))
            {
                selected.push(name.clone());
            }
            sources.push(hosts);
        }
    }
    while !sources.is_empty() && selected.len() < limit {
        sources.retain_mut(|hosts| {
            let Some(name) = hosts.next() else {
                return false;
            };
            if selected.len() < limit && seen.insert(name.as_str()) {
                selected.push(name.clone());
            }
            true
        });
    }
    selected
}

async fn update_region(
    store: &Store,
    client: &reqwest::Client,
    url: &str,
    token: &str,
    region: &str,
) -> Result<Option<HashSet<String>>> {
    let now = Utc::now().timestamp();
    let result = if region == "GLOBAL" {
        fetch_global(client, token).await
    } else {
        fetch_region(client, url, token, region).await
    };
    match result {
        Ok((date, domains)) => {
            sqlx::query(
                "INSERT INTO radar_rankings(region,domains,ranking_date,updated_at,attempted_at)
                VALUES(?,?,?,?,?) ON CONFLICT(region) DO UPDATE SET domains=excluded.domains,
                ranking_date=excluded.ranking_date,updated_at=excluded.updated_at,
                attempted_at=excluded.attempted_at,error=NULL",
            )
            .bind(region)
            .bind(serde_json::to_string(&domains)?)
            .bind(date)
            .bind(now)
            .bind(now)
            .execute(&store.pool)
            .await?;
            Ok(Some(domains))
        }
        Err(error) => {
            sqlx::query("INSERT INTO radar_rankings(region,attempted_at,error) VALUES(?,?,?)
                ON CONFLICT(region) DO UPDATE SET attempted_at=excluded.attempted_at,error=excluded.error")
                .bind(region).bind(now).bind(error.to_string()).execute(&store.pool).await?;
            Ok(None)
        }
    }
}

async fn fetch_global(client: &reqwest::Client, token: &str) -> Result<(String, HashSet<String>)> {
    let response = client
        .get("https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000")
        .bearer_auth(token)
        .send()
        .await
        .context("无法连接 Radar")?;
    ensure!(
        response.status().is_success(),
        "Radar HTTP {}",
        response.status().as_u16()
    );
    let bytes = crate::upstream::bounded_body(response, 512 * 1024).await?;
    let mut rows = std::str::from_utf8(&bytes)?.lines();
    ensure!(
        rows.next().map(str::trim) == Some("domain"),
        "全球榜单 CSV 格式错误"
    );
    let domains = rows.map(normalize_domain).collect::<Result<HashSet<_>>>()?;
    ensure!(domains.len() == 1000, "全球 Top 1,000 榜单不完整");
    // The stream has no ranking date; updated_at records local retrieval.
    Ok((String::new(), domains))
}

async fn fetch_region(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    region: &str,
) -> Result<(String, HashSet<String>)> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .query(&[
            ("location", region),
            ("limit", "100"),
            ("rankingType", "POPULAR"),
        ])
        .send()
        .await
        .context("无法连接 Radar")?;
    ensure!(
        response.status().is_success(),
        "Radar HTTP {}",
        response.status().as_u16()
    );
    let body: Value = response.json().await.context("Radar 返回格式错误")?;
    ensure!(body["success"] == true, "Radar 未返回成功结果");
    let date = body
        .pointer("/result/meta/top_0/date")
        .and_then(Value::as_str)
        .context("缺少榜单日期")?;
    let rows = body
        .pointer("/result/top_0")
        .and_then(Value::as_array)
        .context("缺少地区榜单")?;
    let domains = rows
        .iter()
        .take(100)
        .map(|row| normalize_domain(row["domain"].as_str().context("缺少域名")?))
        .collect::<Result<HashSet<_>>>()?;
    ensure!(!domains.is_empty(), "地区榜单为空");
    Ok((date.to_owned(), domains))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Query,
        http::{HeaderMap, StatusCode},
        routing::get,
    };

    #[test]
    fn local_names_use_observed_types_and_displace_public_candidates() {
        let local = vec![LocalHot {
            domain: "local.example".into(),
            count: 17,
            kinds: vec![RecordType::HTTPS, RecordType::A],
        }];
        let public = vec![
            "local.example".into(),
            "public.example".into(),
            "third.example".into(),
        ];
        let (questions, count) = select_warm_questions(&local, &public, 2);
        assert_eq!(count, 1);
        assert_eq!(
            questions,
            vec![
                ("local.example".into(), RecordType::HTTPS),
                ("local.example".into(), RecordType::A),
                ("public.example".into(), RecordType::A),
                ("public.example".into(), RecordType::AAAA),
            ]
        );
    }

    #[test]
    fn regional_parent_and_umbrella_make_room_before_global_parents() {
        let lists = HashMap::from([
            ("TW".into(), HashSet::from(["region.test".into()])),
            (
                "GLOBAL".into(),
                HashSet::from(["alphabet.test".into(), "bulk.test".into()]),
            ),
        ]);
        let public = umbrella::Snapshot {
            hosts: HashMap::from([("region.test".into(), vec!["cdn.region.test".into()])]),
            ..Default::default()
        };
        assert_eq!(
            public_candidates(&lists, &public, 2),
            ["region.test", "cdn.region.test"]
        );
    }

    #[tokio::test]
    async fn radar_ranking_contract_and_http_failures() -> Result<()> {
        let app = Router::new().route("/",get(|headers:HeaderMap, Query(q):Query<HashMap<String,String>>|async move {
            assert_eq!(q["limit"],"100");
            assert_eq!(q["rankingType"],"POPULAR");
            let status = match (headers["authorization"].to_str().unwrap(),q["location"].as_str()) {
                ("Bearer fixture","TW")=>StatusCode::OK,
                ("Bearer fixture",_)=>StatusCode::TOO_MANY_REQUESTS,
                _=>StatusCode::UNAUTHORIZED,
            };
            (status,Json(json!({"success":true,"result":{"meta":{"top_0":{"date":"2026-11-23"}},"top_0":[{"domain":"EXAMPLE.com"},{"domain":"example.com."}]}})))
        }));
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", socket.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(socket, app).await });
        let client = reqwest::Client::new();
        let (date, domains) = fetch_region(&client, &url, "fixture", "TW").await?;
        assert_eq!(date, "2026-11-23");
        assert_eq!(domains, HashSet::from(["example.com".to_owned()]));
        assert!(
            fetch_region(&client, &url, "fixture", "US")
                .await
                .unwrap_err()
                .to_string()
                .contains("429")
        );
        assert_eq!(
            fetch_region(&client, &url, "secret", "TW")
                .await
                .unwrap_err()
                .to_string(),
            "Radar HTTP 401"
        );
        let store = Store::open(std::path::Path::new(":memory:")).await?;
        assert!(
            update_region(&store, &client, &url, "fixture", "TW")
                .await?
                .is_some()
        );
        assert!(
            update_region(&store, &client, &url, "bad", "TW")
                .await?
                .is_none()
        );
        assert!(
            update_region(&store, &client, &url, "fixture", "US")
                .await?
                .is_none()
        );
        let rows:Vec<(String,String,i64,String)> = sqlx::query_as("SELECT region,domains,json_array_length(domains),error FROM radar_rankings ORDER BY region").fetch_all(&store.pool).await?;
        assert_eq!(
            rows[0],
            (
                "TW".into(),
                r#"["example.com"]"#.into(),
                1,
                "Radar HTTP 401".into()
            )
        );
        assert_eq!(rows[1].2, 0);
        assert_eq!(rows[1].3, "Radar HTTP 429");
        server.abort();
        Ok(())
    }
}
