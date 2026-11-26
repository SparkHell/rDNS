use crate::{cache::PersistentCache, config::Config, features::Features, store::Store, upstream};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use chrono::Utc;
use hickory_proto::{
    op::{DnsResponse, Message, OpCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, NS},
    },
};
use reqwest::{
    Client, StatusCode,
    header::{ETAG, IF_NONE_MATCH, USER_AGENT},
};
use std::{collections::HashMap, sync::Arc, time::Duration};

const USER_AGENT_VALUE: &str = concat!("rDns/", env!("CARGO_PKG_VERSION"));
const SOURCE: &str = "https://www.internic.net/domain/root.zone";
const SEED: &str = include_str!("../resources/root-delegations.zone");
// Time the bundled InterNIC snapshot was retrieved. Reinstalling must not renew it.
const SEED_AT: i64 = 1795486395;

#[derive(Default)]
pub struct RootDelegations(ArcSwapOption<Snapshot>);

struct Snapshot {
    ns: HashMap<Name, Vec<Record>>,
    glue: HashMap<Name, Vec<Record>>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    checked_at: i64,
    etag: Option<String>,
}

impl Snapshot {
    // InterNIC publishes one absolute, tab/space-delimited IN record per line.
    fn parse(text: &str, checked_at: i64, etag: Option<String>) -> Result<Self> {
        let mut ns = HashMap::<_, Vec<_>>::new();
        let mut glue = HashMap::<_, Vec<_>>::new();
        let mut soa = None;
        let mut chain = HashMap::new();
        for line in text.lines() {
            let mut fields = line.split_ascii_whitespace();
            let (Some(owner), Some(ttl), Some("IN"), Some(kind)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                anyhow::bail!("invalid InterNIC record");
            };
            if owner == "." && kind == "SOA" {
                let numbers: Vec<u32> = fields.skip(2).map(str::parse).collect::<Result<_, _>>()?;
                ensure!(
                    numbers.len() == 5 && numbers[1..4].iter().all(|v| *v > 0),
                    "invalid root SOA"
                );
                soa = Some((numbers[0], numbers[1], numbers[2], numbers[3]));
                continue;
            }
            if kind == "NSEC" {
                let next = fields.next().context("missing NSEC successor")?;
                let delegated = fields.any(|kind| kind == "NS") && owner != ".";
                ensure!(
                    chain.insert(owner, (next, delegated)).is_none(),
                    "duplicate NSEC"
                );
                continue;
            }
            if owner == "." || !matches!(kind, "NS" | "A" | "AAAA") {
                continue;
            }
            let name = Name::from_ascii(owner)?;
            let value = fields.next().context("missing delegation data")?;
            let data = match kind {
                "NS" if name.num_labels() == 1 => RData::NS(NS(Name::from_ascii(value)?)),
                "A" => RData::A(A(value.parse()?)),
                "AAAA" => RData::AAAA(AAAA(value.parse()?)),
                _ => continue,
            };
            let record = Record::from_rdata(name.clone(), ttl.parse()?, data);
            let target = if kind == "NS" { &mut ns } else { &mut glue };
            target.entry(name).or_default().push(record);
        }
        let (serial, refresh, retry, expire) = soa.context("missing root SOA")?;
        ensure!(
            !ns.is_empty() && !glue.is_empty(),
            "empty delegation snapshot"
        );
        // The root NSEC chain enumerates the whole zone. Detect incomplete downloads
        // before publishing a replacement, including omissions of delegated NS sets.
        let mut owner = ".";
        loop {
            let (next, delegated) = chain.remove(owner).context("incomplete root NSEC chain")?;
            ensure!(
                !delegated || ns.contains_key(&Name::from_ascii(owner)?),
                "missing NS for {owner}"
            );
            owner = next;
            if owner == "." {
                break;
            }
        }
        ensure!(chain.is_empty(), "disconnected root NSEC chain");
        Ok(Self {
            ns,
            glue,
            serial,
            refresh,
            retry,
            expire,
            checked_at,
            etag,
        })
    }
}

impl RootDelegations {
    pub fn clear(&self) {
        self.0.store(None);
    }
    pub fn status(&self) -> serde_json::Value {
        self.0.load().as_ref().map_or(
            serde_json::Value::Null,
            |s| serde_json::json!({"serial":s.serial,"count":s.ns.len(),"checked_at":s.checked_at}),
        )
    }
    pub async fn load(&self, store: &Store) -> Result<()> {
        let stored: Option<(String, i64, Option<String>)> =
            sqlx::query_as("SELECT zone,checked_at,etag FROM root_delegations WHERE id=1")
                .fetch_optional(&store.pool)
                .await?;
        let Some((zone, at, etag)) = stored else {
            let seed = Snapshot::parse(SEED, SEED_AT, None)?;
            sqlx::query(
                "INSERT OR IGNORE INTO root_delegations(id,serial,zone,checked_at) VALUES(1,?,?,?)",
            )
            .bind(seed.serial)
            .bind(SEED)
            .bind(SEED_AT)
            .execute(&store.pool)
            .await?;
            self.0.store(Some(Arc::new(seed)));
            return Ok(());
        };
        match Snapshot::parse(&zone, at, etag) {
            Ok(snapshot) => self.0.store(Some(Arc::new(snapshot))),
            Err(error) => {
                tracing::warn!(%error,"invalid stored root delegations, using public roots until refreshed")
            }
        }
        Ok(())
    }

    pub fn referral(&self, request: &Message, ttl_cap: u32) -> Option<DnsResponse> {
        let snapshot = self.0.load();
        let snapshot = snapshot.as_ref()?;
        let [question] = request.queries.as_slice() else {
            return None;
        };
        if question.query_class() != DNSClass::IN || question.query_type() != RecordType::NS {
            return None;
        }
        let records = snapshot.ns.get(question.name())?;
        let age = u32::try_from(Utc::now().timestamp() - snapshot.checked_at).ok()?;
        let remaining = snapshot.expire.checked_sub(age)?.min(ttl_cap);
        let aged = |record: &Record| {
            let mut record = record.clone();
            record.ttl = record.ttl.saturating_sub(age).min(remaining);
            (record.ttl > 0).then_some(record)
        };
        let mut message = Message::response(request.metadata.id, OpCode::Query);
        message.add_query(question.clone());
        for record in records {
            message.add_authority(aged(record)?);
            if let RData::NS(ns) = &record.data
                && let Some(addresses) = snapshot.glue.get(&ns.0)
            {
                message.add_additionals(addresses.iter().filter_map(aged));
            }
        }
        DnsResponse::from_message(message).ok()
    }

    async fn refresh(&self, store: &Store, client: &Client, source: &str) -> Result<()> {
        let current = self.0.load_full();
        let mut request = client.get(source).header(USER_AGENT, USER_AGENT_VALUE);
        if let Some(tag) = current.as_ref().and_then(|s| s.etag.as_ref()) {
            request = request.header(IF_NONE_MATCH, tag);
        }
        let mut response = request.send().await?;
        let now = Utc::now().timestamp();
        if response.status() == StatusCode::NOT_MODIFIED {
            let snapshot = current.context("unexpected 304 for root zone")?;
            ensure!(snapshot.etag.is_some(), "unconditional 304 for root zone");
            sqlx::query(
                "UPDATE root_delegations SET checked_at=? WHERE id=1 AND serial=? AND etag=?",
            )
            .bind(now)
            .bind(snapshot.serial)
            .bind(&snapshot.etag)
            .execute(&store.pool)
            .await?;
            return self.load(store).await;
        }
        ensure!(
            response.status() == StatusCode::OK,
            "InterNIC 根区下载返回 HTTP {}",
            response.status().as_u16()
        );
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 16 * 1024 * 1024,
                "root zone too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let zone = std::str::from_utf8(&bytes)?;
        let snapshot = Snapshot::parse(zone, now, etag)?;
        let written = sqlx::query("UPDATE root_delegations SET zone=?, serial=?, checked_at=?, etag=? WHERE id=1 AND serial<=?")
            .bind(zone).bind(snapshot.serial).bind(now).bind(&snapshot.etag).bind(snapshot.serial)
            .execute(&store.pool).await?;
        ensure!(written.rows_affected() == 1, "older root zone serial");
        self.0.store(Some(Arc::new(snapshot)));
        Ok(())
    }
}

pub async fn maintain(
    config: Config,
    features: Arc<Features>,
    cache: Arc<PersistentCache>,
    store: Store,
    mut force: bool,
) {
    loop {
        let snapshot = cache.root.0.load_full();
        let now = Utc::now().timestamp();
        let delay = snapshot
            .as_ref()
            .filter(|s| s.checked_at <= now)
            .map_or(0, |s| (s.checked_at + i64::from(s.refresh) - now).max(0));
        if !force {
            tokio::time::sleep(Duration::from_secs(delay as u64)).await;
        }
        force = false;
        let proxy = features
            .current
            .load()
            .settings
            .subscription_proxy()
            .to_owned();
        let client = match upstream::http_client(&config, &proxy)
            .and_then(|builder| Ok(builder.timeout(Duration::from_secs(60)).build()?))
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "root zone HTTP client failed");
                tokio::time::sleep(Duration::from_secs(
                    snapshot.map_or(900, |s| s.retry).into(),
                ))
                .await;
                continue;
            }
        };
        let result = cache.root.refresh(&store, &client, SOURCE).await;
        let _ = store
            .set_setting(
                "root_update_error",
                &result.as_ref().err().map(|e| e.to_string()),
            )
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "root delegation refresh failed");
            tokio::time::sleep(Duration::from_secs(
                snapshot.map_or(900, |s| s.retry).into(),
            ))
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, header},
        routing::get,
    };
    use hickory_proto::op::Query;

    fn question(domain: &str, kind: RecordType) -> Message {
        let mut message = Message::query();
        message.metadata.id = 37;
        message.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
        message
    }

    #[tokio::test]
    async fn conditional_refresh_and_restart() -> Result<()> {
        let store = Store::open(std::path::Path::new(":memory:")).await?;
        let root = RootDelegations::default();
        root.load(&store).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let app = Router::new().route("/", get(|headers: HeaderMap| async move {
                        assert_eq!(headers[USER_AGENT], USER_AGENT_VALUE);
            if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v == "\"zone\"") {
                (StatusCode::NOT_MODIFIED, "")
            } else {
                (StatusCode::OK, SEED)
            }
        })).layer(axum::middleware::map_response(|mut response: axum::response::Response| async {
            response.headers_mut().insert(header::ETAG, "\"zone\"".parse().unwrap());
            response
        })).route("/partial", get(|| async { ". 60 IN SOA a. b. 3000000000 30 30 90 60\ncom. 60 IN NS ns.com.\nns.com. 60 IN A 192.0.2.1" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = Client::new();
        root.refresh(&store, &client, &url).await?;
        let restored = RootDelegations::default();
        restored.load(&store).await?;
        let q = question("com.", RecordType::NS);
        let response = restored.referral(&q, 3600).unwrap();
        assert_eq!(response.metadata.id, 37);
        assert_eq!(response.authorities.len(), 13);
        assert_eq!(response.additionals.len(), 26);
        assert!(response.authorities.iter().all(|r| r.ttl == 3600));
        assert!(
            restored
                .referral(&question("com.", RecordType::DS), 3600)
                .is_none()
        );
        assert!(
            restored
                .referral(&question("example.com.", RecordType::NS), 3600)
                .is_none()
        );
        sqlx::query("UPDATE root_delegations SET checked_at=0")
            .execute(&store.pool)
            .await?;
        restored.load(&store).await?;
        assert!(restored.referral(&q, 3600).is_none());
        restored.refresh(&store, &client, &url).await?;
        assert!(
            restored
                .refresh(&store, &client, &format!("{url}/partial"))
                .await
                .is_err()
        );
        restored.load(&store).await?;
        assert!(restored.referral(&q, 3600).is_some());
        server.abort();
        Ok(())
    }
}
