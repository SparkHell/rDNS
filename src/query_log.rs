use anyhow::{Context, Result};
use sqlx::{QueryBuilder, SqlitePool};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{mpsc, oneshot};

pub struct QueryLogEntry {
    pub at: String,
    pub client: String,
    pub domain: String,
    pub qtype: String,
    pub outcome: String,
    pub protocol: String,
    pub duration_ms: f64,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub upstream: Option<String>,
}

enum Item {
    Entry(Box<QueryLogEntry>),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct QueryLog {
    sender: mpsc::Sender<Item>,
    metrics: Arc<Metrics>,
}
#[derive(Default)]
struct Metrics {
    write_us: AtomicU64,
    failed_entries: AtomicU64,
}

impl QueryLog {
    pub fn new(pool: SqlitePool) -> Self {
        let (sender, mut receiver) = mpsc::channel(1024);
        let metrics = Arc::new(Metrics::default());
        let worker_metrics = metrics.clone();
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(64);
            while receiver.recv_many(&mut batch, 64).await > 0 {
                let entries = batch.iter().filter_map(|item| match item {
                    Item::Entry(entry) => Some(entry),
                    _ => None,
                });
                let count = entries.clone().count();
                if count > 0 {
                    let started = std::time::Instant::now();
                    let mut query = QueryBuilder::new(
                        "INSERT INTO query_log(at,client,domain,qtype,outcome,protocol,duration_ms,country,province,city,upstream) ",
                    );
                    query.push_values(entries, |mut row, e| {
                        row.push_bind(&e.at)
                            .push_bind(&e.client)
                            .push_bind(&e.domain)
                            .push_bind(&e.qtype)
                            .push_bind(&e.outcome)
                            .push_bind(&e.protocol)
                            .push_bind(e.duration_ms)
                            .push_bind(&e.country)
                            .push_bind(&e.province)
                            .push_bind(&e.city)
                            .push_bind(&e.upstream);
                    });
                    if let Err(error) = query.build().execute(&pool).await {
                        worker_metrics
                            .failed_entries
                            .fetch_add(count as u64, Ordering::Relaxed);
                        tracing::warn!(%error, count, "query log batch write failed");
                    }
                    worker_metrics
                        .write_us
                        .store(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                }
                for item in batch.drain(..) {
                    if let Item::Flush(ack) = item {
                        let _ = ack.send(());
                    }
                }
            }
        });
        Self { sender, metrics }
    }

    pub async fn push(&self, entry: QueryLogEntry) -> Result<()> {
        self.sender
            .send(Item::Entry(Box::new(entry)))
            .await
            .map_err(|_| anyhow::anyhow!("query log writer stopped"))
    }

    pub async fn flush(&self) -> Result<()> {
        let (ack, result) = oneshot::channel();
        self.sender
            .send(Item::Flush(ack))
            .await
            .map_err(|_| anyhow::anyhow!("query log writer stopped"))?;
        result.await.context("query log writer stopped")
    }

    pub fn metrics(&self) -> serde_json::Value {
        serde_json::json!({"last_batch_write_us": self.metrics.write_us.load(Ordering::Relaxed),
            "failed_entries": self.metrics.failed_entries.load(Ordering::Relaxed),
            "queue_depth": self.sender.max_capacity() - self.sender.capacity()})
    }
}
