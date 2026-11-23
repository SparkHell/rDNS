use super::*;
use axum::extract::Query;

#[derive(Deserialize, Default)]
pub(super) struct Filter {
    days: Option<i64>,
    page: Option<i64>,
    user: Option<i64>,
    entry: Option<String>,
}
pub(super) async fn personal(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(mut f): Query<Filter>,
) -> Reply {
    f.user = Some(authenticate(&s, &h).await?);
    f.entry = Some("personal".into());
    report(&s, f).await
}
pub(super) async fn admin(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(f): Query<Filter>,
) -> Reply {
    administrator(&s, &h).await?;
    report(&s, f).await
}
#[derive(sqlx::FromRow, Serialize)]
struct DomainCount {
    domain: String,
    count: i64,
}
#[derive(sqlx::FromRow, Serialize)]
struct Bucket {
    time: String,
    count: i64,
}
#[derive(sqlx::FromRow, Serialize)]
struct Detail {
    at: String,
    domain: String,
    qtype: String,
    outcome: String,
    duration_ms: Option<f64>,
    entry: String,
    user: Option<i64>,
}

fn filtered<'a>(
    columns: &str,
    cutoff: &'a str,
    filter: &'a Filter,
) -> sqlx::QueryBuilder<'a, Sqlite> {
    let mut sql = sqlx::QueryBuilder::new(format!("SELECT {columns} FROM query_log WHERE at >= "));
    sql.push_bind(cutoff);
    if let Some(user) = filter.user {
        sql.push(" AND portal_user_id = ").push_bind(user);
    }
    if let Some(entry) = &filter.entry {
        sql.push(" AND entry = ").push_bind(entry);
    }
    sql
}

async fn report(s: &ApiState, f: Filter) -> Reply {
    let days = f.days.unwrap_or(1);
    let page = f.page.unwrap_or(1);
    if ![1, 7, 30].contains(&days) || !(1..=1_000_000).contains(&page) {
        return Err(bad("时间范围或页码无效"));
    }
    let store = &s.engine.store;
    store.query_log.flush().await.map_err(internal)?;
    let cutoff = (chrono::Utc::now()
        - chrono::Duration::days(days.min(s.engine.config.query_log_days)))
    .to_rfc3339();
    let mut tx = store.pool.begin().await.map_err(internal)?;
    let (total, blocked, latency): (i64, i64, Option<f64>) = filtered(
        "COUNT(*), COUNT(*) FILTER (WHERE outcome='blocked'), AVG(duration_ms)",
        &cutoff,
        &f,
    )
    .build_query_as()
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    let domains = filtered("domain, COUNT(*) AS count", &cutoff, &f)
        .push(" GROUP BY domain ORDER BY count DESC, domain LIMIT 10")
        .build_query_as::<DomainCount>()
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    let columns = if days == 1 {
        "substr(at,1,13) AS time, COUNT(*) AS count"
    } else {
        "substr(at,1,10) AS time, COUNT(*) AS count"
    };
    let trend = filtered(columns, &cutoff, &f)
        .push(" GROUP BY time ORDER BY time")
        .build_query_as::<Bucket>()
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    let logs = filtered(
        "at,domain,qtype,outcome,duration_ms,entry,portal_user_id AS user",
        &cutoff,
        &f,
    )
    .push(" ORDER BY id DESC LIMIT 50 OFFSET ")
    .push_bind((page - 1) * 50)
    .build_query_as::<Detail>()
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({
        "total": total, "blocked": blocked, "latency": latency, "domains": domains,
        "trend": trend, "logs": logs, "retention": s.engine.config.query_log_days
    })))
}
