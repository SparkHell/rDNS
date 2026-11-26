use super::*;
use axum::extract::Query;
use chrono::{DateTime, Duration, Local, Utc};
use hickory_proto::op::Message;
use std::collections::BTreeMap;

#[derive(Deserialize, Default)]
pub(super) struct Filter {
    days: Option<i64>,
    page: Option<i64>,
    user: Option<i64>,
    entry: Option<String>,
    search: Option<String>,
    qtype: Option<String>,
    outcome: Option<String>,
    rcode: Option<u16>,
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
    id: i64,
    at: String,
    domain: String,
    qtype: String,
    outcome: String,
    duration_ms: Option<f64>,
    entry: String,
    user: Option<i64>,
    rcode: Option<i64>,
    #[serde(skip_serializing)]
    response_wire: Option<Vec<u8>>,
    #[sqlx(skip)]
    local_at: String,
    #[sqlx(skip)]
    response: Option<lookup::DnsResponse>,
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

fn detail_filtered<'a>(
    columns: &str,
    from: &str,
    cutoff: &'a str,
    f: &'a Filter,
) -> sqlx::QueryBuilder<'a, Sqlite> {
    let mut query = sqlx::QueryBuilder::new(format!("SELECT {columns} FROM {from} WHERE q.at >= "));
    query.push_bind(cutoff);
    if let Some(user) = f.user {
        query.push(" AND q.portal_user_id = ").push_bind(user);
    }
    if let Some(entry) = &f.entry {
        query.push(" AND q.entry = ").push_bind(entry);
    }
    if let Some(search) = &f.search {
        query
            .push(" AND instr(lower(q.domain), ")
            .push_bind(search)
            .push(")>0");
    }
    if let Some(qtype) = &f.qtype {
        query.push(" AND q.qtype = ").push_bind(qtype);
    }
    if let Some(outcome) = &f.outcome {
        query.push(" AND q.outcome = ").push_bind(outcome);
    }
    if let Some(rcode) = f.rcode {
        query.push(" AND q.rcode = ").push_bind(i64::from(rcode));
    }
    query
}

fn timeline(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hourly: bool,
    rows: Vec<Bucket>,
) -> Vec<Bucket> {
    let mut buckets: BTreeMap<_, _> = rows.into_iter().map(|row| (row.time, row.count)).collect();
    let format = if hourly { "%Y-%m-%dT%H:00" } else { "%Y-%m-%d" };
    let step = if hourly {
        Duration::minutes(30)
    } else {
        Duration::hours(12)
    };
    let mut cursor = start;
    while cursor < end {
        buckets
            .entry(cursor.with_timezone(&Local).format(format).to_string())
            .or_insert(0);
        cursor += step;
    }
    buckets
        .entry(end.with_timezone(&Local).format(format).to_string())
        .or_insert(0);
    buckets
        .into_iter()
        .map(|(time, count)| Bucket { time, count })
        .collect()
}

async fn report(s: &ApiState, mut f: Filter) -> Reply {
    let days = f.days.unwrap_or(1);
    let page = f.page.unwrap_or(1);
    if ![1, 7, 30].contains(&days) || !(1..=1_000_000).contains(&page) {
        return Err(bad("时间范围或页码无效"));
    }
    f.search = f
        .search
        .map(|q| q.trim().trim_end_matches('.').to_lowercase())
        .filter(|q| !q.is_empty());
    if f.search.as_ref().is_some_and(|q| q.len() > 253)
        || f.outcome.as_ref().is_some_and(|q| q.len() > 64)
        || f.rcode.is_some_and(|code| code > 4095)
    {
        return Err(bad("筛选条件无效"));
    }
    if let Some(qtype) = &mut f.qtype {
        *qtype = lookup::type_label(lookup::record_type(qtype).ok_or_else(|| bad("记录类型无效"))?);
    }
    let store = &s.engine.store;
    store.query_log.flush().await.map_err(internal)?;
    let now = Utc::now();
    let start = now - Duration::days(days.min(s.engine.config.query_log_days));
    let cutoff = start.to_rfc3339();
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
        "COALESCE(strftime('%Y-%m-%dT%H:00', at, 'localtime'), '') AS time, COUNT(*) AS count"
    } else {
        "COALESCE(strftime('%Y-%m-%d', at, 'localtime'), '') AS time, COUNT(*) AS count"
    };
    let trend = filtered(columns, &cutoff, &f)
        .push(" GROUP BY time HAVING time <> '' ORDER BY time")
        .build_query_as::<Bucket>()
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    let detail_total: i64 = detail_filtered("COUNT(*)", "query_log q", &cutoff, &f)
        .build_query_scalar()
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
    let outcomes = filtered("DISTINCT outcome", &cutoff, &f)
        .push(" ORDER BY outcome")
        .build_query_scalar::<String>()
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    let mut logs = detail_filtered(
        "q.id,q.at,q.domain,q.qtype,q.outcome,q.duration_ms,q.entry,q.portal_user_id AS user,q.rcode,COALESCE(qr.response_wire, q.response_wire) AS response_wire",
        "query_log q LEFT JOIN query_log_responses qr ON qr.query_log_id=q.id",
        &cutoff,
        &f,
    )
    .push(" ORDER BY q.id DESC LIMIT 50 OFFSET ")
    .push_bind((page - 1) * 50)
    .build_query_as::<Detail>()
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    for row in &mut logs {
        row.local_at = DateTime::parse_from_rfc3339(&row.at).map_or_else(
            |_| row.at.clone(),
            |at| {
                at.with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            },
        );
        row.response = row
            .response_wire
            .take()
            .and_then(|wire| Message::from_vec(&wire).ok())
            .as_ref()
            .map(lookup::DnsResponse::from);
    }
    let rcodes = [0u16, 1, 2, 3, 4, 5]
        .into_iter()
        .map(|code| (code, lookup::rcode_label(code.into())))
        .collect::<BTreeMap<_, _>>();
    Ok(Json(json!({
        "total": total, "blocked": blocked, "latency": latency, "domains": domains,
        "trend": timeline(start, now, days == 1, trend), "logs": logs,
        "detail_total": detail_total, "outcomes": outcomes, "rcodes": rcodes,
        "retention": s.engine.config.query_log_days, "server_offset": now.with_timezone(&Local).format("%:z").to_string()
    })))
}
