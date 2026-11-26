use super::*;
use crate::{resolver::Engine, store::RuleInput};
use sqlx::FromRow;

#[derive(Clone, Copy, Default, Deserialize, Serialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsPreferences {
    pub adguard: bool,
    pub gfwlist: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordInput {
    domain: String,
    record_type: String,
    value: String,
    ttl: Option<i64>,
}

#[derive(Clone, Serialize, sqlx::FromRow)]
pub(crate) struct PersonalRecord {
    id: i64,
    pub domain: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

const ACTIVE: &str = "SELECT EXISTS(SELECT 1 FROM portal_users WHERE id=? AND status='active' AND credential IS NOT NULL)";

fn inactive() -> Error {
    (StatusCode::FORBIDDEN, "账号尚未开通专属 DoH 地址".into())
}

pub(super) async fn authenticate_active(s: &ApiState, h: &HeaderMap) -> Result<i64> {
    let id = authenticate(s, h).await?;
    if !sqlx::query_scalar::<_, bool>(ACTIVE)
        .bind(id)
        .fetch_one(&s.engine.store.pool)
        .await
        .map_err(internal)?
    {
        return Err(inactive());
    }
    Ok(id)
}

async fn edit_transaction(
    s: &ApiState,
    h: &HeaderMap,
) -> Result<(i64, Transaction<'static, Sqlite>)> {
    let id = authenticate(s, h).await?;
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    if !sqlx::query_scalar::<_, bool>(ACTIVE)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?
    {
        return Err(inactive());
    }
    Ok((id, tx))
}

pub(super) async fn settings(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    let id = authenticate(&s, &h).await?;
    let mut tx = s.engine.store.pool.begin().await.map_err(internal)?;
    let preferences = sqlx::query_as::<_, DnsPreferences>(
        "SELECT COALESCE(p.adguard,0) AS adguard,COALESCE(p.gfwlist,0) AS gfwlist
         FROM portal_users u LEFT JOIN portal_dns_preferences p ON p.user_id=u.id
         WHERE u.id=? AND u.status='active' AND u.credential IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?
    .ok_or_else(inactive)?;
    let records = sqlx::query_as::<_, PersonalRecord>(
        "SELECT id,domain,record_type,value,ttl FROM portal_dns_records WHERE user_id=? ORDER BY domain,record_type,id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let runtime = s.engine.features.current.load();
    Ok(Json(json!({
        "preferences": preferences, "records": records,
        "available": { "adguard": runtime.settings.adguard.enabled, "gfwlist": runtime.settings.gfwlist.enabled }
    })))
}

pub(super) async fn save_preferences(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(input): Json<DnsPreferences>,
) -> Reply {
    check_same_origin(&h)?;
    let (user, mut tx) = edit_transaction(&s, &h).await?;
    sqlx::query(
        "INSERT INTO portal_dns_preferences(user_id,adguard,gfwlist) VALUES(?,?,?)
         ON CONFLICT(user_id) DO UPDATE SET adguard=excluded.adguard,gfwlist=excluded.gfwlist",
    )
    .bind(user)
    .bind(input.adguard)
    .bind(input.gfwlist)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_user_dns(user);
    Ok(Json(json!(input)))
}

pub(crate) async fn query_policy(
    store: &crate::store::Store,
    user: i64,
    domain: &str,
) -> anyhow::Result<Option<(DnsPreferences, Vec<PersonalRecord>)>> {
    if let Some(cached) = store.portal_cache.user_dns.get(&user) {
        return Ok(cached
            .as_ref()
            .map(|entry| (entry.0, entry.1.get(domain).cloned().unwrap_or_default())));
    }
    let rows = sqlx::query(
        "SELECT COALESCE(p.adguard,0) AS adguard,COALESCE(p.gfwlist,0) AS gfwlist,
                r.id,r.domain,r.record_type,r.value,r.ttl
         FROM portal_users u LEFT JOIN portal_dns_preferences p ON p.user_id=u.id
         LEFT JOIN portal_dns_records r ON r.user_id=u.id
         WHERE u.id=? AND u.status='active' AND u.credential IS NOT NULL ORDER BY r.id",
    )
    .bind(user)
    .fetch_all(&store.pool)
    .await?;
    let Some(first) = rows.first() else {
        store.portal_cache.user_dns.insert(user, None);
        return Ok(None);
    };
    let preferences = DnsPreferences::from_row(first)?;
    let mut records_by_domain: std::collections::HashMap<String, Vec<PersonalRecord>> =
        std::collections::HashMap::new();
    for row in rows {
        if row.try_get::<Option<i64>, _>("id")?.is_some() {
            let record = PersonalRecord::from_row(&row)?;
            records_by_domain
                .entry(record.domain.clone())
                .or_default()
                .push(record);
        }
    }
    let domain_records = records_by_domain.get(domain).cloned().unwrap_or_default();
    store
        .portal_cache
        .user_dns
        .insert(user, Some(Arc::new((preferences, records_by_domain))));
    Ok(Some((preferences, domain_records)))
}

fn conflict(message: &str) -> Error {
    (StatusCode::CONFLICT, message.into())
}

fn missing_record() -> Error {
    (StatusCode::NOT_FOUND, "记录不存在".into())
}

fn record_write_error(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        conflict("相同的解析记录已存在")
    } else {
        internal(error)
    }
}

fn validate(input: RecordInput) -> Result<RuleInput> {
    use crate::resolver::normalize_domain;

    let domain =
        normalize_domain(&input.domain).map_err(|_| bad("请填写有效的域名，不支持通配符"))?;
    let record_type = input.record_type.trim().to_ascii_uppercase();
    let value = match record_type.as_str() {
        "A" => input
            .value
            .trim()
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| bad("请填写有效的 IPv4 地址"))?
            .to_string(),
        "AAAA" => input
            .value
            .trim()
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| bad("请填写有效的 IPv6 地址"))?
            .to_string(),
        "CNAME" => {
            let target = normalize_domain(&input.value).map_err(|_| bad("请填写有效的目标域名"))?;
            if target == domain {
                return Err(bad("CNAME 不能指向自身"));
            }
            target
        }
        "TXT" if input.value.len() <= 255 => input.value,
        "TXT" => return Err(bad("TXT 内容最多 255 字节")),
        _ => return Err(bad("仅支持 A、AAAA、CNAME 和 TXT 记录")),
    };
    let ttl = input.ttl.unwrap_or(300);
    if !(1..=86400).contains(&ttl) {
        return Err(bad("TTL 必须为 1 到 86400 秒"));
    }
    Engine::validate_rule(&RuleInput {
        kind: "local".into(),
        domain,
        record_type: Some(record_type),
        value: Some(value),
        ttl: Some(ttl),
    })
    .map_err(|_| bad("解析记录格式无效"))
}

async fn write_record(s: &ApiState, h: &HeaderMap, id: Option<i64>, input: RecordInput) -> Reply {
    let (user, mut tx) = edit_transaction(s, h).await?;
    let record = validate(input)?;
    if let Some(id) = id {
        let owns_record = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM portal_dns_records WHERE user_id=? AND id=?)",
        )
        .bind(user)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        if !owns_record {
            return Err(missing_record());
        }
    } else {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM portal_dns_records WHERE user_id=?")
                .bind(user)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?;
        if count >= 200 {
            return Err(conflict("每个账号最多可保存 200 条解析记录"));
        }
    }
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT record_type FROM portal_dns_records WHERE user_id=? AND domain=? AND id!=?",
    )
    .bind(user)
    .bind(&record.domain)
    .bind(id.unwrap_or(0))
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    if kinds.len() >= 16 {
        return Err(conflict("每个域名最多可保存 16 条解析记录"));
    }
    if !kinds.is_empty()
        && (record.record_type.as_deref() == Some("CNAME")
            || kinds.iter().any(|kind| kind == "CNAME"))
    {
        return Err(conflict("同一个域名只能有一条 CNAME，且不能与其他类型共存"));
    }
    let saved = if let Some(id) = id {
        sqlx::query_as::<_, PersonalRecord>(
            "UPDATE portal_dns_records SET domain=?,record_type=?,value=?,ttl=? WHERE user_id=? AND id=?
             RETURNING id,domain,record_type,value,ttl",
        ).bind(record.domain).bind(record.record_type).bind(record.value).bind(record.ttl).bind(user).bind(id)
        .fetch_one(&mut *tx).await
    } else {
        sqlx::query_as::<_, PersonalRecord>(
            "INSERT INTO portal_dns_records(domain,record_type,value,ttl,user_id) VALUES(?,?,?,?,?)
             RETURNING id,domain,record_type,value,ttl",
        ).bind(record.domain).bind(record.record_type).bind(record.value).bind(record.ttl).bind(user)
        .fetch_one(&mut *tx).await
    }.map_err(record_write_error)?;
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_user_dns(user);
    Ok(Json(json!(saved)))
}

pub(super) async fn add_record(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(input): Json<RecordInput>,
) -> Reply {
    check_same_origin(&h)?;
    write_record(&s, &h, None, input).await
}

pub(super) async fn edit_record(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<RecordInput>,
) -> Reply {
    check_same_origin(&h)?;
    write_record(&s, &h, Some(id), input).await
}

pub(super) async fn delete_record(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> Reply {
    check_same_origin(&h)?;
    let (user, mut tx) = edit_transaction(&s, &h).await?;
    let result = sqlx::query("DELETE FROM portal_dns_records WHERE user_id=? AND id=?")
        .bind(user)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    if result.rows_affected() == 0 {
        return Err(missing_record());
    }
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_user_dns(user);
    Ok(Json(json!({"ok": true})))
}
