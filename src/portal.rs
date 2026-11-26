mod dns;
mod email;
mod federation;
pub(crate) mod lookup;
mod mobileconfig;
mod reporting;

pub(crate) use dns::{DnsPreferences, PersonalRecord, query_policy};

use crate::api::{ApiState, require};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use moka::sync::Cache;
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

type CachedUserDns = Arc<(DnsPreferences, HashMap<String, Vec<PersonalRecord>>)>;

pub struct PortalCache {
    public_doh: Cache<(), bool>,
    credentials: Cache<String, Option<i64>>,
    pub(crate) user_dns: Cache<i64, Option<CachedUserDns>>,
    login_failures: Cache<String, (u32, Instant)>,
}

impl Default for PortalCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PortalCache {
    pub fn new() -> Self {
        Self {
            public_doh: Cache::builder()
                .max_capacity(1)
                .time_to_live(Duration::from_secs(30))
                .build(),
            credentials: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            user_dns: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            login_failures: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(60))
                .build(),
        }
    }

    pub fn invalidate_public(&self) {
        self.public_doh.invalidate_all();
    }

    pub fn invalidate_user(&self, user_id: i64) {
        self.credentials.invalidate_all();
        self.user_dns.invalidate(&user_id);
    }

    pub fn invalidate_user_dns(&self, user_id: i64) {
        self.user_dns.invalidate(&user_id);
    }
}

pub(crate) fn check_login_rate_limit(cache: &PortalCache, scope: &str, key: &str) -> bool {
    let cache_key = format!("{scope}:{key}");
    if let Some((count, since)) = cache.login_failures.get(&cache_key)
        && count >= 5
        && since.elapsed() < Duration::from_secs(60)
    {
        return false;
    }
    true
}

pub(crate) fn record_login_failure(cache: &PortalCache, scope: &str, key: &str) {
    let cache_key = format!("{scope}:{key}");
    let entry = match cache.login_failures.get(&cache_key) {
        Some((count, since)) if since.elapsed() < Duration::from_secs(60) => (count + 1, since),
        _ => (1, Instant::now()),
    };
    cache.login_failures.insert(cache_key, entry);
}

pub(crate) fn clear_login_failures(cache: &PortalCache, scope: &str, key: &str) {
    cache.login_failures.invalidate(&format!("{scope}:{key}"));
}

pub(crate) fn check_same_origin(headers: &HeaderMap) -> Result<()> {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && site.eq_ignore_ascii_case("cross-site")
    {
        return Err((StatusCode::FORBIDDEN, "禁止跨站请求".into()));
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        && let Ok(url) = reqwest::Url::parse(origin)
        && let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok())
    {
        let origin_host = match (url.host_str(), url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_owned(),
            _ => return Err((StatusCode::FORBIDDEN, "无效的请求来源".into())),
        };
        if !origin_host.eq_ignore_ascii_case(host) {
            return Err((StatusCode::FORBIDDEN, "请求来源不匹配".into()));
        }
    }
    Ok(())
}

type Error = (StatusCode, String);
type Result<T> = std::result::Result<T, Error>;
type Reply = Result<Json<Value>>;
fn bad(msg: &str) -> Error {
    (StatusCode::BAD_REQUEST, msg.into())
}
fn denied() -> Error {
    (StatusCode::UNAUTHORIZED, "请重新登录".into())
}
fn internal(_: impl std::fmt::Display) -> Error {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "门户服务暂时不可用".into(),
    )
}
fn random(n: usize) -> String {
    OsRng
        .sample_iter(Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}
fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|s| s.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}
// Bound concurrent Argon2 allocations on the public HTTPS listener.
static PASSWORD_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
fn password_slot() -> Result<tokio::sync::SemaphorePermit<'static>> {
    PASSWORD_WORK
        .try_acquire()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "请稍后重试".into()))
}
const SESSION: &str = "__Host-rdns-portal";
pub async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for sql in [
        "CREATE TABLE IF NOT EXISTS portal_settings(id INTEGER PRIMARY KEY CHECK(id=1), registration TEXT NOT NULL DEFAULT 'open', public INTEGER NOT NULL DEFAULT 1, base TEXT NOT NULL DEFAULT '', providers TEXT NOT NULL DEFAULT '[]')",
        "INSERT OR IGNORE INTO portal_settings(id) VALUES(1)",
        "CREATE TABLE IF NOT EXISTS portal_users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT, identity TEXT UNIQUE, status TEXT NOT NULL, credential TEXT COLLATE BINARY UNIQUE)",
        "CREATE UNIQUE INDEX IF NOT EXISTS portal_local_name ON portal_users(name) WHERE identity IS NULL",
        "CREATE TABLE IF NOT EXISTS portal_dns_preferences(user_id INTEGER PRIMARY KEY REFERENCES portal_users(id) ON DELETE CASCADE, adguard INTEGER NOT NULL, gfwlist INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS portal_dns_records(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE, domain TEXT NOT NULL, record_type TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER NOT NULL, UNIQUE(user_id,domain,record_type,value))",
        "DROP TABLE IF EXISTS portal_profile_tickets",
        "CREATE TABLE IF NOT EXISTS portal_sessions(hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES portal_users(id),expires INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS portal_mail(id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL)",
        "INSERT OR IGNORE INTO portal_mail VALUES(1,'{}')",
        "CREATE TABLE IF NOT EXISTS portal_codes(address TEXT PRIMARY KEY, hash TEXT NOT NULL, sent INTEGER NOT NULL, attempts INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS portal_flows(state TEXT PRIMARY KEY,browser TEXT NOT NULL,provider TEXT NOT NULL,revision TEXT NOT NULL,verifier TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL)",
    ] {
        sqlx::query(sql).execute(&mut *tx).await?;
    }
    if sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pragma_table_info('portal_settings') WHERE name='password_login'",
    )
    .fetch_one(&mut *tx)
    .await?
        == 0
    {
        sqlx::query(
            "ALTER TABLE portal_settings ADD COLUMN password_login INTEGER NOT NULL DEFAULT 1",
        )
        .execute(&mut *tx)
        .await?;
    }
    let cols = sqlx::query("PRAGMA table_info(query_log)")
        .fetch_all(&mut *tx)
        .await?;
    for (name, kind) in [
        ("portal_user_id", "INTEGER"),
        ("entry", "TEXT NOT NULL DEFAULT 'historical'"),
        ("rcode", "INTEGER"),
        ("response_wire", "BLOB"),
    ] {
        if !cols.iter().any(|r| r.get::<String, _>("name") == name) {
            sqlx::query(&format!("ALTER TABLE query_log ADD COLUMN {name} {kind}"))
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("CREATE INDEX IF NOT EXISTS portal_queries ON query_log(portal_user_id,at)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_query_log_entry_at ON query_log(entry,at)")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS query_log_responses(query_log_id INTEGER PRIMARY KEY REFERENCES query_log(id) ON DELETE CASCADE, response_wire BLOB NOT NULL)",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
#[derive(Clone, Copy)]
pub(crate) struct EntryPoint {
    pub doh: bool,
    pub tls: bool,
}

pub fn routes() -> Router<ApiState> {
    Router::new()
        .route("/portal/api/options", get(options))
        .route("/portal/api/email/send", post(email::send))
        .route("/portal/api/email/login", post(email::login))
        .route("/portal/api/register", post(register))
        .route("/portal/api/login", post(login))
        .route("/portal/api/logout", post(logout))
        .route("/portal/api/rdns.mobileconfig", get(mobileconfig::download))
        .route("/portal/api/ios-qr", post(mobileconfig::create_qr))
        .route("/portal/api/me", get(me))
        .route("/portal/api/rotate", post(rotate))
        .route("/portal/api/lookup", post(lookup::test))
        .route(
            "/portal/api/dns-settings",
            get(dns::settings).put(dns::save_preferences),
        )
        .route("/portal/api/dns-records", post(dns::add_record))
        .route(
            "/portal/api/dns-records/{id}",
            axum::routing::put(dns::edit_record).delete(dns::delete_record),
        )
        .route("/portal/api/analytics", get(reporting::personal))
        .route("/portal/auth/{provider}", get(federation::start))
        .route("/portal/callback/{provider}", get(federation::callback))
        .layer(axum::middleware::map_response(
            |mut r: Response| async move {
                r.headers_mut()
                    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                r.headers_mut()
                    .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
                r
            },
        ))
}
pub fn admin_routes() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/portal/settings", get(settings).put(configure))
        .route("/api/v1/portal/users", get(users).post(add_user))
        .route(
            "/api/v1/portal/users/{id}",
            post(manage).put(edit_user).delete(delete_user),
        )
        .route("/api/v1/portal/analytics", get(reporting::admin))
}
pub async fn identify_doh(State(s): State<ApiState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let pool = &s.engine.store.pool;
    let cache = &s.engine.store.portal_cache;
    let identity = if path == "/dns-query" {
        if let Some(on) = cache.public_doh.get(&()) {
            Ok(on.then_some(None))
        } else {
            let res =
                sqlx::query_scalar::<_, bool>("SELECT public FROM portal_settings WHERE id=1")
                    .fetch_one(pool)
                    .await;
            if let Ok(on) = res {
                cache.public_doh.insert((), on);
            }
            res.map(|on| on.then_some(None))
        }
    } else if let Some(key) = path
        .strip_prefix("/dns/")
        .filter(|k| k.len() == 22 && k.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        if matches!(
            *req.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        ) && req.uri().query() == Some("mobileconfig=1")
        {
            let mut response = mobileconfig::download_credential(&s, key, req.headers(), req.uri())
                .await
                .into_response();
            if req.method() == axum::http::Method::HEAD {
                *response.body_mut() = axum::body::Body::empty();
            }
            return response;
        }
        if let Some(cached) = cache.credentials.get(key) {
            Ok(cached.map(Some))
        } else {
            let res = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM portal_users WHERE credential=? AND status='active'",
            )
            .bind(key)
            .fetch_optional(pool)
            .await;
            if let Ok(id) = res {
                cache.credentials.insert(key.to_owned(), id);
            }
            res.map(|id| id.map(Some))
        }
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match identity {
        Ok(Some(id)) => {
            req.extensions_mut().insert(id);
            next.run(req).await
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[derive(Deserialize, Serialize, Clone)]
struct Settings {
    #[serde(default)]
    email: Option<email::Config>,
    #[serde(default)]
    password_login: Option<bool>,
    registration: String,
    public: bool,
    base: String,
    providers: Vec<federation::Provider>,
}
async fn load(pool: &SqlitePool) -> Result<Settings> {
    let row = sqlx::query("SELECT * FROM portal_settings WHERE id=1")
        .fetch_one(pool)
        .await
        .map_err(internal)?;
    Ok(Settings {
        email: Some(email::config(pool).await?),
        password_login: Some(row.get("password_login")),
        registration: row.get("registration"),
        public: row.get("public"),
        base: row.get("base"),
        providers: serde_json::from_str(row.get("providers")).map_err(internal)?,
    })
}
async fn options(State(s): State<ApiState>) -> Reply {
    let cfg = load(&s.engine.store.pool).await?;
    Ok(Json(
        json!({"password_login":cfg.password_login,"email":cfg.email.is_some_and(|c| c.enabled),"registration":cfg.registration,"providers":cfg.providers.iter().filter(|p|p.enabled).map(|p|json!({"id":p.id,"label":p.label})).collect::<Vec<_>>()}),
    ))
}
async fn administrator(s: &ApiState, h: &HeaderMap) -> Result<String> {
    Ok(require(h, &s.engine.store, "admin").await?.username)
}
async fn settings(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    administrator(&s, &h).await?;
    let mut cfg = load(&s.engine.store.pool).await?;
    if let Some(c) = &mut cfg.email {
        c.password.clear();
    }
    for p in &mut cfg.providers {
        p.secret.clear();
    }
    Ok(Json(json!(cfg)))
}
async fn audit(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    action: &str,
    detail: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(actor)
        .bind(action)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}
async fn configure(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(mut cfg): Json<Settings>,
) -> Reply {
    let actor = administrator(&s, &h).await?;
    if !["open", "approval", "closed"].contains(&cfg.registration.as_str()) {
        return Err(bad("注册策略无效"));
    }
    cfg.base = cfg.base.trim_end_matches('/').into();
    if !cfg.base.is_empty() || !cfg.providers.is_empty() {
        let url = federation::https(&cfg.base)?;
        if url.path() != "/" || url.query().is_some() {
            return Err(bad("请输入 HTTPS 站点根地址"));
        }
    }
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    if let Some(mail) = cfg.email.take() {
        email::save(&mut tx, mail).await?;
    }
    let raw: String = sqlx::query_scalar("SELECT providers FROM portal_settings WHERE id=1")
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
    let old: Vec<federation::Provider> = serde_json::from_str(&raw).map_err(internal)?;
    let mut ids = std::collections::HashSet::new();
    for p in &mut cfg.providers {
        p.validate()?;
        if !ids.insert(p.id.clone()) {
            return Err(bad("提供方 ID 重复"));
        }
        if p.secret.is_empty()
            && let Some(last) = old.iter().find(|v| v.id == p.id && v.same_endpoints(p))
        {
            p.secret = last.secret.clone();
        }
    }
    sqlx::query("UPDATE portal_settings SET password_login=COALESCE(?,password_login),registration=?,public=?,base=?,providers=? WHERE id=1")
        .bind(cfg.password_login)
        .bind(&cfg.registration)
        .bind(cfg.public)
        .bind(&cfg.base)
        .bind(serde_json::to_string(&cfg.providers).map_err(internal)?)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    audit(&mut tx, &actor, "portal.settings", "updated").await?;
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_public();
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}
async fn allocate(tx: &mut Transaction<'_, Sqlite>, id: i64) -> Result<()> {
    loop {
        match sqlx::query("UPDATE portal_users SET credential=? WHERE id=?")
            .bind(random(22))
            .bind(id)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => return Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(e) => return Err(internal(e)),
        }
    }
}
async fn create(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    password: Option<String>,
    identity: Option<&str>,
) -> Result<i64> {
    let mode: String = sqlx::query_scalar("SELECT registration FROM portal_settings WHERE id=1")
        .fetch_one(&mut **tx)
        .await
        .map_err(internal)?;
    let status = match mode.as_str() {
        "open" => "active",
        "approval" => "pending",
        _ => return Err((StatusCode::FORBIDDEN, "注册已关闭".into())),
    };
    insert_user(tx, name, password, identity, status).await
}
async fn insert_user(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    password: Option<String>,
    identity: Option<&str>,
    status: &str,
) -> Result<i64> {
    let id = sqlx::query("INSERT INTO portal_users(name,password,identity,status) VALUES(?,?,?,?)")
        .bind(name)
        .bind(password)
        .bind(identity)
        .bind(status)
        .execute(&mut **tx)
        .await
        .map_err(user_write_error)?
        .last_insert_rowid();
    if status == "active" {
        allocate(tx, id).await?;
    }
    Ok(id)
}
async fn session(tx: &mut Transaction<'_, Sqlite>, id: i64) -> Result<String> {
    let token = random(48);
    let updated=sqlx::query("INSERT INTO portal_sessions SELECT ?,id,unixepoch()+43200 FROM portal_users WHERE id=? AND status!='disabled'").bind(digest(&token)).bind(id).execute(&mut **tx).await.map_err(internal)?;
    if updated.rows_affected() == 0 {
        return Err(denied());
    }
    Ok(format!(
        "{SESSION}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200"
    ))
}
async fn authenticate(s: &ApiState, h: &HeaderMap) -> Result<i64> {
    sqlx::query_scalar("SELECT u.id FROM portal_sessions p JOIN portal_users u ON u.id=p.user_id WHERE hash=? AND expires>unixepoch() AND status!='disabled'").bind(digest(cookie(h,SESSION).ok_or_else(denied)?)).fetch_optional(&s.engine.store.pool).await.map_err(internal)?.ok_or_else(denied)
}
async fn require_password_login<'a>(db: impl sqlx::Executor<'a, Database = Sqlite>) -> Result<()> {
    if !sqlx::query_scalar::<_, bool>("SELECT password_login FROM portal_settings WHERE id=1")
        .fetch_one(db)
        .await
        .map_err(internal)?
    {
        return Err((StatusCode::FORBIDDEN, "门户已关闭账号密码登录".into()));
    }
    Ok(())
}
async fn hash_portal_password(password: String) -> Result<String> {
    let slot = password_slot()?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|v| v.to_string())
            .map_err(internal)
    })
    .await
    .map_err(internal)?
}

fn user_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if !(3..=128).contains(&name.len()) {
        return Err(bad("用户名须为 3–128 字节"));
    }
    Ok(name)
}

fn user_write_error(error: sqlx::Error) -> Error {
    match error.as_database_error() {
        Some(e) if e.is_unique_violation() => (StatusCode::CONFLICT, "用户名已被使用".into()),
        _ => internal(error),
    }
}

async fn register(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(c): Json<Credentials>,
) -> Result<Response> {
    check_same_origin(&h)?;
    require_password_login(&s.engine.store.pool).await?;
    let name = c.username.trim();
    if !(3..=128).contains(&name.len()) || c.password.is_empty() || c.password.len() > 1024 {
        return Err(bad("用户名须为 3–128 字节，密码须为 1–1024 字节"));
    }
    let hash = hash_portal_password(c.password).await?;
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    require_password_login(&mut *tx).await?;
    let id = create(&mut tx, name, Some(hash), None).await?;
    let cookie = session(&mut tx, id).await?;
    tx.commit().await.map_err(internal)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
async fn login(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(c): Json<Credentials>,
) -> Result<Response> {
    check_same_origin(&h)?;
    require_password_login(&s.engine.store.pool).await?;
    let username = c.username.trim().to_owned();
    if !check_login_rate_limit(&s.engine.store.portal_cache, "portal", &username) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "登录失败次数过多，请稍后再试".into(),
        ));
    }
    let Some(row) = sqlx::query(
        "SELECT id,password FROM portal_users WHERE identity IS NULL AND name=? AND status!='disabled'",
    )
    .bind(&username)
    .fetch_optional(&s.engine.store.pool)
    .await
    .map_err(internal)?
    else {
        record_login_failure(&s.engine.store.portal_cache, "portal", &username);
        return Err(denied());
    };
    let hash: String = row.get("password");
    let verified_hash = hash.clone();
    let slot = password_slot()?;
    let ok = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        PasswordHash::new(&hash).is_ok_and(|h| {
            Argon2::default()
                .verify_password(c.password.as_bytes(), &h)
                .is_ok()
        })
    })
    .await
    .map_err(internal)?;
    if !ok {
        record_login_failure(&s.engine.store.portal_cache, "portal", &username);
        return Err(denied());
    }
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    require_password_login(&mut *tx).await?;
    let id: i64 = row.get("id");
    let current: Option<String> =
        sqlx::query_scalar("SELECT password FROM portal_users WHERE id=? AND status!='disabled'")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
    if current.as_deref() != Some(verified_hash.as_str()) {
        record_login_failure(&s.engine.store.portal_cache, "portal", &username);
        return Err(denied());
    }
    let cookie = session(&mut tx, id).await?;
    tx.commit().await.map_err(internal)?;
    clear_login_failures(&s.engine.store.portal_cache, "portal", &username);
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
async fn logout(State(s): State<ApiState>, h: HeaderMap, Json(_): Json<Value>) -> Result<Response> {
    check_same_origin(&h)?;
    sqlx::query("DELETE FROM portal_sessions WHERE hash=?")
        .bind(digest(cookie(&h, SESSION).unwrap_or("")))
        .execute(&s.engine.store.pool)
        .await
        .map_err(internal)?;
    Ok((
        [(
            header::SET_COOKIE,
            format!("{SESSION}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn me(
    State(s): State<ApiState>,
    Extension(entry): Extension<EntryPoint>,
    h: HeaderMap,
    uri: Uri,
) -> Reply {
    let id = authenticate(&s, &h).await?;
    let row = sqlx::query("SELECT name,status,credential,base FROM portal_users,portal_settings WHERE portal_users.id=?")
        .bind(id)
        .fetch_one(&s.engine.store.pool)
        .await
        .map_err(internal)?;
    let base: String = row.get("base");
    let path = row
        .get::<Option<String>, _>("credential")
        .map(|key| format!("/dns/{key}"));
    let resolver_url = if let Some(path) = &path {
        mobileconfig::resolver_origin(&base, entry, &h, &uri)?.map(|origin| origin + path)
    } else {
        None
    };
    Ok(Json(json!({
        "id": id, "name": row.get::<String, _>("name"), "status": row.get::<String, _>("status"),
        "base": base, "path": path, "resolver_url": resolver_url
    })))
}
async fn rotate(State(s): State<ApiState>, h: HeaderMap, Json(_): Json<Value>) -> Reply {
    check_same_origin(&h)?;
    let id = authenticate(&s, &h).await?;
    change(&s, id, "rotate", &format!("portal:{id}")).await
}
async fn users(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    administrator(&s, &h).await?;
    let rows = sqlx::query(
        "SELECT id,name,status,identity IS NOT NULL AS external, COALESCE(identity LIKE 'email:%',0) AS email_login FROM portal_users ORDER BY id DESC",
    )
    .fetch_all(&s.engine.store.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<i64,_>("id"),"name":r.get::<String,_>("name"),"status":r.get::<String,_>("status"),"external":r.get::<bool,_>("external"),"email_login":r.get::<bool,_>("email_login")})).collect::<Vec<_>>())))
}
async fn add_user(State(s): State<ApiState>, h: HeaderMap, Json(c): Json<Credentials>) -> Reply {
    let actor = administrator(&s, &h).await?;
    let name = user_name(&c.username)?;
    if c.password.is_empty() || c.password.len() > 1024 {
        return Err(bad("密码须为 1–1024 字节"));
    }
    let hash = hash_portal_password(c.password).await?;
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let id = insert_user(&mut tx, name, Some(hash), None, "active").await?;
    audit(&mut tx, &actor, "portal.user.create", &id.to_string()).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({"id":id})))
}

#[derive(Deserialize)]
struct UserEdit {
    username: String,
    password: Option<String>,
}

async fn edit_user(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<UserEdit>,
) -> Reply {
    let actor = administrator(&s, &h).await?;
    let name = user_name(&input.username)?;
    let password = input.password.filter(|password| !password.is_empty());
    if password
        .as_ref()
        .is_some_and(|password| password.len() > 1024)
    {
        return Err(bad("密码须为 1–1024 字节"));
    }
    let hash = match password {
        Some(password) => Some(hash_portal_password(password).await?),
        None => None,
    };
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let external: bool =
        sqlx::query_scalar("SELECT identity IS NOT NULL FROM portal_users WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or((StatusCode::NOT_FOUND, "用户不存在".into()))?;
    if external && hash.is_some() {
        return Err(bad("只有账号密码登录的用户可以重设密码"));
    }
    sqlx::query("UPDATE portal_users SET name=?, password=COALESCE(?,password) WHERE id=?")
        .bind(name)
        .bind(&hash)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(user_write_error)?;
    if hash.is_some() {
        revoke_user_sessions(&mut tx, id).await?;
    }
    audit(&mut tx, &actor, "portal.user.update", &id.to_string()).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}

async fn delete_user(State(s): State<ApiState>, h: HeaderMap, Path(id): Path<i64>) -> Reply {
    let actor = administrator(&s, &h).await?;
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    revoke_user_sessions(&mut tx, id).await?;
    let result = sqlx::query("DELETE FROM portal_users WHERE id=?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "用户不存在".into()));
    }
    audit(&mut tx, &actor, "portal.user.delete", &id.to_string()).await?;
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_user(id);
    Ok(Json(json!({"ok":true})))
}

async fn revoke_user_sessions(tx: &mut Transaction<'_, Sqlite>, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM portal_sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

#[derive(Deserialize)]
struct Action {
    action: String,
}
async fn manage(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(a): Json<Action>,
) -> Reply {
    let actor = administrator(&s, &h).await?;
    change(&s, id, &a.action, &actor).await
}
async fn change(s: &ApiState, id: i64, action: &str, actor: &str) -> Reply {
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let status: String = sqlx::query_scalar("SELECT status FROM portal_users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "用户不存在".into()))?;
    match action {
        "activate" if status != "active" => {
            sqlx::query("UPDATE portal_users SET status='active' WHERE id=?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            allocate(&mut tx, id).await?;
        }
        "disable" => {
            sqlx::query("UPDATE portal_users SET status='disabled',credential=NULL WHERE id=?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            revoke_user_sessions(&mut tx, id).await?;
        }
        "rotate" if status == "active" => allocate(&mut tx, id).await?,
        _ => return Err(bad("当前状态不允许此操作")),
    }
    audit(&mut tx, actor, &format!("portal.{action}"), &id.to_string()).await?;
    tx.commit().await.map_err(internal)?;
    s.engine.store.portal_cache.invalidate_user(id);
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_rate_limit_blocks_after_five_failures_and_clears() {
        let cache = PortalCache::new();
        assert!(check_login_rate_limit(&cache, "admin", "alice"));
        for _ in 0..5 {
            record_login_failure(&cache, "admin", "alice");
        }
        assert!(!check_login_rate_limit(&cache, "admin", "alice"));
        assert!(check_login_rate_limit(&cache, "portal", "alice"));
        clear_login_failures(&cache, "admin", "alice");
        assert!(check_login_rate_limit(&cache, "admin", "alice"));
    }

    #[test]
    fn same_origin_rejects_cross_site_headers() {
        let mut headers = HeaderMap::new();
        assert!(check_same_origin(&headers).is_ok());
        headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(check_same_origin(&headers).is_ok());
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(check_same_origin(&headers).is_err());

        let mut origin_headers = HeaderMap::new();
        origin_headers.insert(header::HOST, "dns.example.com".parse().unwrap());
        origin_headers.insert(header::ORIGIN, "https://dns.example.com".parse().unwrap());
        assert!(check_same_origin(&origin_headers).is_ok());
        origin_headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(check_same_origin(&origin_headers).is_err());
    }

    #[tokio::test]
    async fn query_log_persists_personal_response_wire_in_side_table() -> anyhow::Result<()> {
        let store = crate::store::Store::open(std::path::Path::new(":memory:")).await?;
        let wire = vec![1u8, 2, 3, 4];
        store.query_log.push(crate::query_log::QueryLogEntry {
            user_id: Some(7),
            at: chrono::Utc::now().to_rfc3339(),
            client: "127.0.0.1".into(),
            domain: "side-table.test".into(),
            qtype: "A".into(),
            outcome: "local".into(),
            protocol: "doh".into(),
            duration_ms: 0.5,
            country: None,
            province: None,
            city: None,
            upstream: None,
            rcode: Some(0),
            response_wire: Some(wire.clone()),
        })?;
        store.query_log.flush().await?;
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT qr.response_wire FROM query_log q JOIN query_log_responses qr ON qr.query_log_id=q.id WHERE q.domain='side-table.test'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(stored, wire);
        Ok(())
    }
}
