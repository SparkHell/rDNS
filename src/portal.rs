mod federation;
mod reporting;

use crate::api::{ApiState, require};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

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
        "CREATE TABLE IF NOT EXISTS portal_sessions(hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES portal_users(id),expires INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS portal_flows(state TEXT PRIMARY KEY,browser TEXT NOT NULL,provider TEXT NOT NULL,revision TEXT NOT NULL,verifier TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL)",
    ] {
        sqlx::query(sql).execute(&mut *tx).await?;
    }
    let cols = sqlx::query("PRAGMA table_info(query_log)")
        .fetch_all(&mut *tx)
        .await?;
    for (name, kind) in [
        ("portal_user_id", "INTEGER"),
        ("entry", "TEXT NOT NULL DEFAULT 'historical'"),
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
    tx.commit().await?;
    Ok(())
}
pub fn routes() -> Router<ApiState> {
    Router::new()
        .route("/portal/api/options", get(options))
        .route("/portal/api/register", post(register))
        .route("/portal/api/login", post(login))
        .route("/portal/api/logout", post(logout))
        .route("/portal/api/me", get(me))
        .route("/portal/api/rotate", post(rotate))
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
        .route("/api/v1/portal/users", get(users))
        .route("/api/v1/portal/users/{id}", post(manage))
        .route("/api/v1/portal/analytics", get(reporting::admin))
}
pub async fn identify_doh(State(s): State<ApiState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let pool = &s.engine.store.pool;
    let identity = if path == "/dns-query" {
        sqlx::query_scalar::<_, bool>("SELECT public FROM portal_settings WHERE id=1")
            .fetch_one(pool)
            .await
            .map(|on| on.then_some(None))
    } else if let Some(key) = path
        .strip_prefix("/dns-")
        .filter(|k| k.len() == 22 && k.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        sqlx::query_scalar::<_, i64>(
            "SELECT id FROM portal_users WHERE credential=? AND status='active'",
        )
        .bind(key)
        .fetch_optional(pool)
        .await
        .map(|id| id.map(Some))
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
        registration: row.get("registration"),
        public: row.get("public"),
        base: row.get("base"),
        providers: serde_json::from_str(row.get("providers")).map_err(internal)?,
    })
}
async fn options(State(s): State<ApiState>) -> Reply {
    let cfg = load(&s.engine.store.pool).await?;
    Ok(Json(
        json!({"registration":cfg.registration,"providers":cfg.providers.iter().map(|p|json!({"id":p.id,"label":p.label})).collect::<Vec<_>>()}),
    ))
}
async fn administrator(s: &ApiState, h: &HeaderMap) -> Result<String> {
    Ok(require(h, &s.engine.store, "admin").await?.username)
}
async fn settings(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    administrator(&s, &h).await?;
    let mut cfg = load(&s.engine.store.pool).await?;
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
    sqlx::query("UPDATE portal_settings SET registration=?,public=?,base=?,providers=? WHERE id=1")
        .bind(&cfg.registration)
        .bind(cfg.public)
        .bind(&cfg.base)
        .bind(serde_json::to_string(&cfg.providers).map_err(internal)?)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    audit(&mut tx, &actor, "portal.settings", "updated").await?;
    tx.commit().await.map_err(internal)?;
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
    let id = sqlx::query("INSERT INTO portal_users(name,password,identity,status) VALUES(?,?,?,?)")
        .bind(name)
        .bind(password)
        .bind(identity)
        .bind(status)
        .execute(&mut **tx)
        .await
        .map_err(|e| match e.as_database_error() {
            Some(d) if d.is_unique_violation() => (StatusCode::CONFLICT, "用户名已被使用".into()),
            _ => internal(e),
        })?
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
async fn register(State(s): State<ApiState>, Json(c): Json<Credentials>) -> Result<Response> {
    let name = c.username.trim();
    if !(3..=128).contains(&name.len()) || c.password.is_empty() || c.password.len() > 1024 {
        return Err(bad("用户名须为 3–128 字节，密码须为 1–1024 字节"));
    }
    let slot = password_slot()?;
    let hash = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        Argon2::default()
            .hash_password(c.password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|v| v.to_string())
            .map_err(internal)
    })
    .await
    .map_err(internal)??;
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let id = create(&mut tx, name, Some(hash), None).await?;
    let cookie = session(&mut tx, id).await?;
    tx.commit().await.map_err(internal)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
async fn login(State(s): State<ApiState>, Json(c): Json<Credentials>) -> Result<Response> {
    let row=sqlx::query("SELECT id,password FROM portal_users WHERE identity IS NULL AND name=? AND status!='disabled'").bind(c.username.trim()).fetch_optional(&s.engine.store.pool).await.map_err(internal)?.ok_or_else(denied)?;
    let hash: String = row.get("password");
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
        return Err(denied());
    }
    let mut tx = s.engine.store.pool.begin().await.map_err(internal)?;
    let cookie = session(&mut tx, row.get("id")).await?;
    tx.commit().await.map_err(internal)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
async fn logout(State(s): State<ApiState>, h: HeaderMap, Json(_): Json<Value>) -> Result<Response> {
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
async fn me(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    let id = authenticate(&s, &h).await?;
    let row=sqlx::query("SELECT name,status,credential,base FROM portal_users,portal_settings WHERE portal_users.id=?").bind(id).fetch_one(&s.engine.store.pool).await.map_err(internal)?;
    Ok(Json(
        json!({"id":id,"name":row.get::<String,_>("name"),"status":row.get::<String,_>("status"),"base":row.get::<String,_>("base"),"path":row.get::<Option<String>,_>("credential").map(|c|format!("/dns-{c}"))}),
    ))
}
async fn rotate(State(s): State<ApiState>, h: HeaderMap, Json(_): Json<Value>) -> Reply {
    let id = authenticate(&s, &h).await?;
    change(&s, id, "rotate", &format!("portal:{id}")).await
}
async fn users(State(s): State<ApiState>, h: HeaderMap) -> Reply {
    administrator(&s, &h).await?;
    let rows = sqlx::query(
        "SELECT id,name,status,identity IS NOT NULL AS external FROM portal_users ORDER BY id DESC",
    )
    .fetch_all(&s.engine.store.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<i64,_>("id"),"name":r.get::<String,_>("name"),"status":r.get::<String,_>("status"),"external":r.get::<bool,_>("external")})).collect::<Vec<_>>())))
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
            sqlx::query("DELETE FROM portal_sessions WHERE user_id=?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        "rotate" if status == "active" => allocate(&mut tx, id).await?,
        _ => return Err(bad("当前状态不允许此操作")),
    }
    audit(&mut tx, actor, &format!("portal.{action}"), &id.to_string()).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}
