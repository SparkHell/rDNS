mod doh;

use crate::{
    cache::CacheSettings,
    features::{FeatureSettings, SourceUpdate},
    resolver::{Engine, parse_filter_list, parse_imported_filters},
    runtime::{ListenerManager, ListenerSettings},
    store::{Account, RuleInput, Store},
    tls::TlsState,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{
        ConnectInfo, Path, Query, Request, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
pub(crate) use doh::doh_client;
pub use doh::doh_router;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Engine>,
    pub tls: Arc<TlsState>,
    pub listeners: Arc<ListenerManager>,
}
type ApiResult = Result<Json<Value>, (StatusCode, String)>;

pub fn admin_router(state: ApiState) -> Router {
    let router = if state.engine.config.doh_on_admin {
        doh::doh_queries(&state)
    } else {
        Router::new()
    };
    router
        .merge(crate::portal::admin_routes())
        .merge(doh::portal_pages(crate::portal::EntryPoint {
            doh: state.engine.config.doh_on_admin,
            tls: false,
        }))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/clients", get(clients).put(update_clients))
        .route(
            "/api/v1/listeners",
            get(listener_status).put(update_listeners),
        )
        .route("/api/v1/cache", get(cache_status).put(update_cache))
        .route(
            "/api/v1/cache/automation",
            axum::routing::put(update_cache_jobs),
        )
        .route(
            "/api/v1/cache/automation/{kind}/refresh",
            post(refresh_cache_job),
        )
        .route("/api/v1/adguard/refresh", post(refresh_ads))
        .route("/api/v1/sources/{source}/upload", post(upload_source))
        .route("/api/v1/features", get(feature_status).put(update_features))
        .route("/api/v1/proxy/test", post(test_proxy))
        .route("/api/v1/gfwlist/refresh", post(refresh_gfwlist))
        .route("/api/v1/geoip/refresh", post(refresh_geoip))
        .route("/api/v1/geoip/lookup", post(lookup_geoip))
        .route("/api/v1/ws", get(websocket))
        .route("/api/v1/dns/lookup", post(test_dns))
        .route("/api/v1/rules", get(rules).post(add_rule))
        .route("/api/v1/rules/import", post(import_rules))
        .route("/api/v1/rules/{id}", axum::routing::delete(delete_rule))
        .route(
            "/api/v1/subscriptions",
            get(subscriptions).post(add_subscription),
        )
        .route(
            "/api/v1/subscriptions/{id}",
            axum::routing::delete(delete_subscription),
        )
        .route(
            "/api/v1/subscriptions/{id}/refresh",
            post(refresh_subscription),
        )
        .route("/api/v1/accounts", get(accounts).post(add_account))
        .route(
            "/api/v1/accounts/{id}",
            axum::routing::delete(delete_account),
        )
        .route("/api/v1/audit", get(audit_events))
        .route(
            "/api/v1/certificates",
            get(certificate_paths).put(update_certificate_paths),
        )
        .route("/api/v1/certificates/reload", post(reload_certificate))
        .route("/admin", get(doh::index))
        .route("/admin/", get(doh::index))
        .route("/{*path}", get(doh::asset))
        .with_state(state)
}

fn unauthorized() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "authentication required".into())
}
fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(%error, "API failure");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
pub(crate) async fn require(
    headers: &HeaderMap,
    store: &Store,
    role: &str,
) -> Result<Account, (StatusCode, String)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    authorize(token, store, role).await
}

async fn authorize(
    token: &str,
    store: &Store,
    role: &str,
) -> Result<Account, (StatusCode, String)> {
    let account = store
        .account_for_token(token)
        .await
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    let allowed = match role {
        "viewer" => matches!(account.role.as_str(), "admin" | "editor" | "viewer"),
        "editor" => matches!(account.role.as_str(), "admin" | "editor"),
        "admin" => account.role == "admin",
        _ => false,
    };
    if !allowed {
        return Err((StatusCode::FORBIDDEN, "insufficient role".into()));
    }
    Ok(account)
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}
async fn login(State(state): State<ApiState>, Json(input): Json<Credentials>) -> ApiResult {
    let cache = &state.engine.store.portal_cache;
    let username = input.username.trim();
    if !crate::portal::check_login_rate_limit(cache, "admin", username) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed login attempts, retry shortly".into(),
        ));
    }
    let token = state
        .engine
        .store
        .login(&input.username, &input.password)
        .await
        .map_err(internal)?;
    match token {
        Some(token) => {
            crate::portal::clear_login_failures(cache, "admin", username);
            state
                .engine
                .store
                .audit(&input.username, "login", "session created")
                .await
                .map_err(internal)?;
            Ok(Json(json!({"token":token})))
        }
        None => {
            crate::portal::record_login_failure(cache, "admin", username);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Err(unauthorized())
        }
    }
}

#[derive(Deserialize)]
struct PasswordChange {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<PasswordChange>,
) -> ApiResult {
    let store = &state.engine.store;
    let account = require(&headers, store, "admin").await?;
    if input.new_password.is_empty() || input.new_password == input.current_password {
        return Err((
            StatusCode::BAD_REQUEST,
            "请输入与当前密码不同的新密码".into(),
        ));
    }
    if !store
        .change_password(&account, input.current_password, input.new_password)
        .await
        .map_err(internal)?
    {
        tokio::time::sleep(Duration::from_millis(300)).await;
        return Err((
            StatusCode::BAD_REQUEST,
            "当前密码不正确，或密码刚刚被更改".into(),
        ));
    }
    state.listeners.publish(json!({"type":"session.check"}));
    Ok(Json(json!({"ok":true})))
}

async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "viewer").await?;
    let token = headers
        .get(header::AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches("Bearer ");
    state.engine.store.logout(token).await.map_err(internal)?;
    state.listeners.publish(json!({"type":"session.check"}));
    state
        .engine
        .store
        .audit(&account.username, "logout", "session closed")
        .await
        .map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}

async fn me(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(json!(account)))
}
async fn stats(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(state.engine.store.stats().await.map_err(internal)?))
}
async fn metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    require(&headers, &state.engine.store, "viewer").await?;
    let stats = state.engine.store.stats().await.map_err(internal)?;
    let cache = state.engine.cache_stats().await;
    let features = state.engine.features.snapshot(true).await;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let mut out = String::new();
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "# TYPE rdns_queries_total counter\nrdns_queries_total {}",
        stats["total"].as_i64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_queries_blocked_total counter\nrdns_queries_blocked_total {}",
        stats["blocked"].as_i64().unwrap_or(0)
    );
    let _ = writeln!(out, "# TYPE rdns_cache_hits_total counter");
    let _ = writeln!(
        out,
        "rdns_cache_hits_total{{tier=\"memory\"}} {}",
        cache["memory_hits"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "rdns_cache_hits_total{{tier=\"disk\"}} {}",
        cache["disk_hits"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_cache_misses_total counter\nrdns_cache_misses_total {}",
        cache["misses"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_cache_memory_bytes gauge\nrdns_cache_memory_bytes {}",
        cache["memory_bytes"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_cache_memory_entries gauge\nrdns_cache_memory_entries {}",
        cache["memory_entries"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_cache_disk_entries gauge\nrdns_cache_disk_entries {}",
        cache["disk_entries"].as_i64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_cache_disk_bytes gauge\nrdns_cache_disk_bytes {}",
        cache["disk_bytes"].as_i64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_process_rss_bytes gauge\nrdns_process_rss_bytes {}",
        cache["process_rss_bytes"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_query_log_queue_depth gauge\nrdns_query_log_queue_depth {}",
        stats["query_log"]["queue_depth"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_query_log_failed_total counter\nrdns_query_log_failed_total {}",
        stats["query_log"]["failed_entries"].as_u64().unwrap_or(0)
    );
    let _ = writeln!(
        out,
        "# TYPE rdns_query_log_dropped_total counter\nrdns_query_log_dropped_total {}",
        stats["query_log"]["dropped_entries"].as_u64().unwrap_or(0)
    );
    if let Some(groups) = features["groups"].as_array() {
        let _ = writeln!(out, "# TYPE rdns_upstream_requests_total counter");
        let _ = writeln!(out, "# TYPE rdns_upstream_failures_total counter");
        let _ = writeln!(out, "# TYPE rdns_upstream_cooldown_active gauge");
        for group in groups {
            let gname = group["name"].as_str().unwrap_or("");
            if let Some(servers) = group["servers"].as_array() {
                for srv in servers {
                    let url = srv["url"].as_str().unwrap_or("");
                    let req = srv["requests"].as_u64().unwrap_or(0);
                    let fail = srv["failures"].as_u64().unwrap_or(0);
                    let cool = u64::from(srv["cooldown_until"].as_u64().unwrap_or(0) > now);
                    let _ = writeln!(
                        out,
                        "rdns_upstream_requests_total{{group=\"{gname}\",url=\"{url}\"}} {req}"
                    );
                    let _ = writeln!(
                        out,
                        "rdns_upstream_failures_total{{group=\"{gname}\",url=\"{url}\"}} {fail}"
                    );
                    let _ = writeln!(
                        out,
                        "rdns_upstream_cooldown_active{{group=\"{gname}\",url=\"{url}\"}} {cool}"
                    );
                }
            }
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response())
}
async fn logs(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(json!(
        state.engine.store.logs().await.map_err(internal)?
    )))
}

async fn clients(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(json!(
        state
            .engine
            .store
            .client_networks()
            .await
            .map_err(internal)?
    )))
}

async fn listener_status(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(state.listeners.snapshot().await))
}

async fn cache_status(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(state.engine.cache_stats().await))
}

async fn feature_status(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(
        state
            .engine
            .features
            .snapshot(account.role == "admin")
            .await,
    ))
}

async fn update_features(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(settings): Json<FeatureSettings>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .features
        .apply(settings)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .engine
        .store
        .audit(
            &account.username,
            "features.update",
            "applied without restart",
        )
        .await
        .map_err(internal)?;
    // Broadcast only a change notification; each session obtains its authorized view.
    state.listeners.publish(json!({"type":"features.changed"}));
    Ok(Json(state.engine.features.snapshot(true).await))
}

#[derive(Deserialize)]
struct ProxyTestInput {
    address: String,
}

async fn test_proxy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ProxyTestInput>,
) -> ApiResult {
    require(&headers, &state.engine.store, "admin").await?;
    let address = input.address.trim();
    if address.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "请输入代理地址".into()));
    }
    let client = crate::upstream::http_client(&state.engine.config, address)
        .and_then(|builder| {
            Ok(builder
                .timeout(std::time::Duration::from_secs(12))
                .build()?)
        })
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "代理地址无效或客户端初始化失败".into(),
            )
        })?;
    let start = std::time::Instant::now();
    let response = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                if error.is_timeout() {
                    "代理测试超时"
                } else {
                    "代理测试失败，请检查地址、凭据和网络连接"
                }
                .into(),
            )
        })?;
    if !response.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("代理测试目标返回 HTTP {}", response.status().as_u16()),
        ));
    }
    Ok(Json(json!({"elapsed_ms":start.elapsed().as_millis()})))
}

#[derive(Deserialize)]
struct SourceUpload {
    name: Option<String>,
}

async fn upload_source(
    State(state): State<ApiState>,
    Path(source): Path<String>,
    Query(input): Query<SourceUpload>,
    request: Request,
) -> ApiResult {
    let (limit, role) = match source.as_str() {
        "adguard" => (20, "admin"),
        "gfwlist" => (10, "admin"),
        "geoip4" | "geoip6" => (80, "admin"),
        "custom" => (10, "editor"),
        _ => return Err((StatusCode::NOT_FOUND, "未知的订阅类型".into())),
    };
    let account = require(request.headers(), &state.engine.store, role).await?;
    let bytes = to_bytes(request.into_body(), limit * 1024 * 1024)
        .await
        .map_err(|error| {
            if error.to_string().contains("length limit") {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("上传文件不能超过 {limit} MiB"),
                )
            } else {
                (StatusCode::BAD_REQUEST, "无法读取上传文件".to_owned())
            }
        })?;
    if bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "上传文件为空".to_owned()));
    }
    if source == "custom" {
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 255
                    && !name.contains(['/', '\\'])
                    && !name.chars().any(char::is_control)
            })
            .ok_or((StatusCode::BAD_REQUEST, "请提供有效的文件名".into()))?;
        let domains = tokio::task::spawn_blocking(move || parse_subscription_domains(&bytes))
            .await
            .map_err(internal)?
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "文件中没有可用的自定义过滤规则".into(),
                )
            })?;
        let id = state
            .engine
            .store
            .save_uploaded_subscription(name, &domains)
            .await
            .map_err(internal)?;
        state.engine.reload_policy().await.map_err(internal)?;
        state
            .engine
            .store
            .audit(
                &account.username,
                "subscription.upload",
                &format!("id={id} domains={}", domains.len()),
            )
            .await
            .map_err(internal)?;
        return Ok(Json(json!({"id": id, "count": domains.len()})));
    }
    let features = &state.engine.features;
    let update = SourceUpdate::Upload(bytes);
    let result = match source.as_str() {
        "adguard" => features.refresh_ads(update).await,
        "gfwlist" => features.refresh_list(update).await,
        "geoip4" => features.refresh_geo(4, update).await,
        _ => features.refresh_geo(6, update).await,
    };
    result.map_err(|error| {
        tracing::warn!(%source, %error, "subscription upload failed");
        (
            StatusCode::BAD_REQUEST,
            "上传失败，请检查文件格式、IP 版本或订阅状态中的错误信息".into(),
        )
    })?;
    state
        .engine
        .store
        .audit(&account.username, "subscription.upload", &source)
        .await
        .map_err(internal)?;
    Ok(Json(features.snapshot(true).await))
}

async fn refresh_gfwlist(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .features
        .refresh_list(SourceUpdate::Download)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "GFWList 更新失败，已保留原有名单，请检查来源地址和下载代理".into(),
            )
        })?;
    state
        .engine
        .store
        .audit(&account.username, "gfwlist.refresh", "updated")
        .await
        .map_err(internal)?;
    state.listeners.publish(json!({"type":"features.changed"}));
    Ok(Json(state.engine.features.snapshot(true).await))
}

#[derive(Deserialize)]
struct GeoVersion {
    ip_version: u8,
}
async fn refresh_geoip(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<GeoVersion>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .features
        .refresh_geo(input.ip_version, SourceUpdate::Download)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "GeoIP 更新失败，可检查该数据库的错误信息后重试".into(),
            )
        })?;
    state
        .engine
        .store
        .audit(
            &account.username,
            "geoip.refresh",
            &format!("IPv{}", input.ip_version),
        )
        .await
        .map_err(internal)?;
    state.listeners.publish(json!({"type":"features.changed"}));
    Ok(Json(state.engine.features.snapshot(true).await))
}

#[derive(Deserialize)]
struct GeoLookup {
    ip: std::net::IpAddr,
}
async fn lookup_geoip(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<GeoLookup>,
) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    let current = state.engine.features.current.load_full();
    let location = current.geo.lookup(crate::access::canonical_ip(input.ip));
    let decision = current.access.decide(input.ip, &location);
    Ok(Json(
        json!({"ip":input.ip,"location":location,"allowed":decision.is_ok(),"reason":decision.err()}),
    ))
}

async fn update_cache_jobs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<crate::resolver::CacheJobInput>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .set_cache_jobs(input)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .engine
        .store
        .audit(&account.username, "cache.automation.update", "applied")
        .await
        .map_err(internal)?;
    let stats = state.engine.cache_stats().await;
    state
        .listeners
        .publish(json!({"type":"cache","stats":stats}));
    Ok(Json(stats))
}
async fn refresh_cache_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(kind): Path<String>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .refresh_cache_job(&kind)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .engine
        .store
        .audit(&account.username, "cache.automation.refresh", &kind)
        .await
        .map_err(internal)?;
    Ok(Json(json!({"queued":true})))
}
async fn refresh_ads(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .features
        .refresh_ads(SourceUpdate::Download)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "AdGuard 更新失败，请检查来源地址和规则格式".to_owned(),
            )
        })?;
    state
        .engine
        .store
        .audit(&account.username, "adguard.refresh", "updated")
        .await
        .map_err(internal)?;
    state.listeners.publish(json!({"type":"features.changed"}));
    Ok(Json(state.engine.features.snapshot(true).await))
}

async fn update_cache(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(settings): Json<CacheSettings>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .update_cache_settings(settings)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    state
        .engine
        .store
        .audit(&account.username, "cache.update", "applied without restart")
        .await
        .map_err(internal)?;
    let stats = state.engine.cache_stats().await;
    state
        .listeners
        .publish(json!({"type":"cache", "stats":stats}));
    Ok(Json(stats))
}

async fn update_listeners(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(settings): Json<ListenerSettings>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    match state.listeners.apply(state.clone(), settings, true).await {
        Ok(()) => {
            state
                .engine
                .store
                .audit(
                    &account.username,
                    "listeners.update",
                    "applied without restart",
                )
                .await
                .map_err(internal)?;
            Ok(Json(state.listeners.snapshot().await))
        }
        Err(error) => Err((StatusCode::CONFLICT, error.to_string())),
    }
}

async fn websocket(State(state): State<ApiState>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| websocket_session(state, socket))
}

async fn websocket_account(
    socket: &mut WebSocket,
    state: &ApiState,
    token: &str,
) -> Option<Account> {
    match authorize(token, &state.engine.store, "viewer").await {
        Ok(account) => Some(account),
        Err((status, _)) => {
            let code = if status == StatusCode::UNAUTHORIZED {
                1008
            } else {
                1011
            };
            let _ = socket
                .send(WsMessage::Close(Some(axum::extract::ws::CloseFrame {
                    code,
                    reason: "session unavailable".into(),
                })))
                .await;
            None
        }
    }
}

async fn websocket_session(state: ApiState, mut socket: WebSocket) {
    let auth = tokio::time::timeout(Duration::from_secs(5), socket.next()).await;
    let Some(Ok(WsMessage::Text(text))) = auth.ok().flatten() else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    if value["type"] != "auth" {
        return;
    }
    let Some(token) = value["token"].as_str() else {
        return;
    };
    let Some(account) = websocket_account(&mut socket, &state, token).await else {
        return;
    };
    let mut events = state.listeners.subscribe();
    if socket
        .send(WsMessage::Text(
            json!({"type":"ready","account":account}).to_string().into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    if socket
        .send(WsMessage::Text(
            state.listeners.snapshot().await.to_string().into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    if socket
        .send(WsMessage::Text(
            state
                .engine
                .features
                .snapshot(account.role == "admin")
                .await
                .to_string()
                .into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    let mut last_auth_check = tokio::time::Instant::now();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Ok(event) = event else { return; };
                let value: Value = serde_json::from_str(&event).unwrap_or_default();
                let check_now = value["type"] == "session.check"
                    || last_auth_check.elapsed() >= Duration::from_secs(60);
                if check_now {
                    if websocket_account(&mut socket, &state, token).await.is_none() {
                        return;
                    }
                    last_auth_check = tokio::time::Instant::now();
                }
                if value["type"] == "session.check" {
                    continue;
                }
                // Reconnecting delivers fresh snapshots if a slow subscriber missed an update.
                let event = if value["type"] == "features.changed" { state.engine.features.snapshot(account.role == "admin").await.to_string() } else { event };
                if socket.send(WsMessage::Text(event.into())).await.is_err() { return; }
            }
            message = socket.next() => {
                let Some(Ok(WsMessage::Text(text))) = message else { return; };
                let Ok(value) = serde_json::from_str::<Value>(&text) else { continue; };
                if !["listeners.update", "cache.update", "features.update", "gfwlist.refresh", "geoip.refresh"].iter().any(|kind| value["type"] == *kind) { continue; }
                let request_id = value["request_id"].clone();
                let Some(account) = websocket_account(&mut socket, &state, token).await else { return; };
                last_auth_check = tokio::time::Instant::now();
                let result = if account.role == "admin" {
                    if value["type"] == "listeners.update" {
                        match serde_json::from_value::<ListenerSettings>(value["settings"].clone()) {
                            Ok(settings) => state.listeners.apply(state.clone(), settings, true).await.map_err(|e| e.to_string()),
                            Err(error) => Err(error.to_string()),
                        }
                    } else if value["type"] == "cache.update" {
                        match serde_json::from_value::<CacheSettings>(value["settings"].clone()) {
                            Ok(settings) => state.engine.update_cache_settings(settings).await.map_err(|e| e.to_string()),
                            Err(error) => Err(error.to_string()),
                        }
                    } else if value["type"] == "features.update" {
                        match serde_json::from_value::<FeatureSettings>(value["settings"].clone()) {
                            Ok(settings) => state.engine.features.apply(settings).await.map_err(|e| e.to_string()),
                            Err(error) => Err(error.to_string()),
                        }
                    } else if value["type"] == "gfwlist.refresh" {
                        state.engine.features.refresh_list(SourceUpdate::Download).await.map(|_| ()).map_err(|_| "GFWList 更新失败，保留原有名单".to_string())
                    } else {
                        state.engine.features.refresh_geo(value["settings"]["ip_version"].as_u64().unwrap_or(0) as u8, SourceUpdate::Download).await.map_err(|_| "GeoIP 更新失败，保留原有数据库".to_string())
                    }
                } else { Err("administrator role required".to_string()) };
                if result.is_ok() {
                    let action = value["type"].as_str().unwrap_or("settings.update");
                    let _ = state.engine.store.audit(&account.username, action, "applied without restart").await;
                    if value["type"] == "cache.update" {
                        state.listeners.publish(json!({"type":"cache","stats":state.engine.cache_stats().await}));
                    }
                    if ["features.update", "gfwlist.refresh", "geoip.refresh"].iter().any(|kind| value["type"] == *kind) {
                        state.listeners.publish(json!({"type":"features.changed"}));
                    }
                }
                let reply = json!({"type":"result","request_id":request_id,"ok":result.is_ok(),"error":result.err()});
                if socket.send(WsMessage::Text(reply.to_string().into())).await.is_err() { return; }
            }
        }
    }
}

#[derive(Deserialize)]
struct ClientInput {
    cidrs: Vec<String>,
}
async fn update_clients(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ClientInput>,
) -> ApiResult {
    let actor = require(&headers, &state.engine.store, "admin").await?;
    if input.cidrs.is_empty() || input.cidrs.len() > 100 {
        return Err((StatusCode::BAD_REQUEST, "provide 1..100 CIDRs".into()));
    }
    let cidrs = input
        .cidrs
        .iter()
        .map(|item| item.parse::<ipnet::IpNet>().map(|net| net.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    state
        .engine
        .store
        .replace_client_networks(&cidrs)
        .await
        .map_err(internal)?;
    state.engine.reload_clients().await.map_err(internal)?;
    state
        .engine
        .store
        .audit(&actor.username, "clients.update", &cidrs.join(","))
        .await
        .map_err(internal)?;
    Ok(Json(json!({"cidrs":cidrs})))
}
async fn test_dns(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<crate::portal::lookup::Input>,
) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    crate::portal::lookup::run(&state, peer, &headers, input, None).await
}

async fn rules(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(json!(
        state.engine.store.rules().await.map_err(internal)?
    )))
}
async fn add_rule(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<RuleInput>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    let input = Engine::validate_rule(&input)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let id = state.engine.store.add_rule(&input).await.map_err(|error| {
        match error.as_database_error() {
            Some(db) if db.is_unique_violation() => {
                (StatusCode::CONFLICT, "rule already exists".into())
            }
            _ => internal(error),
        }
    })?;
    state.engine.reload_policy().await.map_err(internal)?;
    state
        .engine
        .store
        .audit(
            &account.username,
            "rule.add",
            &format!("{} {} id={id}", input.kind, input.domain),
        )
        .await
        .map_err(internal)?;
    Ok(Json(json!({"id":id})))
}
async fn delete_rule(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    state.engine.store.delete_rule(id).await.map_err(internal)?;
    state.engine.reload_policy().await.map_err(internal)?;
    state
        .engine
        .store
        .audit(&account.username, "rule.delete", &id.to_string())
        .await
        .map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
struct FilterImport {
    text: String,
}

async fn import_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<FilterImport>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    let rules = parse_imported_filters(&input.text)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let count = rules.len();
    state
        .engine
        .store
        .import_filter_rules(&rules)
        .await
        .map_err(internal)?;
    state.engine.reload_policy().await.map_err(internal)?;
    state
        .engine
        .store
        .audit(&account.username, "rule.import", &format!("count={count}"))
        .await
        .map_err(internal)?;
    Ok(Json(json!({"count":count})))
}

async fn subscriptions(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "viewer").await?;
    Ok(Json(json!(
        state.engine.store.subscriptions().await.map_err(internal)?
    )))
}
#[derive(Deserialize)]
struct UrlInput {
    url: String,
}
async fn add_subscription(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<UrlInput>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    if !input.url.starts_with("https://") {
        return Err((StatusCode::BAD_REQUEST, "HTTPS URL required".into()));
    }
    let id = state
        .engine
        .store
        .add_subscription(&input.url)
        .await
        .map_err(internal)?;
    state
        .engine
        .store
        .audit(
            &account.username,
            "subscription.add",
            &format!("id={id} url={}", input.url),
        )
        .await
        .map_err(internal)?;
    Ok(Json(json!({"id":id})))
}
async fn delete_subscription(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    state
        .engine
        .store
        .delete_subscription(id)
        .await
        .map_err(internal)?;
    state.engine.reload_policy().await.map_err(internal)?;
    state
        .engine
        .store
        .audit(&account.username, "subscription.delete", &id.to_string())
        .await
        .map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}
async fn refresh_subscription(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "editor").await?;
    let sub = state
        .engine
        .store
        .subscriptions()
        .await
        .map_err(internal)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or((StatusCode::NOT_FOUND, "subscription not found".into()))?;
    if sub.url.starts_with("upload:") {
        return Err((StatusCode::BAD_REQUEST, "请上传文件更新手动订阅".into()));
    }
    let count = match fetch_subscription(&state.engine, sub.id, &sub.url).await {
        Ok(count) => count,
        Err(error) => {
            state
                .engine
                .store
                .subscription_error(id, &error.to_string())
                .await
                .map_err(internal)?;
            return Err((StatusCode::BAD_GATEWAY, error.to_string()));
        }
    };
    state
        .engine
        .store
        .audit(
            &account.username,
            "subscription.refresh",
            &format!("id={id} domains={count}"),
        )
        .await
        .map_err(internal)?;
    Ok(Json(json!({"count":count})))
}

#[derive(Deserialize)]
struct AccountInput {
    username: String,
    password: String,
    role: String,
}
async fn add_account(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .store
        .create_account(&input.username, &input.password, &input.role)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    state
        .engine
        .store
        .audit(
            &account.username,
            "account.add",
            &format!("{} role={}", input.username, input.role),
        )
        .await
        .map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}

async fn accounts(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "admin").await?;
    Ok(Json(json!(
        state.engine.store.accounts().await.map_err(internal)?
    )))
}

async fn delete_account(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let actor = require(&headers, &state.engine.store, "admin").await?;
    state
        .engine
        .store
        .delete_account(id, actor.id)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    state
        .engine
        .store
        .audit(&actor.username, "account.delete", &id.to_string())
        .await
        .map_err(internal)?;
    Ok(Json(json!({"ok":true})))
}

async fn audit_events(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "admin").await?;
    Ok(Json(json!(
        state.engine.store.audit_events().await.map_err(internal)?
    )))
}

async fn reload_certificate(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    match state.tls.reload().await {
        Ok(()) => {
            state
                .listeners
                .refresh_doq_config(&state.tls)
                .await
                .map_err(internal)?;
            state
                .engine
                .store
                .audit(&account.username, "certificate.reload", "success")
                .await
                .map_err(internal)?;
            Ok(Json(json!({"ok":true})))
        }
        Err(error) => {
            state
                .engine
                .store
                .audit(
                    &account.username,
                    "certificate.reload",
                    &format!("failed: {error}"),
                )
                .await
                .map_err(internal)?;
            Err((StatusCode::BAD_REQUEST, error.to_string()))
        }
    }
}

async fn certificate_paths(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    require(&headers, &state.engine.store, "admin").await?;
    let (certificate, private_key) = state
        .tls
        .paths()
        .await
        .map(|(cert, key)| {
            (
                cert.to_string_lossy().into_owned(),
                key.to_string_lossy().into_owned(),
            )
        })
        .unwrap_or_else(|| (String::new(), String::new()));
    Ok(Json(
        json!({"certificate":certificate,"private_key":private_key}),
    ))
}

#[derive(Deserialize)]
struct CertificatePathsInput {
    certificate: String,
    private_key: String,
}

async fn update_certificate_paths(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CertificatePathsInput>,
) -> ApiResult {
    let account = require(&headers, &state.engine.store, "admin").await?;
    let certificate = std::path::PathBuf::from(input.certificate);
    let private_key = std::path::PathBuf::from(input.private_key);
    match state
        .tls
        .set_paths(
            &state.engine.store,
            certificate.clone(),
            private_key.clone(),
        )
        .await
    {
        Ok(()) => {
            state
                .listeners
                .refresh_doq_config(&state.tls)
                .await
                .map_err(internal)?;
            state
                .engine
                .store
                .audit(
                    &account.username,
                    "certificate.paths.update",
                    &format!(
                        "certificate={} private_key={}",
                        certificate.display(),
                        private_key.display()
                    ),
                )
                .await
                .map_err(internal)?;
            Ok(Json(
                json!({"certificate":certificate,"private_key":private_key}),
            ))
        }
        Err(error) => {
            state
                .engine
                .store
                .audit(
                    &account.username,
                    "certificate.paths.update",
                    &format!("failed: {error}"),
                )
                .await
                .map_err(internal)?;
            Err((StatusCode::BAD_REQUEST, error.to_string()))
        }
    }
}

pub async fn fetch_subscription(engine: &Engine, id: i64, url: &str) -> anyhow::Result<usize> {
    anyhow::ensure!(url.starts_with("https://"), "HTTPS URL required");
    let runtime = engine.features.current.load_full();
    let data = crate::upstream::download_with_timeout(
        &engine.config,
        url,
        runtime.settings.subscription_proxy(),
        10 * 1024 * 1024,
        Duration::from_secs(20),
    )
    .await?;
    let domains = tokio::task::spawn_blocking(move || parse_subscription_domains(&data)).await??;
    engine
        .store
        .replace_subscription_domains(id, &domains)
        .await?;
    engine.reload_policy().await?;
    Ok(domains.len())
}

fn parse_subscription_domains(data: &[u8]) -> anyhow::Result<Vec<String>> {
    let text = std::str::from_utf8(data)?.trim_start_matches('\u{feff}');
    let domains = parse_filter_list(text)?;
    anyhow::ensure!(
        !domains.is_empty(),
        "subscription contains no supported domains"
    );
    Ok(domains)
}

pub async fn refresh_all(engine: &Engine) {
    if let Ok(subscriptions) = engine.store.subscriptions().await {
        for sub in subscriptions
            .into_iter()
            .filter(|sub| !sub.url.starts_with("upload:"))
        {
            if let Err(error) = fetch_subscription(engine, sub.id, &sub.url).await {
                tracing::warn!(%error, url = %sub.url, "subscription refresh failed");
                let _ = engine
                    .store
                    .subscription_error(sub.id, &error.to_string())
                    .await;
            }
        }
    }
}
