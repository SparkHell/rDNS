use crate::{
    resolver::{Engine, parse_filter_list},
    store::{Account, RuleInput, Store},
    tls::TlsState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Engine>,
    pub tls: Arc<TlsState>,
}
type ApiResult = Result<Json<Value>, (StatusCode, String)>;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Web;

pub fn admin_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/clients", get(clients).put(update_clients))
        .route("/api/v1/rules", get(rules).post(add_rule))
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
        .route("/api/v1/certificates/reload", post(reload_certificate))
        .route("/", get(index))
        .route("/{*path}", get(asset))
        .with_state(state)
}

pub fn doh_router(state: ApiState) -> Router {
    Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .with_state(state)
}

fn unauthorized() -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, "authentication required".into())
}
fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(%error, "API failure");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
async fn require(
    headers: &HeaderMap,
    store: &Store,
    role: &str,
) -> Result<Account, (StatusCode, String)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let account = store
        .account_for_token(token)
        .await
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    let allowed = match role {
        "viewer" => true,
        "editor" => account.role != "viewer",
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
    let token = state
        .engine
        .store
        .login(&input.username, &input.password)
        .await
        .map_err(internal)?;
    match token {
        Some(token) => {
            state
                .engine
                .store
                .audit(&input.username, "login", "session created")
                .await
                .map_err(internal)?;
            Ok(Json(json!({"token":token})))
        }
        None => {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Err(unauthorized())
        }
    }
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
    let id = state
        .engine
        .store
        .add_rule(&input)
        .await
        .map_err(internal)?;
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

#[derive(Deserialize)]
struct DohQuery {
    dns: String,
}
async fn doh_get(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(input): Query<DohQuery>,
) -> Response {
    let Ok(wire) = URL_SAFE_NO_PAD.decode(input.dns.as_bytes()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    doh_answer(state, peer, &wire).await
}
async fn doh_post(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/dns-message")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    doh_answer(state, peer, &body).await
}
async fn doh_answer(state: ApiState, peer: SocketAddr, wire: &[u8]) -> Response {
    if wire.len() > 65535 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.engine.answer(wire, peer, "doh").await {
        Ok(answer) => (
            [
                (header::CONTENT_TYPE, "application/dns-message"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            answer,
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn index() -> Response {
    serve("index.html")
}
async fn asset(Path(path): Path<String>) -> Response {
    serve(&path)
}
fn serve(path: &str) -> Response {
    if path.contains("..") || path.starts_with('/') {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if Web::get(path).is_some() {
        path
    } else if path.contains('.') {
        return StatusCode::NOT_FOUND.into_response();
    } else {
        "index.html"
    };
    let Some(asset) = Web::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = if path.ends_with(".js") {
        "text/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "text/html"
    };
    (
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "no-store"),
        ],
        asset.data.to_vec(),
    )
        .into_response()
}

pub async fn fetch_subscription(engine: &Engine, id: i64, url: &str) -> anyhow::Result<usize> {
    anyhow::ensure!(url.starts_with("https://"), "HTTPS URL required");
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20));
    if let Some(path) = &engine.config.subscription_ca {
        let pem = tokio::fs::read(path).await?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
    }
    let client = builder.build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            data.len() + chunk.len() <= 10 * 1024 * 1024,
            "subscription exceeds 10 MiB"
        );
        data.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&data)?;
    let domains = parse_filter_list(text)?;
    anyhow::ensure!(
        !domains.is_empty(),
        "subscription contains no supported domains"
    );
    engine
        .store
        .replace_subscription_domains(id, &domains)
        .await?;
    engine.reload_policy().await?;
    Ok(domains.len())
}

pub async fn refresh_all(engine: &Engine) {
    if let Ok(subscriptions) = engine.store.subscriptions().await {
        for sub in subscriptions {
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
