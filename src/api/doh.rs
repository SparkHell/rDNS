use super::ApiState;
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Web;

pub fn doh_router(state: ApiState) -> Router {
    doh_queries(&state)
        .merge(portal_pages(crate::portal::EntryPoint {
            doh: true,
            tls: !state.engine.config.doh_http,
        }))
        .route(
            "/assets/{file}",
            get(|Path(file): Path<String>| async move { serve(&format!("assets/{file}")) }),
        )
        .with_state(state)
}

pub(super) fn doh_queries(state: &ApiState) -> Router<ApiState> {
    Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .route("/dns/{credential}", get(doh_get).post(doh_post))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::portal::identify_doh,
        ))
}

pub(super) fn portal_pages(entry: crate::portal::EntryPoint) -> Router<ApiState> {
    Router::new()
        .merge(crate::portal::routes())
        .route(
            "/",
            get(|| async { axum::response::Redirect::temporary("/portal") }),
        )
        .route("/portal", get(index))
        .route("/portal/", get(index))
        .layer(axum::Extension(entry))
}

#[derive(Deserialize)]
struct DohQuery {
    dns: String,
}

async fn doh_get(
    State(state): State<ApiState>,
    axum::Extension(user): axum::Extension<Option<i64>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(input): Query<DohQuery>,
) -> Response {
    let Ok(wire) = URL_SAFE_NO_PAD.decode(input.dns.as_bytes()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    doh_answer(state, peer, user, forwarded, &wire).await
}

async fn doh_post(
    State(state): State<ApiState>,
    axum::Extension(user): axum::Extension<Option<i64>>,
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
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    doh_answer(state, peer, user, forwarded, &body).await
}

async fn doh_answer(
    state: ApiState,
    peer: SocketAddr,
    user: Option<i64>,
    forwarded: Option<&str>,
    wire: &[u8],
) -> Response {
    if wire.len() > 65535 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let peer = doh_client(&state, peer, forwarded);
    match state.engine.answer_for(wire, peer, "doh", user).await {
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

pub(crate) fn doh_client(
    state: &ApiState,
    peer: SocketAddr,
    forwarded: Option<&str>,
) -> SocketAddr {
    let ip = state
        .engine
        .features
        .current
        .load()
        .access
        .client_ip(peer.ip(), forwarded);
    SocketAddr::new(ip, peer.port())
}

pub(super) async fn index() -> Response {
    serve("index.html")
}

pub(super) async fn asset(Path(path): Path<String>) -> Response {
    serve(&path)
}

fn serve(path: &str) -> Response {
    if path.contains("..") || path.starts_with('/') {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if Web::get(path).is_some() {
        path
    } else if path.contains('.')
        || path.starts_with("api/")
        || path.starts_with("portal/")
        || path.starts_with("dns/")
        || path.starts_with("dns-")
    {
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
    } else if path.ends_with(".list") {
        "text/plain; charset=utf-8"
    } else {
        "text/html"
    };
    let cache_control = if path.starts_with("assets/") || path.starts_with("fonts/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    (
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, cache_control),
        ],
        asset.data.to_vec(),
    )
        .into_response()
}
