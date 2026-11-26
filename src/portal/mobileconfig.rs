use super::*;
use uuid::Uuid;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qrcode::{QrCode, render::svg};

pub(super) async fn download(
    State(s): State<ApiState>,
    Extension(entry): Extension<EntryPoint>,
    h: HeaderMap,
    uri: Uri,
) -> Result<Response> {
    let id = authenticate(&s, &h).await?;
    download_personal(&s, id, entry, &h, &uri).await
}

pub(super) async fn download_credential(
    s: &ApiState,
    credential: &str,
    h: &HeaderMap,
    uri: &Uri,
) -> Result<Response> {
    let (id, base): (i64, String) = sqlx::query_as(
        "SELECT portal_users.id,base FROM portal_users,portal_settings WHERE credential=? AND status='active'",
    )
    .bind(credential)
    .fetch_optional(&s.engine.store.pool)
    .await
    .map_err(internal)?
    .ok_or((StatusCode::NOT_FOUND, "专属地址已失效".into()))?;
    let origin = profile_origin(&base, h, uri)?;
    Ok(profile(id, credential, &origin))
}

async fn download_personal(
    s: &ApiState,
    id: i64,
    entry: EntryPoint,
    h: &HeaderMap,
    uri: &Uri,
) -> Result<Response> {
    let row = sqlx::query("SELECT credential,base FROM portal_users,portal_settings WHERE portal_users.id=? AND status='active' AND credential IS NOT NULL")
        .bind(id)
        .fetch_optional(&s.engine.store.pool)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::FORBIDDEN, "账号尚未开通专属 DoH 地址".into()))?;
    let origin = resolver_origin(row.get("base"), entry, h, uri)?.ok_or_else(no_https_doh)?;
    Ok(profile(id, row.get("credential"), &origin))
}

fn profile_origin(base: &str, h: &HeaderMap, uri: &Uri) -> Result<String> {
    let base = if base.is_empty() {
        let host = uri
            .authority()
            .map(|v| v.as_str())
            .or_else(|| h.get(header::HOST)?.to_str().ok())
            .ok_or_else(|| bad("缺少门户主机地址"))?;
        let authority = host
            .parse::<axum::http::uri::Authority>()
            .map_err(|_| bad("无效的门户主机地址"))?;
        return Ok(federation::https(&format!("https://{authority}"))?
            .origin()
            .ascii_serialization());
    } else {
        base
    };
    Ok(federation::https(base)?.origin().ascii_serialization())
}

pub(super) fn resolver_origin(
    base: &str,
    entry: EntryPoint,
    h: &HeaderMap,
    uri: &Uri,
) -> Result<Option<String>> {
    let https = entry.tls
        || uri.scheme_str() == Some("https")
        || h.get("x-forwarded-proto")
            .is_some_and(|scheme| scheme == "https");
    if base.is_empty() && !(entry.doh && https) {
        return Ok(None);
    }
    profile_origin(base, h, uri).map(Some)
}

fn no_https_doh() -> Error {
    (
        StatusCode::CONFLICT,
        "当前门户没有 HTTPS DoH 入口。请从 HTTPS DoH 地址打开门户，或由管理员配置公开地址。".into(),
    )
}

pub(super) async fn create_qr(
    State(s): State<ApiState>,
    Extension(entry): Extension<EntryPoint>,
    h: HeaderMap,
    uri: Uri,
) -> Reply {
    check_same_origin(&h)?;
    let id = authenticate(&s, &h).await?;
    let (credential, base): (String, String) = sqlx::query_as(
        "SELECT credential,base FROM portal_users,portal_settings WHERE portal_users.id=? AND status='active' AND credential IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&s.engine.store.pool)
    .await
    .map_err(internal)?
    .ok_or((StatusCode::FORBIDDEN, "账号尚未开通专属 DoH 地址".into()))?;
    let origin = resolver_origin(&base, entry, &h, &uri)?.ok_or_else(no_https_doh)?;
    let url = format!("{origin}/dns/{credential}?mobileconfig=1");
    let image = QrCode::new(&url)
        .map_err(|_| bad("门户地址过长，无法生成二维码"))?
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .build();
    Ok(Json(json!({
        "url": url,
        "image": format!("data:image/svg+xml;base64,{}", STANDARD.encode(image)),
    })))
}

fn profile(id: i64, credential: &str, origin: &str) -> Response {
    let profile_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{origin}/portal/users/{id}").as_bytes(),
    );
    let payload_id = Uuid::new_v5(&profile_id, b"dns");
    let server = format!("{origin}/dns/{credential}")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let xml = format!(
        include_str!("dns.mobileconfig"),
        profile_id = profile_id,
        payload_id = payload_id,
        server = server
    );
    (
        [
            (header::CONTENT_TYPE, "application/x-apple-aspen-config"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"rdns.mobileconfig\"",
            ),
        ],
        xml,
    )
        .into_response()
}
