use super::*;
use axum::http::Uri;
use uuid::Uuid;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qrcode::{QrCode, render::svg};

const TICKET_SECONDS: i64 = 300;

pub(super) async fn download(
    State(s): State<ApiState>,
    h: HeaderMap,
    uri: Uri,
) -> Result<Response> {
    let id = authenticate(&s, &h).await?;
    let row = sqlx::query("SELECT credential,base FROM portal_users,portal_settings WHERE portal_users.id=? AND status='active' AND credential IS NOT NULL")
        .bind(id)
        .fetch_optional(&s.engine.store.pool)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::FORBIDDEN, "账号尚未开通专属 DoH 地址".into()))?;
    let origin = profile_origin(row.get("base"), &h, &uri)?;
    Ok(profile(id, row.get("credential"), &origin))
}

fn profile_origin(base: String, h: &HeaderMap, uri: &Uri) -> Result<String> {
    let base = if base.is_empty() {
        let host = uri
            .authority()
            .map(|v| v.as_str())
            .or_else(|| h.get(header::HOST)?.to_str().ok())
            .ok_or_else(|| bad("缺少门户主机地址"))?;
        let authority = host
            .parse::<axum::http::uri::Authority>()
            .map_err(|_| bad("无效的门户主机地址"))?;
        format!("https://{authority}")
    } else {
        base
    };
    Ok(federation::https(&base)?.origin().ascii_serialization())
}

pub(super) async fn create_qr(State(s): State<ApiState>, h: HeaderMap, uri: Uri) -> Reply {
    let id = authenticate(&s, &h).await?;
    let pool = &s.engine.store.pool;
    let base: String = sqlx::query_scalar("SELECT base FROM portal_settings WHERE id=1")
        .fetch_one(pool)
        .await
        .map_err(internal)?;
    let origin = profile_origin(base, &h, &uri)?;
    let ticket = random(48);
    let portal = profile_origin(String::new(), &h, &uri)?;
    let url = format!("{portal}/portal/install/{ticket}/rdns.mobileconfig");
    let image = QrCode::new(&url)
        .map_err(|_| bad("门户地址过长，无法生成二维码"))?
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .build();
    let expires: Option<i64> = sqlx::query_scalar(
        "INSERT INTO portal_profile_tickets(user_id,hash,origin,expires)
         SELECT id,?,?,unixepoch()+? FROM portal_users
         WHERE id=? AND status='active' AND credential IS NOT NULL
         ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash,origin=excluded.origin,expires=excluded.expires
         RETURNING expires"
    ).bind(digest(&ticket)).bind(&origin).bind(TICKET_SECONDS).bind(id)
        .fetch_optional(pool).await.map_err(internal)?;
    if expires.is_none() {
        return Err((StatusCode::FORBIDDEN, "账号尚未开通专属 DoH 地址".into()));
    }
    Ok(Json(
        json!({"url":url,"expires_in":TICKET_SECONDS,"image":format!("data:image/svg+xml;base64,{}",STANDARD.encode(image))}),
    ))
}

pub(super) async fn download_qr(
    State(s): State<ApiState>,
    Path(ticket): Path<String>,
) -> Result<Response> {
    let unavailable = || {
        (
            StatusCode::NOT_FOUND,
            "二维码已失效，请返回 rDns 门户重新生成。".into(),
        )
    };
    if ticket.len() != 48 || !ticket.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(unavailable());
    }
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let (id, origin): (i64,String) = sqlx::query_as("DELETE FROM portal_profile_tickets WHERE hash=? AND expires>unixepoch() RETURNING user_id,origin")
        .bind(digest(&ticket)).fetch_optional(&mut *tx).await.map_err(internal)?.ok_or_else(unavailable)?;
    let credential: String = sqlx::query_scalar("SELECT credential FROM portal_users WHERE id=? AND status='active' AND credential IS NOT NULL")
        .bind(id).fetch_optional(&mut *tx).await.map_err(internal)?.ok_or_else(unavailable)?;
    tx.commit().await.map_err(internal)?;
    Ok(profile(id, &credential, &origin))
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
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"rdns.mobileconfig\"",
            ),
        ],
        xml,
    )
        .into_response()
}
