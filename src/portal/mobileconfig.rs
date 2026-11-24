use super::*;
use axum::http::Uri;
use uuid::Uuid;

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
    let mut base: String = row.get("base");
    if base.is_empty() {
        let host = uri
            .authority()
            .map(|v| v.as_str())
            .or_else(|| h.get(header::HOST)?.to_str().ok())
            .ok_or_else(|| bad("缺少门户主机地址"))?;
        let authority = host
            .parse::<axum::http::uri::Authority>()
            .map_err(|_| bad("无效的门户主机地址"))?;
        base = format!("https://{authority}");
    }
    let origin = federation::https(&base)?.origin().ascii_serialization();
    let profile_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{origin}/portal/users/{id}").as_bytes(),
    );
    let payload_id = Uuid::new_v5(&profile_id, b"dns");
    let credential: String = row.get("credential");
    let server = format!("{origin}/dns-{credential}")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let xml = format!(
        include_str!("dns.mobileconfig"),
        profile_id = profile_id,
        payload_id = payload_id,
        server = server
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-apple-aspen-config"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"rdns.mobileconfig\"",
            ),
        ],
        xml,
    )
        .into_response())
}
