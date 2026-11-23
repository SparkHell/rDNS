use super::*;
use axum::{extract::Query, response::Redirect};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl,
    core::{CoreClient, CoreProviderMetadata},
};
use reqwest::{Client, Url};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub(super) struct Provider {
    pub id: String,
    pub label: String,
    kind: String,
    issuer: String,
    authorization: String,
    token: String,
    profile: String,
    client_id: String,
    pub secret: String,
    scope: String,
    user_id: String,
    auth_method: String,
}
pub(super) fn https(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| bad("无效的 HTTPS 地址"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(bad("端点必须使用 HTTPS"));
    }
    Ok(url)
}
impl Provider {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.label.trim().is_empty()
            || self.client_id.is_empty()
        {
            return Err(bad("提供方 ID、显示名称和客户端 ID 必填"));
        }
        match self.kind.as_str() {
            "oidc" => {
                https(&self.issuer)?;
            }
            "oauth" => {
                for url in [&self.authorization, &self.token, &self.profile] {
                    https(url)?;
                }
                if self.user_id.is_empty() {
                    return Err(bad("需要稳定用户 ID 字段"));
                }
            }
            _ => return Err(bad("不支持的提供方类型")),
        }
        if !matches!(self.auth_method.as_str(), "" | "basic" | "body") {
            return Err(bad("客户端认证方式无效"));
        }
        Ok(())
    }
    pub fn same_endpoints(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.issuer == other.issuer
            && self.authorization == other.authorization
            && self.token == other.token
            && self.profile == other.profile
            && self.client_id == other.client_id
    }
    fn revision(&self, base: &str) -> String {
        digest(&serde_json::to_string(&(base, self)).expect("provider serializes"))
    }
    fn identity(&self, sub: &str) -> String {
        let (namespace, field) = if self.kind == "oidc" {
            (self.issuer.as_str(), "sub")
        } else {
            (self.profile.as_str(), self.user_id.as_str())
        };
        serde_json::to_string(&(&self.id, &self.kind, namespace, field, sub))
            .expect("strings serialize")
    }
}
fn upstream(_: impl std::fmt::Display) -> Error {
    (StatusCode::BAD_GATEWAY, "身份提供方认证失败".into())
}
fn client() -> Result<Client> {
    static HTTP: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
    if let Some(client) = HTTP.get() {
        return Ok(client.clone());
    }
    let mut builder = Client::builder()
        .https_only(true)
        .user_agent("rDns portal")
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(12));
    for cert in rustls_native_certs::load_native_certs().certs {
        builder = builder
            .add_root_certificate(reqwest::Certificate::from_der(cert.as_ref()).map_err(internal)?);
    }
    let client = builder.build().map_err(internal)?;
    Ok(HTTP.get_or_init(|| client).clone())
}
async fn discover(p: &Provider, http: &Client) -> Result<CoreProviderMetadata> {
    let meta = CoreProviderMetadata::discover_async(
        IssuerUrl::new(p.issuer.clone()).map_err(upstream)?,
        http,
    )
    .await
    .map_err(upstream)?;
    https(meta.authorization_endpoint().as_str())?;
    https(
        meta.token_endpoint()
            .ok_or_else(|| bad("缺少令牌端点"))?
            .as_str(),
    )?;
    Ok(meta)
}
const BROWSER: &str = "__Host-rdns-flow";
pub(super) async fn start(State(s): State<ApiState>, Path(id): Path<String>) -> Result<Response> {
    let cfg = load(&s.engine.store.pool).await?;
    let p = cfg
        .providers
        .iter()
        .find(|p| p.id == id)
        .ok_or((StatusCode::NOT_FOUND, "未知提供方".into()))?;
    let mut url = if p.kind == "oidc" {
        https(
            discover(p, &client()?)
                .await?
                .authorization_endpoint()
                .as_str(),
        )?
    } else {
        https(&p.authorization)?
    };
    let state = random(48);
    let browser = random(48);
    let verifier = random(64);
    let nonce = random(48);
    let redirect = format!("{}/portal/callback/{}", cfg.base, p.id);
    let mut scopes = p.scope.split_whitespace().collect::<Vec<_>>();
    if p.kind == "oidc" && !scopes.contains(&"openid") {
        scopes.push("openid");
    }
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &p.client_id)
            .append_pair("redirect_uri", &redirect)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge_method", "S256")
            .append_pair(
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            );
        if p.kind == "oidc" {
            query.append_pair("nonce", &nonce);
        }
    }
    sqlx::query("INSERT INTO portal_flows VALUES(?,?,?,?,?,?,unixepoch()+600)")
        .bind(digest(&state))
        .bind(digest(&browser))
        .bind(id)
        .bind(p.revision(&cfg.base))
        .bind(verifier)
        .bind(nonce)
        .execute(&s.engine.store.pool)
        .await
        .map_err(internal)?;
    Ok((
        [(
            header::SET_COOKIE,
            format!("{BROWSER}={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
        )],
        Redirect::to(url.as_str()),
    )
        .into_response())
}
#[derive(Deserialize)]
pub(super) struct Callback {
    state: String,
    code: String,
}
pub(super) async fn callback(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(provider): Path<String>,
    Query(q): Query<Callback>,
) -> Result<Response> {
    let browser = cookie(&h, BROWSER).ok_or_else(denied)?;
    let pool = &s.engine.store.pool;
    let flow = sqlx::query(
        "DELETE FROM portal_flows WHERE state=? AND browser=? AND provider=? AND expires>unixepoch() RETURNING *",
    )
    .bind(digest(&q.state))
    .bind(digest(browser))
    .bind(provider)
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .ok_or_else(denied)?;
    let cfg = load(pool).await?;
    let p = cfg
        .providers
        .iter()
        .find(|p| {
            p.id == flow.get::<String, _>("provider")
                && p.revision(&cfg.base) == flow.get::<String, _>("revision")
        })
        .ok_or_else(denied)?;
    let redirect = format!("{}/portal/callback/{}", cfg.base, p.id);
    let http = client()?;
    let verifier: String = flow.get("verifier");
    let (sub, name) = if p.kind == "oidc" {
        let meta = discover(p, &http).await?;
        let client = CoreClient::from_provider_metadata(
            meta,
            ClientId::new(p.client_id.clone()),
            (!p.secret.is_empty()).then(|| ClientSecret::new(p.secret.clone())),
        )
        .set_auth_type(if p.auth_method == "body" {
            openidconnect::AuthType::RequestBody
        } else {
            openidconnect::AuthType::BasicAuth
        })
        .set_redirect_uri(RedirectUrl::new(redirect).map_err(upstream)?);
        let tokens = client
            .exchange_code(AuthorizationCode::new(q.code))
            .map_err(upstream)?
            .set_pkce_verifier(PkceCodeVerifier::new(verifier))
            .request_async(&http)
            .await
            .map_err(upstream)?;
        let claims = tokens
            .extra_fields()
            .id_token()
            .ok_or_else(denied)?
            .claims(&client.id_token_verifier(), &Nonce::new(flow.get("nonce")))
            .map_err(upstream)?;
        if claims
            .authorized_party()
            .is_some_and(|azp| azp.as_str() != p.client_id)
            || (claims.audiences().len() > 1 && claims.authorized_party().is_none())
        {
            return Err(denied());
        }
        let sub = claims.subject().as_str().to_owned();
        (
            sub.clone(),
            claims
                .preferred_username()
                .map(|n| n.as_str().to_owned())
                .unwrap_or(sub),
        )
    } else {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", q.code.as_str()),
            ("redirect_uri", &redirect),
            ("code_verifier", &verifier),
        ];
        let mut request = http.post(&p.token).header("Accept", "application/json");
        if p.auth_method == "body" || p.secret.is_empty() {
            form.push(("client_id", &p.client_id));
            if !p.secret.is_empty() {
                form.push(("client_secret", &p.secret));
            }
        } else {
            request = request.basic_auth(&p.client_id, Some(&p.secret));
        }
        let token: Value = request
            .form(&form)
            .send()
            .await
            .map_err(upstream)?
            .error_for_status()
            .map_err(upstream)?
            .json()
            .await
            .map_err(upstream)?;
        let profile: Value = http
            .get(&p.profile)
            .bearer_auth(token["access_token"].as_str().ok_or_else(denied)?)
            .send()
            .await
            .map_err(upstream)?
            .error_for_status()
            .map_err(upstream)?
            .json()
            .await
            .map_err(upstream)?;
        let field = if p.user_id.starts_with('/') {
            profile.pointer(&p.user_id)
        } else {
            profile.get(&p.user_id)
        };
        let sub = match field {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => return Err(denied()),
        };
        (
            sub.clone(),
            profile["login"]
                .as_str()
                .or(profile["name"].as_str())
                .unwrap_or(&sub)
                .into(),
        )
    };
    if sub.is_empty() || sub.len() > 512 {
        return Err(denied());
    }
    let identity = p.identity(&sub);
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(internal)?;
    let current = sqlx::query("SELECT providers,base FROM portal_settings WHERE id=1")
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
    let providers: Vec<Provider> =
        serde_json::from_str(current.get("providers")).map_err(internal)?;
    if !providers
        .iter()
        .any(|v| v.revision(current.get("base")) == flow.get::<String, _>("revision"))
    {
        return Err(denied());
    }
    let existing = sqlx::query_scalar("SELECT id FROM portal_users WHERE identity=?")
        .bind(&identity)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
    let id = match existing {
        Some(id) => id,
        None => {
            create(
                &mut tx,
                &name.chars().take(128).collect::<String>(),
                None,
                Some(&identity),
            )
            .await?
        }
    };
    let cookie = session(&mut tx, id).await?;
    tx.commit().await.map_err(internal)?;
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/portal")).into_response())
}
