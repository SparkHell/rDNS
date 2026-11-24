use super::*;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};

#[derive(Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub(super) struct Config {
    pub enabled: bool,
    host: String,
    port: u16,
    starttls: bool,
    username: String,
    pub password: String,
    sender: String,
    domains: String,
}

pub(super) async fn config<'e>(db: impl sqlx::Executor<'e, Database = Sqlite>) -> Result<Config> {
    let raw: String = sqlx::query_scalar("SELECT config FROM portal_mail WHERE id=1")
        .fetch_one(db)
        .await
        .map_err(internal)?;
    serde_json::from_str(&raw).map_err(internal)
}

fn domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl Config {
    fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
    }

    fn address(&self, input: &str) -> Result<String> {
        let address = input.trim();
        if !self.enabled
            || address.len() > 254
            || !address.is_ascii()
            || address.parse::<lettre::Address>().is_err()
            || !address
                .split_once('@')
                .is_some_and(|(_, d)| self.domains().any(|v| d.eq_ignore_ascii_case(v)))
        {
            return Err((StatusCode::FORBIDDEN, "此邮箱无法使用邮箱登录".into()));
        }
        let (local, domain) = address.split_once('@').ok_or_else(denied)?;
        Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
    }
}

pub(super) async fn save(tx: &mut Transaction<'_, Sqlite>, mut cfg: Config) -> Result<()> {
    let old = config(&mut **tx).await?;
    if cfg.password.is_empty()
        && (
            cfg.host.as_str(),
            cfg.port,
            cfg.starttls,
            cfg.username.as_str(),
        ) == (
            old.host.as_str(),
            old.port,
            old.starttls,
            old.username.as_str(),
        )
    {
        cfg.password.clone_from(&old.password);
    }
    if cfg.enabled
        && (!domain(&cfg.host)
            || cfg.port == 0
            || cfg.sender.parse::<lettre::Address>().is_err()
            || cfg.domains().next().is_none()
            || !cfg.domains().all(domain)
            || cfg.username.is_empty() != cfg.password.is_empty())
    {
        return Err(bad(
            "请检查 SMTP 主机、端口、凭据、发件地址和允许的邮箱域名",
        ));
    }
    if cfg != old {
        sqlx::query("UPDATE portal_mail SET config=? WHERE id=1")
            .bind(serde_json::to_string(&cfg).map_err(internal)?)
            .execute(&mut **tx)
            .await
            .map_err(internal)?;
        sqlx::query("DELETE FROM portal_codes")
            .execute(&mut **tx)
            .await
            .map_err(internal)?;
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct Input {
    email: String,
    #[serde(default)]
    code: String,
}

pub(super) async fn send(State(s): State<ApiState>, Json(input): Json<Input>) -> Reply {
    let pool = &s.engine.store.pool;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(internal)?;
    let cfg = config(&mut *tx).await?;
    let address = cfg.address(&input.email)?;
    sqlx::query("DELETE FROM portal_codes WHERE sent <= unixepoch()-600")
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let limited: bool = sqlx::query_scalar("SELECT count(*) >= 100 OR count(*) FILTER (WHERE address=?) > 0 FROM portal_codes WHERE sent > unixepoch()-60")
        .bind(&address).fetch_one(&mut *tx).await.map_err(internal)?;
    if limited {
        return Err((StatusCode::TOO_MANY_REQUESTS, "请稍后再获取验证码".into()));
    }
    let code = format!("{:08}", OsRng.gen_range(0..100_000_000u32));
    let hash = digest(&format!("{address}:{code}"));
    sqlx::query("INSERT OR REPLACE INTO portal_codes VALUES(?,?,unixepoch(),0)")
        .bind(&address)
        .bind(&hash)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let message = Message::builder()
        .from(cfg.sender.parse().map_err(internal)?)
        .to(address.parse().map_err(internal)?)
        .subject("rDns 登录验证码")
        .body(format!("您的验证码为 {code}，10 分钟内有效。"))
        .map_err(internal)?;
    let builder = if cfg.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
    };
    let mut builder = builder
        .map_err(internal)?
        .port(cfg.port)
        .timeout(Some(std::time::Duration::from_secs(15)));
    if !cfg.username.is_empty() {
        builder = builder.credentials(Credentials::new(cfg.username, cfg.password));
    }
    if builder.build().send(message).await.is_err() {
        sqlx::query("UPDATE portal_codes SET attempts=5 WHERE address=? AND hash=?")
            .bind(address)
            .bind(hash)
            .execute(pool)
            .await
            .map_err(internal)?;
        return Err((
            StatusCode::BAD_GATEWAY,
            "验证码发送失败，请联系管理员检查 SMTP 设置".into(),
        ));
    }
    Ok(Json(json!({"ok":true})))
}

pub(super) async fn login(State(s): State<ApiState>, Json(input): Json<Input>) -> Result<Response> {
    let mut tx = s
        .engine
        .store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(internal)?;
    let address = config(&mut *tx).await?.address(&input.email)?;
    let hash: Option<String> = sqlx::query_scalar("UPDATE portal_codes SET attempts=attempts+1 WHERE address=? AND attempts<5 AND sent>unixepoch()-600 RETURNING hash")
        .bind(&address).fetch_optional(&mut *tx).await.map_err(internal)?;
    if hash != Some(digest(&format!("{}:{}", address, input.code))) {
        tx.commit().await.map_err(internal)?;
        return Err((StatusCode::UNAUTHORIZED, "验证码错误或已过期".into()));
    }
    sqlx::query("UPDATE portal_codes SET attempts=5 WHERE address=?")
        .bind(&address)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let identity = format!("email:{address}");
    let id = match sqlx::query_scalar("SELECT id FROM portal_users WHERE identity=?")
        .bind(&identity)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
    {
        Some(id) => id,
        None => create(&mut tx, &address, None, Some(&identity)).await?,
    };
    let cookie = session(&mut tx, id).await?;
    tx.commit().await.map_err(internal)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok":true}))).into_response())
}
