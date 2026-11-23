use crate::{cache::CacheSettings, runtime::ListenerSettings};
use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone)]
pub struct Store {
    pub pool: SqlitePool,
    pub query_log: crate::query_log::QueryLog,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    pub id: i64,
    pub kind: String,
    pub domain: String,
    pub record_type: Option<String>,
    pub value: Option<String>,
    pub ttl: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleInput {
    pub kind: String,
    pub domain: String,
    pub record_type: Option<String>,
    pub value: Option<String>,
    pub ttl: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Subscription {
    pub id: i64,
    pub url: String,
    pub last_error: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub role: String,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        for ddl in [
            "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, domain TEXT NOT NULL, record_type TEXT, value TEXT, ttl INTEGER, UNIQUE(kind,domain,record_type,value))",
            "CREATE TABLE IF NOT EXISTS subscriptions (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, last_error TEXT, updated_at TEXT)",
            "CREATE TABLE IF NOT EXISTS subscription_domains (subscription_id INTEGER NOT NULL, domain TEXT NOT NULL, PRIMARY KEY(subscription_id,domain), FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, role TEXT NOT NULL, password_hash TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL, expires_at TEXT NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS query_log (id INTEGER PRIMARY KEY, at TEXT NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL, qtype TEXT NOT NULL, outcome TEXT NOT NULL, protocol TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS client_networks (cidr TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS certificate_paths (id INTEGER PRIMARY KEY CHECK(id=1), certificate TEXT NOT NULL, private_key TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS listener_settings (id INTEGER PRIMARY KEY CHECK(id=1), settings TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS cache_settings (id INTEGER PRIMARY KEY CHECK(id=1), settings TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS runtime_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS cache_entries (cache_key TEXT PRIMARY KEY, response BLOB NOT NULL, inserted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, kind TEXT NOT NULL, byte_size INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_cache_entries_expiry ON cache_entries(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_query_log_at ON query_log(at DESC)",
        ] {
            sqlx::query(ddl).execute(&pool).await?;
        }
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let migrated: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name='idx_rules_forward_target')")
            .fetch_one(&mut *tx).await?;
        if !migrated {
            sqlx::query("DELETE FROM rules WHERE kind IN ('allow','block','forward') AND id NOT IN (SELECT MIN(id) FROM rules WHERE kind IN ('allow','block','forward') GROUP BY kind,domain,CASE WHEN kind='forward' THEN value END)")
                .execute(&mut *tx).await?;
            sqlx::query("CREATE UNIQUE INDEX idx_rules_filter ON rules(kind,domain) WHERE kind IN ('allow','block')")
                .execute(&mut *tx).await?;
            sqlx::query("CREATE UNIQUE INDEX idx_rules_forward_target ON rules(domain,value) WHERE kind='forward'")
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let columns = sqlx::query("PRAGMA table_info(query_log)")
            .fetch_all(&pool)
            .await?;
        if !columns
            .iter()
            .any(|column| column.get::<String, _>("name") == "duration_ms")
        {
            sqlx::query("ALTER TABLE query_log ADD COLUMN duration_ms REAL")
                .execute(&pool)
                .await?;
        }
        for name in ["country", "province", "city", "upstream"] {
            if !columns
                .iter()
                .any(|column| column.get::<String, _>("name") == name)
            {
                sqlx::query(&format!("ALTER TABLE query_log ADD COLUMN {name} TEXT"))
                    .execute(&pool)
                    .await?;
            }
        }
        crate::portal::migrate(&pool).await?;
        Ok(Self {
            query_log: crate::query_log::QueryLog::new(pool.clone()),
            pool,
        })
    }

    pub async fn setting<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT value FROM runtime_settings WHERE key=?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
            .transpose()
    }

    pub async fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        sqlx::query("INSERT INTO runtime_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .bind(key).bind(serde_json::to_string(value)?).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_features(&self, settings: &crate::features::FeatureSettings) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO runtime_settings(key,value) VALUES('features',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .bind(serde_json::to_string(settings)?).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM client_networks")
            .execute(&mut *tx)
            .await?;
        for cidr in &settings.access.cidrs {
            sqlx::query("INSERT OR IGNORE INTO client_networks(cidr) VALUES(?)")
                .bind(cidr)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn certificate_paths(&self) -> Result<Option<(PathBuf, PathBuf)>> {
        let row = sqlx::query("SELECT certificate, private_key FROM certificate_paths WHERE id=1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| {
            (
                PathBuf::from(row.get::<String, _>("certificate")),
                PathBuf::from(row.get::<String, _>("private_key")),
            )
        }))
    }

    pub async fn listener_settings(&self) -> Result<Option<ListenerSettings>> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT settings FROM listener_settings WHERE id=1")
                .fetch_optional(&self.pool)
                .await?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub async fn cache_settings(&self) -> Result<Option<CacheSettings>> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT settings FROM cache_settings WHERE id=1")
                .fetch_optional(&self.pool)
                .await?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub async fn set_cache_settings(&self, settings: &CacheSettings) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO cache_settings(id,settings) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET settings=excluded.settings")
            .bind(serde_json::to_string(settings)?).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM cache_entries")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn cache_entry(&self, key: &str) -> Result<Option<(Vec<u8>, i64, i64)>> {
        let row = sqlx::query("SELECT response,inserted_at,expires_at FROM cache_entries WHERE cache_key=? AND expires_at>?")
            .bind(key).bind(Utc::now().timestamp()).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| (r.get("response"), r.get("inserted_at"), r.get("expires_at"))))
    }

    pub async fn set_cache_entry(
        &self,
        key: &str,
        response: &[u8],
        inserted: i64,
        expiry: i64,
        kind: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO cache_entries(cache_key,response,inserted_at,expires_at,kind,byte_size) VALUES(?,?,?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET response=excluded.response,inserted_at=excluded.inserted_at,expires_at=excluded.expires_at,kind=excluded.kind,byte_size=excluded.byte_size")
            .bind(key).bind(response).bind(inserted).bind(expiry).bind(kind).bind(response.len() as i64)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn cache_stats(&self) -> Result<(i64, i64)> {
        let row = sqlx::query("SELECT COUNT(*) AS count,COALESCE(SUM(byte_size),0) AS bytes FROM cache_entries WHERE expires_at>?")
            .bind(Utc::now().timestamp()).fetch_one(&self.pool).await?;
        Ok((row.get("count"), row.get("bytes")))
    }

    pub async fn set_listener_settings(&self, settings: &ListenerSettings) -> Result<()> {
        sqlx::query("INSERT INTO listener_settings(id,settings) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET settings=excluded.settings")
            .bind(serde_json::to_string(settings)?).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_certificate_paths(
        &self,
        certificate: &Path,
        private_key: &Path,
    ) -> Result<()> {
        sqlx::query("INSERT INTO certificate_paths(id,certificate,private_key) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET certificate=excluded.certificate, private_key=excluded.private_key")
            .bind(certificate.to_string_lossy().as_ref())
            .bind(private_key.to_string_lossy().as_ref())
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_account(&self, username: &str, password: &str, role: &str) -> Result<()> {
        anyhow::ensure!(
            ["admin", "editor", "viewer"].contains(&role),
            "invalid role"
        );
        anyhow::ensure!(
            username.len() >= 3,
            "username must have at least 3 characters"
        );
        anyhow::ensure!(!password.is_empty(), "password cannot be empty");
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .to_string();
        sqlx::query("INSERT INTO accounts(username,role,password_hash) VALUES(?,?,?)")
            .bind(username)
            .bind(role)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn accounts(&self) -> Result<Vec<Account>> {
        let rows = sqlx::query("SELECT id,username,role FROM accounts ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| Account {
                id: row.get("id"),
                username: row.get("username"),
                role: row.get("role"),
            })
            .collect())
    }

    pub async fn delete_account(&self, id: i64, actor_id: i64) -> Result<()> {
        anyhow::ensure!(id != actor_id, "cannot delete your own account");
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT role FROM accounts WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let row = row.context("account not found")?;
        if row.get::<String, _>("role") == "admin" {
            let admins: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE role='admin'")
                    .fetch_one(&mut *tx)
                    .await?;
            anyhow::ensure!(admins > 1, "cannot delete the last administrator");
        }
        sqlx::query("DELETE FROM accounts WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT id,password_hash FROM accounts WHERE username=?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let hash: String = row.get("password_hash");
        let parsed = PasswordHash::new(&hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return Ok(None);
        }
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let token_hash = hash_token(&token);
        let expires = (Utc::now() + chrono::Duration::hours(12)).to_rfc3339();
        sqlx::query("INSERT INTO sessions(token_hash,account_id,expires_at) VALUES(?,?,?)")
            .bind(token_hash)
            .bind(row.get::<i64, _>("id"))
            .bind(expires)
            .execute(&self.pool)
            .await?;
        Ok(Some(token))
    }

    pub async fn account_for_token(&self, token: &str) -> Result<Option<Account>> {
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let row = sqlx::query("SELECT a.id,a.username,a.role FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at>?")
            .bind(hash_token(token)).bind(Utc::now().to_rfc3339()).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| Account {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
        }))
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash=?")
            .bind(hash_token(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rules(&self) -> Result<Vec<Rule>> {
        let mut connection = self.pool.acquire().await?;
        Self::read_rules(&mut connection).await
    }

    async fn read_rules(connection: &mut sqlx::SqliteConnection) -> Result<Vec<Rule>> {
        let rows = sqlx::query(
            "SELECT id,kind,domain,record_type,value,ttl FROM rules ORDER BY kind,domain,id",
        )
        .fetch_all(connection)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| Rule {
                id: row.get("id"),
                kind: row.get("kind"),
                domain: row.get("domain"),
                record_type: row.get("record_type"),
                value: row.get("value"),
                ttl: row.get("ttl"),
            })
            .collect())
    }

    pub async fn client_networks(&self) -> Result<Vec<String>> {
        Ok(
            sqlx::query("SELECT cidr FROM client_networks ORDER BY cidr")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|row| row.get("cidr"))
                .collect(),
        )
    }

    pub async fn replace_client_networks(&self, cidrs: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM client_networks")
            .execute(&mut *tx)
            .await?;
        for cidr in cidrs {
            sqlx::query("INSERT INTO client_networks(cidr) VALUES(?)")
                .bind(cidr)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn add_rule(&self, input: &RuleInput) -> Result<i64, sqlx::Error> {
        let result =
            sqlx::query("INSERT INTO rules(kind,domain,record_type,value,ttl) VALUES(?,?,?,?,?)")
                .bind(&input.kind)
                .bind(&input.domain)
                .bind(&input.record_type)
                .bind(&input.value)
                .bind(input.ttl)
                .execute(&self.pool)
                .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn delete_rule(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM rules WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn subscriptions(&self) -> Result<Vec<Subscription>> {
        let rows =
            sqlx::query("SELECT id,url,last_error,updated_at FROM subscriptions ORDER BY id")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|row| Subscription {
                id: row.get("id"),
                url: row.get("url"),
                last_error: row.get("last_error"),
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    pub async fn add_subscription(&self, url: &str) -> Result<i64> {
        let result = sqlx::query("INSERT INTO subscriptions(url) VALUES(?)")
            .bind(url)
            .execute(&self.pool)
            .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn delete_subscription(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM subscriptions WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn policy_snapshot(&self) -> Result<(Vec<Rule>, Vec<String>)> {
        let mut tx = self.pool.begin().await?;
        let rules = Self::read_rules(&mut tx).await?;
        let domains = sqlx::query_scalar("SELECT DISTINCT domain FROM subscription_domains")
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((rules, domains))
    }

    pub async fn replace_subscription_domains(&self, id: i64, domains: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM subscription_domains WHERE subscription_id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for domain in domains {
            sqlx::query("INSERT INTO subscription_domains(subscription_id,domain) VALUES(?,?)")
                .bind(id)
                .bind(domain)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE subscriptions SET updated_at=?,last_error=NULL WHERE id=?")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn subscription_error(&self, id: i64, message: &str) -> Result<()> {
        sqlx::query("UPDATE subscriptions SET last_error=? WHERE id=?")
            .bind(message)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn audit(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        sqlx::query("INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)")
            .bind(Utc::now().to_rfc3339())
            .bind(actor)
            .bind(action)
            .bind(detail)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn audit_events(&self) -> Result<Vec<serde_json::Value>> {
        let rows =
            sqlx::query("SELECT at,actor,action,detail FROM audit ORDER BY id DESC LIMIT 100")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({"at":r.get::<String,_>("at"),"actor":r.get::<String,_>("actor"),"action":r.get::<String,_>("action"),"detail":r.get::<String,_>("detail")})).collect())
    }

    pub async fn logs(&self) -> Result<Vec<serde_json::Value>> {
        self.query_log.flush().await?;
        let rows = sqlx::query("SELECT at,client,domain,qtype,outcome,protocol,duration_ms,country,province,city,upstream FROM query_log ORDER BY id DESC LIMIT 200")
            .fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({"at":r.get::<String,_>("at"), "client":r.get::<String,_>("client"), "domain":r.get::<String,_>("domain"), "qtype":r.get::<String,_>("qtype"), "outcome":r.get::<String,_>("outcome"), "protocol":r.get::<String,_>("protocol"), "duration_ms":r.get::<Option<f64>,_>("duration_ms"), "country":r.get::<Option<String>,_>("country"),"province":r.get::<Option<String>,_>("province"),"city":r.get::<Option<String>,_>("city"),"upstream":r.get::<Option<String>,_>("upstream")})).collect())
    }

    pub async fn stats(&self) -> Result<serde_json::Value> {
        self.query_log.flush().await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(&self.pool)
            .await?;
        let blocked: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM query_log WHERE outcome='blocked'")
                .fetch_one(&self.pool)
                .await?;
        let rows = sqlx::query("SELECT COALESCE(country,'未知') AS country,COALESCE(province,'未知') AS province,COUNT(*) AS count FROM query_log GROUP BY country,province ORDER BY count DESC LIMIT 50").fetch_all(&self.pool).await?;
        let regions: Vec<_> = rows.into_iter().map(|r| serde_json::json!({"country":r.get::<String,_>("country"),"province":r.get::<String,_>("province"),"count":r.get::<i64,_>("count")})).collect();
        Ok(
            serde_json::json!({"total":total,"blocked":blocked,"regions":regions,"query_log":self.query_log.metrics()}),
        )
    }

    pub async fn prune(&self, days: i64) -> Result<()> {
        let cutoff: DateTime<Utc> = Utc::now() - chrono::Duration::days(days);
        sqlx::query("DELETE FROM query_log WHERE at<?")
            .bind(cutoff.to_rfc3339())
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE expires_at<?")
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM portal_sessions WHERE expires<=unixepoch()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM portal_flows WHERE expires<=unixepoch()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM cache_entries WHERE expires_at<=?")
            .bind(Utc::now().timestamp())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn old_query_logs_migrate_without_inventing_durations() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "rdns-log-migration-{}.sqlite3",
            rand::random::<u64>()
        ));
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::query("CREATE TABLE query_log (id INTEGER PRIMARY KEY, at TEXT NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL, qtype TEXT NOT NULL, outcome TEXT NOT NULL, protocol TEXT NOT NULL)").execute(&pool).await?;
        sqlx::query("INSERT INTO query_log VALUES(1,'2026-01-01','127.0.0.1','old.example','A','local','udp')").execute(&pool).await?;
        pool.close().await;
        let store = Store::open(&path).await?;
        assert!(store.logs().await?[0]["duration_ms"].is_null());
        store
            .query_log
            .push(crate::query_log::QueryLogEntry {
                at: Utc::now().to_rfc3339(),
                client: "127.0.0.1".into(),
                domain: "new.example".into(),
                qtype: "A".into(),
                outcome: "local".into(),
                protocol: "udp".into(),
                user_id: None,
                duration_ms: 0.125,
                country: None,
                province: None,
                city: None,
                upstream: None,
            })
            .await?;
        assert_eq!(store.logs().await?[0]["duration_ms"], 0.125);
        store.pool.close().await;
        let reopened = Store::open(&path).await?;
        assert_eq!(reopened.logs().await?.len(), 2);
        reopened.pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn short_nonempty_password_can_be_used_to_create_and_log_in() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "rdns-short-password-{}-{}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = Store::open(&path).await?;
        store.create_account("admin", "x", "admin").await?;
        assert!(store.login("admin", "x").await?.is_some());
        assert!(store.create_account("other", "", "viewer").await.is_err());
        store.pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }
}
