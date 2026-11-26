use crate::{
    access::{AccessPolicy, AccessSettings, RegionMode},
    cache::PersistentCache,
    config::Config,
    geoip::GeoIpService,
    gfwlist::{GfwList, GfwSettings},
    store::Store,
    upstream::{self, DohGroup, GroupSettings, ResolutionSettings, ResolveMode},
};
use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

pub enum SourceUpdate {
    Automatic,
    Download,
    Upload(axum::body::Bytes),
}

impl SourceUpdate {
    fn should_skip(&self, meta: &Value) -> bool {
        matches!(self, Self::Automatic) && meta["manual"].as_bool() == Some(true)
    }

    fn is_upload(&self) -> bool {
        matches!(self, Self::Upload(_))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoSettings {
    pub enabled: bool,
    pub ipv4_path: PathBuf,
    pub ipv6_path: PathBuf,
    pub ipv4_url: String,
    pub ipv6_url: String,
    pub update_hours: u64,
    #[serde(skip_serializing)]
    pub use_proxy: bool,
    #[serde(skip_serializing)]
    pub proxy: String,
}
impl Default for GeoSettings {
    fn default() -> Self {
        Self { enabled: true, ipv4_path: "data/geoip/ip2region_v4.xdb".into(), ipv6_path: "data/geoip/ip2region_v6.xdb".into(), ipv4_url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb".into(), ipv6_url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb".into(), update_hours: 0, use_proxy:false, proxy: String::new() }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeatureSettings {
    pub proxy_url: Option<String>,
    pub proxy_subscriptions: Option<bool>,
    pub access: AccessSettings,
    pub resolution: ResolutionSettings,
    pub groups: Vec<GroupSettings>,
    pub geo: GeoSettings,
    pub gfwlist: GfwSettings,
    pub adguard: crate::adguard::Settings,
}

impl FeatureSettings {
    fn migrate_proxy(&mut self) {
        self.migrate_proxy_address();
        let enabled = *self.proxy_subscriptions.get_or_insert({
            self.geo.use_proxy
                || self.gfwlist.use_proxy
                || self.adguard.use_proxy
                || !self.geo.proxy.is_empty()
                || !self.gfwlist.proxy.is_empty()
        });
        if enabled
            && self.proxy_url.as_deref().unwrap_or_default().is_empty()
            && let Some(url) = [&self.geo.proxy, &self.gfwlist.proxy]
                .into_iter()
                .find(|s| !s.is_empty())
        {
            self.proxy_url = Some(url.clone());
        }
        self.geo.proxy.clear();
        self.gfwlist.proxy.clear();
        self.geo.use_proxy = false;
        self.gfwlist.use_proxy = false;
        self.adguard.use_proxy = false;
    }

    fn migrate_proxy_address(&mut self) {
        if self.proxy_url.is_some() {
            return;
        }
        // Multiple distinct legacy addresses keep their routes until edited.
        let global = self
            .groups
            .iter()
            .map(|g| &g.proxy)
            .chain([&self.geo.proxy])
            .find(|url| !url.is_empty())
            .cloned()
            .unwrap_or_default();
        if let Some(group) = self.groups.iter().find(|g| g.name == self.gfwlist.group) {
            self.gfwlist.proxy.clone_from(&group.proxy);
        }
        let migrate = |legacy: &mut String, enabled: &mut bool| {
            if !legacy.is_empty() {
                *enabled = true;
                if *legacy == global {
                    legacy.clear();
                }
            }
        };
        for group in &mut self.groups {
            migrate(&mut group.proxy, &mut group.use_proxy);
        }
        migrate(&mut self.geo.proxy, &mut self.geo.use_proxy);
        migrate(&mut self.gfwlist.proxy, &mut self.gfwlist.use_proxy);
        self.proxy_url = Some(global);
    }

    fn proxy_for<'a>(&'a self, enabled: bool, legacy: &'a str) -> &'a str {
        if !legacy.is_empty() {
            legacy
        } else if enabled {
            self.proxy_url.as_deref().unwrap_or_default()
        } else {
            ""
        }
    }
    fn list_source(&self) -> (&str, &str, &str, bool) {
        (
            &self.gfwlist.url,
            &self.gfwlist.group,
            self.subscription_proxy(),
            self.gfwlist.enabled,
        )
    }
    pub(crate) fn subscription_proxy(&self) -> &str {
        self.proxy_for(self.proxy_subscriptions.unwrap_or(false), "")
    }
}

pub struct FeatureRuntime {
    pub cache_revision: u64,
    ad_revision: u64,
    list_revision: u64,
    geo_revision: u64,
    pub settings: FeatureSettings,
    pub access: AccessPolicy,
    pub geo: Arc<GeoIpService>,
    pub groups: HashMap<String, Arc<DohGroup>>,
}

pub struct Features {
    pub current: ArcSwap<FeatureRuntime>,
    pub list: ArcSwap<GfwList>,
    pub ads: ArcSwap<crate::adguard::Rules>,
    ad_refresh: Mutex<()>,
    pub subscription_updates: tokio::sync::watch::Sender<()>,
    config: Config,
    store: Store,
    cache: Arc<PersistentCache>,
    write: Mutex<()>,
    list_refresh: Mutex<()>,
    geo_refresh: [Mutex<()>; 2],
}

impl Features {
    pub async fn new(
        config: Config,
        store: Store,
        cache: Arc<PersistentCache>,
    ) -> Result<Arc<Self>> {
        let settings = match store.setting::<FeatureSettings>("features").await? {
            Some(settings) => settings,
            None => {
                let base = config
                    .database
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                FeatureSettings {
                    access: AccessSettings {
                        cidrs: store.client_networks().await?,
                        ..Default::default()
                    },
                    geo: GeoSettings {
                        ipv4_path: base.join("geoip/ip2region_v4.xdb"),
                        ipv6_path: base.join("geoip/ip2region_v6.xdb"),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }
        };
        let runtime = Self::compile(&config, settings, cache.clone(), None)?;
        let resources = std::env::current_exe()?.with_file_name("resources");
        for version in [4, 6] {
            let path = runtime.geo.database_path(version)?;
            let seed = resources
                .join("geoip")
                .join(format!("ip2region_v{version}.xdb"));
            if !path.exists() && seed.is_file() {
                let result = tokio::fs::read(&seed)
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|bytes| {
                        let prepared = runtime.geo.prepare_database(version, bytes)?;
                        runtime.geo.install_prepared(version, prepared)
                    });
                if let Err(error) = result {
                    tracing::warn!(version,%error,"could not install packaged GeoIP data");
                }
            }
        }
        let list = store
            .setting::<String>("gfwlist_data")
            .await?
            .as_deref()
            .and_then(|text| GfwList::parse(text).ok())
            .or_else(|| {
                std::fs::read_to_string(resources.join("gfwlist.txt"))
                    .ok()
                    .and_then(|text| GfwList::parse(&text).ok())
            });
        let list = match list {
            Some(list) => list,
            None => GfwList::parse(include_str!("../resources/gfwlist.txt"))?,
        };
        let mut ads: crate::adguard::Rules = match store.setting("adguard_data").await? {
            Some(rules) => rules,
            None => {
                let mut rules = crate::adguard::Rules::default();
                let result = (|| -> Result<()> {
                    for name in ["adguard-dns.txt", "adaway.txt"] {
                        rules.add(&std::fs::read(resources.join(name))?)?;
                    }
                    Ok(())
                })();
                if result.is_ok() {
                    rules
                } else {
                    Default::default()
                }
            }
        };
        ads.compile()?;
        Ok(Arc::new(Self {
            ads: ArcSwap::from_pointee(ads),
            ad_refresh: Default::default(),
            subscription_updates: tokio::sync::watch::channel(()).0,
            current: ArcSwap::from_pointee(runtime),
            list: ArcSwap::from_pointee(list),
            config,
            store,
            cache,
            write: Mutex::new(()),
            list_refresh: Default::default(),
            geo_refresh: Default::default(),
        }))
    }

    fn compile(
        config: &Config,
        mut settings: FeatureSettings,
        cache: Arc<PersistentCache>,
        previous: Option<&FeatureRuntime>,
    ) -> Result<FeatureRuntime> {
        for group in &mut settings.groups {
            group.name = group.name.trim().to_owned();
        }
        settings.resolution.group = settings.resolution.group.trim().to_owned();
        settings.gfwlist.group = settings.gfwlist.group.trim().to_owned();
        settings.migrate_proxy();
        let global = settings.proxy_url.as_deref().unwrap_or_default();
        let _ = upstream::http_client(config, global)?;
        let needs_global = settings
            .groups
            .iter()
            .any(|g| g.use_proxy && g.proxy.is_empty())
            || settings.proxy_subscriptions.unwrap_or(false);
        ensure!(
            !global.is_empty() || !needs_global,
            "请先在解析上游填写全局代理地址"
        );
        settings.adguard.validate()?;
        let access = AccessPolicy::compile(settings.access.clone())?;
        settings.access = access.settings.clone();
        let r = &settings.resolution;
        ensure!(
            (100..=60000).contains(&r.timeout_ms) && r.priority_ms <= r.timeout_ms,
            "解析总超时需为 100..60000 ms，优先等待不能超过总超时"
        );
        ensure!(settings.groups.len() <= 32, "too many upstream groups");
        let mut groups = HashMap::new();
        for group in &settings.groups {
            ensure!(!groups.contains_key(&group.name), "上游组名称不能重复");
            let proxy = settings.proxy_for(group.use_proxy, &group.proxy);
            let reusable = previous
                .filter(|runtime| {
                    runtime.settings.groups.contains(group)
                        && runtime.settings.proxy_for(group.use_proxy, &group.proxy) == proxy
                })
                .and_then(|runtime| runtime.groups.get(&group.name));
            let pool = match reusable {
                Some(pool) => pool.clone(),
                None => {
                    let mut effective = group.clone();
                    effective.proxy = proxy.to_owned();
                    DohGroup::build(config, &effective, cache.clone())?
                }
            };
            groups.insert(group.name.clone(), pool);
        }
        ensure!(
            !settings.gfwlist.enabled || groups.contains_key(&settings.gfwlist.group),
            "GFWList 分流上游组「{}」未配置，请在解析规则 → 订阅源中选择有效的组",
            settings.gfwlist.group
        );
        ensure!(
            (r.mode == ResolveMode::Recursive
                && r.recursion_compatibility == upstream::RecursionCompatibility::Relaxed
                && !settings.gfwlist.enabled)
                || groups.contains_key(&r.group),
            "默认 DoH 上游组「{}」未配置，请在高级设置 → 解析上游中选择有效的组",
            r.group
        );
        upstream::validate_https(&settings.gfwlist.url)?;
        ensure!(
            (1..=720).contains(&settings.gfwlist.update_hours),
            "GFWList 更新周期需为 1..720 小时"
        );
        let geo_settings = &settings.geo;
        ensure!(
            geo_settings.update_hours <= 8760,
            "GeoIP update interval must be 0..8760 hours"
        );
        ensure!(
            geo_settings.ipv4_path.is_absolute()
                && geo_settings.ipv6_path.is_absolute()
                && geo_settings.ipv4_path != geo_settings.ipv6_path,
            "IPv4 和 IPv6 数据库需设置不同的绝对路径"
        );
        upstream::validate_https(&geo_settings.ipv4_url)?;
        upstream::validate_https(&geo_settings.ipv6_url)?;
        ensure!(
            settings.access.region_mode == RegionMode::Any || geo_settings.enabled,
            "启用地区访问规则时必须启用 GeoIP"
        );
        let reusable_geo = previous.filter(|runtime| {
            let old = &runtime.settings.geo;
            old.enabled == geo_settings.enabled
                && old.ipv4_path == geo_settings.ipv4_path
                && old.ipv6_path == geo_settings.ipv6_path
        });
        let geo = match reusable_geo {
            Some(runtime) => runtime.geo.clone(),
            None => Arc::new(GeoIpService::new(
                geo_settings.enabled,
                geo_settings.ipv4_path.clone(),
                geo_settings.ipv6_path.clone(),
            )),
        };
        let list_revision = previous.map_or(0, |old| {
            old.list_revision + u64::from(old.settings.list_source() != settings.list_source())
        });
        let geo_revision = previous.map_or(0, |old| {
            let source = &old.settings.geo;
            old.geo_revision
                + u64::from(
                    reusable_geo.is_none()
                        || source.ipv4_url != geo_settings.ipv4_url
                        || source.ipv6_url != geo_settings.ipv6_url
                        || old.settings.subscription_proxy() != settings.subscription_proxy(),
                )
        });
        Ok(FeatureRuntime {
            cache_revision: previous.map_or(0, |old| old.cache_revision + 1),
            ad_revision: previous.map_or(0, |p| {
                p.ad_revision
                    + u64::from(
                        p.settings.adguard != settings.adguard
                            || p.settings.subscription_proxy() != settings.subscription_proxy(),
                    )
            }),
            list_revision,
            geo_revision,
            settings,
            access,
            geo,
            groups,
        })
    }

    pub async fn apply(self: &Arc<Self>, settings: FeatureSettings) -> Result<()> {
        let _guard = self.write.lock().await;
        let runtime = Self::compile(
            &self.config,
            settings,
            self.cache.clone(),
            Some(&self.current.load()),
        )?;
        self.store.set_features(&runtime.settings).await?;
        let refresh_ads = runtime.settings.adguard.enabled
            && self.current.load().settings.adguard != runtime.settings.adguard;
        self.current.store(Arc::new(runtime));
        if refresh_ads {
            let features = self.clone();
            tokio::spawn(async move {
                let _ = features.refresh_ads(SourceUpdate::Automatic).await;
            });
        }
        Ok(())
    }

    pub async fn snapshot(&self, admin: bool) -> Value {
        let current = self.current.load_full();
        let list = self.list.load();
        let mut settings = serde_json::to_value(&current.settings).unwrap_or_default();
        // Only administrators may retrieve upstream credentials and endpoint URLs.
        if !admin {
            settings = json!({"access":{"mode":current.settings.access.mode,"region_mode":current.settings.access.region_mode},"resolution":{"mode":current.settings.resolution.mode}});
        }
        let groups = if admin {
            current
                .groups
                .values()
                .map(|g| g.status())
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let ads = self.ads.load_full();
        json!({"type":"features", "settings":settings, "geo":current.geo.status(), "groups":groups, "gfwlist":{"count":list.count,"skipped":list.skipped,"meta":self.store.setting::<Value>("gfwlist_meta").await.ok().flatten()}, "adguard":{"count":ads.count(),"exceptions":ads.exception_count(),"skipped":ads.skipped(),"meta":self.store.setting::<Value>("adguard_meta").await.ok().flatten()}, "geo_meta":self.store.setting::<Value>("geo_meta").await.ok().flatten()})
    }

    pub async fn refresh_ads(&self, update: SourceUpdate) -> Result<()> {
        let _refresh = self.ad_refresh.lock().await;
        let mut meta = self
            .store
            .setting::<Value>("adguard_meta")
            .await?
            .unwrap_or_default();
        if update.should_skip(&meta) {
            return Ok(());
        }
        let uploaded = update.is_upload();
        let current = self.current.load_full();
        let settings = &current.settings.adguard;
        let result = async {
            let sources = if let SourceUpdate::Upload(bytes) = update {
                vec![bytes.into()]
            } else {
                let mut sources = Vec::new();
                for url in &settings.urls {
                    sources.push(
                        upstream::download(
                            &self.config,
                            url,
                            current.settings.subscription_proxy(),
                            20 * 1024 * 1024,
                        )
                        .await?,
                    );
                }
                sources
            };
            tokio::task::spawn_blocking(move || {
                let mut rules = crate::adguard::Rules::default();
                for source in sources {
                    rules.add(&source)?;
                }
                rules.compile()?;
                Ok::<_, anyhow::Error>(rules)
            })
            .await?
        }
        .await;
        let _guard = self.write.lock().await;
        ensure!(
            self.current.load().ad_revision == current.ad_revision,
            "AdGuard 来源已变更"
        );
        meta["attempted_at"] = json!(chrono::Utc::now().timestamp());
        match result {
            Ok(rules) => {
                meta["updated_at"] = meta["attempted_at"].clone();
                meta["manual"] = json!(uploaded);
                meta["error"] = Value::Null;
                self.store
                    .set_source_snapshot("adguard_data", &rules, "adguard_meta", &meta)
                    .await?;
                self.ads.store(Arc::new(rules));
            }
            Err(error) => {
                meta["error"] = json!("更新失败，已保留上一份规则");
                self.store.set_setting("adguard_meta", &meta).await?;
                self.subscription_updates.send_replace(());
                return Err(error);
            }
        }
        self.subscription_updates.send_replace(());
        Ok(())
    }

    pub async fn refresh_list(&self, update: SourceUpdate) -> Result<()> {
        let _refresh = self.list_refresh.lock().await;
        let previous = self
            .store
            .setting::<Value>("gfwlist_meta")
            .await?
            .unwrap_or_default();
        if update.should_skip(&previous) {
            return Ok(());
        }
        let uploaded = update.is_upload();
        let current = self.current.load_full();
        let (url, _, proxy, _) = current.settings.list_source();
        let downloaded = async {
            let bytes = if let SourceUpdate::Upload(bytes) = update {
                bytes.into()
            } else {
                upstream::download(&self.config, url, proxy, 10 * 1024 * 1024).await?
            };
            tokio::task::spawn_blocking(move || {
                let text = String::from_utf8(bytes)?;
                let text = text.trim_start_matches('\u{feff}');
                let list = GfwList::parse(text)?;
                Ok::<_, anyhow::Error>((text.to_owned(), list))
            })
            .await?
        }
        .await;
        let _guard = self.write.lock().await;
        ensure!(
            self.current.load().list_revision == current.list_revision,
            "GFWList source changed during refresh"
        );
        let now = chrono::Utc::now().timestamp();
        let result = match downloaded {
            Ok((text, list)) => {
                let meta =
                    json!({"attempted_at":now, "updated_at":now, "manual":uploaded, "error":null});
                self.store
                    .set_source_snapshot("gfwlist_data", &text, "gfwlist_meta", &meta)
                    .await?;
                self.list.store(Arc::new(list));
                Ok(())
            }
            Err(error) => {
                let mut meta = previous;
                meta["attempted_at"] = json!(now);
                meta["error"] = json!("更新失败，继续使用上一份有效名单");
                self.store.set_setting("gfwlist_meta", &meta).await?;
                Err(error)
            }
        };
        self.subscription_updates.send_replace(());
        result
    }

    pub async fn refresh_geo(&self, version: u8, update: SourceUpdate) -> Result<()> {
        ensure!([4, 6].contains(&version), "ip_version must be 4 or 6");
        let _refresh = self.geo_refresh[usize::from(version == 6)].lock().await;
        let key = version.to_string();
        let uploaded = update.is_upload();
        if matches!(update, SourceUpdate::Automatic)
            && update.should_skip(
                &self
                    .store
                    .setting::<Value>("geo_meta")
                    .await?
                    .unwrap_or_default()[&key],
            )
        {
            return Ok(());
        }
        let current = self.current.load_full();
        let settings = &current.settings.geo;
        let url = if version == 4 {
            &settings.ipv4_url
        } else {
            &settings.ipv6_url
        };
        let prepared = async {
            let bytes = if let SourceUpdate::Upload(bytes) = update {
                bytes.into()
            } else {
                upstream::download_with_timeout(
                    &self.config,
                    url,
                    current.settings.subscription_proxy(),
                    80 * 1024 * 1024,
                    std::time::Duration::from_secs(300),
                )
                .await?
            };
            let geo = current.geo.clone();
            tokio::task::spawn_blocking(move || geo.prepare_database(version, bytes)).await?
        }
        .await;
        let _guard = self.write.lock().await;
        ensure!(
            self.current.load().geo_revision == current.geo_revision,
            "GeoIP source changed during refresh"
        );
        let result = prepared.and_then(|staged| current.geo.install_prepared(version, staged));
        let mut meta = self
            .store
            .setting::<Value>("geo_meta")
            .await?
            .unwrap_or_else(|| json!({}));
        let manual = if result.is_ok() {
            uploaded
        } else {
            meta[&key]["manual"].as_bool().unwrap_or(false)
        };
        let previous = meta[&key]["updated_at"].clone();
        let error = result.as_ref().err().map(|error| {
            if let Some(http) = error.downcast_ref::<reqwest::Error>() {
                if let Some(status) = http.status() {
                    return format!("下载失败，HTTP {status}");
                }
                if http.is_timeout() {
                    return "下载超时，请重试或检查代理配置".to_owned();
                }
                return "下载连接失败，请检查来源地址、网络及代理配置".to_owned();
            }
            // Filesystem paths and arbitrary endpoint URLs stay out of viewer snapshots.
            if error.downcast_ref::<std::io::Error>().is_some() {
                return "无法写入数据库，请检查目录权限与可用空间".to_owned();
            }
            "数据库读取或校验失败，请检查下载内容和 IP 版本".to_owned()
        });
        meta[&key] = json!({"attempted_at":chrono::Utc::now().timestamp(),"updated_at":if result.is_ok(){json!(chrono::Utc::now().timestamp())}else{previous},"manual":manual,"error":error});
        self.store.set_setting("geo_meta", &meta).await?;
        self.subscription_updates.send_replace(());
        result
    }

    pub async fn maintain(&self) {
        let settings = self.current.load().settings.clone();
        let now = chrono::Utc::now().timestamp();
        let due = |last: &Value, hours: u64| {
            hours > 0
                && last["manual"].as_bool() != Some(true)
                && now - last["attempted_at"].as_i64().unwrap_or(0) >= hours as i64 * 3600
        };
        if settings.adguard.enabled
            && due(
                &self
                    .store
                    .setting::<Value>("adguard_meta")
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
                settings.adguard.update_hours,
            )
        {
            let _ = self.refresh_ads(SourceUpdate::Automatic).await;
        }
        let meta = self
            .store
            .setting::<Value>("gfwlist_meta")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if settings.gfwlist.enabled
            && due(&meta, settings.gfwlist.update_hours)
            && self.refresh_list(SourceUpdate::Automatic).await.is_err()
        {
            tracing::warn!("GFWList refresh failed; retaining active rules");
        }
        let meta = self
            .store
            .setting::<Value>("geo_meta")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        for version in [4, 6] {
            if settings.geo.enabled
                && due(&meta[version.to_string()], settings.geo.update_hours)
                && self
                    .refresh_geo(version, SourceUpdate::Automatic)
                    .await
                    .is_err()
            {
                tracing::warn!(version, "GeoIP refresh failed; retaining active database");
            }
        }
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn migrate_legacy_proxy_routes() -> Result<()> {
        let mut settings: FeatureSettings = serde_json::from_value(json!({
            "groups":[{"name":"default","proxy":"http://old-a.test:8080"},
                      {"name":"special","proxy":"socks5://old-b.test:1080"}],
            "geo":{"proxy":"http://old-a.test:8080"},"gfwlist":{"group":"special"}
        }))?;
        settings.migrate_proxy();
        assert_eq!(
            settings.proxy_url.as_deref(),
            Some("http://old-a.test:8080")
        );
        assert_eq!(settings.subscription_proxy(), "http://old-a.test:8080");
        assert_eq!(settings.list_source().2, "http://old-a.test:8080");
        assert!(settings.groups[0].use_proxy && settings.groups[0].proxy.is_empty());
        settings.proxy_url = Some("http://new.test:8080".into());
        assert_eq!(settings.subscription_proxy(), "http://new.test:8080");
        assert_eq!(settings.list_source().2, "http://new.test:8080");
        settings.proxy_subscriptions = Some(false);
        assert_eq!(settings.subscription_proxy(), "");
        Ok(())
    }
}
