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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoSettings {
    pub enabled: bool,
    pub ipv4_path: PathBuf,
    pub ipv6_path: PathBuf,
    pub ipv4_url: String,
    pub ipv6_url: String,
    pub update_hours: u64,
    pub proxy: String,
}
impl Default for GeoSettings {
    fn default() -> Self {
        Self { enabled: true, ipv4_path: "data/geoip/ip2region_v4.xdb".into(), ipv6_path: "data/geoip/ip2region_v6.xdb".into(), ipv4_url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb".into(), ipv6_url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb".into(), update_hours: 0, proxy: String::new() }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeatureSettings {
    pub access: AccessSettings,
    pub resolution: ResolutionSettings,
    pub groups: Vec<GroupSettings>,
    pub geo: GeoSettings,
    pub gfwlist: GfwSettings,
}

pub struct FeatureRuntime {
    pub settings: FeatureSettings,
    pub access: AccessPolicy,
    pub geo: Arc<GeoIpService>,
    pub groups: HashMap<String, Arc<DohGroup>>,
}

pub struct Features {
    pub current: ArcSwap<FeatureRuntime>,
    pub list: ArcSwap<GfwList>,
    config: Config,
    store: Store,
    cache: Arc<PersistentCache>,
    write: Mutex<()>,
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
        let runtime = Self::compile(&config, settings, cache.clone())?;
        let saved = store.setting::<String>("gfwlist_data").await?;
        let list = saved
            .as_deref()
            .and_then(|text| GfwList::parse(text).ok())
            .unwrap_or(GfwList::parse(include_str!("../resources/gfwlist.txt"))?);
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(runtime),
            list: ArcSwap::from_pointee(list),
            config,
            store,
            cache,
            write: Mutex::new(()),
        }))
    }

    fn compile(
        config: &Config,
        mut settings: FeatureSettings,
        cache: Arc<PersistentCache>,
    ) -> Result<FeatureRuntime> {
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
            groups.insert(
                group.name.clone(),
                DohGroup::build(config, group, cache.clone())?,
            );
        }
        ensure!(
            r.mode == ResolveMode::Recursive || groups.contains_key(&r.group),
            "请选择有效的默认 DoH 上游组"
        );
        ensure!(
            !settings.gfwlist.enabled
                || (groups.contains_key(&settings.gfwlist.group) && groups.contains_key(&r.group)),
            "GFWList 必须指定有效的 DoH 上游组"
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
        let _ = upstream::http_client(config, &geo_settings.proxy)?;
        ensure!(
            settings.access.region_mode == RegionMode::Any || geo_settings.enabled,
            "启用地区访问规则时必须启用 GeoIP"
        );
        let geo = Arc::new(GeoIpService::new(
            geo_settings.enabled,
            geo_settings.ipv4_path.clone(),
            geo_settings.ipv6_path.clone(),
        ));
        Ok(FeatureRuntime {
            settings,
            access,
            geo,
            groups,
        })
    }

    pub async fn apply(&self, settings: FeatureSettings) -> Result<()> {
        let _guard = self.write.lock().await;
        let runtime = Self::compile(&self.config, settings, self.cache.clone())?;
        self.store.set_features(&runtime.settings).await?;
        self.current.store(Arc::new(runtime));
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
        json!({"type":"features", "settings":settings, "geo":current.geo.status(), "groups":groups, "gfwlist":{"count":list.count,"skipped":list.skipped,"meta":self.store.setting::<Value>("gfwlist_meta").await.ok().flatten()}, "geo_meta":self.store.setting::<Value>("geo_meta").await.ok().flatten()})
    }

    pub async fn refresh_list(&self) -> Result<usize> {
        let _guard = self.write.lock().await;
        let current = self.current.load_full();
        let group = current
            .settings
            .groups
            .iter()
            .find(|g| g.name == current.settings.gfwlist.group);
        let proxy = group.map(|g| g.proxy.as_str()).unwrap_or("");
        let result = async {
            let bytes = upstream::download(
                &self.config,
                &current.settings.gfwlist.url,
                proxy,
                10 * 1024 * 1024,
            )
            .await?;
            let text = String::from_utf8(bytes)?;
            let list = GfwList::parse(&text)?;
            self.store.set_setting("gfwlist_data", &text).await?;
            let count = list.count;
            self.list.store(Arc::new(list));
            Ok::<_, anyhow::Error>(count)
        }
        .await;
        let previous = self
            .store
            .setting::<Value>("gfwlist_meta")
            .await?
            .unwrap_or_default();
        let meta = json!({"attempted_at":chrono::Utc::now().timestamp(),"updated_at":if result.is_ok(){json!(chrono::Utc::now().timestamp())}else{previous["updated_at"].clone()},"error":result.as_ref().err().map(|_| "更新失败，继续使用上一份有效名单")});
        self.store.set_setting("gfwlist_meta", &meta).await?;
        result
    }

    pub async fn refresh_geo(&self, version: u8) -> Result<()> {
        ensure!([4, 6].contains(&version), "ip_version must be 4 or 6");
        let _guard = self.write.lock().await;
        let current = self.current.load_full();
        let settings = &current.settings.geo;
        let url = if version == 4 {
            &settings.ipv4_url
        } else {
            &settings.ipv6_url
        };
        let result = async {
            let bytes =
                upstream::download(&self.config, url, &settings.proxy, 80 * 1024 * 1024).await?;
            let geo = current.geo.clone();
            tokio::task::spawn_blocking(move || geo.install_database(version, &bytes)).await??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let mut meta = self
            .store
            .setting::<Value>("geo_meta")
            .await?
            .unwrap_or_else(|| json!({}));
        let key = version.to_string();
        let previous = meta[&key]["updated_at"].clone();
        meta[&key] = json!({"attempted_at":chrono::Utc::now().timestamp(),"updated_at":if result.is_ok(){json!(chrono::Utc::now().timestamp())}else{previous},"error":result.as_ref().err().map(|_| "更新失败，继续使用上一份有效数据库")});
        self.store.set_setting("geo_meta", &meta).await?;
        result
    }

    pub async fn maintain(&self) {
        let settings = self.current.load().settings.clone();
        let now = chrono::Utc::now().timestamp();
        let due = |last: &Value, hours: u64| {
            hours > 0 && now - last["attempted_at"].as_i64().unwrap_or(0) >= hours as i64 * 3600
        };
        let meta = self
            .store
            .setting::<Value>("gfwlist_meta")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if settings.gfwlist.enabled
            && due(&meta, settings.gfwlist.update_hours)
            && self.refresh_list().await.is_err()
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
                && self.refresh_geo(version).await.is_err()
            {
                tracing::warn!(version, "GeoIP refresh failed; retaining active database");
            }
        }
    }
}
