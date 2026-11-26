use crate::{
    api::{self, ApiState},
    config::Config,
    tls::TlsState,
    transport,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Mutex, RwLock, broadcast},
    task::JoinHandle,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketSetting {
    pub enabled: bool,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListenerSettings {
    pub dns_udp: SocketSetting,
    pub dns_tcp: SocketSetting,
    pub doh: SocketSetting,
    pub dot: SocketSetting,
    pub doq: SocketSetting,
}

impl ListenerSettings {
    pub fn from_config(config: &Config) -> Self {
        fn setting(actual: Option<SocketAddr>, default: &str) -> SocketSetting {
            SocketSetting {
                enabled: actual.is_some(),
                address: actual
                    .unwrap_or_else(|| default.parse().expect("static listener address")),
            }
        }
        Self {
            dns_udp: setting(config.dns_udp, "0.0.0.0:53"),
            dns_tcp: setting(config.dns_tcp, "0.0.0.0:53"),
            doh: setting(config.doh, "0.0.0.0:443"),
            dot: setting(config.dot, "0.0.0.0:853"),
            doq: setting(config.doq, "0.0.0.0:853"),
        }
    }
    fn get(&self, kind: Kind) -> &SocketSetting {
        match kind {
            Kind::Udp => &self.dns_udp,
            Kind::Tcp => &self.dns_tcp,
            Kind::Doh => &self.doh,
            Kind::Dot => &self.dot,
            Kind::Doq => &self.doq,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Kind {
    Udp,
    Tcp,
    Doh,
    Dot,
    Doq,
}
impl Kind {
    const ALL: [Self; 5] = [Self::Udp, Self::Tcp, Self::Doh, Self::Dot, Self::Doq];
    fn name(self) -> &'static str {
        match self {
            Self::Udp => "dns_udp",
            Self::Tcp => "dns_tcp",
            Self::Doh => "doh",
            Self::Dot => "dot",
            Self::Doq => "doq",
        }
    }
}

enum Bound {
    Udp(UdpSocket),
    Tcp(TcpListener),
    Doh(std::net::TcpListener),
    DohHttp(TcpListener),
    Dot(TcpListener),
    Doq(quinn::Endpoint),
}
struct Running {
    address: SocketAddr,
    handle: JoinHandle<()>,
    endpoint: Option<quinn::Endpoint>,
}

pub struct ListenerManager {
    current: Mutex<HashMap<Kind, Running>>,
    settings: RwLock<ListenerSettings>,
    events: broadcast::Sender<String>,
}

impl ListenerManager {
    pub fn new(config: &Config) -> Arc<Self> {
        let (events, _) = broadcast::channel(64);
        Arc::new(Self {
            current: Mutex::new(HashMap::new()),
            settings: RwLock::new(ListenerSettings::from_config(config)),
            events,
        })
    }
    pub fn has_subscribers(&self) -> bool {
        self.events.receiver_count() > 0
    }
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.events.subscribe()
    }
    pub fn publish(&self, event: serde_json::Value) {
        let _ = self.events.send(event.to_string());
    }
    pub async fn snapshot(&self) -> serde_json::Value {
        let current = self.current.lock().await;
        let settings = self.settings.read().await.clone();
        let running = Kind::ALL
            .iter()
            .map(|kind| {
                (
                    kind.name().to_owned(),
                    current
                        .get(kind)
                        .is_some_and(|entry| !entry.handle.is_finished()),
                )
            })
            .collect::<HashMap<_, _>>();
        serde_json::json!({"type":"listeners", "settings":settings, "running":running})
    }
    pub async fn refresh_doq_config(&self, tls: &TlsState) -> Result<()> {
        let current = self.current.lock().await;
        if let Some(endpoint) = current
            .get(&Kind::Doq)
            .and_then(|entry| entry.endpoint.as_ref())
        {
            endpoint.set_server_config(Some(tls.doq_config()?));
        }
        Ok(())
    }
    pub async fn apply(
        &self,
        state: ApiState,
        desired: ListenerSettings,
        persist: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            !state.engine.config.doh_on_admin || !desired.doh.enabled,
            "DoH is already served on the admin port via doh_on_admin"
        );
        for kind in Kind::ALL {
            let setting = desired.get(kind);
            if !setting.enabled {
                continue;
            }
            anyhow::ensure!(
                setting.address.port() > 0,
                "{} port must be 1..65535",
                kind.name()
            );
            match kind {
                Kind::Doh if state.engine.config.doh_http => {
                    anyhow::ensure!(
                        setting.address.ip().is_loopback(),
                        "HTTP DoH behind a reverse proxy requires a loopback address"
                    );
                }
                Kind::Doh => {
                    state.tls.doh_config().await?;
                }
                Kind::Dot => {
                    state.tls.dot_config()?;
                }
                Kind::Doq => {
                    state.tls.doq_config()?;
                }
                Kind::Udp | Kind::Tcp => {}
            }
        }
        let mut current = self.current.lock().await;
        for kind in Kind::ALL {
            if current
                .get(&kind)
                .is_some_and(|entry| entry.handle.is_finished())
            {
                let entry = current.remove(&kind).expect("finished listener exists");
                if let Some(endpoint) = entry.endpoint {
                    endpoint.close(0u32.into(), b"listener stopped");
                }
            }
        }
        // Release old sockets when changing bind IP on the same port (e.g. 0.0.0.0:53 -> 127.0.0.1:53).
        let mut stopped_same_port = Vec::new();
        for kind in Kind::ALL {
            let setting = desired.get(kind);
            if setting.enabled
                && let Some(entry) = current.get(&kind)
                && entry.address != setting.address
                && entry.address.port() == setting.address.port()
            {
                let old = current.remove(&kind).expect("same-port listener exists");
                let old_addr = old.address;
                stop_running(old, b"listener rebinding").await;
                stopped_same_port.push((kind, old_addr));
            }
        }
        let mut bound = HashMap::new();
        for kind in Kind::ALL {
            let setting = desired.get(kind);
            if !setting.enabled
                || current
                    .get(&kind)
                    .is_some_and(|entry| entry.address == setting.address)
            {
                continue;
            }
            match bind_listener(kind, setting.address, &state).await {
                Ok(listener) => {
                    bound.insert(kind, listener);
                }
                Err(error) => {
                    drop(bound);
                    for (old_kind, old_addr) in stopped_same_port {
                        if let Ok(listener) = bind_listener(old_kind, old_addr, &state).await {
                            current.insert(
                                old_kind,
                                spawn_listener(old_kind, old_addr, listener, &state, &self.events),
                            );
                        }
                    }
                    return Err(error);
                }
            }
        }
        if persist && let Err(error) = state.engine.store.set_listener_settings(&desired).await {
            drop(bound);
            for (old_kind, old_addr) in stopped_same_port {
                if let Ok(listener) = bind_listener(old_kind, old_addr, &state).await {
                    current.insert(
                        old_kind,
                        spawn_listener(old_kind, old_addr, listener, &state, &self.events),
                    );
                }
            }
            return Err(error);
        }
        for kind in Kind::ALL {
            let setting = desired.get(kind);
            if (!setting.enabled
                || bound.contains_key(&kind)
                || current
                    .get(&kind)
                    .is_some_and(|entry| entry.handle.is_finished()))
                && let Some(entry) = current.remove(&kind)
            {
                stop_running(entry, b"listener changed").await;
            }
            if let Some(listener) = bound.remove(&kind) {
                current.insert(
                    kind,
                    spawn_listener(kind, setting.address, listener, &state, &self.events),
                );
            }
        }
        *self.settings.write().await = desired;
        let snapshot = serde_json::json!({"type":"listeners", "settings":*self.settings.read().await, "running":Kind::ALL.iter().map(|kind| (kind.name(), current.get(kind).is_some_and(|entry| !entry.handle.is_finished()))).collect::<HashMap<_,_>>()});
        let _ = self.events.send(snapshot.to_string());
        Ok(())
    }
}

async fn stop_running(entry: Running, reason: &[u8]) {
    if let Some(endpoint) = entry.endpoint {
        endpoint.close(0u32.into(), reason);
    }
    entry.handle.abort();
    let _ = entry.handle.await;
}

async fn bind_listener(kind: Kind, address: SocketAddr, state: &ApiState) -> Result<Bound> {
    match kind {
        Kind::Udp => Ok(Bound::Udp(UdpSocket::bind(address).await.with_context(
            || format!("{} {} 端口不可用（可能已被占用）", kind.name(), address),
        )?)),
        Kind::Tcp => Ok(Bound::Tcp(TcpListener::bind(address).await.with_context(
            || format!("{} {} 端口不可用（可能已被占用）", kind.name(), address),
        )?)),
        Kind::Doh if state.engine.config.doh_http => {
            anyhow::ensure!(
                address.ip().is_loopback(),
                "HTTP DoH behind a reverse proxy requires a loopback address"
            );
            Ok(Bound::DohHttp(
                TcpListener::bind(address).await.with_context(|| {
                    format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
                })?,
            ))
        }
        Kind::Doh => {
            state.tls.doh_config().await?;
            let socket = std::net::TcpListener::bind(address).with_context(|| {
                format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
            })?;
            socket.set_nonblocking(true)?;
            Ok(Bound::Doh(socket))
        }
        Kind::Dot => {
            state.tls.dot_config()?;
            Ok(Bound::Dot(TcpListener::bind(address).await.with_context(
                || format!("{} {} 端口不可用（可能已被占用）", kind.name(), address),
            )?))
        }
        Kind::Doq => Ok(Bound::Doq(
            quinn::Endpoint::server(state.tls.doq_config()?, address).with_context(|| {
                format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
            })?,
        )),
    }
}

fn spawn_listener(
    kind: Kind,
    address: SocketAddr,
    listener: Bound,
    state: &ApiState,
    events: &broadcast::Sender<String>,
) -> Running {
    let app = state.clone();
    let events = events.clone();
    let endpoint = if let Bound::Doq(endpoint) = &listener {
        Some(endpoint.clone())
    } else {
        None
    };
    let handle = tokio::spawn(async move {
        let result = match listener {
            Bound::Udp(socket) => transport::udp(app.engine.clone(), socket).await,
            Bound::Tcp(socket) => transport::tcp(app.engine.clone(), socket).await,
            Bound::Dot(socket) => transport::dot(app.engine.clone(), app.tls.clone(), socket).await,
            Bound::Doq(endpoint) => transport::doq(app.engine.clone(), endpoint).await,
            Bound::DohHttp(socket) => axum::serve(
                socket,
                api::doh_router(app.clone()).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(Into::into),
            Bound::Doh(socket) => {
                match app.tls.doh_config().await.and_then(|config| {
                    axum_server::from_tcp_rustls(socket, config).map_err(Into::into)
                }) {
                    Ok(server) => server
                        .serve(
                            api::doh_router(app.clone())
                                .into_make_service_with_connect_info::<SocketAddr>(),
                        )
                        .await
                        .map_err(Into::into),
                    Err(error) => Err(error),
                }
            }
        };
        if let Err(error) = result {
            tracing::error!(%error, protocol = kind.name(), "DNS listener stopped");
            let _ = events.send(
                serde_json::json!({"type":"listener_error", "protocol":kind.name(), "error":error.to_string()})
                    .to_string(),
            );
        }
    });
    Running {
        address,
        handle,
        endpoint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache::PersistentCache, resolver::Engine, store::Store};

    #[tokio::test]
    async fn listener_apply_allows_same_port_bind_ip_change() -> Result<()> {
        let db_path = std::env::temp_dir().join(format!(
            "rdns-listener-{}-{}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config: Config = toml::from_str(&format!(
            r#"
            database = {:?}
            admin = "127.0.0.1:0"
            allowed_clients = ["127.0.0.0/8"]
        "#,
            db_path
        ))?;
        let store = Store::open(&config.database).await?;
        let tls = TlsState::new(None, None).await?;
        let cache = PersistentCache::new(store.clone()).await?;
        let engine = Engine::new(config.clone(), store.clone(), cache).await?;
        let listeners = ListenerManager::new(&config);
        let state = ApiState {
            engine,
            tls,
            listeners: listeners.clone(),
        };
        let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = probe.local_addr()?.port();
        drop(probe);

        let mut settings = ListenerSettings::from_config(&config);
        settings.dns_udp = SocketSetting {
            enabled: true,
            address: SocketAddr::from(([127, 0, 0, 1], port)),
        };
        listeners
            .apply(state.clone(), settings.clone(), false)
            .await?;

        settings.dns_udp.address = SocketAddr::from(([0, 0, 0, 0], port));
        listeners
            .apply(state.clone(), settings.clone(), false)
            .await?;
        let snapshot = listeners.snapshot().await;
        assert_eq!(snapshot["running"]["dns_udp"], true);
        assert_eq!(
            snapshot["settings"]["dns_udp"]["address"],
            format!("0.0.0.0:{port}")
        );

        settings.dns_udp.enabled = false;
        listeners.apply(state, settings, false).await?;
        store.pool.close().await;
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", db_path.display()));
        Ok(())
    }
}
