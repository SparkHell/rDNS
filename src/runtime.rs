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
        let mut bound = HashMap::new();
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
            if current.get(&kind).is_some_and(|entry| {
                entry.address == setting.address && !entry.handle.is_finished()
            }) {
                continue;
            }
            let address = setting.address;
            let listener = match kind {
                Kind::Udp => Bound::Udp(UdpSocket::bind(address).await.with_context(|| {
                    format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
                })?),
                Kind::Tcp => Bound::Tcp(TcpListener::bind(address).await.with_context(|| {
                    format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
                })?),
                Kind::Doh => {
                    state.tls.doh_config().await?;
                    let socket = std::net::TcpListener::bind(address).with_context(|| {
                        format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
                    })?;
                    socket.set_nonblocking(true)?;
                    Bound::Doh(socket)
                }
                Kind::Dot => {
                    state.tls.dot_config()?;
                    Bound::Dot(TcpListener::bind(address).await.with_context(|| {
                        format!("{} {} 端口不可用（可能已被占用）", kind.name(), address)
                    })?)
                }
                Kind::Doq => Bound::Doq(
                    quinn::Endpoint::server(state.tls.doq_config()?, address).with_context(
                        || format!("{} {} 端口不可用（可能已被占用）", kind.name(), address),
                    )?,
                ),
            };
            bound.insert(kind, listener);
        }
        if persist {
            state.engine.store.set_listener_settings(&desired).await?;
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
                if let Some(endpoint) = entry.endpoint {
                    endpoint.close(0u32.into(), b"listener changed");
                }
                entry.handle.abort();
                let _ = entry.handle.await;
            }
            if let Some(listener) = bound.remove(&kind) {
                let app = state.clone();
                let events = self.events.clone();
                let endpoint = if let Bound::Doq(endpoint) = &listener {
                    Some(endpoint.clone())
                } else {
                    None
                };
                let handle = tokio::spawn(async move {
                    let result = match listener {
                        Bound::Udp(socket) => transport::udp(app.engine.clone(), socket).await,
                        Bound::Tcp(socket) => transport::tcp(app.engine.clone(), socket).await,
                        Bound::Dot(socket) => {
                            transport::dot(app.engine.clone(), app.tls.clone(), socket).await
                        }
                        Bound::Doq(endpoint) => transport::doq(app.engine.clone(), endpoint).await,
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
                        let _ = events.send(serde_json::json!({"type":"listener_error", "protocol":kind.name(), "error":error.to_string()}).to_string());
                    }
                });
                current.insert(
                    kind,
                    Running {
                        address: setting.address,
                        handle,
                        endpoint,
                    },
                );
            }
        }
        *self.settings.write().await = desired;
        let snapshot = serde_json::json!({"type":"listeners", "settings":*self.settings.read().await, "running":Kind::ALL.iter().map(|kind| (kind.name(), current.get(kind).is_some_and(|entry| !entry.handle.is_finished()))).collect::<HashMap<_,_>>()});
        let _ = self.events.send(snapshot.to_string());
        Ok(())
    }
}
