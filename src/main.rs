mod api;
mod cache;
mod config;
mod resolver;
mod runtime;
mod service;
mod store;
mod tls;
mod transport;

use anyhow::{Context, Result};
use std::{path::PathBuf, time::Duration};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rdns=info,warn")),
        )
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("installing rustls ring crypto provider"))?;
    let args: Vec<String> = std::env::args().collect();
    let (config_path, init_user) = match args.as_slice() {
        [_] => (PathBuf::from("config.toml"), None),
        [_, path] => (PathBuf::from(path), None),
        [_, command, action] if command == "service" && action == "install" => {
            service::install(&PathBuf::from("config.toml"))?;
            return Ok(());
        }
        [_, command, action, path] if command == "service" && action == "install" => {
            service::install(&PathBuf::from(path))?;
            return Ok(());
        }
        [_, command, path, user] if command == "init-admin" => {
            (PathBuf::from(path), Some(user.as_str()))
        }
        _ => anyhow::bail!(
            "usage: rdns [config.toml] | rdns service install [config.toml] | rdns init-admin <config.toml> <username> (password on stdin)"
        ),
    };
    let config = config::Config::load(&config_path)?;
    let store = store::Store::open(&config.database).await?;
    if let Some(user) = init_user {
        use std::io::Read;
        let mut password = String::new();
        std::io::stdin().read_to_string(&mut password)?;
        store
            .create_account(user, password.trim_end_matches(['\r', '\n']), "admin")
            .await?;
        println!("administrator created: {user}");
        return Ok(());
    }
    let (cert_path, key_path) = store
        .certificate_paths()
        .await?
        .map(|(cert, key)| (Some(cert), Some(key)))
        .unwrap_or_else(|| (config.certificate.clone(), config.private_key.clone()));
    let tls = tls::TlsState::new(cert_path, key_path).await?;
    let cache = cache::PersistentCache::new(store.clone()).await?;
    let engine = resolver::Engine::new(config.clone(), store, cache.clone()).await?;
    let listeners = runtime::ListenerManager::new(&config);
    let state = api::ApiState {
        engine: engine.clone(),
        tls: tls.clone(),
        listeners: listeners.clone(),
    };
    let admin_listener = TcpListener::bind(config.admin)
        .await
        .context("binding admin API")?;
    let initial = engine
        .store
        .listener_settings()
        .await?
        .unwrap_or_else(|| runtime::ListenerSettings::from_config(&config));
    listeners.apply(state.clone(), initial, false).await?;
    tracing::info!(admin=%config.admin, "rDns starting");

    let maintenance_engine = engine.clone();
    let maintenance = async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            let _ = maintenance_engine
                .store
                .prune(maintenance_engine.config.query_log_days)
                .await;
            api::refresh_all(&maintenance_engine).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let admin = axum::serve(admin_listener, api::admin_router(state));
    tokio::select! {
        result = admin => result.context("admin listener")?,
        result = maintenance => result?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }
    Ok(())
}
