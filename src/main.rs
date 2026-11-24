mod access;
mod adguard;
mod api;
mod cache;
mod config;
mod features;
mod geoip;
mod gfwlist;
mod portal;
mod query_log;
mod resolver;
mod root_zone;
mod runtime;
mod service;
mod store;
mod tls;
mod transport;
mod upstream;

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
    let mut args: Vec<String> = std::env::args().collect();
    let mut instance = String::new();
    if args.get(1).is_some_and(|arg| arg == "--instance") {
        anyhow::ensure!(
            args.len() >= 5,
            "--instance <name> requires a service command"
        );
        instance = args.remove(2);
        args.remove(1);
        anyhow::ensure!(
            args.iter().skip(1).any(|arg| arg == "service"),
            "--instance requires a service command"
        );
    }
    const USAGE: &str = "rdns [config.toml] | rdns service install [config.toml] | rdns --config <config.toml> service install | rdns [--instance <name>] service <start|stop|restart|status|enable|disable|uninstall> | rdns init-admin <config.toml> <username>";
    let (config_path, init_user) = match args.as_slice() {
        [_] => (PathBuf::from("config.toml"), None),
        [_, flag] if matches!(flag.as_str(), "--help" | "-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        [_, flag, path, command, action]
            if flag == "--config" && command == "service" && action == "install" =>
        {
            return service::install(&PathBuf::from(path), &instance);
        }
        [_, path] => (PathBuf::from(path), None),
        [_, command, action] if command == "service" && action == "install" => {
            service::install(&PathBuf::from("config.toml"), &instance)?;
            return Ok(());
        }
        [_, command, action, path] if command == "service" && action == "install" => {
            service::install(&PathBuf::from(path), &instance)?;
            return Ok(());
        }
        [_, command, action] if command == "service" => return service::manage(action, &instance),
        [_, command, path, user] if command == "init-admin" => {
            (PathBuf::from(path), Some(user.as_str()))
        }
        _ => anyhow::bail!("{USAGE}"),
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

    engine.start_cache_jobs().await?;

    let mut changes = engine.features.subscription_updates.subscribe();
    let publish_subscriptions = async {
        while changes.changed().await.is_ok() {
            listeners.publish(serde_json::json!({"type":"features.changed"}));
        }
    };
    let maintenance_engine = engine.clone();
    let maintenance = async move {
        let mut last_subscriptions = tokio::time::Instant::now();
        loop {
            maintenance_engine.features.maintain().await;
            if last_subscriptions.elapsed() >= Duration::from_secs(3600) {
                let _ = maintenance_engine
                    .store
                    .prune(maintenance_engine.config.query_log_days)
                    .await;
                api::refresh_all(&maintenance_engine).await;
                last_subscriptions = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let publish_stats = async {
        let mut ticks = tokio::time::interval(Duration::from_secs(3));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            if listeners.has_subscribers() {
                listeners.publish(
                    serde_json::json!({"type":"cache", "stats":engine.cache_stats().await}),
                );
            }
        }
    };
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await?;
        Ok::<(), std::io::Error>(())
    };
    let admin = axum::serve(
        admin_listener,
        api::admin_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    tokio::select! {
        result = admin => result.context("admin listener")?,
        _ = publish_stats => {},
        _ = publish_subscriptions => {},
        result = maintenance => result?,
        result = shutdown => result?,
    }
    engine.store.query_log.flush().await?;
    Ok(())
}
