mod api;
mod config;
mod resolver;
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
    let tls = tls::TlsState::new(
        config.certificate.clone(),
        config.private_key.clone(),
        config.doq,
    )
    .await?;
    let engine = resolver::Engine::new(config.clone(), store).await?;
    let state = api::ApiState {
        engine: engine.clone(),
        tls: tls.clone(),
    };
    let admin_listener = TcpListener::bind(config.admin)
        .await
        .context("binding admin API")?;
    tracing::info!(dns_udp=%config.dns_udp, dns_tcp=%config.dns_tcp, doh=%config.doh, dot=%config.dot, doq=%config.doq, admin=%config.admin, "rDns starting");

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
    let doh = axum_server::bind_rustls(config.doh, tls.doh.clone()).serve(
        api::doh_router(state.clone())
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    let admin = axum::serve(admin_listener, api::admin_router(state));
    tokio::select! {
        result = transport::udp(engine.clone()) => result?,
        result = transport::tcp(engine.clone()) => result?,
        result = transport::dot(engine.clone(), tls.clone()) => result?,
        result = transport::doq(engine, tls) => result?,
        result = doh => result.context("DoH listener")?,
        result = admin => result.context("admin listener")?,
        result = maintenance => result?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }
    Ok(())
}
