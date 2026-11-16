use crate::store::Store;
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use axum_server::tls_rustls::RustlsConfig;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{io::Cursor, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock};

pub struct TlsState {
    paths: RwLock<Option<(PathBuf, PathBuf)>>,
    doh: RwLock<Option<RustlsConfig>>,
    dot: ArcSwapOption<ServerConfig>,
    doq: ArcSwapOption<quinn::ServerConfig>,
    reload_lock: Mutex<()>,
}

impl TlsState {
    pub async fn new(cert_path: Option<PathBuf>, key_path: Option<PathBuf>) -> Result<Arc<Self>> {
        let state = Arc::new(Self {
            paths: RwLock::new(None),
            doh: RwLock::new(None),
            dot: ArcSwapOption::empty(),
            doq: ArcSwapOption::empty(),
            reload_lock: Mutex::new(()),
        });
        match (cert_path, key_path) {
            (Some(cert), Some(key)) => {
                let configs = prepare_configs(&cert, &key).await?;
                state.apply_configs(configs).await;
                *state.paths.write().await = Some((cert, key));
            }
            (None, None) => {}
            _ => anyhow::bail!("certificate and private key paths must be configured together"),
        }
        Ok(state)
    }

    pub async fn reload(&self) -> Result<()> {
        let _guard = self.reload_lock.lock().await;
        let (cert, key) = self
            .paths
            .read()
            .await
            .clone()
            .context("certificate paths are not configured")?;
        let configs = prepare_configs(&cert, &key).await?;
        self.apply_configs(configs).await;
        Ok(())
    }

    pub async fn paths(&self) -> Option<(PathBuf, PathBuf)> {
        self.paths.read().await.clone()
    }

    pub async fn set_paths(
        &self,
        store: &Store,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<()> {
        anyhow::ensure!(
            cert_path.is_absolute() && key_path.is_absolute(),
            "certificate and private key paths must be absolute"
        );
        let _guard = self.reload_lock.lock().await;
        let configs = prepare_configs(&cert_path, &key_path).await?;
        store.set_certificate_paths(&cert_path, &key_path).await?;
        self.apply_configs(configs).await;
        *self.paths.write().await = Some((cert_path, key_path));
        Ok(())
    }

    pub async fn doh_config(&self) -> Result<RustlsConfig> {
        self.doh
            .read()
            .await
            .clone()
            .context("configure certificate paths before enabling DoH")
    }

    pub fn dot_config(&self) -> Result<Arc<ServerConfig>> {
        self.dot
            .load_full()
            .context("configure certificate paths before enabling DoT")
    }

    pub fn doq_config(&self) -> Result<quinn::ServerConfig> {
        self.doq
            .load_full()
            .map(|config| (*config).clone())
            .context("configure certificate paths before enabling DoQ")
    }

    async fn apply_configs(
        &self,
        (doh, dot, doq): (Arc<ServerConfig>, Arc<ServerConfig>, quinn::ServerConfig),
    ) {
        let mut current = self.doh.write().await;
        if let Some(config) = current.as_ref() {
            config.reload_from_config(doh);
        } else {
            *current = Some(RustlsConfig::from_config(doh));
        }
        self.dot.store(Some(dot));
        self.doq.store(Some(Arc::new(doq)));
    }
}

async fn prepare_configs(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(Arc<ServerConfig>, Arc<ServerConfig>, quinn::ServerConfig)> {
    let (certs, key) = read_pem(cert_path, key_path).await?;
    let doh = Arc::new(make_config(
        &certs,
        &key,
        &[b"h2".as_slice(), b"http/1.1".as_slice()],
    )?);
    let dot = Arc::new(make_config(&certs, &key, &[b"dot"])?);
    let doq = make_quic_config(&certs, &key)?;
    Ok((doh, dot, doq))
}

async fn read_pem(
    cert: &PathBuf,
    key: &PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = tokio::fs::read(cert)
        .await
        .with_context(|| format!("reading {}", cert.display()))?;
    let key_bytes = tokio::fs::read(key)
        .await
        .with_context(|| format!("reading {}", key.display()))?;
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut Cursor::new(cert_bytes)).collect::<std::io::Result<_>>()?;
    anyhow::ensure!(!certs.is_empty(), "certificate chain is empty");
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
        .context("private key not found")?;
    Ok((certs, key))
}

fn make_config(
    certs: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.to_vec(), key.clone_key())
        .context("certificate and key do not match")?;
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    Ok(config)
}

fn make_quic_config(
    certs: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let config = make_config(certs, key, &[b"doq"])?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(config)?,
    )))
}
