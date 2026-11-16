use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum_server::tls_rustls::RustlsConfig;
use quinn::{Endpoint, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{io::Cursor, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

pub struct TlsState {
    cert_path: PathBuf,
    key_path: PathBuf,
    pub doh: RustlsConfig,
    pub dot: ArcSwap<ServerConfig>,
    pub doq: Endpoint,
    reload_lock: Mutex<()>,
}

impl TlsState {
    pub async fn new(
        cert_path: PathBuf,
        key_path: PathBuf,
        doq_addr: SocketAddr,
    ) -> Result<Arc<Self>> {
        let (certs, key) = read_pem(&cert_path, &key_path).await?;
        let doh = RustlsConfig::from_config(Arc::new(make_config(
            &certs,
            &key,
            &[b"h2".as_slice(), b"http/1.1".as_slice()],
        )?));
        let dot = ArcSwap::from_pointee(make_config(&certs, &key, &[b"dot"])?);
        let doq_config = make_quic_config(&certs, &key)?;
        let doq = Endpoint::server(doq_config, doq_addr).context("binding DoQ")?;
        Ok(Arc::new(Self {
            cert_path,
            key_path,
            doh,
            dot,
            doq,
            reload_lock: Mutex::new(()),
        }))
    }

    pub async fn reload(&self) -> Result<()> {
        let _guard = self.reload_lock.lock().await;
        let (certs, key) = read_pem(&self.cert_path, &self.key_path).await?;
        // Construct every protocol configuration before changing any live listener.
        let doh = Arc::new(make_config(
            &certs,
            &key,
            &[b"h2".as_slice(), b"http/1.1".as_slice()],
        )?);
        let dot = Arc::new(make_config(&certs, &key, &[b"dot"])?);
        let doq = make_quic_config(&certs, &key)?;
        self.doh.reload_from_config(doh);
        self.dot.store(dot);
        self.doq.set_server_config(Some(doq));
        Ok(())
    }
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
