use anyhow::{Context, Result};
use hickory_proto::op::Message;
use quinn::crypto::rustls::QuicClientConfig;
use std::{io::Cursor, net::SocketAddr, sync::Arc};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("installing rustls provider"))?;
    let mut args = std::env::args().skip(1);
    let addr: SocketAddr = args.next().context("DoQ address required")?.parse()?;
    let certificate = args.next().context("certificate path required")?;
    let bytes = std::fs::read(certificate)?;
    let cert = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .next()
        .context("no certificate")??;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    let mut query = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["internal", "example"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    send.write_u16(query.len() as u16).await?;
    send.write_all(&query).await?;
    send.finish()?;
    let frame = receive.read_to_end(65537).await?;
    anyhow::ensure!(
        frame.len() > 2 && u16::from_be_bytes([frame[0], frame[1]]) as usize == frame.len() - 2,
        "DoQ framing invalid"
    );
    let answer = Message::from_vec(&frame[2..])?;
    anyhow::ensure!(
        answer.metadata.id == 0 && !answer.answers.is_empty(),
        "DoQ answer invalid"
    );
    let ip: std::net::IpAddr = "192.0.2.10".parse()?;
    anyhow::ensure!(
        answer
            .answers
            .iter()
            .any(|record| record.data.ip_addr() == Some(ip)),
        "DoQ A record missing"
    );
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    println!("PASS: DoQ");
    Ok(())
}
