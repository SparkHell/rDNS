use crate::{resolver::Engine, tls::TlsState};
use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;

pub async fn udp(engine: Arc<Engine>, socket: UdpSocket) -> Result<()> {
    let socket = Arc::new(socket);
    let limit = Arc::new(Semaphore::new(256));
    let mut buffer = [0u8; 4096];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let packet = buffer[..length].to_vec();
        let engine = engine.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match engine.answer(&packet, peer, "udp").await {
                Ok(answer) => {
                    let max_len = hickory_proto::op::Message::from_vec(&packet)
                        .ok()
                        .map(|query| query.max_payload().max(512) as usize)
                        .unwrap_or(512);
                    if answer.len() <= max_len {
                        let _ = socket.send_to(&answer, peer).await;
                    } else if let Ok(mut message) = hickory_proto::op::Message::from_vec(&answer) {
                        message.metadata.truncation = true;
                        message.answers.clear();
                        message.authorities.clear();
                        message.additionals.clear();
                        if let Ok(short) = message.to_vec()
                            && short.len() <= max_len
                        {
                            let _ = socket.send_to(&short, peer).await;
                        }
                    }
                }
                Err(error) => tracing::debug!(%error, %peer, "invalid UDP query"),
            }
        });
    }
}

pub async fn tcp(engine: Arc<Engine>, listener: TcpListener) -> Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    let limit = Arc::new(Semaphore::new(512));
    loop {
        while connections.try_join_next().is_some() {}
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = dns_stream(stream, peer, engine, "tcp").await {
                tracing::debug!(%error, %peer, "DNS TCP connection ended");
            }
        });
    }
}

pub async fn dot(engine: Arc<Engine>, tls: Arc<TlsState>, listener: TcpListener) -> Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    let limit = Arc::new(Semaphore::new(512));
    loop {
        while connections.try_join_next().is_some() {}
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        let tls = tls.clone();
        connections.spawn(async move {
            let _permit = permit;
            let Ok(config) = tls.dot_config() else {
                return;
            };
            let acceptor = TlsAcceptor::from(config);
            match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    if let Err(error) = dns_stream(stream, peer, engine, "dot").await {
                        tracing::debug!(%error, %peer, "DoT connection ended");
                    }
                }
                _ => tracing::debug!(%peer, "DoT handshake failed"),
            }
        });
    }
}

async fn dns_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    engine: Arc<Engine>,
    protocol: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let length = match tokio::time::timeout(Duration::from_secs(30), stream.read_u16()).await {
            Ok(Ok(length)) if length > 0 => length as usize,
            _ => return Ok(()),
        };
        let mut message = vec![0u8; length];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut message)).await??;
        let response = engine.answer(&message, peer, protocol).await?;
        anyhow::ensure!(
            response.len() <= u16::MAX as usize,
            "DNS response too large"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await?;
            stream.flush().await
        })
        .await??;
    }
}

pub async fn doq(engine: Arc<Engine>, endpoint: quinn::Endpoint) -> Result<()> {
    let connections = Arc::new(Semaphore::new(512));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(5), incoming).await
            else {
                return;
            };
            let peer = connection.remote_address();
            let streams = Arc::new(Semaphore::new(64));
            while let Ok(Ok((mut send, mut receive))) =
                tokio::time::timeout(Duration::from_secs(30), connection.accept_bi()).await
            {
                let Ok(stream_permit) = streams.clone().try_acquire_owned() else {
                    let _ = send.reset(0x3u32.into());
                    continue;
                };
                let engine = engine.clone();
                tokio::spawn(async move {
                    let _stream_permit = stream_permit;
                    let Ok(frame) = receive.read_to_end(65537).await else {
                        return;
                    };
                    if frame.len() < 2 {
                        let _ = send.reset(0x2u32.into());
                        return;
                    }
                    let length = u16::from_be_bytes([frame[0], frame[1]]) as usize;
                    if length != frame.len() - 2
                        || (frame.len() >= 4 && (frame[2] != 0 || frame[3] != 0))
                    {
                        let _ = send.reset(0x2u32.into());
                        return;
                    }
                    if let Ok(response) = engine.answer(&frame[2..], peer, "doq").await
                        && response.len() <= u16::MAX as usize
                    {
                        let _ = send.write_u16(response.len() as u16).await;
                        let _ = send.write_all(&response).await;
                        let _ = send.finish();
                    }
                });
            }
        });
    }
    Ok(())
}
