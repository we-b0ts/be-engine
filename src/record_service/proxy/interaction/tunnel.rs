//! Transparent upgraded TCP forwarding retains real peer FIN/RST in each direction.
use crate::dependency::termination::ConnectionControl;
use bytes::Bytes;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::io;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

fn transport(upgraded: Upgraded) -> io::Result<(TcpStream, Bytes, ConnectionControl)> {
    let parts = upgraded
        .downcast::<TokioIo<TcpStream>>()
        .map_err(|_| io::Error::other("recording ingress upgrade has no raw TCP transport"))?;
    let stream = parts.io.into_inner();
    let control = ConnectionControl::new(&stream)?;
    Ok((stream, parts.read_buf, control))
}

pub(super) async fn forward(downstream: Upgraded, upstream: Upgraded) -> io::Result<()> {
    let (downstream, client_prefix, client_control) = transport(downstream)?;
    let (upstream, server_prefix, server_control) = transport(upstream)?;
    let (mut client_read, mut client_write) = tokio::io::split(downstream);
    let (mut server_read, mut server_write) = tokio::io::split(upstream);
    // A failed opposite-direction write cannot cancel the read that establishes
    // the real peer end. Only that independent read may mirror FIN or RST.
    let client = direction(
        client_prefix,
        &mut client_read,
        &mut server_write,
        &server_control,
    );
    let server = direction(
        server_prefix,
        &mut server_read,
        &mut client_write,
        &client_control,
    );
    tokio::pin!(client, server);
    tokio::select! {
        result = &mut client => finish_direction(result, &mut server).await,
        result = &mut server => finish_direction(result, &mut client).await,
    }
}

#[derive(Debug)]
enum PeerEnd {
    Fin,
    Reset,
}

async fn finish_direction(
    first: io::Result<PeerEnd>,
    other: impl std::future::Future<Output = io::Result<PeerEnd>>,
) -> io::Result<()> {
    if matches!(first, Ok(PeerEnd::Reset)) {
        // A proven read reset has already been mirrored. It ends both halves;
        // do not interpret errors from that engine-owned reset as a peer input.
        return Ok(());
    }
    let second = other.await;
    first?;
    second?;
    Ok(())
}

async fn direction<R, W>(
    prefix: Bytes,
    reader: &mut R,
    writer: &mut W,
    destination: &ConnectionControl,
) -> io::Result<PeerEnd>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Hyper may already have read upgraded bytes with the HTTP header. They
    // precede all new TCP reads and must remain part of the transparent stream.
    writer.write_all(&prefix).await?;
    let mut buffer = [0; 16 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                destination.shutdown_write()?;
                return Ok(PeerEnd::Fin);
            }
            Ok(count) => writer.write_all(&buffer[..count]).await?,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                destination.reset()?;
                return Ok(PeerEnd::Reset);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
