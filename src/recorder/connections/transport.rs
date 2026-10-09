use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{DependencyConnectionGuard, DependencyConnections};

/// Keep registration with the transport, including HTTP CONNECT upgrades and TLS.
pub(crate) struct DependencyIo {
    stream: TcpStream,
    _registration: DependencyConnectionGuard,
}

impl DependencyIo {
    pub(crate) fn new(
        stream: TcpStream,
        registry: &DependencyConnections,
        protocol: &'static str,
    ) -> io::Result<Self> {
        let registration = registry.register(protocol, &[&stream])?;
        Ok(Self {
            stream,
            _registration: registration,
        })
    }
}

impl AsyncRead for DependencyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DependencyIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
