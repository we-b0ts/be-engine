//! Observe downstream connection termination without closing it on the client's behalf.
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Instant;

use crate::dependency::TerminationSide;
pub(crate) use crate::dependency::termination::ObservedTermination;
use crate::dependency::termination::{ConnectionControl, ConnectionTermination};
use crate::dependency::{DependencyTermination, TerminationKind, TerminationScope};
mod delivery;
mod diagnosis;
pub(crate) use diagnosis::observed_since;
use diagnosis::{IoDiagnosis, IoLayer, IoOperation};
#[cfg(test)]
mod tests;
pub(crate) use delivery::{DeliveryProgress, FlushReceipt, PrefixDelivery};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub(crate) struct ClientTermination {
    observation: ConnectionTermination,
    control: Option<ConnectionControl>,
    delivery: DeliveryProgress,
    server_write_half_closed: Arc<AtomicBool>,
    input_after_server_end: Arc<AtomicBool>,
    watch_raw_input: Arc<AtomicBool>,
    events: tokio::sync::watch::Sender<u64>,
    io_diagnosis: IoDiagnosis,
}

impl Default for ClientTermination {
    fn default() -> Self {
        Self {
            observation: ConnectionTermination::default(),
            control: None,
            delivery: DeliveryProgress::default(),
            server_write_half_closed: Arc::new(AtomicBool::new(false)),
            input_after_server_end: Arc::new(AtomicBool::new(false)),
            watch_raw_input: Arc::new(AtomicBool::new(false)),
            events: tokio::sync::watch::channel(0).0,
            io_diagnosis: IoDiagnosis::default(),
        }
    }
}

impl ClientTermination {
    pub(crate) fn with_control(stream: &tokio::net::TcpStream) -> io::Result<Self> {
        Ok(Self::with_connection_control(ConnectionControl::new(
            stream,
        )?))
    }

    pub(crate) fn with_connection_control(control: ConnectionControl) -> Self {
        Self {
            control: Some(control),
            ..Self::default()
        }
    }

    pub(crate) fn watch_raw_input_after_server_end(&self) {
        self.watch_raw_input.store(true, Ordering::Release);
    }

    /// Hyper's half_close(true) suppresses reads while a response is pending.
    /// Peek independently without consuming HTTP/TLS input or manufacturing EOF.
    pub(crate) async fn wait_for_cancellation(&self) -> io::Error {
        let Some(control) = &self.control else {
            return std::future::pending().await;
        };
        let Ok(stream) = control.clone_stream() else {
            return std::future::pending().await;
        };
        loop {
            // Buffered HTTP/TLS input can keep MSG_PEEK readable even after
            // RST. SO_ERROR supplies independent typed evidence without
            // consuming payload; EPIPE alone remains insufficient.
            if let Ok(Some(error)) = stream.take_error()
                && matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                )
            {
                self.observe_io_error(IoLayer::Transport, IoOperation::Peek, &error);
                if self.cancelled().is_some() || self.engine_stopped() {
                    return error;
                }
            }
            match stream.peek(&mut [0; 1]).await {
                Ok(0) => {
                    self.observation.observe_client_eof();
                    self.notify();
                    // FIN is only a half-close. Keep watching SO_ERROR for an
                    // independently observed later reset without busy polling EOF.
                    loop {
                        if self.engine_stopped() {
                            return io::Error::other("HTTP transport ended during engine cleanup");
                        }
                        if self.cancelled().is_some() {
                            return io::ErrorKind::ConnectionReset.into();
                        }
                        if let Ok(Some(error)) = stream.take_error() {
                            self.observe_io_error(IoLayer::Transport, IoOperation::Peek, &error);
                            if self.cancelled().is_some() {
                                return error;
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
                Ok(_) => {
                    if self.watch_raw_input.load(Ordering::Acquire)
                        && self.server_write_half_closed()
                    {
                        self.input_after_server_end.store(true, Ordering::Release);
                        self.notify();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => {
                    self.observe_io_error(IoLayer::Transport, IoOperation::Peek, &error);
                    if self.cancelled().is_some() || self.engine_stopped() {
                        return error;
                    }
                    return self.wait_for_engine_stop().await;
                }
            }
        }
    }

    async fn wait_for_engine_stop(&self) -> io::Error {
        while !self.engine_stopped() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        io::Error::other("HTTP transport ended during engine cleanup")
    }

    pub(crate) async fn serve<F>(&self, connection: F) -> anyhow::Result<()>
    where
        F: std::future::Future<Output = Result<(), hyper::Error>>,
    {
        tokio::select! {
            result = connection => result.map_err(Into::into),
            error = self.wait_for_cancellation() => Err(error.into()),
        }
    }
    pub(crate) fn cancelled_at(&self) -> Option<Instant> {
        self.cancelled().map(|observed| observed.at)
    }

    pub(crate) fn observed(&self) -> Option<ObservedTermination> {
        self.observation
            .peer_snapshot()
            .filter(|observed| observed.termination.side == TerminationSide::Client)
    }

    pub(crate) fn cancelled(&self) -> Option<ObservedTermination> {
        self.observation.connection_end(TerminationSide::Client)
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.events.subscribe()
    }

    fn notify(&self) {
        self.events
            .send_modify(|sequence| *sequence = sequence.saturating_add(1));
    }

    pub(crate) fn connection_observation(&self) -> &ConnectionTermination {
        &self.observation
    }

    pub(crate) fn engine_stopped(&self) -> bool {
        self.observation.engine_stopped()
    }
    pub(crate) fn delivery(&self) -> DeliveryProgress {
        self.delivery.clone()
    }

    pub(crate) fn server_write_half_closed(&self) -> bool {
        self.server_write_half_closed.load(Ordering::Acquire)
    }

    pub(crate) fn mark_server_write_half_closed(&self) {
        self.server_write_half_closed.store(true, Ordering::Release);
    }

    pub(crate) fn input_after_server_end(&self) -> bool {
        self.input_after_server_end.load(Ordering::Acquire)
    }

    /// The connection owner keeps its existing registration while draining the
    /// opposite direction, without retaining any case's dependency reservation.
    pub(crate) async fn retain_read_half(&self) -> io::Result<()> {
        use tokio::io::AsyncReadExt;
        if !self.server_write_half_closed() || self.engine_stopped() {
            return Ok(());
        }
        let mut stream = self
            .control
            .as_ref()
            .ok_or_else(|| io::Error::other("HTTP downstream control is unavailable"))?
            .clone_stream()?;
        let mut bytes = [0; 4096];
        while !self.engine_stopped() {
            match stream.read(&mut bytes).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if connection_ended(&error) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn propagate_server(&self, end: DependencyTermination) -> io::Result<()> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| io::Error::other("HTTP downstream connection control is unavailable"))?;
        match (end.kind, end.scope) {
            (TerminationKind::Eof, TerminationScope::WriteHalf) => {
                control.shutdown_write()?;
                self.mark_server_write_half_closed();
                Ok(())
            }
            (TerminationKind::Reset, TerminationScope::Connection) => control.reset(),
            _ => Err(io::Error::other("unsupported HTTP server termination")),
        }
    }

    fn observe_error(&self, error: &io::Error) {
        if self.observation.observe_client_io_error(error) {
            self.notify();
        }
    }
}

pub(crate) struct ObservedClientIo<T> {
    inner: T,
    termination: ClientTermination,
    layer: IoLayer,
}

impl<T> ObservedClientIo<T> {
    pub(crate) fn new(inner: T, termination: ClientTermination) -> Self {
        Self {
            inner,
            termination,
            layer: IoLayer::Http,
        }
    }

    /// Observe raw socket errors before TLS can translate them. Only the outer
    /// HTTP writer can certify that a response prefix has flushed through TLS.
    pub(crate) fn transport(inner: T, termination: ClientTermination) -> Self {
        Self {
            inner,
            termination,
            layer: IoLayer::Transport,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedClientIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let has_capacity = buf.remaining() > 0;
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(()))
                if buf.filled().len() > before && self.termination.server_write_half_closed() =>
            {
                self.termination
                    .input_after_server_end
                    .store(true, Ordering::Release);
                self.termination.notify();
            }
            Poll::Ready(Ok(())) if has_capacity && buf.filled().len() == before => {
                self.termination.observation.observe_client_eof();
                self.termination.notify();
            }
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                self.termination
                    .observe_io_error(self.layer, IoOperation::Read, error);
                // rustls reports a TCP FIN without close_notify as typed EOF.
                // HTTP framing still rejects any incomplete request, while a
                // complete request may receive its response after write-half FIN.
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(error)) => {
                self.termination
                    .observe_io_error(self.layer, IoOperation::Read, error)
            }
            _ => {}
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedClientIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.termination
                .observe_io_error(self.layer, IoOperation::Write, error);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &result {
            self.termination
                .observe_io_error(self.layer, IoOperation::Flush, error);
        }
        if matches!(result, Poll::Ready(Ok(()))) && self.layer == IoLayer::Http {
            self.termination.delivery.flushed();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}
