//! Raw TCP termination remains independent of the WebSocket close handshake.
use super::{ClientTransportEnd, ReaderEvent, ReaderObservation, WebSocket};
use crate::dependency::termination::ConnectionControl;
use anyhow::{Context, Result, ensure};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_tungstenite::{
    MaybeTlsStream,
    tungstenite::{Error, error::ProtocolError},
};

#[derive(Clone)]
pub(super) struct Control {
    tcp: ConnectionControl,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    requested_at: Option<Instant>,
    terminal_at: Option<Instant>,
}

impl Control {
    pub(super) fn new(socket: &WebSocket) -> Result<Self> {
        let stream = match socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream,
            MaybeTlsStream::Rustls(stream) => stream.get_ref().0,
            _ => anyhow::bail!("WebSocket transport has no supported raw termination control"),
        };
        Ok(Self {
            tcp: ConnectionControl::new(stream)
                .context("cannot retain WebSocket transport control")?,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// Timestamp the reader fact before its queue send can block. A delayed
    /// consumer cannot turn an earlier Target close into our terminal input.
    pub(super) fn note_terminal(&self, at: Instant) -> bool {
        let mut state = self.state.lock().expect("transport termination state");
        state.terminal_at.get_or_insert(at);
        state.requested_at.is_some_and(|requested| at >= requested)
    }

    pub(super) fn send(&self, end: ClientTransportEnd) -> Result<Instant> {
        // Publish the intent before the syscall can wake the existing reader.
        // A failed syscall is still a failed execution, never a completed input.
        let mut state = self.state.lock().expect("transport termination state");
        ensure!(
            state.terminal_at.is_none(),
            "Target ended before recorded client transport input"
        );
        let at = Instant::now();
        state.requested_at = Some(at);
        match end {
            ClientTransportEnd::Eof => self.tcp.shutdown_write(),
            ClientTransportEnd::Reset => self.tcp.reset(),
        }
        .context("Target raw transport termination failed")?;
        Ok(at)
    }

    pub(super) async fn wait_peer_end(&self, tx: &mpsc::Sender<ReaderObservation>) {
        let result = async {
            let mut stream = self.tcp.clone_stream()?;
            let mut buffer = [0; 8192];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::NotConnected
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        .await;
        let event = match result {
            Ok(()) => ReaderEvent::Closed,
            Err(_) => {
                ReaderEvent::Error("physical WebSocket termination could not be observed".into())
            }
        };
        let _ = tx.send(ReaderObservation::now(event)).await;
    }
}

pub(super) fn physical_end(error: &Error) -> bool {
    matches!(
        error,
        Error::ConnectionClosed
            | Error::AlreadyClosed
            | Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)
    ) || matches!(error, Error::Io(error) if matches!(error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected))
}
