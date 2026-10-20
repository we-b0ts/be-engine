use std::future::Future;
use std::io::ErrorKind;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, sleep, timeout_at};

use crate::dependency::DependencyExchangeOutcome;
use crate::dependency::termination::ConnectionControl;
use crate::dependency::{TerminationKind, TerminationScope};

const CLIENT_TERMINATION_EARLY_TOLERANCE: Duration = Duration::from_millis(50);
const CLIENT_TERMINATION_LATE_TOLERANCE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ReplayExchangeStatus {
    #[default]
    Available,
    Responding,
    AwaitingClientTermination,
    Consumed,
    Failed,
}

impl ReplayExchangeStatus {
    pub(super) fn is_available(self) -> bool {
        self == Self::Available
    }

    pub(super) fn is_consumed(self) -> bool {
        self == Self::Consumed
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ReplayExchangeTiming {
    duration: Duration,
    outcome: DependencyExchangeOutcome,
}

impl ReplayExchangeTiming {
    pub(super) fn from_recorded(duration_ms: u64, outcome: DependencyExchangeOutcome) -> Self {
        Self {
            duration: Duration::from_millis(duration_ms),
            outcome,
        }
    }

    pub(super) fn outcome(self) -> DependencyExchangeOutcome {
        self.outcome
    }

    pub(super) fn termination_deadline(self, started: Instant) -> Instant {
        started + self.duration + CLIENT_TERMINATION_LATE_TOLERANCE
    }

    pub(super) fn response_deadline(self, started: Instant) -> Instant {
        started + self.duration
    }

    pub(super) fn validate_client_termination(self, elapsed: Duration) -> Result<()> {
        if elapsed + CLIENT_TERMINATION_EARLY_TOLERANCE < self.duration {
            return Err(anyhow!(
                "client terminated dependency connection too early: observed {}ms, recorded {}ms",
                elapsed.as_millis(),
                self.duration.as_millis()
            ));
        }
        if elapsed > self.duration + CLIENT_TERMINATION_LATE_TOLERANCE {
            return Err(anyhow!(
                "client did not terminate dependency connection within recorded timing window"
            ));
        }
        Ok(())
    }

    pub(super) fn validate_client_termination_kind(
        self,
        kind: TerminationKind,
        scope: TerminationScope,
    ) -> Result<()> {
        if let Some(expected) = self.outcome.termination() {
            anyhow::ensure!(
                expected.kind == kind && expected.scope == scope,
                "client dependency termination mechanism or scope differs from recording"
            );
        }
        Ok(())
    }

    pub(super) async fn delay_response(self) {
        if !self.duration.is_zero() {
            sleep(self.duration).await;
        }
    }

    /// Observe Target while a recorded server action is pending. Extra inputs
    /// are returned to the protocol owner rather than silently discarded.
    pub(super) async fn await_server_deadline<R>(
        self,
        reader: &mut R,
        started: Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        anyhow::ensure!(
            self.outcome.is_server_terminated(),
            "server deadline requires server-origin termination"
        );
        let deadline = self.response_deadline(started);
        let mut inputs = Vec::new();
        let mut bytes = [0; 1024];
        loop {
            let count = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return Ok(inputs),
                result = reader.read(&mut bytes) => result?,
            };
            anyhow::ensure!(
                count != 0,
                "Target closed before the recorded dependency server termination"
            );
            anyhow::ensure!(
                inputs.len().saturating_add(count) <= max_bytes,
                "dependency input exceeded its pending termination capture bound"
            );
            inputs.extend_from_slice(&bytes[..count]);
        }
    }

    /// The dependency server owns only a recorded server-origin termination.
    /// Client-origin outcomes must instead await the Target's actual action.
    #[cfg(test)]
    pub(super) async fn terminate_server<W>(
        self,
        writer: &mut W,
        control: &ConnectionControl,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        self.terminate_server_at(writer, control, Instant::now())
            .await
    }

    pub(super) async fn terminate_server_at<W>(
        self,
        writer: &mut W,
        control: &ConnectionControl,
        started: Instant,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        anyhow::ensure!(
            self.outcome.is_server_terminated(),
            "cannot close a dependency on behalf of its client"
        );
        let end = self.outcome.termination().expect("server termination");
        tokio::time::sleep_until(started + self.duration).await;
        match (end.kind, end.scope) {
            (TerminationKind::Eof, TerminationScope::WriteHalf) => {
                writer.shutdown().await?;
                Ok(())
            }
            (TerminationKind::Reset, TerminationScope::Connection) => Ok(control.reset()?),
            _ => Err(anyhow!("unsupported server termination kind or scope")),
        }
    }

    #[cfg(test)]
    pub(super) async fn await_client_termination<R>(self, reader: &mut R) -> Result<Duration>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        self.await_client_termination_at(reader, Instant::now())
            .await
    }

    pub(super) async fn await_client_termination_at<R>(
        self,
        reader: &mut R,
        started: Instant,
    ) -> Result<Duration>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if !self.outcome.is_client_terminated() {
            return Err(anyhow!(
                "cannot await client termination for a response exchange"
            ));
        }
        let deadline = started + self.duration + CLIENT_TERMINATION_LATE_TOLERANCE;
        let mut probe = [0_u8; 1];
        let termination = timeout_at(deadline, reader.read(&mut probe)).await;
        let elapsed = started.elapsed();
        match termination {
            Ok(Ok(0)) => self.validate_client_termination_kind(
                TerminationKind::Eof,
                TerminationScope::WriteHalf,
            )?,
            Ok(Err(error)) if error.kind() == ErrorKind::UnexpectedEof => self
                .validate_client_termination_kind(
                    TerminationKind::Eof,
                    TerminationScope::WriteHalf,
                )?,
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ) =>
            {
                self.validate_client_termination_kind(
                    TerminationKind::Reset,
                    TerminationScope::Connection,
                )?
            }
            Ok(Ok(_)) => {
                return Err(anyhow!(
                    "client sent another dependency request instead of terminating the connection"
                ));
            }
            Ok(Err(error)) => {
                return Err(error).map_err(|error| {
                    anyhow!("failed while awaiting recorded client termination: {error}")
                });
            }
            Err(_) => {
                return Err(anyhow!(
                    "client did not terminate dependency connection within recorded timing window"
                ));
            }
        }
        self.validate_client_termination(elapsed)?;
        Ok(elapsed)
    }

    pub(super) async fn await_client_termination_signal_at<F>(
        self,
        termination: F,
        started: Instant,
    ) -> Result<Duration>
    where
        F: Future<Output = Result<()>>,
    {
        if !self.outcome.is_client_terminated() {
            return Err(anyhow!(
                "cannot await client termination for a response exchange"
            ));
        }
        let deadline = started + self.duration + CLIENT_TERMINATION_LATE_TOLERANCE;
        match timeout_at(deadline, termination).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(anyhow!(
                    "client did not terminate dependency connection within recorded timing window"
                ));
            }
        }
        let elapsed = started.elapsed();
        self.validate_client_termination(elapsed)?;
        Ok(elapsed)
    }
}

pub(super) fn is_connection_termination(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

/// A failed verification is reported before waiting here. Releasing a test's
/// resources belongs to its supervisor, not to a simulated peer's watchdog.
pub(super) async fn retain_connection<R>(reader: &mut R)
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut bytes = [0; 1024];
    loop {
        match reader.read(&mut bytes).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DependencyTermination, TerminationSide};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn delays_normal_response_by_recorded_duration() {
        let timing = ReplayExchangeTiming::from_recorded(20, DependencyExchangeOutcome::Response);
        let started = Instant::now();
        timing.delay_response().await;
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[tokio::test]
    async fn consumes_client_termination_only_after_eof() {
        let timing =
            ReplayExchangeTiming::from_recorded(20, DependencyExchangeOutcome::ClientTerminated);
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let close = tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            writer.shutdown().await.unwrap();
        });
        let elapsed = timing.await_client_termination(&mut reader).await.unwrap();
        close.await.unwrap();
        assert!(elapsed >= Duration::from_millis(20));
    }

    #[tokio::test]
    async fn rejects_client_termination_that_is_too_early() {
        let timing =
            ReplayExchangeTiming::from_recorded(200, DependencyExchangeOutcome::ClientTerminated);
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.shutdown().await.unwrap();
        let error = timing
            .await_client_termination(&mut reader)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("too early"));
    }

    #[tokio::test]
    async fn reset_expectation_rejects_a_client_write_half_eof() {
        let timing = ReplayExchangeTiming::from_recorded(
            0,
            DependencyExchangeOutcome::Terminated(DependencyTermination {
                side: TerminationSide::Client,
                kind: TerminationKind::Reset,
                scope: TerminationScope::Connection,
            }),
        );
        let (mut peer, mut server) = tokio::io::duplex(16);
        peer.shutdown().await.unwrap();
        let error = timing
            .await_client_termination(&mut server)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("mechanism or scope"));
    }

    #[tokio::test]
    async fn response_prefix_does_not_restart_the_termination_clock() {
        let timing =
            ReplayExchangeTiming::from_recorded(100, DependencyExchangeOutcome::ClientTerminated);
        let started = Instant::now();
        let (mut peer, mut server) = tokio::io::duplex(16);
        server.write_all(b"prefix").await.unwrap();
        let mut prefix = [0; 6];
        peer.read_exact(&mut prefix).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        peer.shutdown().await.unwrap();
        timing
            .await_client_termination_at(&mut server, started)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn server_fin_preserves_the_reverse_direction() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
        let (client, accepted) = tokio::join!(client, listener.accept());
        let mut client = client.unwrap();
        let mut stream = accepted.unwrap().0;
        let control = ConnectionControl::new(&stream).unwrap();
        let timing = ReplayExchangeTiming::from_recorded(
            0,
            DependencyExchangeOutcome::Terminated(DependencyTermination {
                side: TerminationSide::Server,
                kind: TerminationKind::Eof,
                scope: TerminationScope::WriteHalf,
            }),
        );
        timing
            .terminate_server(&mut stream, &control)
            .await
            .unwrap();
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        client.write_all(b"reverse").await.unwrap();
        let mut bytes = [0; 7];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"reverse");
    }

    #[tokio::test]
    async fn server_action_cannot_consume_an_earlier_target_close() {
        let timing = ReplayExchangeTiming::from_recorded(
            100,
            DependencyExchangeOutcome::Terminated(DependencyTermination {
                side: TerminationSide::Server,
                kind: TerminationKind::Reset,
                scope: TerminationScope::Connection,
            }),
        );
        let (mut client, mut server) = tokio::io::duplex(32);
        client.shutdown().await.unwrap();
        let error = timing
            .await_server_deadline(&mut server, Instant::now(), 32)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("before the recorded"));
    }

    #[tokio::test]
    async fn server_wait_returns_extra_protocol_inputs_and_limits_memory() {
        let timing = ReplayExchangeTiming::from_recorded(
            10,
            DependencyExchangeOutcome::Terminated(DependencyTermination {
                side: TerminationSide::Server,
                kind: TerminationKind::Eof,
                scope: TerminationScope::WriteHalf,
            }),
        );
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(b"next request").await.unwrap();
        let bytes = timing
            .await_server_deadline(&mut server, Instant::now(), 32)
            .await
            .unwrap();
        assert_eq!(bytes, b"next request");
        client.write_all(b"too many").await.unwrap();
        assert!(
            timing
                .await_server_deadline(&mut server, Instant::now(), 3)
                .await
                .is_err()
        );
    }
}
