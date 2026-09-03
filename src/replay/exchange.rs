use std::future::Future;
use std::io::ErrorKind;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, sleep, timeout_at};

use crate::dependency::DependencyExchangeOutcome;

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

    pub(super) async fn delay_response(self) {
        if !self.duration.is_zero() {
            sleep(self.duration).await;
        }
    }

    pub(super) async fn await_client_termination<R>(self, reader: &mut R) -> Result<Duration>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if !self.outcome.is_client_terminated() {
            return Err(anyhow!(
                "cannot await client termination for a response exchange"
            ));
        }
        let started = Instant::now();
        let deadline = started + self.duration + CLIENT_TERMINATION_LATE_TOLERANCE;
        let mut probe = [0_u8; 1];
        let termination = timeout_at(deadline, reader.read(&mut probe)).await;
        let elapsed = started.elapsed();
        match termination {
            Ok(Ok(0)) => {}
            Ok(Err(error)) if is_connection_termination(error.kind()) => {}
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
        if elapsed + CLIENT_TERMINATION_EARLY_TOLERANCE < self.duration {
            return Err(anyhow!(
                "client terminated dependency connection too early: observed {}ms, recorded {}ms",
                elapsed.as_millis(),
                self.duration.as_millis()
            ));
        }
        Ok(elapsed)
    }

    pub(super) async fn await_client_termination_signal<F>(self, termination: F) -> Result<Duration>
    where
        F: Future<Output = Result<()>>,
    {
        if !self.outcome.is_client_terminated() {
            return Err(anyhow!(
                "cannot await client termination for a response exchange"
            ));
        }
        let started = Instant::now();
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
        if elapsed + CLIENT_TERMINATION_EARLY_TOLERANCE < self.duration {
            return Err(anyhow!(
                "client terminated dependency connection too early: observed {}ms, recorded {}ms",
                elapsed.as_millis(),
                self.duration.as_millis()
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
