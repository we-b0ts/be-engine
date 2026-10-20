//! Verify native Motan close mechanisms and retain the reverse direction.
use super::*;

pub(super) async fn wait_for_connection_close(
    incoming: &mut mpsc::Receiver<IncomingEvent>,
    expected: Option<crate::dependency::DependencyTermination>,
) -> Result<()> {
    match incoming.recv().await {
        Some(IncomingEvent::Frame(_)) => Err(anyhow!(
            "client sent another dependency request instead of terminating the connection"
        )),
        Some(IncomingEvent::Closed(Err(error)))
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| is_connection_termination(error.kind()))
            }) =>
        {
            anyhow::ensure!(
                !expected.is_some_and(|end| end.kind == crate::dependency::TerminationKind::Eof),
                "client reset Motan connection instead of recorded write-half EOF"
            );
            Ok(())
        }
        Some(IncomingEvent::Closed(Ok(()))) => {
            anyhow::ensure!(
                !expected.is_some_and(|end| end.kind == crate::dependency::TerminationKind::Reset),
                "client closed Motan write half instead of recorded reset"
            );
            Ok(())
        }
        Some(IncomingEvent::Closed(result)) => result,
        None => Err(anyhow!(
            "Motan reader ended without observed peer termination"
        )),
    }
}

pub(super) async fn retain(incoming: &mut mpsc::Receiver<IncomingEvent>) {
    while let Some(event) = incoming.recv().await {
        if matches!(event, IncomingEvent::Closed(_)) {
            break;
        }
    }
}

pub(super) async fn await_server_end(
    incoming: &mut mpsc::Receiver<IncomingEvent>,
    deadline: Instant,
) -> Result<()> {
    tokio::select! {
        biased;
        event = incoming.recv() => match event {
            Some(IncomingEvent::Frame(_)) => Err(anyhow!("Target pipelined another Motan request before recorded server termination; native termination batch replay is unsupported")),
            Some(IncomingEvent::Closed(_)) => Err(anyhow!("Target closed Motan connection before recorded server termination")),
            None => Err(anyhow!("Motan reader ended without observed peer termination")),
        },
        _ = tokio::time::sleep_until(deadline) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{
        DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
    };

    #[tokio::test]
    async fn early_target_eof_cannot_satisfy_a_server_termination() {
        let (sender, mut incoming) = mpsc::channel(1);
        sender.send(IncomingEvent::Closed(Ok(()))).await.unwrap();
        let error = await_server_end(&mut incoming, Instant::now() + Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("before recorded server termination")
        );
    }

    #[tokio::test]
    async fn missing_reader_is_not_peer_termination_evidence() {
        let (sender, mut incoming) = mpsc::channel(1);
        drop(sender);
        assert!(
            wait_for_connection_close(&mut incoming, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fin_and_reset_remain_distinct_for_client_termination() {
        let (sender, mut incoming) = mpsc::channel(1);
        sender.send(IncomingEvent::Closed(Ok(()))).await.unwrap();
        let reset = DependencyTermination {
            side: TerminationSide::Client,
            kind: TerminationKind::Reset,
            scope: TerminationScope::Connection,
        };
        assert!(
            wait_for_connection_close(&mut incoming, Some(reset))
                .await
                .is_err()
        );
        let (sender, mut incoming) = mpsc::channel(1);
        sender
            .send(IncomingEvent::Closed(Err(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            )
            .into())))
            .await
            .unwrap();
        let eof = DependencyTermination {
            side: TerminationSide::Client,
            kind: TerminationKind::Eof,
            scope: TerminationScope::WriteHalf,
        };
        assert!(
            wait_for_connection_close(&mut incoming, Some(eof))
                .await
                .is_err()
        );
    }
}
