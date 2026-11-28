use super::*;
use crate::termination::{ClientTermination, FlushReceipt, ObservedClientIo};
use std::{io, sync::Mutex};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use traffic_model::{DependencyExchangeOutcome, TerminationKind, trace::OutputKind};

#[derive(Default)]
struct Host {
    record: Mutex<Option<crate::events::HttpExchangeEvent>>,
    outputs: Mutex<Vec<OutputKind>>,
}

impl StreamHost for Host {
    fn activity(&self) {}
    fn source_stop_requested(&self) -> bool {
        false
    }
    fn managed_session(&self) -> bool {
        true
    }
    fn output(&self, output: OutputKind) {
        self.outputs.lock().unwrap().push(output);
    }
    fn finish(&self, event: crate::events::HttpExchangeEvent) {
        *self.record.lock().unwrap() = Some(event);
    }
    fn invalidate(&self, _: &str, _: u128, _: serde_json::Value, _: bool) {}
}

struct ClosedWrite;

impl AsyncWrite for ClosedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn drop_preserves_only_the_prefix_flushed_before_a_proven_client_cancel() {
    for (fin, failed_write) in [(true, true), (false, true), (true, false)] {
        let termination = ClientTermination::default();
        let host = Arc::new(Host::default());
        let time = Utc::now();
        let mut capture = Capture::new(CaptureContext {
            host: host.clone(),
            started: Instant::now(),
            termination: termination.clone(),
            redact_headers: Vec::new(),
            drain_timeout: std::time::Duration::from_secs(1),
            requires_complete_body_rewrite: false,
            event: crate::events::HttpExchangeEvent {
                outcome: DependencyExchangeOutcome::Response,
                id: uuid::Uuid::new_v4(),
                timestamp: time,
                request_started_at: time,
                client_addr: None,
                upstream_addr: None,
                scheme: "http".into(),
                method: "GET".into(),
                uri: "/stream".into(),
                authority: Some("api.test".into()),
                request_headers: Default::default(),
                request_body: Bytes::new().into(),
                response_status: Some(200),
                response_headers: Some(Default::default()),
                response_body: None,
                response_stream: None,
                discovered_tcp_targets: Vec::new(),
                duration_ms: 0,
                error: None,
            },
        });
        let progress = termination.delivery();
        let delivered = capture.recorded_stream.as_ref().unwrap().0.clone();
        let receipt = || FlushReceipt::new(|| {}, || {}).with_timestamp(delivered.clone());
        progress.observe_flush(receipt());
        capture.bytes(b"delivered");
        progress.observe_flush(receipt());
        progress.flushed();
        capture.bytes(b"undelivered");
        if fin {
            termination.connection_observation().observe_client_eof();
        }
        if failed_write {
            let mut writer = ObservedClientIo::new(ClosedWrite, termination);
            assert_eq!(
                writer.write(b"pending").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        drop(capture);

        let record = host.record.lock().unwrap().take().unwrap();
        let stream = record.response_stream.unwrap();
        assert_eq!(stream.complete, fin && failed_write);
        if fin && failed_write {
            let end = record.outcome.termination().unwrap();
            assert_eq!(end.kind, TerminationKind::Cancelled);
            assert_eq!(stream.chunks.len(), 1);
            assert_eq!(record.response_body.unwrap().stored_len, b"delivered".len());
            assert_eq!(
                *host.outputs.lock().unwrap(),
                [OutputKind::Terminated { termination: end }]
            );
            assert!(record.error.is_none());
        } else {
            assert!(record.error.is_some());
            assert!(host.outputs.lock().unwrap().is_empty());
        }
    }
}
