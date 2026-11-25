use super::*;
use std::sync::Mutex as StdMutex;
use traffic_protocol::connection::{CaptureOutput, NativeFuture};

#[derive(Default)]
struct Observations {
    exchanges: StdMutex<Vec<(RedisExchangeEvent, bool)>>,
    degraded: StdMutex<Option<String>>,
}

struct Host(Arc<Observations>);
struct Capture(Arc<Observations>);

impl CapturedRequest for Capture {
    fn cached_response(&mut self) -> NativeFuture<'_, Option<Bytes>> {
        Box::pin(async { Ok(None) })
    }
    fn observe_response(&mut self, _response: Bytes, _reusable: bool) -> NativeFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn abort_response(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn prepare_output(
        &self,
        _output: traffic_model::trace::OutputKind,
    ) -> Option<Box<dyn CaptureOutput>> {
        None
    }
    fn complete(
        self: Box<Self>,
        event: RedisExchangeEvent,
        confirmed: bool,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            self.0.exchanges.lock().unwrap().push((event, confirmed));
            Ok(())
        })
    }
}

impl CaptureHost for Host {
    fn begin_request<'a>(
        &'a self,
        _request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision> {
        Box::pin(async move { Ok(CaptureDecision::Admitted(Box::new(Capture(self.0.clone())))) })
    }
    fn capture_push(&self, _request: PushRequest<'_>) -> Result<Box<dyn CapturedPush>> {
        anyhow::bail!("unexpected push in native writer test")
    }
    fn observe_connection(&self, _event: RedisConnectionEvent) -> NativeFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn record_error(&self, error: String) {
        panic!("{error}");
    }
    fn degrade(&self, reason: String) {
        *self.0.degraded.lock().unwrap() = Some(reason);
    }
    fn is_degraded(&self) -> bool {
        self.0.degraded.lock().unwrap().is_some()
    }
    fn degradation_reason(&self) -> Option<String> {
        self.0.degraded.lock().unwrap().clone()
    }
    fn raw_activity(&self, _side: TerminationSide) {}
}

fn context() -> ConnectionContext {
    ConnectionContext {
        client_addr: None,
        target_host: "redis.test".into(),
        target_port: 6379,
        target_addr: "redis.test:6379".into(),
        upstream_addr: "127.0.0.1:6379".into(),
    }
}

fn pending(observations: &Arc<Observations>, command: &str) -> PendingRedisExchange {
    PendingRedisExchange {
        capture: Box::new(Capture(observations.clone())),
        sequence: 1,
        command: RedisCommand {
            name: command.into(),
            args: vec![b"events".to_vec()],
        },
        recorded_args: vec![b"events".to_vec()],
        session: RedisSession {
            resp_version: 2,
            database: 0,
            username: None,
            subscriptions: Subscriptions::default(),
        },
        session_setup: false,
        replay_safe: true,
        warnings: Vec::new(),
        started: Instant::now(),
        request_started_at: Utc::now(),
        ended_at: None,
    }
}

#[tokio::test]
async fn subscription_proof_preserves_the_complete_confirmation() {
    use traffic_protocol::capture::CaptureEvidence;
    let observations = Arc::new(Observations::default());
    let response = b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n";
    record_exchange(
        Uuid::new_v4(),
        &context(),
        pending(&observations, "SUBSCRIBE"),
        RedisFrameKind::Array,
        response,
        DependencyExchangeOutcome::Response,
    )
    .await
    .unwrap();
    let exchanges = observations.exchanges.lock().unwrap();
    assert_eq!(exchanges.len(), 1);
    let (event, confirmed) = &exchanges[0];
    assert!(*confirmed);
    assert!(event.replay_safe);
    assert_eq!(
        event.response,
        traffic_model::capture::capture_body(response, response.len())
    );
    assert!(event.capture_facts().case_dependency);
    assert!(event.capture_facts().complete);
}

#[tokio::test]
async fn response_literals_require_exact_complete_resp2_binary_frames() {
    use traffic_protocol::capture::CaptureEvidence;

    for (response, kind, version, expected) in [
        (
            b"+OK\r\n".as_slice(),
            RedisFrameKind::SimpleString,
            2,
            Some("redis_ok"),
        ),
        (b"$-1\r\n", RedisFrameKind::Null, 2, Some("redis_nil_bulk")),
        (b"*-1\r\n", RedisFrameKind::Null, 2, None),
        (b"$-1\r\n", RedisFrameKind::Null, 3, None),
        (b"+ok\r\n", RedisFrameKind::SimpleString, 2, None),
    ] {
        let observations = Arc::new(Observations::default());
        let mut exchange = pending(&observations, "GET");
        exchange.session.resp_version = version;
        record_exchange(
            Uuid::new_v4(),
            &context(),
            exchange,
            kind,
            response,
            DependencyExchangeOutcome::Response,
        )
        .await
        .unwrap();

        let mut event = observations.exchanges.lock().unwrap().pop().unwrap().0;
        assert_eq!(event.capture_facts().recording_response_literal, expected);
        event.response.encoding = "utf8";
        event.response.data = String::from_utf8(response.to_vec()).unwrap();
        assert_eq!(event.capture_facts().recording_response_literal, None);
    }
}

#[tokio::test]
async fn disconnected_client_close_does_not_invent_peer_completion() {
    for (engine_stop, pending_request) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let observations = Arc::new(Observations::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let _peer = client.unwrap();
        let stream = accepted.unwrap().0;
        let control = ConnectionControl::new(&stream).unwrap();
        control.reset().unwrap();
        assert_eq!(
            control.shutdown_write().unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
        let (_read, write) = stream.into_split();
        let termination = ConnectionTermination::default();
        if engine_stop {
            termination.observe_engine_stop();
        }
        let exchanges = if pending_request {
            vec![pending(&observations, "GET")]
        } else {
            vec![]
        };
        let (tx, rx) = mpsc::channel(1);
        tx.send(RedisOutput::Terminated {
            exchanges,
            response: Bytes::new(),
            reset: false,
        })
        .await
        .unwrap();
        drop(tx);
        let result = run_ordered_writer(
            Arc::new(Mutex::new(write)),
            rx,
            Arc::new(Host(observations.clone())),
            context(),
            Uuid::new_v4(),
            termination.clone(),
            control,
        )
        .await;
        assert_eq!(result.unwrap(), (0, !pending_request));
        assert!(termination.peer_snapshot().is_none());
        if pending_request {
            let exchanges = observations.exchanges.lock().unwrap();
            assert_eq!(exchanges.len(), 1);
            assert!(!exchanges[0].0.replay_safe);
            assert_eq!(exchanges[0].0.outcome, DependencyExchangeOutcome::Response);
            assert!(!exchanges[0].0.parse_warnings.is_empty());
        }
    }
}
