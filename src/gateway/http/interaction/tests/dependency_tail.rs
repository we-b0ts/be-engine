//! Real HTTP peers keep dependency capture independent of the primary stream lifetime.

use super::*;
use crate::recorder::CaseContext;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

const FIRST: &str = "data: first\n\n";

struct Fixture {
    state: AppState,
    address: SocketAddr,
    release: Option<oneshot::Sender<()>>,
    source: JoinHandle<()>,
    dependency: JoinHandle<()>,
    proxy: JoinHandle<()>,
    gateway: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.source.abort();
        self.dependency.abort();
        self.proxy.abort();
        self.gateway.abort();
    }
}

impl Fixture {
    async fn new(
        temp: &Path,
        primary_eof: bool,
        request_budget_ms: u64,
        process_owned: bool,
    ) -> Self {
        Self::with_primary_suffix(temp, primary_eof, request_budget_ms, process_owned, "").await
    }

    async fn with_primary_suffix(
        temp: &Path,
        primary_eof: bool,
        request_budget_ms: u64,
        process_owned: bool,
        suffix: &'static str,
    ) -> Self {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dependency = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dependency_address = dependency.local_addr().unwrap();
        let mut settings = config(temp, source.local_addr().unwrap());
        settings.http_gateway.request_timeout_ms = request_budget_ms;
        settings.http_gateway.interaction.request_timeout_ms = request_budget_ms;
        settings.http_gateway.interaction.max_duration_ms = request_budget_ms * 2;
        settings.http_gateway.interaction.business_idle_ms = request_budget_ms;
        settings.recording.case_dependency_post_response_window_ms = 0;
        settings.recording.case_dependency_drain_timeout_ms = 20;
        if process_owned {
            settings.process_owned_dependencies =
                vec![crate::BackgroundDependencyRuleConfig::Http {
                    name: "synthetic-process-stream".into(),
                    authorities: vec![dependency_address.to_string()],
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/dependency".into()],
                    source_revision: "a".repeat(64),
                    source_evidence: "fixture/worker.rs:1 periodic synthetic stream".into(),
                }];
        }
        let state = AppState::new(settings).await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy = tokio::spawn({
            let state = state.clone();
            async move {
                crate::proxy::http::run_with_listener(state, proxy)
                    .await
                    .unwrap();
            }
        });
        let (release, released) = oneshot::channel();
        let dependency = tokio::spawn(async move {
            let (mut socket, _) = dependency.accept().await.unwrap();
            read_head(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n").await.unwrap();
            released.await.unwrap();
            // The engine must preserve this real socket beyond its observation budget.
            socket.write_all(b"3\r\ntwo\r\n0\r\n\r\n").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let source = tokio::spawn(async move {
            let (mut primary, _) = source.accept().await.unwrap();
            read_head(&mut primary).await;
            let socket = TcpStream::connect(proxy_address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket))
                    .await
                    .unwrap();
            let connection = tokio::spawn(connection);
            let mut response = sender
                .send_request(
                    Request::builder()
                        .uri(format!("http://{dependency_address}/dependency"))
                        .header("host", dependency_address.to_string())
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response
                    .body_mut()
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap(),
                "one"
            );
            // Dependency admission precedes primary headers and stream adoption.
            primary.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{FIRST}\r\n", FIRST.len()).as_bytes()).await.unwrap();
            if !suffix.is_empty() {
                primary
                    .write_all(format!("{:x}\r\n{suffix}\r\n", suffix.len()).as_bytes())
                    .await
                    .unwrap();
            }
            if primary_eof {
                primary.write_all(b"0\r\n\r\n").await.unwrap();
                primary.shutdown().await.unwrap();
            }
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "two"
            );
            drop(sender);
            connection.await.unwrap().unwrap();
        });
        let (address, gateway) = gateway(state.clone()).await;
        Self {
            state,
            address,
            release: Some(release),
            source,
            dependency,
            proxy,
            gateway,
        }
    }

    async fn client(&self, explicit_stream: bool) -> TcpStream {
        self.client_with_method(explicit_stream, "GET").await
    }

    async fn client_with_method(&self, explicit_stream: bool, method: &str) -> TcpStream {
        let mut client = TcpStream::connect(self.address).await.unwrap();
        let accept = if explicit_stream {
            "Accept: text/event-stream\r\n"
        } else {
            ""
        };
        client
            .write_all(
                format!(
                    "{method} /events HTTP/1.1\r\nHost: {}\r\n{accept}Content-Length: 0\r\nConnection: close\r\n\r\n",
                    self.address
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let mut length = Vec::new();
        while !length.ends_with(b"\r\n") {
            length.push(client.read_u8().await.unwrap());
        }
        let length =
            usize::from_str_radix(std::str::from_utf8(&length).unwrap().trim(), 16).unwrap();
        assert_eq!(length, FIRST.len());
        let mut chunk = vec![0; length + 2];
        client.read_exact(&mut chunk).await.unwrap();
        assert_eq!(chunk, format!("{FIRST}\r\n").as_bytes());
        client
    }

    fn case(&self) -> CaseContext {
        self.state.capture_dependency_targets().cases[0].0.clone()
    }

    async fn finish_dependency(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
        (&mut self.source).await.unwrap();
        (&mut self.dependency).await.unwrap();
    }
}

async fn recorded_dependency(directory: &Path) -> Value {
    let dependencies = tokio::fs::read_to_string(directory.join("dependencies.jsonl"))
        .await
        .unwrap();
    let events: Vec<Value> = dependencies
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events.len(),
        1,
        "the original case must retain its late event"
    );
    let event = events.into_iter().next().unwrap();
    assert_eq!(event["event_type"], "http_exchange");
    assert_eq!(event["response_stream"]["complete"], true);
    assert_eq!(event["response_body"]["data"], "b25ldHdv");
    assert!(event["error"].is_null());
    event
}

async fn stream_tail(primary_eof: bool) {
    let temp = tempdir().unwrap();
    let mut fixture = Fixture::new(temp.path(), primary_eof, 2_000, false).await;
    let mut client = fixture.client(!primary_eof).await;
    let case = fixture.case();
    if primary_eof {
        let mut remainder = Vec::new();
        timeout(
            Duration::from_millis(300),
            client.read_to_end(&mut remainder),
        )
        .await
        .expect("primary EOF must reach its client while the dependency is still pending")
        .unwrap();
        assert!(remainder.ends_with(b"0\r\n\r\n"));
    } else {
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
    }
    assert!(
        !fixture
            .state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(90))
            .await,
        "a pending exchange without data must outlive both idle and writer drain windows"
    );
    assert_eq!(fixture.state.recording_lifecycle_phase(), "running");
    assert!(!*fixture.state.inner.interactions.source_stop.borrow());
    assert!(!fixture.state.recorder().case_dir(&case).exists());
    fixture.finish_dependency().await;
    let directory = published(&fixture.state).await;
    assert_eq!(directory, fixture.state.recorder().case_dir(&case));
    let event = recorded_dependency(&directory).await;
    let report: Value = serde_json::from_slice(
        &tokio::fs::read(directory.join("dependency-tail-observation.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["outcome"], "quiet");
    assert_eq!(report["inventory_complete"], true);
    assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
    assert_eq!(report["completed_refs"][0]["exchange_id"], event["id"]);
    let expected: Value = serde_json::from_slice(
        &tokio::fs::read(directory.join("expected-response.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    assert_eq!(
        expected["interaction"]["end"]["reason"],
        if primary_eof {
            "server_eof"
        } else {
            "client_close"
        }
    );
    assert!(!*fixture.state.inner.interactions.source_stop.borrow());
}

#[tokio::test]
async fn primary_client_cancel_retains_pending_http_dependency_beyond_writer_drain() {
    timeout(Duration::from_secs(5), stream_tail(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn primary_stream_eof_delivers_immediately_and_retains_pending_http_dependency() {
    timeout(Duration::from_secs(5), stream_tail(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn stream_tail_deadline_requests_supervisor_stop_and_preserves_pending_evidence() {
    timeout(Duration::from_secs(5), async {
        let temp = tempdir().unwrap();
        let mut fixture = Fixture::new(temp.path(), true, 200, false).await;
        let mut client = fixture.client(false).await;
        let case = fixture.case();
        client.read_to_end(&mut Vec::new()).await.unwrap();
        assert!(
            !fixture
                .state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_millis(350))
                .await,
            "observation expiry must retain ownership until live dependency capture ends"
        );
        assert_eq!(fixture.state.recording_lifecycle_phase(), "quiescing");
        timeout(
            Duration::from_millis(100),
            fixture.state.inner.active_cases.wait_for_quiescing(),
        )
        .await
        .expect("the recording supervisor must be notified while dependency capture is pending");
        assert!(!fixture.state.recorder().case_failed_dir(&case).exists());
        let mut fallback = TcpStream::connect(fixture.address).await.unwrap();
        fallback
            .write_all(
                format!(
                    "GET /another HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    fixture.address
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        fallback.read_to_end(&mut response).await.unwrap();
        assert!(
            response.ends_with(b"busy"),
            "quarantined admission must fall back"
        );
        fixture.finish_dependency().await;
        assert!(
            fixture
                .state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let directory = fixture.state.recorder().case_failed_dir(&case);
        recorded_dependency(&directory).await;
        let error: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("recording-error.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error["reason"], "dependency_tail_observation_timeout");
        let report: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("dependency-tail-observation.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["outcome"], "request_deadline");
        assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
        assert!(*fixture.state.inner.interactions.source_stop.borrow());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn primary_timeout_precedes_secondary_dependency_drop_and_notifies_supervisor() {
    timeout(Duration::from_secs(5), async {
        let temp = tempdir().unwrap();
        let mut fixture = Fixture::new(temp.path(), false, 200, false).await;
        let _client = fixture.client_with_method(false, "POST").await;
        let case = fixture.case();
        timeout(
            Duration::from_secs(1),
            fixture.state.wait_for_interaction_source_stop(),
        )
        .await
        .expect("a primary timeout must request Source cleanup before waiting for dependencies");
        assert_eq!(fixture.state.recording_lifecycle_phase(), "quiescing");
        assert!(!fixture.state.recorder().case_failed_dir(&case).exists());
        // Cancellation of Source's dependency reader can arrive after the
        // primary deadline. It must not replace that deadline as the root cause.
        fixture.state.invalidate_active_case(
            case.id,
            crate::recorder::CaseInvalidation::new(
                "http_stream_capture_incomplete",
                "HTTP dependency response body was dropped before EOF without observed client termination",
            ),
        );
        fixture.finish_dependency().await;
        assert!(
            fixture
                .state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let directory = fixture.state.recorder().case_failed_dir(&case);
        recorded_dependency(&directory).await;
        let error: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("recording-error.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error["reason"], "interaction_max_duration");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("MaxDuration"));
        assert!(message.contains("http_stream_capture_incomplete"));
        assert!(message.contains("without observed client termination"));
        let expected: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("expected-response.json.invalid"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected["interaction"]["end"]["reason"], "max_duration");
        assert_eq!(expected["interaction"]["end"]["clean"], false);
        assert_eq!(expected["interaction"]["end"]["pending"], serde_json::json!([0]));
        assert!(!fixture.state.recorder().case_dir(&case).exists());
        assert!(*fixture.state.inner.interactions.source_stop.borrow());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn timeout_with_partial_primary_sse_drains_late_dependency_before_failed_publication() {
    timeout(Duration::from_secs(5), async {
        let temp = tempdir().unwrap();
        let mut fixture =
            Fixture::with_primary_suffix(temp.path(), false, 200, false, "data: unfinished\n")
                .await;
        let _client = fixture.client_with_method(false, "POST").await;
        let case = fixture.case();
        timeout(
            Duration::from_secs(1),
            fixture.state.wait_for_interaction_source_stop(),
        )
        .await
        .expect("the incomplete primary must request supervisor cleanup");
        assert!(!fixture.state.recorder().case_failed_dir(&case).exists());
        assert!(fixture.state.inner.active_cases.has_case(case.id));
        let publication = fixture
            .state
            .inner
            .active_cases
            .register_interaction_publication(case.id)
            .unwrap();
        assert!(fixture.state.invalidate_interaction_reservation(
            Some(case.id),
            crate::recorder::CaseInvalidation::new(
                "interaction_reservation_lost",
                "lease lost during failed primary drain",
            ),
        ));
        fixture.finish_dependency().await;
        assert!(
            fixture
                .state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let directory = fixture.state.recorder().case_failed_dir(&case);
        let dependency = recorded_dependency(&directory).await;
        let error: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("recording-error.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error["reason"], "interaction_max_duration");
        assert_eq!(
            error["message"]
                .as_str()
                .unwrap()
                .matches("lease lost during failed primary drain")
                .count(),
            1
        );
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("stream observation ended within a partial message")
        );
        let report: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("dependency-tail-observation.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
        assert_eq!(report["completed_refs"][0]["exchange_id"], dependency["id"]);
        assert_eq!(report["inventory_complete"], true);
        assert!(!directory.join("expected-response.json").exists());
        assert!(!fixture.state.recorder().case_dir(&case).exists());
        assert!(publication.begin().await.finalized);
        assert!(!fixture.state.invalidate_interaction_reservation(
            Some(case.id),
            crate::recorder::CaseInvalidation::new("late_loss", "after failed publication"),
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn proven_process_http_stream_does_not_hold_primary_case_and_records_late_event_globally() {
    timeout(Duration::from_secs(5), async {
        let temp = tempdir().unwrap();
        let mut fixture = Fixture::new(temp.path(), true, 2_000, true).await;
        let mut client = fixture.client(false).await;
        client.read_to_end(&mut Vec::new()).await.unwrap();
        let directory = published(&fixture.state).await;
        assert!(
            !fixture.source.is_finished() && !fixture.dependency.is_finished(),
            "a live process-owned HTTP stream must not prevent primary case publication"
        );
        let report: Value = serde_json::from_slice(
            &tokio::fs::read(directory.join("dependency-tail-observation.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["outcome"], "quiet");
        assert!(report["completed_refs"].as_array().unwrap().is_empty());
        let dependencies = tokio::fs::read_to_string(directory.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert!(dependencies.trim().is_empty());
        assert_eq!(fixture.state.recording_lifecycle_phase(), "running");
        assert!(!*fixture.state.inner.interactions.source_stop.borrow());
        fixture.finish_dependency().await;
        assert!(
            !fixture
                .state
                .recorder()
                .finish_run_after_runtime(true)
                .await
                .unwrap()
        );
        let global = tokio::fs::read_to_string(
            fixture
                .state
                .recorder()
                .run_dir
                .join("global-dependencies.jsonl"),
        )
        .await
        .unwrap();
        let events: Vec<Value> = global
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "http_exchange");
        assert_eq!(events[0]["global_dependency_reason"], "background_rule");
        assert_eq!(events[0]["response_stream"]["complete"], true);
        assert_eq!(events[0]["response_body"]["data"], "b25ldHdv");
        assert!(events[0]["error"].is_null());
        assert!(
            tokio::fs::read_to_string(directory.join("dependencies.jsonl"))
                .await
                .unwrap()
                .trim()
                .is_empty()
        );
    })
    .await
    .unwrap();
}
