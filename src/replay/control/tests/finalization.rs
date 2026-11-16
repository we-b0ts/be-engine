//! Focused Case acceptance retains independent startup and whole-run debt.
use super::*;
use crate::replay::test_support::recording as fixtures;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Fixture {
    runtime: Arc<ReplayRuntime>,
    cases: Vec<String>,
    report: PathBuf,
    _temp: tempfile::TempDir,
}

fn body(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false})
}

impl Fixture {
    async fn new(count: usize) -> Self {
        Self::load(count, None).await
    }

    async fn load(count: usize, unused_with_lazy_loading: Option<bool>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let recorder = crate::Recorder::new(temp.path().join("recordings"))
            .await
            .unwrap();
        fixtures::append(&recorder,&json!({"event_type":"redis_exchange","connection_id":Uuid::new_v4(),
            "sequence":1,"target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
            "command":"GET","args":[body("startup")],"response_kind":"bulk_string", "response":body("$1\r\nx\r\n"),
            "replay_safe":true}),false).await;
        fixtures::append(
            &recorder,
            &json!({"event_type":"http_exchange","method":"POST","uri":"/startup",
            "authority":"dependency.test","request_body":body(""),"response_body":body("ok")}),
            false,
        )
        .await;
        let mut cases = Vec::new();
        for index in 0..count {
            let case = crate::recorder::CaseContext {
                id: Uuid::from_u128(index as u128 + 1),
                rule_name: "focused".into(),
                uri_group: None,
            };
            for (name, value) in [
                ("admission.json", json!({"fixture":true})),
                (
                    "request.json",
                    json!({"method":"GET","uri":"/api","timestamp":Utc::now(),"headers":{},"body":body("")}),
                ),
                (
                    "expected-response.json",
                    json!({"status":200,"headers":{},"body":body("ok")}),
                ),
            ] {
                recorder.write_case_json(&case, name, &value).await.unwrap();
            }
            if unused_with_lazy_loading.is_some() {
                let redis = Uuid::new_v4();
                for value in [
                    json!({"event_type":"mysql_exchange","connection_id":Uuid::new_v4(),
                        "query_sequence":1,"target_host":"mysql.test","target_port":3306,
                        "sql":"UPDATE notes SET seen = 1 WHERE id = 2"}),
                    json!({"event_type":"redis_exchange","connection_id":redis,"sequence":1,
                        "target_host":"redis.test","target_port":6379,"command":"GET","args":[body("unused")],
                        "response_kind":"bulk_string","response":body("$1\r\nx\r\n"),"replay_safe":true}),
                ] {
                    recorder
                        .append_case_dependency(&case, &fixtures::native_event(&value), "fixture")
                        .await
                        .unwrap();
                }
            }
            recorder.publish_case(&case).await.unwrap();
            cases.push(case.id.to_string());
        }
        recorder.finish_run().await.unwrap();
        let report = temp.path().join("report.json");
        let addr = "127.0.0.1:0".parse().unwrap();
        let runtime = Arc::new(
            ReplayRuntime::load_with_lifecycle(
                ReplayConfig {
                    case_dir: recorder.run_dir.as_ref().clone(),
                    selected_case_ids: vec![],
                    dns_listen: addr,
                    tcp_listen: addr,
                    fake_cidr: "198.18.0.0/15".into(),
                    report_path: Some(report.clone()),
                    session_path: None,
                    control_socket_path: None,
                    ca_cert_path: Some(temp.path().join("ca.pem")),
                    ca_key_path: Some(temp.path().join("key.pem")),
                    policy_path: None,
                    http_ignore_query_params: vec![],
                    process_owned_dependencies: vec![],
                    allowed_unused_http: None,
                },
                addr,
                addr,
                ReplayLifecycleConfig {
                    case_dependency_post_response_window: Duration::ZERO,
                    case_no_progress_timeout: Duration::from_millis(10),
                    dependency_loading: ReplayDependencyLoading {
                        lazy_cases: unused_with_lazy_loading.unwrap_or_default(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        Self {
            runtime,
            cases,
            report,
            _temp: temp,
        }
    }

    async fn command(&self, command: &str, case: Option<&str>, strict: bool) -> (Value, bool) {
        handle_control_request(
            serde_json::from_value(json!({"command":command,"case_id":case,
                "fail_on_dirty":strict,"fail_on_incomplete":strict}))
            .unwrap(),
            self.runtime.state.clone(),
            Some(self.report.clone()),
            None,
        )
        .await
    }

    async fn begin(&self, case: &str) {
        for command in ["begin", "request_begin"] {
            let response = self.command(command, Some(case), true).await.0;
            assert_eq!(response["ok"], true, "{command}: {response}");
        }
    }

    async fn end(&self, case: &str, strict: bool) {
        let response = self.command("end", Some(case), strict).await.0;
        assert_eq!(response["ok"], true, "{response}");
    }

    async fn complete(&self) {
        for case in &self.cases {
            self.begin(case).await;
            self.end(case, true).await;
        }
    }
}

#[tokio::test]
async fn dirty_finalization_publishes_mysql_and_redis_source_occurrences_in_both_loading_modes() {
    for lazy in [false, true] {
        let fixture = Fixture::load(1, Some(lazy)).await;
        let case = &fixture.cases[0];
        fixture.begin(case).await;
        fixture.end(case, false).await;
        let (response, stop) = fixture.command("finalize_cases", None, false).await;
        assert!(stop, "{response}");
        assert_eq!(response["dirty"], true);
        assert!(response["evidence_generation_ms"].as_u64().is_some());
        let report: Value =
            serde_json::from_slice(&std::fs::read(&fixture.report).unwrap()).unwrap();
        let selected = BTreeSet::from([case.clone()]);
        let identity = report["unused_source_inventory_id"].as_str().unwrap();
        let providers = crate::protocols::default_providers();
        let codecs = providers.report_codecs();
        let published =
            report::unused_source::published_for_cases(&report, identity, &selected, codecs)
                .unwrap();
        assert_eq!(published.len(), 2);
        for (protocol, row) in report::unused_source::case_unused_rows(&report, codecs) {
            assert!(matches!(protocol, "mysql" | "redis"));
            let original = &row["source_occurrence"];
            assert_eq!(original["captured_owner"]["origin_case_id"], case.as_str());
            assert_eq!(original["capture_complete"], true);
        }
        assert!(
            report::unused_source::published_for_cases(
                &report,
                "another recording",
                &selected,
                codecs
            )
            .is_none()
        );
        let mut missing = report.clone();
        missing["redis"]["unused_case"][0]
            .as_object_mut()
            .unwrap()
            .remove("source_occurrence");
        assert!(
            report::unused_source::published_for_cases(&missing, identity, &selected, codecs)
                .is_none()
        );
    }
}

#[tokio::test]
async fn twenty_clean_cases_finalize_with_startup_debt_but_whole_session_stays_strict() {
    let fixture = Fixture::new(20).await;
    fixture.complete().await;
    let strict = fixture.command("finalize", None, true).await;
    assert_eq!(strict.0["ok"], false);
    assert_eq!(strict.0["dirty"], true);
    assert!(!strict.1);
    assert!(fixture.runtime.state.lock().await.finalized_at.is_none());
    let focused = fixture.command("finalize_cases", None, true).await;
    assert_eq!(focused.0["ok"], true, "{}", focused.0);
    assert_eq!(focused.0["dirty"], false);
    assert_eq!(focused.0["complete"], true);
    assert!(focused.1);
    let report: Value = serde_json::from_slice(&std::fs::read(&fixture.report).unwrap()).unwrap();
    assert_eq!(report["cases"].as_array().unwrap().len(), 20);
    assert_eq!(report["finalized"], true);
    assert_eq!(
        report["startup_phase"]["unstarted_business_dependencies"]["redis"],
        1
    );
    assert_eq!(
        report["batch_reconciliation"]["source_capture_complete"],
        true
    );
    assert_eq!(
        report["batch_reconciliation"]["startup_phase_complete"],
        false
    );
    assert_eq!(
        report["batch_reconciliation"]["dependency_inventory_verified"],
        false
    );
    assert!(!crate::protocols::replay::report::evidence::report_has_case_dirty_events(&report));
    assert!(
        crate::protocols::replay::report::validation::validate_completed_receipt(&report).is_err()
    );
}

#[tokio::test]
async fn focused_finalization_rejects_actual_case_dependency_failures() {
    let fixture = Fixture::new(1).await;
    fixture.begin(&fixture.cases[0]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(crate::replay::test_support::serve_native(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        fixture.runtime.state.clone(),
    ));
    client
        .write_all(&crate::redis::encode_array(&[b"GET", b"missing-case-call"]))
        .await
        .unwrap();
    let mut reply = [0; 1024];
    let size = client.read(&mut reply).await.unwrap();
    assert_eq!(size, 0);
    fixture.end(&fixture.cases[0], false).await;
    let (response, stopped) = fixture.command("finalize_cases", None, true).await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["dirty"], true);
    assert!(!stopped);
    assert!(fixture.runtime.state.lock().await.finalized_at.is_none());
    task.abort();
}

#[tokio::test]
async fn focused_finalization_requires_every_selected_case_to_end() {
    let fixture = Fixture::new(1).await;
    fixture.begin(&fixture.cases[0]).await;
    let (response, stopped) = fixture.command("finalize_cases", None, true).await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["complete"], false);
    assert!(!stopped);
    assert!(fixture.runtime.state.lock().await.finalized_at.is_none());
}

#[tokio::test]
async fn focused_finalization_never_ignores_unfinished_http_ingress() {
    let fixture = Fixture::new(1).await;
    fixture.complete().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    let task = tokio::spawn(
        crate::protocols::replay::http::handle_http_replay_connection(
            server,
            peer,
            ReplayTarget {
                host: "dependency.test".into(),
                port: 80,
                fake_ip: "198.18.0.2".parse().unwrap(),
                protocol: ReplayProtocol::Http,
            },
            fixture.runtime.state.clone(),
            fixture.runtime.ca.clone(),
        ),
    );
    client
        .write_all(b"POST /startup HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 1\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.runtime.state.lock().await.http_has_in_flight() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual parsed HTTP body must remain in flight");
    // Actual I/O closure is mandatory even for diagnostic non-strict finalize.
    for strict in [false, true] {
        let (response, stopped) = fixture.command("finalize_cases", None, strict).await;
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("in flight"));
        assert!(!stopped);
    }
    assert!(fixture.runtime.state.lock().await.finalized_at.is_none());
    drop(client);
    task.abort();
}
