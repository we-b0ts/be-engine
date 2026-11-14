//! A classified process write still needs its original value and one delivery.
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::json;
use tokio::net::TcpListener;

#[test]
fn process_owned_set_preserves_exact_arguments_and_single_consumption() {
    let rule:BackgroundDependencyRuleConfig=serde_json::from_value(serde_json::json!({
        "protocol":"redis","name":"shutdown","ports":[6379],"command":"SET","keys":["shutdown:state"],
        "source_revision":"","source_evidence":""})).unwrap();
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule)).unwrap();
    let mut state = RedisReplayState::default();
    state
        .register_exchange(
            RecordedExchange {
                lifecycle_cleanup: false,
                parse_warnings: vec![],
                rpc_callback_capture: None,
                id: None,
                timestamp: None,
                request_started_at: None,
                connection_id: Uuid::new_v4(),
                sequence: 1,
                target_host: "redis.test".into(),
                target_port: 6379,
                resp_version: 2,
                database: 0,
                username: None,
                command: "SET".into(),
                args: vec![capture("shutdown:state"), capture("stopped")],
                response_kind: "simple_string".into(),
                response: capture("+OK\r\n"),
                outcome: DependencyExchangeOutcome::Response,
                duration_ms: 1,
                replay_safe: true,
                cache_snapshot_rule: None,
                cache_snapshot_hit: false,
                session_setup: false,
                capture: Some(crate::dependency::observation::fixture_capture("process")),
            },
            ReplaySource::Process,
            None,
            &mut BTreeMap::new(),
            std::slice::from_ref(&rule),
        )
        .unwrap();
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    assert!(
        state
            .match_redis(
                None,
                &target,
                TargetConnection::default(),
                2,
                0,
                None,
                "SET",
                &[b"shutdown:state".to_vec(), b"different-value".to_vec()]
            )
            .is_err()
    );
    assert_eq!(state.snapshot().matched_count, 0);
    let matched = state
        .match_redis(
            None,
            &target,
            TargetConnection::default(),
            2,
            0,
            None,
            "SET",
            &[b"shutdown:state".to_vec(), b"stopped".to_vec()],
        )
        .unwrap();
    assert_eq!(matched.response, b"+OK\r\n");
    state.complete_exchange(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
    assert!(
        state
            .match_redis(
                None,
                &target,
                TargetConnection::default(),
                2,
                0,
                None,
                "SET",
                &[b"shutdown:state".to_vec(), b"stopped".to_vec()]
            )
            .is_err(),
        "ownership cannot make a finite write reusable"
    );
}

async fn timed_process_write(
    millis: bool,
    fractional: bool,
) -> (tempfile::TempDir, Arc<ReplayRuntime>) {
    use crate::recorder::{CaseContext, Recorder, RecorderEvent, RedisExchangeEvent, capture_body};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let directory = root.join(".traffic-e2e/local/artifacts/recordings");
    std::fs::create_dir_all(&directory).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let policy = root.join(".traffic-e2e/policy.yaml");
    std::fs::write(&policy,"format: traffic-policy/v3\nsource_revision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\njson:\n  fields:\n    /timestamp: {kind: time, formats: [unix_seconds, unix_milliseconds]}\nprocess_dependencies:\n  tasks:\n    lifespan_shutdown:\n      requests:\n        - redis: {operation: SET, ports: [6379], keys: [{kind: exact, value: shutdown:state}]}\n").unwrap();
    let compiled =
        crate::policy::parse_and_compile_policy(&std::fs::read_to_string(&policy).unwrap())
            .unwrap();
    let projection = crate::config::native_policy::project_source_policy(&compiled.native).unwrap();
    let config = crate::AppConfig {
        process_dependency_tasks: projection.process_dependency_tasks,
        process_owned_dependencies: projection.process_owned_dependencies,
        ..Default::default()
    };
    let rule = config.process_owned_dependencies[0].name().to_owned();
    let recorder = Recorder::new(directory)
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    recorder
        .observe_accessed_endpoint("redis.test", 6379)
        .await
        .unwrap();
    let at = "2020-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    let timestamp = if fractional {
        json!(at.timestamp() as f64 + 0.125)
    } else if millis {
        json!(at.timestamp_millis())
    } else {
        json!(at.timestamp())
    };
    let value = json!({"timestamp":timestamp,"state":"stopped"}).to_string();
    let exchange = RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: at,
        request_started_at: at,
        client_addr: None,
        target_host: "redis.test".into(),
        target_port: 6379,
        target_addr: "redis.test:6379".into(),
        upstream_addr: "redis.test:6379".into(),
        resp_version: 2,
        database: 0,
        username: None,
        command: "SET".into(),
        args: ["shutdown:state", &value, "EX", "120"]
            .into_iter()
            .map(|a| capture_body(a.as_bytes(), 1024))
            .collect(),
        response_kind: "simple_string".into(),
        response: capture_body(b"+OK\r\n", 1024),
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 0,
        replay_safe: true,
        parse_warnings: vec![],
    });
    recorder
        .append_global_dependency(&exchange, "background_rule", "shutdown", &rule)
        .await
        .unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".into(),
        uri_group: None,
    };
    for (name, value) in [
        ("admission.json", json!({"fixture":true})),
        (
            "request.json",
            json!({"method":"GET","uri":"/api","timestamp":at}),
        ),
        ("expected-response.json", json!({"status":200})),
    ] {
        recorder.write_case_json(&case, name, &value).await.unwrap();
    }
    recorder.publish_case(&case).await.unwrap();
    recorder.finish_run().await.unwrap();
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load(
            ReplayConfig {
                case_dir: recorder.case_dir(&case),
                selected_case_ids: vec![],
                dns_listen: addr,
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(root.join("ca.pem")),
                ca_key_path: Some(root.join("ca-key.pem")),
                policy_path: Some(policy),
                http_ignore_query_params: vec![],
                process_owned_dependencies: config.process_owned_dependencies,
                allowed_unused_http: None,
            },
            addr,
            addr,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        runtime.state.lock().await.protocols.redis.exchanges[0].source,
        ReplaySource::Process
    );
    (temp, runtime)
}

async fn send_write(runtime: &Arc<ReplayRuntime>, value: &str, expiry: &str) -> Option<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(stream, 1024 * 1024);
    client
        .inner
        .write_all(&crate::redis::encode_array(&[
            b"SET",
            b"shutdown:state",
            value.as_bytes(),
            b"EX",
            expiry.as_bytes(),
        ]))
        .await
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_redis_frame(&mut client),
    )
    .await
    .unwrap()
    .ok()
    .flatten()
    .map(|f| f.raw.to_vec());
    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .unwrap();
    response
}

#[tokio::test]
async fn process_owned_set_uses_global_timestamp_contract_with_independent_dependency_clocks() {
    for (millis, fractional) in [(false, false), (true, false), (false, true)] {
        for mode in [
            "valid",
            "stable_field",
            "stale_time",
            "expiry",
            "overlay_owner",
        ] {
            let (_temp, runtime) = timed_process_write(millis, fractional).await;
            if mode == "overlay_owner" {
                // A frozen scope may have a proven Process owner while the raw
                // capture metadata still states its original unknown owner.
                let mut state = runtime.state.lock().await;
                let capture = state.protocols.redis.exchanges[0]
                    .record
                    .capture
                    .as_mut()
                    .unwrap();
                let id = capture.exchange_id;
                let scope =
                    crate::replay::attribution::run_value_scope(&capture.attribution).unwrap();
                capture.attribution =
                    crate::dependency::attribution::DependencyOwner::Unattributed {
                        reason: "outside_admission".into(),
                    };
                state
                    .protocols
                    .redis
                    .run_value_scopes
                    .insert(id, Arc::<str>::from(scope));
            }
            let now = chrono::Utc::now();
            let timestamp = if mode == "stale_time" {
                // Exact historical copies are allowed by the existing global
                // contract; a changed stale timestamp must still be rejected.
                if fractional {
                    json!(1577840400.125)
                } else if millis {
                    json!(1577840400000_i64)
                } else {
                    json!(1577840400_i64)
                }
            } else if fractional {
                json!(now.timestamp_micros() as f64 / 1_000_000.0)
            } else if millis {
                json!(now.timestamp_millis())
            } else {
                json!(now.timestamp())
            };
            let value=json!({"timestamp":timestamp,"state":if mode=="stable_field" {"running"}else{"stopped"}}).to_string();
            let response = send_write(
                &runtime,
                &value,
                if mode == "expiry" { "121" } else { "120" },
            )
            .await;
            if matches!(mode, "valid" | "overlay_owner") {
                assert_eq!(response.as_deref(), Some(b"+OK\r\n".as_slice()), "{mode}");
                assert_eq!(
                    runtime
                        .state
                        .lock()
                        .await
                        .protocols
                        .redis
                        .snapshot()
                        .matched_count,
                    1
                );
                assert_ne!(
                    send_write(&runtime, &value, "120").await.as_deref(),
                    Some(b"+OK\r\n".as_slice()),
                    "finite process writes cannot repeat"
                );
            } else {
                assert_ne!(response.as_deref(), Some(b"+OK\r\n".as_slice()), "{mode}");
                assert_eq!(
                    runtime
                        .state
                        .lock()
                        .await
                        .protocols
                        .redis
                        .snapshot()
                        .matched_count,
                    0
                );
            }
        }
    }
}
