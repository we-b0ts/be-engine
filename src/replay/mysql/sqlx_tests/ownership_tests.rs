//! Real SQLx calls with a foreign write transaction ending inside the active Case.
use super::*;

fn statement(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut value = exchange(
        sql,
        json!({"status":"ok","server_status":after,
        "affected_rows":0,"last_insert_id":0,"rows_truncated":false,"columns":[],"rows":[]}),
    );
    value["connection_id"] = json!(connection);
    value["query_sequence"] = sequence.into();
    value["server_status_before"] = before.into();
    value["outcome"] = "response".into();
    value["parse_warnings"] = json!([]);
    value["timestamp"] = "2026-10-19T00:00:02Z".into();
    value
}

fn write(path: &Path, values: &[Value]) {
    std::fs::write(
        path,
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
}

#[tokio::test]
async fn selectors_never_create_foreign_ownership_or_steal_the_business_commit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            for commit_business in [false, true] {
                for known_global_start in [false, true] {
                    verify_business_commit(lazy, commit_business, known_global_start).await;
                }
            }
        }
    })
    .await
    .unwrap();
}

async fn verify_business_commit(lazy: bool, commit_business: bool, known_global_start: bool) {
    let temp = tempdir().unwrap();
    let root = temp.path().join(".traffic-e2e/local/recordings");
    let case = root.join("case-id");
    let origin = root.join("origin");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::create_dir_all(&origin).unwrap();
    std::fs::write(
        root.join("recording-run.json"),
        r#"{"status":"completed","run_id":"test"}"#,
    )
    .unwrap();
    for (path, method, uri, body) in [
        (&origin, "POST", "/jobs", r#"{"background":true}"#),
        (&case, "POST", "/lease/release", "{}"),
    ] {
        std::fs::write(path.join("request.json"),json!({"method":method,"uri":uri,
                    "timestamp":"2026-10-19T00:00:00Z","body":{"encoding":"utf8","data":body,"original_len":body.len(),"truncated":false}}).to_string()).unwrap();
        std::fs::write(path.join("expected-response.json"), "{}").unwrap();
    }
    let foreign = Uuid::new_v4();
    let business = Uuid::new_v4();
    let mut insert = statement(
        Uuid::new_v4(),
        1,
        "INSERT INTO jobs_0001 (id,role) VALUES (12,'ASSISTANT')",
        0,
        1,
    );
    insert["timestamp"] = "2026-10-19T00:00:00.100Z".into();
    insert["response"]["affected_rows"] = 1.into();
    write(&origin.join("dependencies.jsonl"), &[insert]);
    let mut background_write = statement(
        foreign,
        410,
        "UPDATE jobs_0001 SET status='DONE' WHERE id=12",
        1,
        1,
    );
    background_write["response"]["affected_rows"] = 1.into();
    write(
        &root.join("global-dependencies.jsonl"),
        &[
            statement(foreign, 409, "BEGIN", u16::from(!known_global_start), 1),
            background_write,
        ],
    );
    let mut business_write = statement(business, 312, "UPDATE users SET active=0 WHERE id=1", 1, 1);
    business_write["response"]["affected_rows"] = 1.into();
    write(
        &case.join("dependencies.jsonl"),
        &[
            statement(foreign, 411, "COMMIT", 1, 0),
            statement(business, 311, "BEGIN", 0, 1),
            business_write,
            statement(business, 313, "COMMIT", 1, 0),
        ],
    );
    let rules=vec![serde_json::from_value(json!({"protocol":"mysql","name":"background-write",
                "source_revision":format!("sha256:{}","1".repeat(64)),"source_evidence":"worker owns its session and commits its update",
                "selector":{"target_host":"127.0.0.1","target_port":3306,"database":"appdb","username":"root",
                    "sql":"UPDATE {{table}} SET status='DONE' WHERE id=?","table_patterns":["jobs_*"]},
                "trigger_source":{"kind":"api","method":"POST","path":"/jobs","request_body_json":{"/background":true},
                    "capture":{"job_id":{"protocol":"mysql","target_host":"127.0.0.1","target_port":3306,
                        "database":"appdb","username":"root","operation":"INSERT","table_patterns":["jobs_*"],
                        "row_match":{"role":"ASSISTANT"},"column":"id"}}},
                "identity_value_index":0,"include_transaction_boundaries":true})).unwrap()];
    // Keep the fixture's normal genuine SQLx socket; the proof is loaded
    // through Replay startup, without exposing recordings to the client.
    super::super::super::write_test_recording_network_manifest(&case);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ReplayConfig {
        case_dir: case.clone(),
        selected_case_ids: vec![],
        dns_listen: "127.0.0.1:0".parse().unwrap(),
        tcp_listen: addr,
        fake_cidr: "198.18.0.0/15".into(),
        report_path: None,
        session_path: None,
        control_socket_path: None,
        ca_cert_path: Some(case.join(".replay/ca.pem")),
        ca_key_path: Some(case.join(".replay/ca-key.pem")),
        policy_path: None,
        http_ignore_query_params: vec![],
        process_owned_dependencies: rules,
        allowed_unused_http: None,
    };
    let mut lifecycle = ReplayLifecycleConfig::default();
    lifecycle.dependency_loading.lazy_cases = lazy;
    let runtime = Arc::new(
        ReplayRuntime::load_with_lifecycle(config, "127.0.0.1:0".parse().unwrap(), addr, lifecycle)
            .await
            .unwrap(),
    );
    if lazy {
        crate::replay::deferred::prepare_case(runtime.state.clone(), "case-id")
            .await
            .unwrap();
    }
    let serving = runtime.clone();
    let task = tokio::spawn(async move {
        serving.run_tcp(listener).await.unwrap();
    });
    let mut client = connect(addr, &case.join(".replay/ca.pem")).await;
    let mut tx = client.begin().await.unwrap();
    sqlx::query("UPDATE users SET active=0 WHERE id=1")
        .execute(&mut *tx)
        .await
        .unwrap();
    if commit_business {
        tx.commit().await.unwrap();
    } else {
        std::mem::forget(tx);
    }
    let state = runtime.state.lock().await;
    let background = state
        .protocols
        .mysql
        .exchanges
        .iter()
        .position(|e| {
            e.record.connection_id == Some(foreign) && e.record.query_sequence == Some(411)
        })
        .unwrap();
    let own = state
        .protocols
        .mysql
        .exchanges
        .iter()
        .position(|e| {
            e.record.connection_id == Some(business) && e.record.query_sequence == Some(313)
        })
        .unwrap();
    assert!(
        state.protocols.mysql.exchanges[background]
            .status
            .is_available()
    );
    assert_eq!(
        state.protocols.mysql.exchanges[own].status.is_consumed(),
        commit_business
    );
    assert!(
        state.process_owned_mysql().is_empty(),
        "a request selector is not independently proven ownership"
    );
    assert!(
        state.global_mysql_transactions().is_empty(),
        "a raw global filename cannot prove a run owner kind"
    );
    assert_eq!(
        state.protocols.mysql.exchanges[background].source,
        ReplaySource::Case
    );
    assert_eq!(
        state.protocols.mysql.exchanges[background]
            .case_id
            .as_deref(),
        Some("case-id")
    );
    task.abort();
}
