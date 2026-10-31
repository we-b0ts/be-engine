//! Genuine HTTP PUT and TLS SQLx prepared writes share the path identity.
use super::*;
use sqlx::Executor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn rule() -> crate::DynamicValueRule {
    serde_yaml::from_str(
        r#"
id: object-key
api: /users
targets:
  - {host: s3.example.test, port: 80}
  - {host: 127.0.0.1, port: 3306}
capture:
  protocol: http
  target: {host: s3.example.test, port: 80}
  method: PUT
  path: /bucket/attachments/*
  path_segment:
    index: 2
    template: "{nonce}_{created_at}_{user_id}_{attachment_id}"
    fields:
      nonce: {kind: random, format: hex, length: 12}
      created_at: {kind: timestamp, format: "%Y%m%d%H%M%S"}
      user_id: {kind: exact}
      attachment_id: {kind: exact}
source_evidence: Storage:key uses UUID hex[:12], UTC now, owner and inserted ID
"#,
    )
    .unwrap()
}

async fn put(addr: SocketAddr, path: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("PUT {path} HTTP/1.1\r\nHost: s3.example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn http_listener(runtime: Arc<ReplayRuntime>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target = runtime
        .state
        .lock()
        .await
        .targets
        .iter()
        .find(|target| target.host == "s3.example.test")
        .unwrap()
        .clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let runtime = runtime.clone();
            let target = target.clone();
            tokio::spawn(async move {
                crate::replay::http::handle_http_replay_connection(
                    stream,
                    peer,
                    target,
                    runtime.state.clone(),
                    runtime.ca.clone(),
                )
                .await
                .unwrap();
            });
        }
    });
    (addr, task)
}

fn records() -> Vec<Value> {
    let mut records = vec![
        json!({"event_type":"http_exchange","id":"recorded-storage-put","scheme":"http","method":"PUT","authority":"s3.example.test",
        "uri":"/bucket/attachments/aabbccddeeff_20200101000000_7_100?part=1",
        "timestamp":"2020-01-01T00:00:00Z","request_started_at":"2020-01-01T00:00:00Z",
        "request_body":{"encoding":"utf8","data":"file bytes","truncated":false},
        "response_status":200,"response_headers":{"content-length":["8"]},
        "response_body":{"encoding":"utf8","data":"accepted","truncated":false},"error":null}),
        exchange(
            "UPDATE subtask_contexts SET type_data='{\"storage_key\":\"attachments/aabbccddeeff_20200101000000_7_100\",\"stable\":1}' WHERE id=100",
            json!({"status":"ok","affected_rows":1}),
        ),
    ];
    records[1]["timestamp"] = json!("2020-01-01T00:00:00Z");
    records[1]["connection_id"] = json!("00000000-0000-4000-8000-000000000001");
    records[1]["query_sequence"] = json!(1);
    records
}

#[tokio::test]
async fn unchanged_historical_key_replays_http_and_tls_sql_without_extra_configuration() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let policy = r#"format: traffic-policy/v3
rules:
- id: preserved-key
  match:
    api: GET /users
    resource: {protocol: http, endpoint: 's3.example.test:80'}
    operation: PUT
    path: /bucket/attachments/*
  effect:
    kind: identity
    value_type: string
    capture:
      kind: http_path
      segment:
        index: 2
        template: '{nonce}_{created_at}_{user_id}_{attachment_id}'
        fields:
          nonce: {kind: random, format: hex, length: 12}
          created_at: {kind: timestamp, format: '%Y%m%d%H%M%S'}
          user_id: {kind: exact}
          attachment_id: {kind: exact}
    references:
    - resource: {protocol: http, endpoint: 's3.example.test:80'}
    - resource: {protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}
  proof: {source: 'attachment.py:overwrite', fact: 'Overwrite loads the original key and writes it back unchanged'}
"#;
        let mut source = records();
        source[0]["request_started_at"] = json!("2026-10-16T03:12:02Z");
        source[0]["timestamp"] = json!("2026-10-16T03:12:02Z");
        let (temp, _, runtime, task) = fixture_with_policy(&source, Some(policy)).await;
        task.abort();
        let (addr, task) = http_listener(runtime.clone()).await;
        let (mysql_addr, mysql_task) =
            super::dynamic_values_tests::endpoint_listener(runtime.clone(), false).await;
        let mut client = connect(
            mysql_addr,
            &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        ).await;
        let path = source[0]["uri"].as_str().unwrap();
        assert!(put(addr, path, "wrong file bytes").await.starts_with("HTTP/1.1 502"));
        assert!(put(addr, path, "file bytes").await.starts_with("HTTP/1.1 200"));
        let sql = source[1]["sql"].as_str().unwrap();
        assert!(client.execute(sql.replace(r#""stable":1"#, r#""stable":2"#).as_str()).await.is_err());
        assert_eq!(client.execute(sql).await.unwrap().rows_affected(), 1);
        assert!(put(addr, path, "file bytes").await.starts_with("HTTP/1.1 502"));
        assert!(client.execute(sql).await.is_err());
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert_eq!(state.replay_policy.as_ref().unwrap().report().dynamic_bindings.len(), 1);
        task.abort();
        mysql_task.abort();
    }).await.expect("preserved-key HTTP/SQL Replay timed out");
}

#[tokio::test]
async fn retired_path_authoring_preserves_evidence_and_native_http_sql_replay_is_finite() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let empty = "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n";
        let (temp, _, runtime, task) = fixture_with_policy(&records(), Some(empty)).await;
        task.abort();
        let (addr, task) = http_listener(runtime.clone()).await;
        let immutable = std::fs::read(
            temp.path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl"),
        )
        .unwrap();
        let key = format!("112233445566_{}_7_100", Utc::now().format("%Y%m%d%H%M%S"));
        let path = format!("/bucket/attachments/{key}?part=1");
        assert!(
            put(addr, &path, "file bytes")
                .await
                .starts_with("HTTP/1.1 502")
        );
        let report_path = temp.path().join("replay.json");
        let report = {
            let mut state = runtime.state.lock().await;
            state.finalized_at = Some(Utc::now());
            serde_json::to_value(state.snapshot_report()).unwrap()
        };
        assert_eq!(
            report["replay_policy"]["dynamic_capture_candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let candidate = report["replay_policy"]["dynamic_capture_candidates"][0].to_string();
        assert!(!candidate.contains(&key));
        assert!(!candidate.contains("aabbccddeeff"));
        std::fs::write(&report_path, report.to_string()).unwrap();
        task.abort();
        let feedback = || crate::DynamicValueRuleFeedback {
            policy_path: temp.path().join("policy.yaml"),
            rule: rule(),
            replay_report: report_path.clone(),
        };
        let policy_before = std::fs::read(temp.path().join("policy.yaml")).unwrap();
        let evidence_before = std::fs::read(&report_path).unwrap();
        let error = crate::plan_dynamic_value_rule(feedback())
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("legacy rule authoring is retired"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(temp.path().join("policy.yaml")).unwrap(),
            policy_before
        );
        assert_eq!(std::fs::read(&report_path).unwrap(), evidence_before);
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")
            )
            .unwrap(),
            immutable
        );
        crate::replay::policy::test_fixture::install_dynamic_value(feedback()).unwrap();
        let policy =
            crate::recorder::test_io::read_to_string_sync(temp.path().join("policy.yaml")).unwrap();
        let document = crate::policy::parse_policy(&policy).unwrap();
        assert!(
            document
                .rules
                .iter()
                .find(|rule| rule.id() == "object-key")
                .unwrap()
                .as_native()
                .is_some()
        );
        let (next, _, runtime, task) = fixture_with_policy(&records(), Some(&policy)).await;
        task.abort();
        let (addr, task) = http_listener(runtime.clone()).await;
        let (mysql_addr, mysql_task) =
            super::dynamic_values_tests::endpoint_listener(runtime.clone(), false).await;
        let mut client = connect(
            mysql_addr,
            &next
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let key = format!("112233445566_{}_7_100", Utc::now().format("%Y%m%d%H%M%S"));
        let path = format!("/bucket/attachments/{key}?part=1");
        let sql = "UPDATE subtask_contexts SET type_data=? WHERE id=?";
        let payload = format!("{{\"storage_key\":\"attachments/{key}\",\"stable\":1}}");
        // A SQL reference before the successful PUT has no binding.
        assert!(
            sqlx::query(sql)
                .bind(&payload)
                .bind(100_i64)
                .execute(&mut client)
                .await
                .is_err()
        );
        for (bad_path, body) in [
            (path.clone(), "wrong file bytes"),
            (path.replace("_7_100", "_8_100"), "file bytes"),
            (path.replace("_7_100", "_7_101"), "file bytes"),
            (path.replace("part=1", "part=2"), "file bytes"),
            (
                "/bucket/attachments/112233445566_20000101000000_7_100?part=1".into(),
                "file bytes",
            ),
        ] {
            assert!(put(addr, &bad_path, body).await.starts_with("HTTP/1.1 502"));
        }
        assert!(
            runtime
                .state
                .lock()
                .await
                .replay_policy
                .as_ref()
                .unwrap()
                .report()
                .dynamic_bindings
                .is_empty()
        );
        assert!(
            put(addr, &path, "file bytes")
                .await
                .starts_with("HTTP/1.1 200")
        );
        for (bad_payload, id) in [
            (payload.replace("112233445566", "665544332211"), 100_i64),
            (payload.replace("\"stable\":1", "\"stable\":2"), 100),
            (payload.clone(), 101),
        ] {
            assert!(
                sqlx::query(sql)
                    .bind(bad_payload)
                    .bind(id)
                    .execute(&mut client)
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            sqlx::query(sql)
                .bind(payload)
                .bind(100_i64)
                .execute(&mut client)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        assert!(
            put(addr, &path, "file bytes")
                .await
                .starts_with("HTTP/1.1 502")
        );
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let policy_report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(policy_report.dynamic_bindings.len(), 1);
        assert_eq!(policy_report.dependency_rules[0].time_validations, 1);
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")
            )
            .unwrap(),
            immutable
        );
        task.abort();
        mysql_task.abort();
    })
    .await
    .expect("path capture HTTP/SQL Replay timed out");
}
