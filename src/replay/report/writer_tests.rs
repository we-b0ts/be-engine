use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::*;

#[tokio::test]
async fn coalesces_bursts_into_one_periodic_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    let report_path = temp.path().join("replay-report.json");
    let runtime = Arc::new(
        ReplayRuntime::load(
            ReplayConfig {
                case_dir,
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: Some(report_path.clone()),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(temp.path().join("ca.pem")),
                ca_key_path: Some(temp.path().join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap(),
    );
    let writer = runtime.report_writer.clone();
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        let _ = task_runtime.run_report_writer().await;
    });

    for _ in 0..1_000 {
        writer.request();
    }
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    assert_eq!(writer.completed_writes(), 1);
    let report: Value =
        serde_json::from_slice(&tokio::fs::read(report_path).await.unwrap()).unwrap();
    assert_eq!(report["version"], 6);
    task.abort();
}

#[tokio::test]
async fn high_volume_successes_keep_report_bounded_and_exactly_counted() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    let report_path = temp.path().join("replay-report.json");
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: Some(report_path.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    {
        let mut state = runtime.state.lock().await;
        let identity = ReplaySessionIdentity {
            target: None,
            database: Some("appdb".to_string()),
            username: Some("root".to_string()),
        };
        for _ in 0..10_000 {
            state.record_builtin(
                &identity,
                "COM_PING",
                None,
                "driver/session command handled by replay server",
            );
        }
    }

    runtime.write_report().await.unwrap();

    let payload = tokio::fs::read(report_path).await.unwrap();
    let report: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(report["builtin_query_count"], 10_000);
    assert_eq!(
        report["builtin_queries"].as_array().unwrap().len(),
        SUCCESS_DETAIL_LIMIT
    );
    assert!(
        payload.len() < 128 * 1024,
        "report was {} bytes",
        payload.len()
    );
}

#[tokio::test]
async fn final_report_publishes_bounded_case_dependency_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    let report_path = temp.path().join("replay-report.json");
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: Some(report_path.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let report = json!({
        "unmatched_http_requests": [
            {"case_id":null,"target":{"host":"startup.internal","port":80},"method":"GET","uri":"/warmup"},
            {"case_id":"case-a","target":{"host":"api.internal","port":80},"method":"GET","uri":"/missing"}
        ],
        "memcached": {
            "unused_case": [
                {"case_id":"case-a","target":{"host":"cache.internal","port":11211},"command":"get"}
            ],
            "unused_global": [
                {"target":{"host":"cache.internal","port":11211},"command":"get"}
            ]
        }
    });

    write_final_report_value(runtime.state.clone(), report_path.clone(), &report)
        .await
        .unwrap();

    let evidence = read_dependency_evidence(&report_path).unwrap();
    assert_eq!(evidence.clusters.len(), 2);
    assert_eq!(evidence.case_event_counts["http"]["unmatched_target"], 1);
    assert_eq!(
        evidence.case_event_counts["memcached"]["unused_recorded"],
        1
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("startup.internal")
    );
}
