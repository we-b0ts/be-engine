use serde_json::{Value, json};

use super::super::*;
use super::dependency_evidence::dependency_evidence_path;

#[tokio::test]
async fn loading_runtime_does_not_publish_report() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    write_test_recording_network_manifest(&case_dir);
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

    assert!(!report_path.exists());
    runtime.write_report().await.unwrap();

    let report: Value =
        serde_json::from_slice(&tokio::fs::read(report_path).await.unwrap()).unwrap();
    assert_eq!(report["version"], 7);
    assert_eq!(report["mysql_transaction_semantics"], "finite_native_v1");
}

#[tokio::test]
async fn final_report_publishes_bounded_case_dependency_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    write_test_recording_network_manifest(&case_dir);
    let report_path = temp.path().join("replay-report.json");
    let report = json!({
        "unrecorded_targets": [
            {"case_id":"case-a","target":{"host":"breeze.recording","port":9301},"reason":"访问了录制时没有访问过的域名:port"}
        ],
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

    write_final_report_value(
        report_path.clone(),
        &report,
        crate::protocols::default_providers().report_codecs(),
    )
    .await
    .unwrap();

    let evidence = read_dependency_evidence(&report_path).unwrap();
    assert_eq!(evidence.clusters.len(), 3);
    assert_eq!(
        evidence.case_event_counts["network"]["unrecorded_endpoint"],
        1
    );
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
    let network = evidence
        .clusters
        .iter()
        .find(|cluster| cluster.protocol == "network")
        .unwrap();
    assert_eq!(network.endpoint.as_ref().unwrap().host, "breeze.recording");
    assert_eq!(network.endpoint.as_ref().unwrap().port, 9301);
}

#[tokio::test]
async fn final_report_is_removed_when_dependency_evidence_cannot_be_published() {
    let temp = tempfile::tempdir().unwrap();
    let report_path = temp.path().join("replay-report.json");
    let evidence_path = dependency_evidence_path(&report_path);
    tokio::fs::create_dir(&evidence_path).await.unwrap();

    let error = write_final_report_value(
        report_path.clone(),
        &json!({}),
        crate::protocols::default_providers().report_codecs(),
    )
    .await
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("failed to publish replay report")
    );
    assert!(!report_path.exists());
}
