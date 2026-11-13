use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::{MysqlReplayConfig, ReplayRuntime};
use crate::{BackgroundDependencyRuleConfig, RedisKeyPatternConfig};

mod dynamic_values_tests;
mod memcached_connection_tests;
mod motan_concurrency_tests;
mod redis_api_origin_tests;
mod redis_authentication_tests;
mod redis_client_info_tests;
mod redis_connection_tests;
mod redis_joint_time_tests;
mod redis_key_contract_tests;
mod redis_lane_tests;
mod redis_process_owned_tests;
mod redis_publish_tests;
mod redis_request_contract_tests;
mod redis_scalar_identity_tests;
mod redis_time_shift_tests;
mod redis_value_tests;
mod unmatched_connection_tests;

#[tokio::test]
async fn replays_redis_pipeline_in_recorded_lane_order() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        redis_dependency(connection_id, 1, "one", b"$1\r\n1\r\n"),
        redis_dependency(connection_id, 2, "two", b"$1\r\n2\r\n"),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (providers, counts) = crate::protocols::tests::counted_providers();
    let (addr, task) = spawn_replay_with_providers(
        &case_dir,
        Some(report_path.clone()),
        None,
        Vec::new(),
        providers,
    )
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\none\r\n*2\r\n$3\r\nGET\r\n$3\r\ntwo\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n$1\r\n2\r\n");

    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert_eq!(report["redis"]["matched"].as_array().unwrap().len(), 2);
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    assert_eq!(
        counts
            .redis
            .sessions
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        counts
            .redis
            .native_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    task.abort();
}

#[tokio::test]
async fn reports_redis_lane_blocker_without_exposing_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        redis_dependency(connection_id, 1, "private-key-one", b"$1\r\n1\r\n"),
        redis_dependency(connection_id, 2, "private-key-two", b"$1\r\n2\r\n"),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$15\r\nprivate-key-two\r\n")
        .await
        .unwrap();
    let mut response = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
    let diagnostic = &report["redis"]["unmatched"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "lane_blocked");
    assert_eq!(diagnostic["candidate"]["sequence"], 2);
    assert_eq!(diagnostic["blocked_by"]["sequence"], 1);
    let serialized = serde_json::to_string(&report["redis"]["unmatched"][0]).unwrap();
    assert!(!serialized.contains("private-key-one"));
    assert!(!serialized.contains("private-key-two"));
    task.abort();
}

#[tokio::test]
async fn background_redis_gets_are_connection_independent() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let first_connection = Uuid::new_v4();
    let second_connection = Uuid::new_v4();
    let blocker = redis_dependency(first_connection, 1, "unrelated", b"$1\r\n0\r\n");
    let mut first = redis_dependency(first_connection, 2, "one", b"$1\r\n1\r\n");
    let mut second = redis_dependency(second_connection, 1, "two", b"$1\r\n2\r\n");
    for dependency in [&mut first, &mut second] {
        dependency["global_dependency_reason"] = Value::String("background_rule".to_string());
    }
    let global = [blocker, first, second]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[1, 2]).await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\none\r\n*2\r\n$3\r\nGET\r\n$3\r\ntwo\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n$1\r\n2\r\n");

    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn configured_bootstrap_hget_is_connection_independent() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let connection_id = Uuid::new_v4();
    let blocker = redis_hash_dependency(
        connection_id,
        1,
        "HGET",
        &["unrelated", "version"],
        b"$1\r\n0\r\n",
    );
    let mut selected = redis_hash_dependency(
        connection_id,
        2,
        "HGET",
        &["exp:matchlist:123", "version"],
        b"$1\r\n1\r\n",
    );
    selected["global_dependency_reason"] = Value::String("bootstrap_window".to_string());
    let global = [blocker, selected]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let rule = BackgroundDependencyRuleConfig::Redis {
        key_sequence: Vec::new(),
        script: None,
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "experiment-bootstrap".to_string(),
        ports: vec![6379],
        command: "HGET".to_string(),
        keys: Vec::new(),
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "exp:matchlist:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: vec!["version".to_string()],
        source_revision: String::new(),
        source_evidence: "src/bootstrap.rs:load experiment cache".to_string(),
    };
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[]).await;
    let report_path = temp.path().join("report.json");
    let (addr, task) =
        spawn_replay_with_background(&case_dir, Some(report_path.clone()), vec![rule]).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$17\r\nexp:matchlist:123\r\n$7\r\nversion\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n");
    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn delays_redis_response_by_recorded_duration() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"$1\r\n1\r\n");
    dependency["duration_ms"] = Value::from(80);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, task) = spawn_replay(&case_dir, None).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    let started = Instant::now();
    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n");
    assert!(started.elapsed() >= Duration::from_millis(70));
    task.abort();
}

#[tokio::test]
async fn consumes_redis_timeout_only_after_client_close() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"");
    dependency["response_kind"] = Value::String("other".to_string());
    dependency["outcome"] = Value::String("client_terminated".to_string());
    dependency["duration_ms"] = Value::from(60);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
        .await
        .unwrap();
    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut probe))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    client.shutdown().await.unwrap();

    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert!(
        report["redis"]["unsafe_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn replays_memcached_set_with_opaque_protobuf_bytes_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let key = temp
        .path()
        .join(".traffic-e2e/local")
        .join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let case_dir = temp.path().join(".traffic-e2e/local/recordings/case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(
        case_dir.join("request.json"),
        r#"{"method":"GET","uri":"/api/config"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(case_dir.join("expected-response.json"), b"{}")
        .await
        .unwrap();

    let recorded_at = Utc::now();
    let recorded_value = protobuf_value(recorded_at.timestamp() as u64 - 3, b"stable");
    let extras = [0_u8; 8];
    let mut recorded_response = vec![0_u8; 24];
    recorded_response[0] = 0x81;
    recorded_response[1] = 0x01;
    let dependency = serde_json::json!({
        "event_type": "memcached_exchange",
        "connection_id": Uuid::new_v4(),
        "sequence": 1,
        "timestamp": recorded_at,
        "target_host": "cache.internal",
        "target_port": 11211,
        "wire_protocol": "binary",
        "command": "set",
        "opcode": 1,
        "key": capture_json(b"u42"),
        "args": [],
        "value": capture_json(&recorded_value),
        "extras": capture_json(&extras),
        "cas": null,
        "quiet": false,
        "noreply": false,
        "response_status": "0",
        "response_frames": [capture_json(&recorded_response)],
        "no_response": false,
        "replay_safe": true
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let policy_path = temp.path().join("policy.yaml");
    std::fs::write(&policy_path,"format: traffic-policy/v3\njson: {fields: {/created_at: {kind: time, formats: [unix_seconds]}}}\n").unwrap();

    let report_path = temp.path().join("report.json");
    let (addr, task) =
        spawn_replay_with_policy(&case_dir, Some(report_path.clone()), policy_path).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let actual_value = recorded_value;
    client
        .write_all(&binary_set_request(42, b"u42", &actual_value))
        .await
        .unwrap();
    let mut response = vec![0_u8; 24];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 42);
    assert_eq!(u16::from_be_bytes(response[6..8].try_into().unwrap()), 0);

    let report = wait_for_matched_count(&report_path, "memcached", 1).await;
    assert_eq!(report["memcached"]["matched"].as_array().unwrap().len(), 1);
    assert!(
        report["replay_policy"]["unused_applicable_dependency_rule_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn background_memcached_gets_are_connection_independent() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let first_connection = Uuid::new_v4();
    let second_connection = Uuid::new_v4();
    let blocker = memcached_binary_dependency(first_connection, 1, b"unrelated");
    let mut first = memcached_binary_dependency(first_connection, 2, b"one");
    let mut second = memcached_binary_dependency(second_connection, 1, b"two");
    for dependency in [&mut first, &mut second] {
        dependency["global_dependency_reason"] = Value::String("background_rule".to_string());
    }
    let global = [blocker, first, second]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[1, 2]).await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(&binary_get_request_for(41, b"one"))
        .await
        .unwrap();
    let mut first_response = vec![0_u8; 24];
    client.read_exact(&mut first_response).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(first_response[12..16].try_into().unwrap()),
        41
    );
    client
        .write_all(&binary_get_request_for(42, b"two"))
        .await
        .unwrap();
    let mut second_response = vec![0_u8; 24];
    client.read_exact(&mut second_response).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(second_response[12..16].try_into().unwrap()),
        42
    );

    let report = wait_for_matched_count(&report_path, "memcached", 2).await;
    assert!(
        report["memcached"]["unmatched"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn replays_recorded_memcached_getkq_as_regular_get() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut recorded_response = vec![0_u8; 24];
    recorded_response[0] = 0x81;
    recorded_response[1] = 0x0d;
    recorded_response[2..4].copy_from_slice(&3_u16.to_be_bytes());
    recorded_response[4] = 4;
    recorded_response[8..12].copy_from_slice(&12_u32.to_be_bytes());
    recorded_response.extend_from_slice(&0_u32.to_be_bytes());
    recorded_response.extend_from_slice(b"keyvalue");
    let dependency = serde_json::json!({
        "event_type": "memcached_exchange",
        "connection_id": Uuid::new_v4(),
        "sequence": 1,
        "target_host": "cache.internal",
        "target_port": 11211,
        "wire_protocol": "binary",
        "command": "get",
        "opcode": 13,
        "key": capture_json(b"key"),
        "args": [],
        "value": null,
        "extras": null,
        "cas": null,
        "quiet": true,
        "noreply": false,
        "response_status": "0",
        "response_frames": [capture_json(&recorded_response)],
        "no_response": false,
        "replay_safe": true
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client.write_all(&binary_get_request(42)).await.unwrap();
    let mut response = vec![0_u8; 33];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[1], 0x00);
    assert_eq!(u16::from_be_bytes(response[2..4].try_into().unwrap()), 0);
    assert_eq!(u32::from_be_bytes(response[8..12].try_into().unwrap()), 9);
    assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 42);
    assert_eq!(&response[28..], b"value");

    let report = wait_for_matched_count(&report_path, "memcached", 1).await;
    assert!(
        report["memcached"]["unmatched"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn consumes_memcached_timeout_only_after_client_close() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let dependency = serde_json::json!({
        "event_type": "memcached_exchange",
        "connection_id": Uuid::new_v4(),
        "sequence": 1,
        "target_host": "cache.internal",
        "target_port": 11211,
        "wire_protocol": "binary",
        "command": "get",
        "opcode": 0,
        "key": capture_json(b"key"),
        "args": [],
        "value": null,
        "extras": null,
        "cas": null,
        "quiet": false,
        "noreply": false,
        "response_status": "incomplete",
        "response_frames": [],
        "no_response": false,
        "outcome": "client_terminated",
        "duration_ms": 60,
        "replay_safe": true
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = binary_get_request(42);
    client.write_all(&request).await.unwrap();

    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut probe))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    client.shutdown().await.unwrap();

    let report = wait_for_matched_count(&report_path, "memcached", 1).await;
    assert!(
        report["memcached"]["unsafe_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn replays_motan_response_after_recorded_delay_with_live_request_id() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let recorded_request = motan_request(1);
    let recorded_response = motan_response(1, b"recorded-response");
    let dependency = motan_dependency(
        Uuid::new_v4(),
        1,
        &recorded_request,
        &recorded_response,
        "response",
        80,
    );
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    let started = Instant::now();
    client.write_all(&motan_request(99)).await.unwrap();
    let mut response = vec![0_u8; recorded_response.len()];
    client.read_exact(&mut response).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(70));
    assert_eq!(u64::from_be_bytes(response[4..12].try_into().unwrap()), 99);
    assert_eq!(u64::from_be_bytes(response[20..28].try_into().unwrap()), 99);

    let report = wait_for_matched_count(&report_path, "motan", 1).await;
    assert!(report["motan"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn consumes_motan_timeout_only_after_client_close() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let request = motan_request(1);
    let dependency = motan_dependency(Uuid::new_v4(), 1, &request, &[], "client_terminated", 60);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client.write_all(&motan_request(42)).await.unwrap();
    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut probe))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    client.shutdown().await.unwrap();

    let report = wait_for_matched_count(&report_path, "motan", 1).await;
    assert!(
        report["motan"]["unsafe_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn unsafe_redis_evidence_prevents_replay_startup() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"$1\r\n1\r\n");
    dependency["replay_safe"] = Value::Bool(false);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    super::write_test_recording_network_manifest(&case_dir);

    let result = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case_dir.clone(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
            ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("unsafe Redis evidence unexpectedly loaded"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsafe"));
}

async fn spawn_replay(
    case_dir: &Path,
    report_path: Option<PathBuf>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_configured(case_dir, report_path, None, Vec::new()).await
}

async fn spawn_replay_with_background(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_configured(case_dir, report_path, None, process_owned_dependencies).await
}

async fn spawn_replay_with_policy(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    policy_path: PathBuf,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_configured(case_dir, report_path, Some(policy_path), Vec::new()).await
}

async fn spawn_replay_configured(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_with_providers(
        case_dir,
        report_path,
        policy_path,
        process_owned_dependencies,
        crate::protocols::default_providers(),
    )
    .await
}

async fn spawn_replay_with_providers(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
    providers: std::sync::Arc<crate::protocols::DependencyProviders>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    super::write_test_recording_network_manifest(case_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case_dir.to_path_buf(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
            ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
            policy_path,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies,
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
    )
    .await
    .unwrap();
    runtime.state.lock().await.providers = providers;
    runtime.write_report().await.unwrap();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = runtime.run_tcp(listener) => {},
            _ = runtime.run_report_writer() => {},
        }
    });
    (addr, task)
}

fn redis_hash_dependency(
    connection_id: Uuid,
    sequence: u64,
    command: &str,
    args: &[&str],
    response: &[u8],
) -> Value {
    let mut value = redis_dependency(
        connection_id,
        sequence,
        args.first().copied().unwrap_or_default(),
        response,
    );
    value["command"] = Value::String(command.to_string());
    value["args"] = Value::Array(
        args.iter()
            .map(|arg| {
                serde_json::json!({
                    "encoding": "utf8",
                    "data": arg,
                    "truncated": false,
                })
            })
            .collect(),
    );
    value
}

fn redis_dependency(connection_id: Uuid, sequence: u64, key: &str, response: &[u8]) -> Value {
    serde_json::json!({
        "event_type": "redis_exchange",
        "timestamp": "1970-01-01T00:16:40Z",
        "duration_ms": 0,
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "redis.internal",
        "target_port": 6379,
        "resp_version": 2,
        "database": 0,
        "username": null,
        "command": "GET",
        "args": [capture_json(key.as_bytes())],
        "response_kind": "bulk_string",
        "response": capture_json(response),
        "session_setup": false,
        "replay_safe": true
    })
}

fn capture_json(bytes: &[u8]) -> Value {
    serde_json::json!({
        "encoding": "base64",
        "original_len": bytes.len(),
        "stored_len": bytes.len(),
        "data": STANDARD.encode(bytes),
        "truncated": false
    })
}

fn binary_get_request(opaque: u32) -> Vec<u8> {
    binary_get_request_for(opaque, b"key")
}

fn binary_get_request_for(opaque: u32, key: &[u8]) -> Vec<u8> {
    let mut request = vec![0_u8; 24];
    request[0] = 0x80;
    request[1] = 0x00;
    request[2..4].copy_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
    request[8..12].copy_from_slice(&u32::try_from(key.len()).unwrap().to_be_bytes());
    request[12..16].copy_from_slice(&opaque.to_be_bytes());
    request.extend_from_slice(key);
    request
}

fn binary_set_request(opaque: u32, key: &[u8], value: &[u8]) -> Vec<u8> {
    let extras = [0_u8; 8];
    let body_len = extras.len() + key.len() + value.len();
    let mut request = vec![0_u8; 24];
    request[0] = 0x80;
    request[1] = 0x01;
    request[2..4].copy_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
    request[4] = extras.len() as u8;
    request[8..12].copy_from_slice(&u32::try_from(body_len).unwrap().to_be_bytes());
    request[12..16].copy_from_slice(&opaque.to_be_bytes());
    request.extend_from_slice(&extras);
    request.extend_from_slice(key);
    request.extend_from_slice(value);
    request
}

fn protobuf_value(timestamp: u64, stable: &[u8]) -> Vec<u8> {
    let mut value = vec![0x08, 0x07, 0x90, 0x03];
    encode_varint(timestamp, &mut value);
    value.extend_from_slice(&[0x12, stable.len() as u8]);
    value.extend_from_slice(stable);
    value
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn memcached_binary_dependency(connection_id: Uuid, sequence: u64, key: &[u8]) -> Value {
    let mut response = vec![0_u8; 24];
    response[0] = 0x81;
    response[1] = 0x00;
    serde_json::json!({
        "event_type": "memcached_exchange",
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "cache.internal",
        "target_port": 11211,
        "wire_protocol": "binary",
        "command": "get",
        "opcode": 0,
        "key": capture_json(key),
        "args": [],
        "value": null,
        "extras": null,
        "cas": null,
        "quiet": false,
        "noreply": false,
        "response_status": "0",
        "response_frames": [capture_json(&response)],
        "no_response": false,
        "replay_safe": true
    })
}

fn motan_dependency(
    connection_id: Uuid,
    sequence: u64,
    request: &[u8],
    response: &[u8],
    outcome: &str,
    duration_ms: u64,
) -> Value {
    serde_json::json!({
        "event_type": "motan_exchange",
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "vintage-node-10-145-1-107.trp.test",
        "target_port": 8881,
        "advertised_ip": "198.19.0.20",
        "codec_version": 1,
        "interface_name": "cn.sina.api.data.service.SinaUserService",
        "method_name": "getUser",
        "parameter_desc": "long",
        "method_sign": null,
        "command": "cn.sina.api.data.service.SinaUserService#getUser",
        "request": capture_json(request),
        "response": capture_json(response),
        "heartbeat": false,
        "outcome": outcome,
        "duration_ms": duration_ms,
        "replay_safe": true
    })
}

fn motan_request(request_id: u64) -> Vec<u8> {
    let values = [
        "cn.sina.api.data.service.SinaUserService",
        "getUser",
        "long",
    ];
    let mut block = Vec::new();
    for value in values {
        block.extend_from_slice(&(value.len() as u16).to_be_bytes());
        block.extend_from_slice(value.as_bytes());
    }
    let mut body = vec![0xAC, 0xED, 0x00, 0x05, 0x77, block.len() as u8];
    body.extend_from_slice(&block);
    motan_frame(request_id, true, 0, &body)
}

fn motan_response(request_id: u64, body: &[u8]) -> Vec<u8> {
    motan_frame(request_id, false, 1, body)
}

fn motan_frame(request_id: u64, request: bool, inner_flag: u8, body: &[u8]) -> Vec<u8> {
    let mut inner = vec![0_u8; 16];
    inner[..2].copy_from_slice(&[0xF0, 0xF0]);
    inner[2] = 1;
    inner[3] = inner_flag;
    inner[4..12].copy_from_slice(&request_id.to_be_bytes());
    inner[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
    inner.extend_from_slice(body);

    let mut outer = vec![0_u8; 16];
    outer[..2].copy_from_slice(&[0xF1, 0xF1]);
    outer[3] = u8::from(!request);
    outer[4..12].copy_from_slice(&request_id.to_be_bytes());
    outer[12..16].copy_from_slice(&(inner.len() as u32).to_be_bytes());
    outer.extend_from_slice(&inner);
    outer
}

async fn wait_for_matched_count(path: &Path, protocol: &str, expected: usize) -> Value {
    for _ in 0..150 {
        if let Ok(raw) = crate::recorder::test_io::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report[protocol]["matched"]
                .as_array()
                .is_some_and(|matched| matched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} matches");
}

async fn wait_for_unmatched_count(path: &Path, protocol: &str, expected: usize) -> Value {
    for _ in 0..150 {
        if let Ok(raw) = crate::recorder::test_io::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report[protocol]["unmatched"]
                .as_array()
                .is_some_and(|unmatched| unmatched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} unmatched requests");
}
