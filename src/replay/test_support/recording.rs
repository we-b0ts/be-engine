//! Real Recorder admissions keep prewarm tests on the sealed central inventory.
use crate::recorder::{
    MysqlExchangeEvent, MysqlExchangeResponse, RecorderEvent, RedisExchangeEvent,
    RedisPubSubPushEvent,
};
use base64::Engine as _;
use chrono::Utc;
use serde_json::{Value, json};
use std::{fs, path::Path};
use uuid::Uuid;

pub(in crate::replay) fn case_path(run: &Path) -> std::path::PathBuf {
    let (_, manifest) = crate::dependency_index::recording::manifest(run).unwrap();
    run.join(&manifest.inputs[0].path)
}

pub(in crate::replay) async fn append(
    recorder: &crate::recorder::Recorder,
    value: &Value,
    process: bool,
) {
    if value["event_type"] == "http_exchange" {
        append_http(recorder, value, process).await;
        return;
    }
    recorder
        .observe_accessed_endpoint(
            value["target_host"].as_str().unwrap(),
            value["target_port"].as_u64().unwrap() as u16,
        )
        .await
        .unwrap();
    let event = native_event(value);
    recorder
        .append_global_dependency(
            &event,
            if process {
                "background_rule"
            } else {
                "bootstrap_window"
            },
            if process { "runtime" } else { "bootstrap" },
            if process {
                "fixture_process"
            } else {
                "fixture_initialization"
            },
        )
        .await
        .unwrap();
}

pub(in crate::replay) fn native_event(value: &Value) -> RecorderEvent {
    let now = Utc::now();
    let host = value["target_host"].as_str().unwrap();
    let port = value["target_port"].as_u64().unwrap() as u16;
    let body = |value: &Value| {
        let data = value["data"].as_str().unwrap();
        let bytes = if value["encoding"] == "base64" {
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap()
        } else {
            data.as_bytes().to_vec()
        };
        crate::recorder::capture_body(&bytes, usize::MAX)
    };
    let connection = value["connection_id"].as_str().unwrap().parse().unwrap();
    match value["event_type"].as_str().unwrap() {
        "redis_exchange" => RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: connection,
            sequence: value["sequence"].as_u64().unwrap(),
            timestamp: now,
            request_started_at: now,
            client_addr: None,
            target_host: host.into(),
            target_port: port,
            target_addr: format!("{host}:{port}"),
            upstream_addr: format!("{host}:{port}"),
            resp_version: 2,
            database: 0,
            username: None,
            command: value["command"].as_str().unwrap().into(),
            args: value["args"].as_array().unwrap().iter().map(body).collect(),
            response_kind: value["response_kind"].as_str().unwrap().into(),
            response: body(&value["response"]),
            rpc_callback_capture: None,
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 0,
            replay_safe: value["replay_safe"].as_bool().unwrap(),
            parse_warnings: vec![],
        }),
        "redis_pub_sub_push" => RecorderEvent::RedisPubSubPush(RedisPubSubPushEvent {
            timestamp: now,
            target_host: host.into(),
            target_port: port,
            database: 0,
            username: None,
            connection_id: connection,
            subscription_sequence: value["subscription_sequence"].as_u64().unwrap(),
            rpc_request: None,
            response: body(&value["response"]),
            duration_ms: 0,
            replay_safe: true,
        }),
        "memcached_exchange" => {
            RecorderEvent::MemcachedExchange(crate::recorder::MemcachedExchangeEvent {
                id: Uuid::new_v4(),
                connection_id: connection,
                sequence: value["sequence"].as_u64().unwrap(),
                timestamp: now,
                request_started_at: value["request_started_at"]
                    .as_str()
                    .map(|value| value.parse().unwrap())
                    .unwrap_or(now),
                client_addr: None,
                target_host: host.into(),
                target_port: port,
                target_addr: format!("{host}:{port}"),
                upstream_addr: format!("{host}:{port}"),
                wire_protocol: value["wire_protocol"].as_str().unwrap().into(),
                command: value["command"].as_str().unwrap().into(),
                opcode: value["opcode"].as_u64().map(|v| v as u8),
                opaque: None,
                key: value.get("key").filter(|v| !v.is_null()).map(body),
                args: value["args"]
                    .as_array()
                    .map(|v| v.iter().map(body).collect())
                    .unwrap_or_default(),
                value: value.get("value").filter(|v| !v.is_null()).map(body),
                extras: value.get("extras").filter(|v| !v.is_null()).map(body),
                cas: None,
                noreply: false,
                quiet: false,
                response_status: "0".into(),
                response_frames: value["response_frames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(body)
                    .collect(),
                response_frame_offsets_ms: vec![],
                no_response: false,
                outcome: crate::DependencyExchangeOutcome::Response,
                duration_ms: 0,
                replay_safe: true,
                parse_warnings: vec![],
            })
        }
        "mysql_exchange" => RecorderEvent::MysqlExchange(MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: connection,
            query_sequence: value["query_sequence"].as_u64().unwrap(),
            timestamp: now,
            request_started_at: value["request_started_at"]
                .as_str()
                .map(|value| value.parse().unwrap())
                .unwrap_or(now),
            client_addr: None,
            route_name: None,
            target_host: Some(host.into()),
            target_port: Some(port),
            target_addr: None,
            upstream_addr: None,
            username: Some("reader".into()),
            database: Some("app".into()),
            command: "COM_QUERY".into(),
            sql: Some(value["sql"].as_str().unwrap().into()),
            statement_id: None,
            params: None,
            server_status_before: Some(2),
            response: MysqlExchangeResponse {
                wire_prefix: vec![],
                server_status: Some(2),
                status: "ok".into(),
                error_code: None,
                error_message: None,
                affected_rows: Some(0),
                last_insert_id: Some(0),
                columns: vec![],
                rows: vec![],
                row_count: 0,
                rows_truncated: false,
            },
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 0,
            parse_warnings: vec![],
        }),
        _ => panic!("unsupported synthetic prewarm event"),
    }
}

async fn append_http(recorder: &crate::recorder::Recorder, value: &Value, process: bool) {
    let authority: hyper::http::uri::Authority =
        value["authority"].as_str().unwrap().parse().unwrap();
    recorder
        .observe_accessed_endpoint(authority.host(), authority.port_u16().unwrap_or(80))
        .await
        .unwrap();
    let now = Utc::now();
    let body = |body: &Value| {
        let data = body["data"].as_str().unwrap();
        let bytes = if body["encoding"] == "base64" {
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap()
        } else {
            data.as_bytes().to_vec()
        };
        crate::recorder::capture_body(&bytes, usize::MAX)
    };
    let event = RecorderEvent::HttpExchange(crate::recorder::HttpExchangeEvent {
        outcome: crate::DependencyExchangeOutcome::Response,
        id: Uuid::new_v4(),
        timestamp: now,
        request_started_at: now,
        client_addr: None,
        scheme: "http".into(),
        method: value["method"].as_str().unwrap().into(),
        uri: value["uri"].as_str().unwrap().into(),
        authority: Some(authority.to_string()),
        request_headers: Default::default(),
        request_body: body(&value["request_body"]),
        response_status: Some(200),
        response_headers: Some(Default::default()),
        response_body: Some(body(&value["response_body"])),
        response_stream: value
            .get("response_stream")
            .map(|stream| serde_json::from_value(stream.clone()).unwrap()),
        discovered_tcp_targets: vec![],
        duration_ms: 0,
        error: None,
    });
    recorder
        .append_global_dependency(
            &event,
            if process {
                "background_rule"
            } else {
                "bootstrap_window"
            },
            if process { "runtime" } else { "bootstrap" },
            if process {
                "fixture_process"
            } else {
                "fixture_initialization"
            },
        )
        .await
        .unwrap();
}

pub(in crate::replay) async fn publish_case(recorder: &crate::recorder::Recorder) {
    let case = crate::recorder::CaseContext {
        id: Uuid::from_u128(123),
        rule_name: "fixture".into(),
        uri_group: None,
    };
    recorder
        .write_case_json(&case, "admission.json", &json!({"fixture":true}))
        .await
        .unwrap();
    recorder
        .write_case_json(
            &case,
            "request.json",
            &json!({"method":"GET","uri":"/example","timestamp":"1970-01-01T00:16:40Z"}),
        )
        .await
        .unwrap();
    recorder
        .write_case_json(&case, "expected-response.json", &json!({}))
        .await
        .unwrap();
    recorder.publish_case(&case).await.unwrap();
}

/// Existing semantic fixtures enter the same current Recorder pipeline before Replay.
/// Ownership is explicit at the callsite; legacy annotations have no authority.
pub(in crate::replay) async fn centralize(
    case: &Path,
    process_indices: &[usize],
) -> std::path::PathBuf {
    assert!(
        fs::read_to_string(case.join("dependencies.jsonl"))
            .unwrap()
            .trim()
            .is_empty()
    );
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("fixture_process".into(), "fixture_process_task".into());
    let recorder = crate::recorder::Recorder::new(case.parent().unwrap().join("central-fixture"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    let raw = fs::read_to_string(case.join("global-dependencies.jsonl")).unwrap();
    for (index, line) in raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        append(
            &recorder,
            &serde_json::from_str(line).unwrap(),
            process_indices.contains(&index),
        )
        .await;
    }
    publish_case(&recorder).await;
    recorder.finish_run().await.unwrap();
    case_path(&recorder.run_dir)
}

/// Explicit Source scopes for pooled native lanes; selectors never assign owners.
pub(in crate::replay) async fn centralize_partitioned(
    case: &Path,
    process_indices: &[usize],
) -> std::path::PathBuf {
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("fixture_process".into(), "fixture_process_task".into());
    let recorder =
        crate::recorder::Recorder::new(case.parent().unwrap().join("partitioned-fixture"))
            .await
            .unwrap()
            .with_global_preparation(&config)
            .await
            .unwrap();
    let context = crate::recorder::CaseContext {
        id: Uuid::from_u128(123),
        rule_name: "fixture".into(),
        uri_group: None,
    };
    for (index, line) in fs::read_to_string(case.join("dependencies.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let value: Value = serde_json::from_str(line).unwrap();
        if process_indices.contains(&index) {
            append(&recorder, &value, true).await;
        } else {
            recorder
                .observe_accessed_endpoint(
                    value["target_host"].as_str().unwrap(),
                    value["target_port"].as_u64().unwrap() as u16,
                )
                .await
                .unwrap();
            recorder
                .append_case_dependency(&context, &native_event(&value), "fixture")
                .await
                .unwrap();
        }
    }
    publish_case(&recorder).await;
    recorder.finish_run().await.unwrap();
    case_path(&recorder.run_dir)
}
