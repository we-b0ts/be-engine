//! Native timing fixtures retain original clocks and protected primary inputs.
use super::*;
use crate::recorder::{
    CaseContext, Recorder, RecorderEvent, RedisExchangeEvent, RedisPubSubPushEvent,
    RedisRpcRequestRef,
};

pub(super) async fn runtime(
    root: &Path,
    cases: &[Value],
    globals: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    capture_and_load(root, cases, globals, lazy, false).await
}

pub(super) async fn ambient_runtime(
    root: &Path,
    cases: &[Value],
    globals: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    capture_and_load(root, cases, globals, lazy, true).await
}

async fn capture_and_load(
    root: &Path,
    cases: &[Value],
    globals: &[Value],
    lazy: bool,
    ambient: bool,
) -> Result<Arc<ReplayRuntime>> {
    let mut config = crate::AppConfig::default();
    config.process_dependency_tasks.insert(
        "native-notification-selector".into(),
        "external_notification_stream".into(),
    );
    let output =
        if crate::request_headers::project_encryption_key_path(&root.join("case/request.json"))
            .is_some()
        {
            // Preserve the original project key, including a deliberately missing
            // key in the authenticated-input failure fixture.
            root.join("central-recording")
        } else {
            std::fs::create_dir_all(root.join(crate::repository::LOCAL_ROOT))?;
            crate::platform::encryption_key::load_or_create(root)?;
            root.join(crate::repository::LOCAL_ROOT)
                .join("central-recording")
        };
    let recorder = Recorder::new(output)
        .await?
        .with_global_preparation(&config)
        .await?;
    for event in globals {
        observe_endpoint(&recorder, event).await?;
        let unowned = ambient
            && (event["event_type"] == "redis_pub_sub_push"
                || event["fixture_unattributed"] == true)
            && event["fixture_process_owned"] != true;
        recorder
            .append_global_dependency(
                &native_event(event),
                if unowned {
                    "outside_admission"
                } else {
                    "background_rule"
                },
                "runtime",
                if unowned {
                    ""
                } else {
                    "native-notification-selector"
                },
            )
            .await?;
    }
    let case = publish(&recorder, &root.join("case"), CASE, cases).await?;
    if root.join("unselected").is_dir() {
        publish(
            &recorder,
            &root.join("unselected"),
            "00000000-0000-0000-0000-000000000124",
            &[],
        )
        .await?;
    }
    recorder.finish_run().await?;
    let addr = "127.0.0.1:0".parse().unwrap();
    Ok(Arc::new(
        ReplayRuntime::load_with_lifecycle(
            ReplayConfig {
                case_dir: case,
                selected_case_ids: vec![],
                dns_listen: addr,
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(root.join("ca.pem")),
                ca_key_path: Some(root.join("ca-key.pem")),
                policy_path: root
                    .join(".traffic-e2e/policy.yaml")
                    .is_file()
                    .then(|| root.join(".traffic-e2e/policy.yaml")),
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            addr,
            addr,
            ReplayLifecycleConfig {
                dependency_loading: ReplayDependencyLoading {
                    lazy_cases: lazy,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?,
    ))
}

async fn publish(
    recorder: &Recorder,
    seed: &Path,
    id: &str,
    events: &[Value],
) -> Result<std::path::PathBuf> {
    let case = CaseContext {
        id: id.parse().unwrap(),
        rule_name: "native-clock".into(),
        uri_group: None,
    };
    recorder
        .write_case_json(&case, "admission.json", &json!({"fixture":true}))
        .await?;
    for (name, default) in [
        (
            "request.json",
            json!({"method":"GET","uri":"/api","timestamp":START}),
        ),
        ("expected-response.json", json!({"status":200})),
    ] {
        let value: Value = if seed.join(name).is_file() {
            serde_json::from_slice(&std::fs::read(seed.join(name))?)?
        } else {
            default
        };
        recorder.write_case_json(&case, name, &value).await?;
    }
    for event in events {
        observe_endpoint(recorder, event).await?;
        recorder
            .append_case_dependency(&case, &native_event(event), "fixture_request_admission")
            .await?;
    }
    recorder.publish_case(&case).await?;
    Ok(recorder.case_dir(&case))
}

async fn observe_endpoint(recorder: &Recorder, event: &Value) -> Result<()> {
    recorder
        .observe_accessed_endpoint(
            event["target_host"].as_str().unwrap(),
            event["target_port"].as_u64().unwrap() as u16,
        )
        .await
}

fn native_event(value: &Value) -> RecorderEvent {
    let timestamp = value["timestamp"]
        .as_str()
        .unwrap_or(START)
        .parse()
        .unwrap();
    let host = value["target_host"].as_str().unwrap();
    let port = value["target_port"].as_u64().unwrap() as u16;
    let connection_id = value["connection_id"].as_str().unwrap().parse().unwrap();
    let body = |capture: &Value| {
        let data = capture["data"].as_str().unwrap();
        let bytes = if capture["encoding"] == "base64" {
            STANDARD.decode(data).unwrap()
        } else {
            data.as_bytes().to_vec()
        };
        crate::recorder::capture_body(&bytes, usize::MAX)
    };
    match value["event_type"].as_str().unwrap() {
        "redis_exchange" => RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            timestamp,
            request_started_at: timestamp,
            connection_id,
            sequence: value["sequence"].as_u64().unwrap(),
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
            duration_ms: value["duration_ms"].as_u64().unwrap_or(0) as u128,
            replay_safe: value["replay_safe"].as_bool().unwrap_or(true),
            parse_warnings: vec![],
        }),
        "redis_pub_sub_push" => RecorderEvent::RedisPubSubPush(RedisPubSubPushEvent {
            timestamp,
            target_host: host.into(),
            target_port: port,
            database: 0,
            username: None,
            connection_id,
            subscription_sequence: value["subscription_sequence"].as_u64().unwrap(),
            rpc_request: value["rpc_request"]
                .as_object()
                .map(|request| RedisRpcRequestRef {
                    connection_id: request["connection_id"].as_str().unwrap().parse().unwrap(),
                    sequence: request["sequence"].as_u64().unwrap(),
                    case_id: request
                        .get("case_id")
                        .and_then(Value::as_str)
                        .map(|id| id.parse().unwrap()),
                }),
            response: body(&value["response"]),
            duration_ms: value["duration_ms"].as_u64().unwrap_or(0),
            replay_safe: true,
        }),
        kind => panic!("unsupported native-clock fixture kind {kind}"),
    }
}
