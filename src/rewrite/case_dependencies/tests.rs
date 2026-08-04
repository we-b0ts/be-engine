use super::*;

#[test]
fn summary_stays_bounded_and_detail_returns_decoded_keys() {
    let temp = tempfile::tempdir().unwrap();
    let target_root = temp.path();
    let case_dir = target_root.join(".traffic-e2e/local/artifacts/run/api/case-a");
    std::fs::create_dir_all(&case_dir).unwrap();
    let redis_key = STANDARD.encode("42.cntbf");
    let redis_response = STANDARD.encode("$1\r\n7\r\n");
    let second_redis_key = STANDARD.encode("43.cntbf");
    let second_redis_response = STANDARD.encode("$1\r\n9\r\n");
    let memcached_key = STANDARD.encode("42.gfl");
    let raw = format!(
        "{{\"event_type\":\"redis_exchange\",\"target_host\":\"breeze.recording\",\"target_port\":9332,\"command\":\"GET\",\"args\":[{{\"encoding\":\"base64\",\"original_len\":8,\"stored_len\":8,\"truncated\":false,\"data\":\"{redis_key}\"}}],\"response_kind\":\"bulk_string\",\"response\":{{\"encoding\":\"base64\",\"original_len\":7,\"stored_len\":7,\"truncated\":false,\"data\":\"{redis_response}\"}},\"outcome\":\"response\"}}\n{{\"event_type\":\"redis_exchange\",\"target_host\":\"breeze.recording\",\"target_port\":9332,\"command\":\"GET\",\"args\":[{{\"encoding\":\"base64\",\"original_len\":8,\"stored_len\":8,\"truncated\":false,\"data\":\"{second_redis_key}\"}}],\"response_kind\":\"bulk_string\",\"response\":{{\"encoding\":\"base64\",\"original_len\":7,\"stored_len\":7,\"truncated\":false,\"data\":\"{second_redis_response}\"}},\"outcome\":\"response\"}}\n{{\"event_type\":\"memcached_exchange\",\"target_host\":\"breeze.recording\",\"target_port\":9400,\"command\":\"get\",\"key\":{{\"encoding\":\"base64\",\"original_len\":6,\"stored_len\":6,\"truncated\":false,\"data\":\"{memcached_key}\"}},\"flags\":4098,\"quiet\":false,\"no_response\":false,\"response_status\":\"0\",\"response_frames\":[{{\"original_len\":128}}],\"outcome\":\"response\"}}\n"
    );
    std::fs::write(case_dir.join("dependencies.jsonl"), raw).unwrap();

    let summary = query(RewriteCaseDependenciesOptions {
        target_root: target_root.to_path_buf(),
        case_dir: case_dir.clone(),
        target_id: None,
    })
    .unwrap();
    let summary_value = serde_json::to_value(&summary).unwrap();
    assert_eq!(summary_value["targets_total"], 2);
    assert!(!summary_value.to_string().contains("cntbf"));
    assert!(
        summary_value["next_step"]
            .as_str()
            .unwrap()
            .contains("detail_command")
    );
    assert!(
        summary_value
            .pointer("/targets/0/detail_command/argv")
            .is_some()
    );
    for target in summary_value["targets"].as_array().unwrap() {
        assert_eq!(
            target["detail_command"]["argv"][0],
            Value::String("backend-rewrite".to_string())
        );
        assert_eq!(
            target["detail_command"]["argv"][1],
            Value::String("case".to_string())
        );
        assert_eq!(
            target["detail_command"]["argv"][2],
            Value::String("dependencies".to_string())
        );
        assert_eq!(target["detail_command"]["argv"][4], target["target_id"]);
    }

    let redis_target = summary_value["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["protocol"] == "redis")
        .unwrap();
    let target_id = redis_target["target_id"].as_str().unwrap();
    let detail = query(RewriteCaseDependenciesOptions {
        target_root: target_root.to_path_buf(),
        case_dir: case_dir.clone(),
        target_id: Some(target_id.to_string()),
    })
    .unwrap();
    let detail_value = serde_json::to_value(detail).unwrap();
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/0/keys/0/data"),
        Some(&Value::String("42.cntbf".to_string()))
    );
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/0/response/data"),
        Some(&Value::String("$1\r\n7\r\n".to_string()))
    );
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/0/response_value"),
        Some(&Value::String("7".to_string()))
    );
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/1/keys/0/data"),
        Some(&Value::String("43.cntbf".to_string()))
    );
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/1/response/data"),
        Some(&Value::String("$1\r\n9\r\n".to_string()))
    );
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/1/response_value"),
        Some(&Value::String("9".to_string()))
    );

    let memcached_target = summary_value["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["protocol"] == "memcached")
        .unwrap();
    let target_id = memcached_target["target_id"].as_str().unwrap();
    let detail = query(RewriteCaseDependenciesOptions {
        target_root: target_root.to_path_buf(),
        case_dir,
        target_id: Some(target_id.to_string()),
    })
    .unwrap();
    let detail_value = serde_json::to_value(detail).unwrap();
    assert_eq!(
        detail_value.pointer("/operations/0/representative_exchanges/0/key/data"),
        Some(&Value::String("42.gfl".to_string()))
    );
    let rendered = detail_value.to_string();
    assert!(!rendered.contains("flags"));
    assert!(!rendered.contains("opaque"));
    assert!(!rendered.contains("extras"));
}

#[test]
fn rejects_case_directories_outside_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".traffic-e2e/local/artifacts")).unwrap();
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("dependencies.jsonl"), "").unwrap();

    let error = query(RewriteCaseDependenciesOptions {
        target_root: temp.path().to_path_buf(),
        case_dir: outside,
        target_id: None,
    })
    .unwrap_err();

    assert!(error.to_string().contains(".traffic-e2e/local/artifacts"));
}

#[test]
fn redis_argument_examples_are_bounded_per_exchange() {
    let capture = serde_json::json!({
        "encoding": "utf8",
        "original_len": 3,
        "truncated": false,
        "data": "key",
    });
    let captures = vec![capture; MAX_ARGUMENTS_PER_REPRESENTATIVE + 5];
    let mut representatives = RepresentativeRedisExchanges::default();
    let event = serde_json::json!({
        "response_kind": "array",
        "outcome": "response",
    });

    representatives.insert(&event, "MGET", &captures).unwrap();

    assert_eq!(
        representatives.values[0].args.len(),
        MAX_ARGUMENTS_PER_REPRESENTATIVE
    );
    assert_eq!(
        representatives.values[0].keys.len(),
        MAX_ARGUMENTS_PER_REPRESENTATIVE
    );
    assert_eq!(representatives.values[0].omitted_args, 5);
    assert_eq!(representatives.values[0].omitted_keys, 5);
}

#[test]
fn large_dependency_responses_return_only_a_length_annotated_preview() {
    let response = serde_json::json!({
        "encoding": "utf8",
        "original_len": 512,
        "truncated": false,
        "data": "x".repeat(512),
    });

    let preview = capture_preview(&response).unwrap();

    assert_eq!(preview.data.len(), MAX_PREVIEW_BYTES);
    assert_eq!(preview.original_len, 512);
    assert!(preview.truncated);
    assert!(redis_scalar_response_value(&response).unwrap().is_none());
}

#[test]
fn operation_reports_exchanges_omitted_by_the_representative_bound() {
    let mut builder = RedisOperationBuilder::default();
    for index in 0..(MAX_REPRESENTATIVES + 1) {
        let key = format!("key-{index}");
        let response = format!("${}\r\n{}\r\n", index.to_string().len(), index);
        builder
            .record(&serde_json::json!({
                "event_type": "redis_exchange",
                "command": "GET",
                "args": [{
                    "encoding": "utf8",
                    "original_len": key.len(),
                    "truncated": false,
                    "data": key,
                }],
                "response_kind": "bulk_string",
                "response": {
                    "encoding": "utf8",
                    "original_len": response.len(),
                    "truncated": false,
                    "data": response,
                },
                "outcome": "response",
            }))
            .unwrap();
    }

    let details = finish_redis(BTreeMap::from([("GET".to_string(), builder)]));

    assert_eq!(
        details[0].representative_exchanges.len(),
        MAX_REPRESENTATIVES
    );
    assert_eq!(details[0].omitted_representative_exchanges, 1);
}
