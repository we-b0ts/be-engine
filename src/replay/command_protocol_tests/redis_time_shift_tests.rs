use super::super::control::{ReplayControlRequest, begin_case, end_case};
use super::*;
use crate::{
    RedisCrossCaseFeedback, RedisTimeShiftFeedback, RedisTimeShiftSelector, plan_redis_cross_case,
    plan_redis_time_shift,
};
use serde_json::json;

async fn hget(client: &mut TcpStream) -> Value {
    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
        .await
        .unwrap();
    let raw = tokio::time::timeout(Duration::from_secs(5), async {
        let mut raw = Vec::new();
        let mut byte = [0];
        while !raw.ends_with(b"\r\n") {
            client.read_exact(&mut byte).await.unwrap();
            raw.push(byte[0]);
        }
        assert_eq!(raw[0], b'$');
        let len: usize = std::str::from_utf8(&raw[1..raw.len() - 2])
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0; len + 2];
        client.read_exact(&mut body).await.unwrap();
        body.truncate(len);
        body
    })
    .await
    .unwrap();
    serde_json::from_slice(&raw).unwrap()
}
fn control(command: &str, case: &str) -> ReplayControlRequest {
    serde_json::from_value(json!({"command":command,"case_id":case})).unwrap()
}
async fn get_token(cache: &mut Option<Value>, client: &mut TcpStream) -> Value {
    if let Some(token) = cache.as_ref()
        && Utc::now().timestamp_millis() - token["timestamp"].as_i64().unwrap() < 10800000
    {
        return token.clone();
    }
    let token = hget(client).await;
    *cache = Some(token.clone());
    token
}
#[tokio::test]
async fn redis_time_shift_plan_apply_restores_cache_reuse_across_cases_over_real_tcp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let api = root.join("apis/playback");
    for id in ["case-1", "case-2"] {
        let case = api.join(id);
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"GET","uri":"/playback"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    }
    std::fs::write(root.join("recording-run.json"), r#"{"status":"completed"}"#).unwrap();
    let capture_time = Utc::now() - chrono::Duration::days(1);
    let token = json!({"timestamp":capture_time.timestamp_millis()-221157,"token":"private-token","secret":"private-secret"});
    let body = token.to_string();
    let wire = format!("${}\r\n{}\r\n", body.len(), body);
    let mut record = redis_hash_dependency(
        Uuid::new_v4(),
        1,
        "HGET",
        &["token_v2", "00123"],
        wire.as_bytes(),
    );
    record["timestamp"] = json!(capture_time);
    let recording = api.join("case-1/dependencies.jsonl");
    std::fs::write(&recording, record.to_string()).unwrap();
    let immutable = std::fs::read(&recording).unwrap();
    // The first attempt reads once in case 1, then fails the extra case-2 read.
    let (addr, state, task) = redis_value_tests::spawn(&api, None).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        begin_case(&control("begin", "case-1"), state.clone()).await["ok"],
        true
    );
    assert_eq!(hget(&mut client).await, token);
    assert_eq!(
        end_case(&control("end", "case-1"), state.clone()).await["ok"],
        true
    );
    assert_eq!(
        begin_case(&control("begin", "case-2"), state.clone()).await["ok"],
        true
    );
    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
        .await
        .unwrap();
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    let mut bytes = vec![0; error.len()];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, error);
    let report = root.join("replay.json");
    {
        let mut s = state.lock().await;
        s.finalized_at = Some(Utc::now());
        std::fs::write(&report, serde_json::to_vec(&s.snapshot_report()).unwrap()).unwrap();
    }
    task.abort();
    let policy = root.join("verification.yaml");
    std::fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let selector:RedisTimeShiftSelector=serde_json::from_value(json!({
        "host":"redis.internal","port":6379,"read":{"command":"HGET","key":"token_v2","hash_field":{"numeric":true},
        "response_json":{"/timestamp":{"time":"preserve_relative","format":"unix_milliseconds"}}}
    })).unwrap();
    plan_redis_time_shift(RedisTimeShiftFeedback {policy_path:policy.clone(),case_source:api.clone(),replay_report_path:report,
        rule_id:"token-time".into(),selector,source_evidence:"tauth.py:67 _is_token_valid: timestamp milliseconds controls 3h cache; credentials remain unchanged".into()})
        .unwrap().apply().unwrap();
    // Fresh Replay returns the same token with its original relative age.
    let (addr, state, task) = redis_value_tests::spawn(&api, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        begin_case(&control("begin", "case-1"), state.clone()).await["ok"],
        true
    );
    let mut cache = None;
    let cached = get_token(&mut cache, &mut client).await;
    assert_eq!(cached["token"], token["token"]);
    assert_eq!(cached["secret"], token["secret"]);
    let age = Utc::now().timestamp_millis() - cached["timestamp"].as_i64().unwrap();
    assert!((221157..226157).contains(&age), "age={age}");
    assert_eq!(
        end_case(&control("end", "case-1"), state.clone()).await["ok"],
        true
    );
    assert_eq!(
        begin_case(&control("begin", "case-2"), state.clone()).await["ok"],
        true
    );
    // Exercise the source's cache gate: the second request needs no Redis call.
    assert_eq!(get_token(&mut cache, &mut client).await, cached);
    assert!(Utc::now().timestamp_millis() - cached["timestamp"].as_i64().unwrap() < 10800000);
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 1);
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    assert_eq!(report["redis"]["time_shifts"][0]["rule_id"], "token-time");
    assert_eq!(
        report["replay_policy"]["dependency_rules"][0]["validations"],
        1
    );
    assert!(!report.to_string().contains("private-token"));
    assert_eq!(std::fs::read(recording).unwrap(), immutable);
    // Scope and finite consumption remain strict even with the rule.
    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
        .await
        .unwrap();
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, error);
    task.abort();
}

#[tokio::test]
async fn redis_time_shift_scope_loads_one_sibling_read_and_preserves_finite_consumption() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let origin = root.join("apis/remote-status/origin");
    let consumer = root.join("apis/tasks/consumer");
    for (case, uri) in [(&origin, "/remote-status"), (&consumer, "/tasks/1")] {
        std::fs::create_dir_all(case).unwrap();
        std::fs::write(
            case.join("request.json"),
            json!({"method":"GET","uri":uri}).to_string(),
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    }
    std::fs::write(root.join("recording-run.json"), r#"{"status":"completed"}"#).unwrap();
    let capture_time = Utc::now() - chrono::Duration::days(1);
    let token = json!({"timestamp":capture_time.timestamp_millis()-60_000,"token":"private-token","secret":"private-secret"});
    let body = token.to_string();
    let wire = format!("${}\r\n{}\r\n", body.len(), body);
    let mut record = redis_hash_dependency(
        Uuid::new_v4(),
        1,
        "HGET",
        &["token_v2", "00123"],
        wire.as_bytes(),
    );
    record["timestamp"] = json!(capture_time);
    std::fs::write(origin.join("dependencies.jsonl"), record.to_string()).unwrap();
    let policy = root.join("verification.yaml");
    std::fs::write(&policy, "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: token-time\n  protocol: redis\n  target: {host: redis.internal, port: 6379}\n  redis:\n    command: HGET\n    key: token_v2\n    hash_field: '00123'\n    response_json:\n      /timestamp: {time: preserve_relative, format: unix_milliseconds}\n").unwrap();

    super::super::write_test_recording_network_manifest(root);
    std::fs::copy(
        root.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        consumer.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
    )
    .unwrap();

    let command = b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n";
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    let (addr, state, task) = redis_value_tests::spawn(&consumer, Some(policy.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
        true
    );
    client.write_all(command).await.unwrap();
    let mut bytes = vec![0; error.len()];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, error);
    let failed_report = root.join("failed-replay.json");
    {
        let mut replay = state.lock().await;
        replay.finalized_at = Some(Utc::now());
        std::fs::write(
            &failed_report,
            serde_json::to_vec(&replay.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let feedback = RedisCrossCaseFeedback {
        policy_path: policy.clone(),
        case_source: consumer.clone(),
        replay_report_path: failed_report.clone(),
        rule_id: "token-time".into(),
        source_evidence: "tauth.py: module cache shares one token across requests".into(),
    };
    let report_bytes = std::fs::read(&failed_report).unwrap();
    let mut wrong_request: Value = serde_json::from_slice(&report_bytes).unwrap();
    wrong_request["redis"]["unmatched"][0]["request_fingerprint"] = json!("wrong-request");
    std::fs::write(&failed_report, wrong_request.to_string()).unwrap();
    assert!(plan_redis_cross_case(feedback.clone()).is_err());
    std::fs::write(&failed_report, report_bytes).unwrap();
    let source_file = origin.join("dependencies.jsonl");
    let original_source = std::fs::read(&source_file).unwrap();
    std::fs::write(&source_file, format!("{}\n{}", record, record)).unwrap();
    assert!(plan_redis_cross_case(feedback.clone()).is_err());
    std::fs::write(&source_file, original_source).unwrap();
    let plan = plan_redis_cross_case(feedback).unwrap();
    assert!(plan.report().requires_replay);
    assert_eq!(
        plan.report().evidence["candidate"]["origin_case_id"],
        "origin"
    );
    plan.apply().unwrap();
    assert!(
        std::fs::read_to_string(&policy)
            .unwrap()
            .contains("replay_scope: recording_run")
    );

    let (addr, state, task) = redis_value_tests::spawn(&consumer, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
        true
    );
    let got = hget(&mut client).await;
    assert_eq!(got["token"], token["token"]);
    assert_eq!(got["secret"], token["secret"]);
    let age = Utc::now().timestamp_millis() - got["timestamp"].as_i64().unwrap();
    assert!((60_000..65_000).contains(&age), "age={age}");
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(
        report["redis"]["matched"][0]["shared_origin"]["case_id"],
        "origin"
    );
    assert_eq!(
        report["redis"]["matched"][0]["shared_origin"]["rule_id"],
        "token-time"
    );
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!report.to_string().contains("private-token"));
    client.write_all(command).await.unwrap();
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, error);
    task.abort();
}
