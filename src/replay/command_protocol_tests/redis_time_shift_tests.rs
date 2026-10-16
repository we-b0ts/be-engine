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
    read_json_response(client).await
}

async fn read_json_response(client: &mut TcpStream) -> Value {
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

#[tokio::test]
async fn redis_time_shift_rfc3339_get_plan_apply_preserves_session_expiry_over_real_tcp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join("apis/sessions/case-1");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/sessions/1"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(root.join("recording-run.json"), r#"{"status":"completed"}"#).unwrap();
    let captured = Utc::now() - chrono::Duration::days(1);
    let expiry = captured + chrono::Duration::hours(1);
    let value = json!({"expires_at":expiry.to_rfc3339(),"token":"private-token","ordered":[2,1]});
    let body = value.to_string();
    let wire = format!("${}\r\n{body}\r\n", body.len());
    let mut record = redis_dependency(Uuid::new_v4(), 1, "vnc_session:1", wire.as_bytes());
    record["timestamp"] = json!(captured);
    let recording = case.join("dependencies.jsonl");
    std::fs::write(&recording, record.to_string()).unwrap();
    let immutable = std::fs::read(&recording).unwrap();
    let command = b"*2\r\n$3\r\nGET\r\n$13\r\nvnc_session:1\r\n";
    let (addr, state, task) = redis_value_tests::spawn(&case, None).await;
    assert_eq!(
        begin_case(&control("begin", "case-1"), state.clone()).await["ok"],
        true
    );
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(command).await.unwrap();
    assert_eq!(read_json_response(&mut client).await, value);
    assert!(expiry < Utc::now());
    let report = root.join("replay.json");
    {
        let mut replay = state.lock().await;
        replay.finalized_at = Some(Utc::now());
        std::fs::write(
            &report,
            serde_json::to_vec(&replay.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let policy = root.join("policy.yaml");
    crate::replay::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let selector: RedisTimeShiftSelector = serde_json::from_value(json!({
        "host":"redis.internal","port":6379,
        "read":{"command":"GET","key":{"prefix":"vnc_session:"},
        "response_json":{"/expires_at":{"time":"preserve_relative","format":"rfc3339"}}}
    }))
    .unwrap();
    plan_redis_time_shift(RedisTimeShiftFeedback {
        policy_path:policy.clone(),case_source:case.clone(),replay_report_path:report,
        rule_id:"session-expiry".into(),selector,
        source_evidence:"session.py: expires_at is an RFC3339 UTC expiry set to now + 1h and compared with UTC now; no signature".into(),
    }).unwrap().apply().unwrap();
    let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy)).await;
    assert_eq!(
        begin_case(&control("begin", "case-1"), state.clone()).await["ok"],
        true
    );
    let mut client = TcpStream::connect(addr).await.unwrap();
    let before = Utc::now();
    client.write_all(command).await.unwrap();
    let actual = read_json_response(&mut client).await;
    let after = Utc::now();
    let shifted_expiry =
        chrono::DateTime::parse_from_rfc3339(actual["expires_at"].as_str().unwrap()).unwrap();
    assert!(shifted_expiry.signed_duration_since(before) >= chrono::Duration::hours(1));
    assert!(shifted_expiry.signed_duration_since(after) <= chrono::Duration::hours(1));
    assert!(actual["expires_at"].as_str().unwrap().ends_with("+00:00"));
    assert_eq!(actual["token"], value["token"]);
    assert_eq!(actual["ordered"], value["ordered"]);
    assert_eq!(
        end_case(&control("end", "case-1"), state.clone()).await["dirty"],
        false
    );
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(
        report["redis"]["time_shifts"][0]["rule_id"],
        "session-expiry"
    );
    assert!(!report.to_string().contains("private-token"));
    assert_eq!(std::fs::read(recording).unwrap(), immutable);
    task.abort();
}
fn control(command: &str, case: &str) -> ReplayControlRequest {
    serde_json::from_value(json!({"command":command,"case_id":case})).unwrap()
}

fn shared_read_recording(read_count: usize) -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let consumer = root.join("apis/tasks/consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("request.json"),
        r#"{"method":"GET","uri":"/tasks/1"}"#,
    )
    .unwrap();
    std::fs::write(consumer.join("expected-response.json"), "{}").unwrap();
    std::fs::write(consumer.join("dependencies.jsonl"), "").unwrap();
    std::fs::write(root.join("recording-run.json"), r#"{"status":"completed"}"#).unwrap();
    for index in 0..read_count {
        let origin = root.join(format!("apis/playback/origin-{index}"));
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(
            origin.join("request.json"),
            r#"{"method":"GET","uri":"/playback"}"#,
        )
        .unwrap();
        std::fs::write(origin.join("expected-response.json"), "{}").unwrap();
        // Deliberately reverse capture order relative to the origin case IDs.
        let capture_time = Utc::now() - chrono::Duration::days(1)
            + chrono::Duration::seconds((read_count - index) as i64);
        let body = json!({"timestamp":capture_time.timestamp_millis(),"read_id":index}).to_string();
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
    }
    crate::replay::write_policy_fixture(root.join("policy.yaml"), "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: token-time\n  replay_scope: recording_run\n  source_evidence: module cache shares one token across requests\n  protocol: redis\n  target: {host: redis.internal, port: 6379}\n  redis:\n    command: HGET\n    key: token_v2\n    hash_field: '00123'\n    response_json:\n      /timestamp: {time: preserve_relative, format: unix_milliseconds}\n").unwrap();
    temp
}

async fn load_shared_read_recording(case: &Path, policy: &Path) -> anyhow::Result<ReplayRuntime> {
    super::super::write_test_recording_network_manifest(case);
    let addr = "127.0.0.1:0".parse().unwrap();
    ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case.into(),
            selected_case_ids: Vec::new(),
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case.join(".replay/ca.pem")),
            ca_key_path: Some(case.join(".replay/ca-key.pem")),
            policy_path: Some(policy.into()),
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
}

#[tokio::test]
async fn redis_time_shift_scope_without_recorded_reads_allows_batch_and_focused_replay() {
    let temp = shared_read_recording(0);
    let root = temp.path();
    let policy = root.join("policy.yaml");
    for case in [root.to_path_buf(), root.join("apis/tasks/consumer")] {
        let runtime = load_shared_read_recording(&case, &policy).await.unwrap();
        assert_eq!(
            begin_case(&control("begin", "consumer"), runtime.state.clone()).await["ok"],
            true
        );
        assert_eq!(
            end_case(&control("end", "consumer"), runtime.state.clone()).await["ok"],
            true
        );
        let state = runtime.state.lock().await;
        assert!(state.targets.is_empty());
        let report = serde_json::to_value(state.snapshot_report()).unwrap();
        assert_eq!(report["redis"]["matched_count"], 0);
        assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
        assert!(
            report["redis"]["unused_case"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn redis_time_shift_scope_without_selected_read_keeps_other_reads_and_unmatched_strict() {
    let temp = shared_read_recording(0);
    let root = temp.path();
    let consumer = root.join("apis/tasks/consumer");
    let recording = consumer.join("dependencies.jsonl");
    let dependency = redis_dependency(Uuid::new_v4(), 1, "other", b"$5\r\nvalue\r\n");
    std::fs::write(&recording, dependency.to_string()).unwrap();
    let immutable = std::fs::read(&recording).unwrap();
    let (addr, state, task) =
        redis_value_tests::spawn(&consumer, Some(root.join("policy.yaml"))).await;
    assert_eq!(
        begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
        true
    );
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$5\r\nother\r\n")
        .await
        .unwrap();
    let mut response = [0; 11];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"$5\r\nvalue\r\n");
    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
        .await
        .unwrap();
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    let mut response = vec![0; error.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, error);
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 1);
    assert!(report["redis"]["matched"][0]["shared_origin"].is_null());
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 1);
    assert_eq!(report["redis"]["unmatched"][0]["command"], "HGET");
    assert!(report["redis"].get("time_shifts").is_none());
    assert_eq!(std::fs::read(recording).unwrap(), immutable);
    task.abort();
}

#[tokio::test]
async fn redis_time_shift_scope_shares_multiple_reads_in_capture_order_with_finite_consumption() {
    let temp = shared_read_recording(2);
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let ordinary = root.join("apis/other/zz-ordinary");
    std::fs::create_dir_all(&ordinary).unwrap();
    std::fs::write(
        ordinary.join("request.json"),
        r#"{"method":"GET","uri":"/other"}"#,
    )
    .unwrap();
    std::fs::write(ordinary.join("expected-response.json"), "{}").unwrap();
    let dependency = redis_dependency(Uuid::new_v4(), 1, "other", b"$5\r\nvalue\r\n");
    std::fs::write(ordinary.join("dependencies.jsonl"), dependency.to_string()).unwrap();
    super::super::write_test_recording_network_manifest(root);
    let consumer = root.join("apis/tasks/consumer");
    std::fs::copy(
        root.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        consumer.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
    )
    .unwrap();
    for case in [root.to_path_buf(), consumer] {
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
        assert_eq!(
            begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
            true
        );
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert_eq!(hget(&mut client).await["read_id"], 1);
        assert_eq!(hget(&mut client).await["read_id"], 0);
        assert_eq!(
            end_case(&control("end", "consumer"), state.clone()).await["dirty"],
            false
        );
        let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
        assert_eq!(report["redis"]["matched_count"], 2);
        assert_eq!(
            report["redis"]["matched"][0]["shared_origin"]["case_id"],
            "origin-1"
        );
        assert_eq!(
            report["redis"]["matched"][1]["shared_origin"]["case_id"],
            "origin-0"
        );
        assert!(
            report["redis"]["unused_global"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(report["redis"]["time_shifts"].as_array().unwrap().len(), 2);
        if case == root {
            // Sorting shared reads must rebuild the ordinary case gate index.
            let replay = state.lock().await;
            assert!(replay.redis.case_is_dirty("zz-ordinary"));
            assert!(!replay.redis.case_is_dirty("origin-0"));
            assert!(!replay.redis.case_is_dirty("origin-1"));
        }
        assert_eq!(
            begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
            true
        );
        client
            .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
            .await
            .unwrap();
        let error = b"-ERR no recorded Redis dependency matched\r\n";
        let mut response = vec![0; error.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, error);
        task.abort();
    }
}

#[tokio::test]
async fn redis_time_shift_scope_rejects_duplicate_partial_and_unsafe_shared_lanes() {
    for variant in ["duplicate", "partial", "nil", "timestamp"] {
        let temp = shared_read_recording(1);
        let root = temp.path();
        let file = root.join("apis/playback/origin-0/dependencies.jsonl");
        let mut record: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let (dependency, expected) = match variant {
            "duplicate" => (
                format!("{record}\n{record}"),
                "duplicate Redis cross-case exchange identity",
            ),
            "partial" => {
                let connection = serde_json::from_value(record["connection_id"].clone()).unwrap();
                let other = redis_dependency(connection, 2, "other", b"$5\r\nvalue\r\n");
                (
                    format!("{record}\n{other}"),
                    "cannot split a recorded connection lane",
                )
            }
            "nil" => {
                record["response_kind"] = json!("nil");
                record["response"] = capture_json(b"$-1\r\n");
                (record.to_string(), "complete successful ordinary JSON read")
            }
            "timestamp" => {
                record.as_object_mut().unwrap().remove("timestamp");
                (record.to_string(), "original exchange timestamp")
            }
            _ => unreachable!(),
        };
        std::fs::write(&file, dependency).unwrap();
        for case in [root.to_path_buf(), root.join("apis/tasks/consumer")] {
            let error = load_shared_read_recording(&case, &root.join("policy.yaml"))
                .await
                .err()
                .expect("invalid shared evidence must prevent startup");
            assert!(
                error.to_string().contains(expected),
                "unexpected {variant} failure: {error:#}"
            );
        }
    }
}

#[tokio::test]
async fn redis_time_shift_scope_plan_apply_shares_a_complete_multi_read_lane() {
    let temp = shared_read_recording(2);
    let root = temp.path();
    let origin = root.join("apis/playback/origin-0/dependencies.jsonl");
    let second = root.join("apis/playback/origin-1/dependencies.jsonl");
    let first: Value = serde_json::from_slice(&std::fs::read(&origin).unwrap()).unwrap();
    let mut refresh: Value = serde_json::from_slice(&std::fs::read(&second).unwrap()).unwrap();
    refresh["connection_id"] = first["connection_id"].clone();
    refresh["sequence"] = json!(2);
    let timestamp: chrono::DateTime<Utc> =
        serde_json::from_value(first["timestamp"].clone()).unwrap();
    refresh["timestamp"] = json!(timestamp + chrono::Duration::seconds(1));
    std::fs::write(&origin, format!("{first}\n{refresh}")).unwrap();
    std::fs::write(&second, "").unwrap();
    let immutable = std::fs::read(&origin).unwrap();
    let policy = root.join("policy.yaml");
    let original_policy = std::fs::read_to_string(&policy)
        .unwrap()
        .replace("  replay_scope: recording_run\n", "")
        .replace(
            "  source_evidence: module cache shares one token across requests\n",
            "",
        );
    std::fs::write(&policy, original_policy).unwrap();
    super::super::write_test_recording_network_manifest(root);
    let consumer = root.join("apis/tasks/consumer");
    std::fs::copy(
        root.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        consumer.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
    )
    .unwrap();
    let (addr, state, task) = redis_value_tests::spawn(&consumer, Some(policy.clone())).await;
    assert_eq!(
        begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
        true
    );
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$8\r\ntoken_v2\r\n$5\r\n00123\r\n")
        .await
        .unwrap();
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    let mut response = vec![0; error.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, error);
    let report = root.join("failed-replay.json");
    {
        let mut replay = state.lock().await;
        replay.finalized_at = Some(Utc::now());
        std::fs::write(
            &report,
            serde_json::to_vec(&replay.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let feedback = RedisCrossCaseFeedback {
        policy_path: policy.clone(),
        case_source: consumer.clone(),
        replay_report_path: report,
        rule_id: "token-time".into(),
        source_evidence: "module cache shares initial and refreshed tokens across requests".into(),
    };
    let plan = plan_redis_cross_case(feedback.clone()).unwrap();
    assert_eq!(plan.report().evidence["matching_exchanges"], 2);
    // Planning must still reject a partial lane and changed evidence at apply.
    let connection = serde_json::from_value(first["connection_id"].clone()).unwrap();
    let other = redis_dependency(connection, 3, "other", b"$5\r\nvalue\r\n");
    std::fs::write(&origin, format!("{first}\n{refresh}\n{other}")).unwrap();
    assert!(plan_redis_cross_case(feedback.clone()).is_err());
    assert!(plan.apply().is_err());
    std::fs::write(&origin, &immutable).unwrap();
    plan_redis_cross_case(feedback).unwrap().apply().unwrap();
    for case in [root.to_path_buf(), consumer] {
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
        assert_eq!(
            begin_case(&control("begin", "consumer"), state.clone()).await["ok"],
            true
        );
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert_eq!(hget(&mut client).await["read_id"], 0);
        assert_eq!(hget(&mut client).await["read_id"], 1);
        let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
        assert_eq!(report["redis"]["matched_count"], 2);
        assert_eq!(report["redis"]["matched"][0]["sequence"], 1);
        assert_eq!(report["redis"]["matched"][1]["sequence"], 2);
        assert!(
            report["redis"]["unused_global"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        task.abort();
    }
    assert_eq!(std::fs::read(origin).unwrap(), immutable);
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
    let policy = root.join("policy.yaml");
    crate::replay::write_policy_fixture(
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
    let policy = root.join("policy.yaml");
    crate::replay::write_policy_fixture(&policy, "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: token-time\n  protocol: redis\n  target: {host: redis.internal, port: 6379}\n  redis:\n    command: HGET\n    key: token_v2\n    hash_field: '00123'\n    response_json:\n      /timestamp: {time: preserve_relative, format: unix_milliseconds}\n").unwrap();

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
