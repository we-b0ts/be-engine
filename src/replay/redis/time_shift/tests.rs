use super::*;
use crate::{RedisTimeShiftFeedback, plan_redis_time_shift};
use serde_json::json;
use std::fs;

fn selector() -> RedisTimeShiftSelector {
    serde_json::from_value(json!({
        "host":"redis.test","port":6379,
        "read":{"command":"HGET", "key":"token_v2","hash_field":{"numeric":true},
          "response_json":{"/timestamp":{"time":"preserve_relative","format":"unix_milliseconds"}}}
    }))
    .unwrap()
}

#[test]
fn recording_run_scope_rejects_patterned_redis_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verification.yaml");
    let document = "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: token-time\n  replay_scope: recording_run\n  source_evidence: tauth.py cache is shared\n  protocol: redis\n  target: {host: redis.test, port: 6379}\n  redis:\n    command: HGET\n    key: token_v2\n    hash_field: {numeric: true}\n    response_json:\n      /timestamp: {time: preserve_relative, format: unix_milliseconds}\n";
    fs::write(&path, document).unwrap();
    let error = crate::replay::validate_replay_policy(&path).unwrap_err();
    assert!(format!("{error:#}").contains("exact key and hash field"));
    fs::write(&path, document.replace("{numeric: true}", "'00123'")).unwrap();
    crate::replay::validate_replay_policy(&path).unwrap();
}
fn record(value: Value) -> RecordedExchange {
    let body = value.to_string();
    serde_json::from_value(json!({
        "timestamp":"2026-09-07T06:22:26.653Z","connection_id":Uuid::new_v4(),"sequence":1,
        "target_host":"redis.test","target_port":6379,"resp_version":2,"database":0,"username":null,
        "command":"HGET","args":[{"encoding":"utf8","data":"token_v2"},{"encoding":"utf8","data":"00123"}],
        "response_kind":"bulk_string","response":{"encoding":"utf8","data":format!("${}\r\n{}\r\n",body.len(),body)},
        "replay_safe":true
    })).unwrap()
}
fn token() -> Value {
    json!({"timestamp":1788761925496_i64,"token":"private-token","secret":"private-secret","ordered":[2,1]})
}

#[test]
fn relative_age_and_expired_or_future_status_are_preserved_without_changing_credentials() {
    for age in [221157_i64, 10800001, -5000] {
        let mut value = token();
        let recorded = record(value.clone());
        let captured = recorded.timestamp.unwrap();
        value["timestamp"] = (captured.timestamp_millis() - age).into();
        let recorded = record(value.clone());
        let shifted =
            ResponseShift::prepare(&recorded, &[("token-time".into(), selector().read)]).unwrap();
        let replayed = captured + chrono::Duration::days(1);
        let (bytes, offset) = shifted.render(replayed).unwrap();
        let actual = decode_payload(&bytes).unwrap();
        assert_eq!(offset, 86400000);
        assert_eq!(
            replayed.timestamp_millis() - actual["timestamp"].as_i64().unwrap(),
            age
        );
        assert_eq!(actual["token"], value["token"]);
        assert_eq!(actual["secret"], value["secret"]);
        assert_eq!(actual["ordered"], value["ordered"]);
        assert_eq!(
            decode_payload(&recorded.response.decode().unwrap()).unwrap(),
            value
        );
        assert_eq!(shifted.render(replayed).unwrap().0, bytes);
    }
}
#[test]
fn compact_key_and_field_patterns_keep_exact_bytes_and_legacy_input() {
    for (yaml, yes, no) in [
        ("'00123'", "00123", "123"),
        ("{numeric: true}", "00123", "１２３"),
        (
            "{prefix: 'app:', suffix: ':token', numeric: true}",
            "app:001:token",
            "app::token",
        ),
        ("{prefix: 'app:'}", "app:any", "other:any"),
        ("{suffix: ':token'}", "any:token", "token:any"),
        ("{kind: exact, value: token_v2}", "token_v2", "other"),
        (
            "{kind: numeric, prefix: 'app:', suffix: ':token'}",
            "app:123:token",
            "app:x:token",
        ),
    ] {
        let s: value::RedisValueKeySelector = serde_yaml::from_str(yaml).unwrap();
        assert!(s.matches(yes.as_bytes()));
        assert!(!s.matches(no.as_bytes()));
        let roundtrip = serde_yaml::from_str::<value::RedisValueKeySelector>(
            &serde_yaml::to_string(&s).unwrap(),
        )
        .unwrap();
        assert_eq!(s, roundtrip);
    }
    for bad in [
        "{}",
        "{numeric: false}",
        "{kind: exact, value: x, prefix: x}",
        "{value: x}",
        "{regex: '.*'}",
    ] {
        assert!(serde_yaml::from_str::<value::RedisValueKeySelector>(bad).is_err());
    }
}
#[test]
fn malformed_missing_or_overflowing_payloads_are_not_silently_replaced() {
    for value in [
        json!({"timestamp":null}),
        json!({"timestamp":"1788761925496"}),
        json!({"timestamp":1.5}),
        json!({}),
    ] {
        assert!(
            ResponseShift::prepare(&record(value), &[("time".into(), selector().read)]).is_err()
        );
    }
    let mut r = record(token());
    r.timestamp = None;
    assert!(ResponseShift::prepare(&r, &[("time".into(), selector().read)]).is_err());
    let mut r = record(token());
    r.response.data = "$31\r\n{\"timestamp\":1,\"timestamp\":2}\r\n".into();
    assert!(ResponseShift::prepare(&r, &[("time".into(), selector().read)]).is_err());
    let r = record(json!({"timestamp":i64::MAX}));
    let shift = ResponseShift::prepare(&r, &[("time".into(), selector().read)]).unwrap();
    assert!(
        shift
            .render(r.timestamp.unwrap() + chrono::Duration::days(1))
            .is_err()
    );
}
fn fixture() -> (
    tempfile::TempDir,
    RedisTimeShiftFeedback,
    std::path::PathBuf,
) {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let case = temp.path().join("apis/playback/case-1");
    fs::create_dir_all(&case).unwrap();
    let r = record(token());
    let mut event = serde_json::to_value(&r).unwrap();
    event["event_type"] = "redis_exchange".into();
    let path = case.join("dependencies.jsonl");
    fs::write(&path, event.to_string()).unwrap();
    let replay = temp.path().join("report.json");
    fs::write(
        &replay,
        json!({"finalized":true,"redis":{"matched":[{
        "case_id":"case-1","connection_id":r.connection_id,"sequence":1
    }],"unmatched":[{"case_id":"case-2","command":"HGET"}]}})
        .to_string(),
    )
    .unwrap();
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let feedback = RedisTimeShiftFeedback {
        policy_path: policy,
        case_source: case,
        replay_report_path: replay,
        rule_id: "token-time".into(),
        selector: selector(),
        source_evidence:
            "tauth.py:67 _is_token_valid: milliseconds; cache age < 3h; timestamp is not signed"
                .into(),
    };
    (temp, feedback, path)
}
#[test]
fn manual_plan_uses_previously_matched_response_without_hints_and_rejects_stale_evidence() {
    let (_temp, f, path) = fixture();
    let original = fs::read(&path).unwrap();
    let plan = plan_redis_time_shift(f.clone()).unwrap();
    let report = serde_json::to_string(plan.report()).unwrap();
    assert!(!report.contains("private-token") && !report.contains("private-secret"));
    assert_eq!(plan.report().evidence["matched_in_attempt"], 1);
    plan.apply().unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(
        plan_redis_time_shift(f.clone())
            .unwrap()
            .report()
            .reused_existing
    );
    let plan = plan_redis_time_shift(f.clone()).unwrap();
    fs::write(
        &path,
        String::from_utf8(original)
            .unwrap()
            .replace("private-token", "changed-token"),
    )
    .unwrap();
    assert!(plan.apply().is_err());
    let plan = plan_redis_time_shift(f.clone()).unwrap();
    fs::write(
        &f.policy_path,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    assert!(plan.apply().is_err());
    fs::write(
        &f.replay_report_path,
        r#"{"finalized":true,"redis":{"matched":[]}}"#,
    )
    .unwrap();
    assert!(plan_redis_time_shift(f).is_err());
}

#[test]
fn seconds_get_scope_and_policy_overlaps_remain_explicit() {
    let (_temp, f, _) = fixture();
    let mut r = record(json!({"timestamp":1788761925_i64}));
    r.command = "GET".into();
    r.args.truncate(1);
    let mut s = selector();
    s.read.command = "GET".into();
    s.read.hash_field = None;
    s.read.response_json.get_mut("/timestamp").unwrap().format = RedisTimestampFormat::UnixSeconds;
    s.validate().unwrap();
    let args = r
        .args
        .iter()
        .map(|a| a.decode().unwrap())
        .collect::<Vec<_>>();
    assert!(s.matches(&r, &args));
    for bad in ["host", "port", "database", "key", "command"] {
        let mut wrong = s.clone();
        match bad {
            "host" => wrong.host = "other.test".into(),
            "port" => wrong.port += 1,
            "database" => wrong.read.database += 1,
            "key" => {
                wrong.read.key = value::RedisValueKeySelector::Exact {
                    value: "wrong".into(),
                }
            }
            _ => wrong.read.command = "HGET".into(),
        }
        assert!(!wrong.matches(&r, &args));
    }
    let now = r.timestamp.unwrap() + chrono::Duration::days(1);
    let shift = ResponseShift::prepare(&r, &[("seconds".into(), s.read)]).unwrap();
    assert_eq!(
        decode_payload(&shift.render(now).unwrap().0).unwrap()["timestamp"],
        1788848325_i64
    );
    plan_redis_time_shift(f.clone()).unwrap().apply().unwrap();
    let mut narrower = f.clone();
    narrower.rule_id = "overlap".into();
    narrower.selector.read.hash_field = Some(value::RedisValueKeySelector::Exact {
        value: "00123".into(),
    });
    assert!(plan_redis_time_shift(narrower).is_err());
    let mut missing = f;
    missing.selector.read.response_json = BTreeMap::from([(
        "/missing".into(),
        RelativeTimeField {
            time: RelativeTime::PreserveRelative,
            format: RedisTimestampFormat::UnixMilliseconds,
        },
    )]);
    assert!(plan_redis_time_shift(missing).is_err());
}
