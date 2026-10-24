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
fn finite_sharing_rejects_patterned_redis_identity() {
    let proof = json!({"source":"tauth.py:cache","fact":"Source shares this exact key and hash field finitely"});
    let rule = json!({"id":"token-time","match":{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"HGET","key":{"kind":"exact","value":"token_v2"}},"proof":proof,
        "effect":{"kind":"finite_sharing","protocol":"redis","hash_field":"00123","response_time":{
            "/timestamp":{"contract":{"format":"unix_milliseconds","relation":"preserve_offset"},"proof":proof}}}});
    let parse = |rule: Value| {
        crate::policy::parse_policy(
            &json!({"format":"traffic-policy/v2","rules":[rule]}).to_string(),
        )
    };
    parse(rule.clone()).unwrap();
    let mut patterned_key = rule.clone();
    patterned_key["match"]["key"] = json!({"kind":"numeric","prefix":"token:"});
    assert!(parse(patterned_key).is_err());
    let mut patterned_field = rule;
    patterned_field["effect"]["hash_field"] = json!({"numeric":true});
    assert!(parse(patterned_field).is_err());
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
fn rfc3339_preserves_relative_expiry_offsets_and_submillisecond_precision() {
    let captured = record(token()).timestamp.unwrap();
    for offset in ["Z", "+00:00", "+08:00", "-05:30"] {
        let timezone = *DateTime::parse_from_rfc3339(&format!("2026-09-07T06:22:26{offset}"))
            .unwrap()
            .offset();
        for lifetime in [-3600, -1, 0, 3600] {
            let expiry = (captured + chrono::Duration::seconds(lifetime)).with_timezone(&timezone);
            let text = expiry.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, offset == "Z");
            let value = json!({"timestamp":text,"token":"private-token","ordered":[2,1]});
            let recorded = record(value.clone());
            let mut read = selector().read;
            read.response_json.get_mut("/timestamp").unwrap().format =
                RedisTimestampFormat::Rfc3339;
            let shift = ResponseShift::prepare(&recorded, &[("expiry".into(), read)]).unwrap();
            for delta in [
                chrono::Duration::days(1) + chrono::Duration::nanoseconds(123_456_789),
                -chrono::Duration::days(1) + chrono::Duration::nanoseconds(1),
            ] {
                let now = captured + delta;
                let (wire, _) = shift.render(now).unwrap();
                let actual = decode_payload(&wire).unwrap();
                let shifted =
                    DateTime::parse_from_rfc3339(actual["timestamp"].as_str().unwrap()).unwrap();
                assert_eq!(
                    shifted.signed_duration_since(now),
                    chrono::Duration::seconds(lifetime)
                );
                assert_eq!(shifted.offset(), &timezone);
                assert!(actual["timestamp"].as_str().unwrap().ends_with(offset));
                assert_eq!(actual["token"], value["token"]);
                assert_eq!(actual["ordered"], value["ordered"]);
                assert_eq!(shift.render(now).unwrap().0, wire);
            }
            assert_eq!(
                decode_payload(&recorded.response.decode().unwrap()).unwrap(),
                value
            );
        }
    }
}

#[test]
fn rfc3339_rejects_invalid_types_dates_missing_timezones_and_year_overflow() {
    let mut read = selector().read;
    read.response_json.get_mut("/timestamp").unwrap().format = RedisTimestampFormat::Rfc3339;
    for value in [
        json!({}),
        json!({"timestamp":null}),
        json!({"timestamp":1788761925496_i64}),
        json!({"timestamp":true}),
        json!({"timestamp":[]}),
        json!({"timestamp":"1788761925496"}),
        json!({"timestamp":"not-a-timestamp"}),
        json!({"timestamp":"2026-09-07T06:22:26"}),
        json!({"timestamp":"2026-02-30T06:22:26+00:00"}),
    ] {
        assert!(
            ResponseShift::prepare(&record(value), &[("expiry".into(), read.clone())]).is_err()
        );
    }
    for (text, delta) in [
        ("9999-12-31T23:59:59+08:00", chrono::Duration::seconds(1)),
        ("0000-01-01T00:00:00-05:30", -chrono::Duration::seconds(1)),
    ] {
        let recorded = record(json!({"timestamp":text}));
        let shift = ResponseShift::prepare(&recorded, &[("expiry".into(), read.clone())]).unwrap();
        assert!(shift.render(recorded.timestamp.unwrap() + delta).is_err());
    }
}

#[test]
fn mixed_timestamp_formats_use_one_delivery_anchor() {
    let captured = record(token()).timestamp.unwrap();
    let expiry = captured + chrono::Duration::hours(1);
    let recorded = record(json!({
        "seconds":expiry.timestamp(),"milliseconds":expiry.timestamp_millis(),
        "timestamp":expiry.to_rfc3339(),"untouched":"2026-09-07T00:00:00Z"
    }));
    let mut read = selector().read;
    read.response_json = [
        ("/seconds", RedisTimestampFormat::UnixSeconds),
        ("/milliseconds", RedisTimestampFormat::UnixMilliseconds),
        ("/timestamp", RedisTimestampFormat::Rfc3339),
    ]
    .into_iter()
    .map(|(path, format)| {
        (
            path.into(),
            RelativeTimeField {
                time: RelativeTime::PreserveRelative,
                format,
            },
        )
    })
    .collect();
    let now = captured + chrono::Duration::days(1);
    let shift = ResponseShift::prepare(&recorded, &[("mixed".into(), read)]).unwrap();
    let actual = decode_payload(&shift.render(now).unwrap().0).unwrap();
    assert_eq!(actual["seconds"], now.timestamp() + 3600);
    assert_eq!(actual["milliseconds"], now.timestamp_millis() + 3_600_000);
    let shifted = DateTime::parse_from_rfc3339(actual["timestamp"].as_str().unwrap()).unwrap();
    assert_eq!(
        shifted.signed_duration_since(now),
        chrono::Duration::hours(1)
    );
    assert_eq!(actual["untouched"], "2026-09-07T00:00:00Z");
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
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
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
fn matched_response_evidence_preserves_recording_bytes_and_retired_authoring_writes_nothing() {
    let (_temp, f, path) = fixture();
    let before = [
        fs::read(&f.policy_path).unwrap(),
        fs::read(&path).unwrap(),
        fs::read(&f.replay_report_path).unwrap(),
    ];
    let proof = evidence::verify(&f.case_source, &f.replay_report_path, &f.selector).unwrap();
    assert_eq!(proof["matched_in_attempt"], 1);
    assert!(
        !proof.to_string().contains("private-token")
            && !proof.to_string().contains("private-secret")
    );
    let error = plan_redis_time_shift(f.clone()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(
        before,
        [
            fs::read(&f.policy_path).unwrap(),
            fs::read(&path).unwrap(),
            fs::read(&f.replay_report_path).unwrap()
        ]
    );
    fs::write(
        &path,
        String::from_utf8(before[1].clone())
            .unwrap()
            .replace("private-token", "changed-token"),
    )
    .unwrap();
    let updated = evidence::verify(&f.case_source, &f.replay_report_path, &f.selector).unwrap();
    assert_ne!(proof["recording_revision"], updated["recording_revision"]);
    fs::write(
        &f.replay_report_path,
        r#"{"finalized":true,"redis":{"matched":[]}}"#,
    )
    .unwrap();
    assert!(evidence::verify(&f.case_source, &f.replay_report_path, &f.selector).is_err());
}

#[test]
fn rfc3339_get_and_hget_evidence_validate_without_rewriting_recordings() {
    for command in ["GET", "HGET"] {
        let (_temp, mut feedback, path) = fixture();
        let mut event: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        event["command"] = command.into();
        feedback.selector.read.command = command.into();
        if command == "GET" {
            event["args"].as_array_mut().unwrap().truncate(1);
            feedback.selector.read.hash_field = None;
        }
        feedback
            .selector
            .read
            .response_json
            .get_mut("/timestamp")
            .unwrap()
            .format = RedisTimestampFormat::Rfc3339;
        feedback.source_evidence =
            "session.py: expires_at is an unsigned RFC3339 expiry string compared with UTC now"
                .into();
        for text in ["2026-09-07T07:22:26.653+00:00", "2026-09-07T07:22:26"] {
            let body = json!({"timestamp":text,"token":"private-token"}).to_string();
            event["response"]["data"] = format!("${}\r\n{body}\r\n", body.len()).into();
            fs::write(&path, event.to_string()).unwrap();
            if !text.ends_with("+00:00") {
                assert!(
                    evidence::verify(
                        &feedback.case_source,
                        &feedback.replay_report_path,
                        &feedback.selector
                    )
                    .is_err()
                );
                continue;
            }
            let immutable = fs::read(&path).unwrap();
            let proof = evidence::verify(
                &feedback.case_source,
                &feedback.replay_report_path,
                &feedback.selector,
            )
            .unwrap();
            assert_eq!(proof["matched_in_attempt"], 1);
            assert!(!proof.to_string().contains("private-token"));
            assert_eq!(fs::read(&path).unwrap(), immutable);
        }
    }
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
    let mut overlapping = f.selector.read.clone();
    overlapping.response_json.insert(
        "/timestamp/child".into(),
        RelativeTimeField {
            time: RelativeTime::PreserveRelative,
            format: RedisTimestampFormat::UnixMilliseconds,
        },
    );
    assert!(overlapping.validate().is_err());
    let mut missing = f;
    missing.selector.read.response_json = BTreeMap::from([(
        "/missing".into(),
        RelativeTimeField {
            time: RelativeTime::PreserveRelative,
            format: RedisTimestampFormat::UnixMilliseconds,
        },
    )]);
    assert!(
        evidence::verify(
            &missing.case_source,
            &missing.replay_report_path,
            &missing.selector
        )
        .is_err()
    );
}
