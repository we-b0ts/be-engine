use super::*;
use crate::value_contract::time::ClockPair;
use chrono::TimeZone;
use serde_json::json;
mod calendar;
mod optional;
mod representation;

#[test]
fn naive_delivery_preserves_civil_text_without_timezone_configuration() {
    for (format, source, target) in [
        (
            TimestampFormat::Iso8601Naive,
            "2026-10-18T23:59:59.123456",
            "2026-10-19T00:01:39.123456",
        ),
        (
            TimestampFormat::SqlDatetime,
            "2026-10-18 23:59:59.123456",
            "2026-10-19 00:01:39.123456",
        ),
    ] {
        let mut config = TimeContract {
            format,
            relation: crate::policy::TimeRelation::PreserveOffset,
            anchor: TimeAnchor::DependencyRequestStart,
            utc_offset: None,
            clock_group: None,
            clock_scope: Default::default(),
        };
        let source = json!(source);
        let delta = 100 * time::NANOS_PER_SECOND;
        assert_eq!(shift(&source, &config, delta).unwrap(), json!(target));
        config.utc_offset = Some("+08:00".into());
        assert_eq!(shift(&source, &config, delta).unwrap(), json!(target));
    }
}

#[test]
fn delivery_only_translates_declared_time_and_keeps_source_immutable() {
    let doc:serde_yaml::Value=serde_yaml::from_str(r#"format: traffic-policy/v3
rules:
  - id: session-input
    surface: dependency.response
    match:
      resource: {protocol: redis, endpoint: 'cache.internal:6379', database: 0}
      operation: GET
      key: {prefix: 'session:'}
    slot: value
    codec: json
    contract:
      /members: {kind: unordered}
      /expiry: {kind: time, format: unix_microseconds, relation: preserve_offset}
    delivery: {rebase_time: [/expiry]}
    proof: {source: 'src/session.py:40 read', fact: 'Source expiry retains its offset from the recorded input delivery.'}
"#).unwrap();
    let rule: crate::policy::Rule = serde_yaml::from_value(doc["rules"][0].clone()).unwrap();
    let compiled = crate::policy::compile_rule(&rule).unwrap();
    let source = json!({"members":[2,1,2],"expiry":12_000_001,"stable":true});
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Some(Utc.timestamp_opt(10, 0).unwrap()),
            target: Some(Utc.timestamp_opt(110, 0).unwrap()),
        },
        ..Default::default()
    };
    let actual = materialize(&source, &[&compiled], clocks).unwrap();
    assert_eq!(
        actual,
        json!({"members":[2,1,2],"expiry":112_000_001,"stable":true})
    );
    assert_eq!(source["expiry"], 12_000_001);
    assert!(materialize(&source, &[&compiled], AnchorClocks::default()).is_err());
}
