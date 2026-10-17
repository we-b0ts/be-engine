use super::*;
use crate::value_contract::time::ClockPair;
use chrono::TimeZone;
use serde_json::json;

#[test]
fn delivery_only_translates_declared_time_and_keeps_source_immutable() {
    let doc=crate::policy::parse_policy(r#"format: traffic-policy/v1
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
      /expiry: {kind: time, format: unix_microseconds, relation: preserve_offset, anchor: dependency.response_delivery}
    delivery: {rebase_time: [/expiry]}
    proof: {source: 'src/session.py:40 read', fact: 'Source expiry retains its offset from the recorded input delivery.'}
"#).unwrap();
    let compiled = crate::policy::compile_policy(&doc).unwrap();
    let source = json!({"members":[2,1,2],"expiry":12_000_001,"stable":true});
    let clocks = AnchorClocks {
        delivery: ClockPair {
            source: Some(Utc.timestamp_opt(10, 0).unwrap()),
            target: Some(Utc.timestamp_opt(110, 0).unwrap()),
        },
        ..Default::default()
    };
    let actual = materialize(&source, &compiled.rules.iter().collect::<Vec<_>>(), clocks).unwrap();
    assert_eq!(
        actual,
        json!({"members":[2,1,2],"expiry":112_000_001,"stable":true})
    );
    assert_eq!(source["expiry"], 12_000_001);
    assert!(
        materialize(
            &source,
            &compiled.rules.iter().collect::<Vec<_>>(),
            AnchorClocks::default()
        )
        .is_err()
    );
}
