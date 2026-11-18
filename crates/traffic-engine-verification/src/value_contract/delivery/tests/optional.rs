use super::*;

fn policy(fields: Value) -> CompiledRule {
    let paths = fields.as_object().unwrap().keys().collect::<Vec<_>>();
    let rule: crate::policy::Rule = serde_json::from_value(json!({
        "id":"input", "surface":"dependency.response",
        "match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"GET","key":{"prefix":"session:"}},
        "slot":"value","codec":"json","contract":fields,"delivery":{"rebase_time":paths},
        "proof":{"source":"cache.py:read","fact":"Present timestamps retain their request-relative offset; other values remain exact"}
    })).unwrap();
    crate::policy::compile_rule(&rule).unwrap()
}

fn response_rules(policy: &CompiledRule) -> Vec<&CompiledRule> {
    vec![policy]
}

#[test]
fn absent_delivery_fields_and_empty_wildcards_need_no_clocks_or_changes() {
    let policy = policy(json!({
        "/at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},
        "/items/*/date":{"kind":"time","format":"calendar_date","relation":"preserve_offset","utc_offset":"+08:00"}
    }));
    let rules = response_rules(&policy);
    for source in [
        json!({"stable":7}),
        json!({"items":[],"stable":7}),
        json!({"items":[{}, {"stable":7}]}),
    ] {
        assert_eq!(
            materialize(&source, &rules, AnchorClocks::default()).unwrap(),
            source
        );
    }
}

#[test]
fn absent_coarse_timestamp_does_not_reduce_present_timestamp_precision() {
    let policy = policy(json!({
        "/seconds":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},
        "/micros":{"kind":"time","format":"unix_microseconds","relation":"preserve_offset"}
    }));
    let rules = response_rules(&policy);
    let source = json!({"micros":1_000_000_123,"stable":7});
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Some(Utc.timestamp_opt(1000, 0).unwrap()),
            target: Some(Utc.timestamp_opt(2000, 123_456_000).unwrap()),
        },
        ..Default::default()
    };
    assert_eq!(
        materialize(&source, &rules, clocks).unwrap(),
        json!({"micros":2_000_123_579,"stable":7})
    );
}

#[test]
fn wildcard_delivery_preserves_missing_leaves_and_rejects_present_invalid_dates() {
    let policy = policy(json!({
        "/items/*/date":{"kind":"time","format":"calendar_date","relation":"preserve_offset","utc_offset":"+08:00"}
    }));
    let rules = response_rules(&policy);
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Some("2026-10-20T15:01:00Z".parse().unwrap()),
            target: Some("2026-10-21T19:13:00Z".parse().unwrap()),
        },
        ..Default::default()
    };
    let source = json!({"items":[{"stable":7},{"date":"2026-10-20"},{}]});
    assert_eq!(
        materialize(&source, &rules, clocks).unwrap(),
        json!({"items":[{"stable":7},{"date":"2026-10-22"},{}]})
    );
    for invalid in [Value::Null, json!(""), json!("2026-02-30"), json!(123)] {
        let mut source = source.clone();
        source["items"][1]["date"] = invalid;
        assert!(materialize(&source, &rules, clocks).is_err());
    }
}
