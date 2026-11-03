use super::*;

#[test]
fn state_contract_roundtrips_all_effects_and_separate_read_back() {
    let raw = policy(json!({
        "stream:*":{"state":{"append":"concatenate","expire":"refresh"}},
        "current:*":{"kind":"identity","formats":["uuid"],"read_back":true,
            "state":{"get":{"transient":["nil"]},"set":"transition"}},
        "activity:*":{"state":{"get":"observe","set":{"reduce":"last","fields":["/last_activity_at"]}}},
        "poll:*":{"state":{"get":"observe"}}
    }));
    let document = parse_policy(&raw.to_string()).unwrap();
    let compiled = compile_policy(&document).unwrap();
    assert_eq!(compiled.native.len(), 6);
    let rendered = render_policy(&document).unwrap();
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(
        authored["redis"]["keys"]["current:*"]["state"]["get"],
        json!({"transient":["nil"]})
    );
    assert_eq!(authored["redis"]["keys"]["current:*"]["read_back"], true);
    assert_eq!(
        authored["redis"]["keys"]["activity:*"]["state"]["set"],
        json!({"reduce":"last","fields":["/last_activity_at"]})
    );
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn state_contract_rejects_unbounded_or_unknown_reductions() {
    for state in [
        json!({}),
        json!({"get":true}),
        json!({"get":{"transient":[]}}),
        json!({"get":{"transient":["nil","nil"]}}),
        json!({"get":{"transient":["any"]}}),
        json!({"get":{"transient":["nil"],"writes":"skip"}}),
        json!({"append":"last"}),
        json!({"expire":"ignore"}),
        json!({"set":{"reduce":"last","fields":[]}}),
        json!({"set":{"reduce":"last","fields":["/*"]}}),
        json!({"set":{"reduce":"last","fields":["/value"]},"delete":"optional"}),
    ] {
        assert!(
            parse_policy(&policy(json!({"key:*":{"state":state.clone()}})).to_string()).is_err(),
            "{state}"
        );
    }
    let duplicate = "format: traffic-policy/v3\nredis:\n  keys:\n    'poll:*':\n      state: {get: observe, get: observe}\n";
    assert!(parse_policy(duplicate).is_err());
}
