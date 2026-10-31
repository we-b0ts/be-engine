use super::*;
use crate::policy::*;

#[test]
fn conditional_duration_reuses_pb_types_and_preserves_inactive_wire_identity() {
    let input = r#"
format: traffic-policy/v3
rules:
- id: waiting-duration
  surface: api.response
  match: {api: GET /requests}
  slot: body
  codec:
    kind: protobuf
    fields:
      /duration: {field_path: [1], field_type: uint64}
      /status: {field_path: [2], field_type: string}
  contract:
    /duration:
      kind: conditional
      when: {relative_pointer: ../status, not_in: [closed]}
      contract: {kind: duration, unit: seconds}
  proof: {source: 'source.py:duration', fact: 'Source freezes duration for closed items and measures elapsed request time for other items'}
"#;
    for input in [
        input.to_owned(),
        input.replace("not_in: [closed]", "equals: pending"),
    ] {
        let input = input.as_str();
        let raw: serde_yaml::Value = serde_yaml::from_str(input).unwrap();
        let rule: Rule = serde_yaml::from_value(raw["rules"][0].clone()).unwrap();
        let compiled = compile_rule(&rule).unwrap();
        let rules = vec![&compiled];
        let clocks = AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: chrono::DateTime::from_timestamp(10, 0),
                target: chrono::DateTime::from_timestamp(110, 0),
            },
            ..Default::default()
        };
        assert!(
            compare(
                b"\x08\x0a\x12\x07pending",
                b"\x08\x6e\x12\x07pending",
                &rules,
                clocks
            )
            .unwrap()
            .passed()
        );
        assert!(
            compare(
                b"\x08\x0a\x12\x06closed",
                b"\x08\x0a\x12\x06closed",
                &rules,
                clocks
            )
            .unwrap()
            .passed()
        );
        assert!(
            !compare(
                b"\x08\x0a\x12\x06closed",
                b"\x08\x6e\x12\x06closed",
                &rules,
                clocks
            )
            .unwrap()
            .passed()
        );
        let noncanonical = compare(
            b"\x08\x0a\x12\x06closed",
            b"\x08\x8a\x00\x12\x06closed",
            &rules,
            clocks,
        );
        assert!(noncanonical.is_err() || !noncanonical.unwrap().passed());
        let invalid = |input: String| {
            let raw: serde_yaml::Value = serde_yaml::from_str(&input).unwrap();
            let rule: Rule = serde_yaml::from_value(raw["rules"][0].clone()).unwrap();
            compile_rule(&rule).is_err()
        };
        assert!(invalid(input.replace(
            "      /status: {field_path: [2], field_type: string}\n",
            ""
        )));
        assert!(invalid(
            input.replace("field_type: string", "field_type: bool")
        ));
        let delivery = input.replace("surface: api.response", "surface: dependency.response").replace("match: {api: GET /requests}", "match: {api: GET /requests, resource: {protocol: redis, endpoint: 'cache:6379'}, operation: GET, key: {prefix: 'request:'}}").replace("slot: body", "slot: value").replace("  proof:", "  delivery: {rebase_time: [/duration]}\n  proof:");
        assert!(invalid(delivery));
    }
}
