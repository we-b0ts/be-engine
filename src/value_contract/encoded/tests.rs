use super::*;
use crate::policy::*;

#[test]
fn conditional_duration_reuses_pb_types_and_preserves_inactive_wire_identity() {
    let input = r#"
format: traffic-policy/v2
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
        let compiled = compile_policy(&parse_policy(input).unwrap()).unwrap();
        let rules = compiled.rules.iter().collect::<Vec<_>>();
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
        assert!(
            parse_policy(
                &input.replace("      /status: {field_path: [2], field_type: string}\n", "")
            )
            .is_err()
        );
        assert!(parse_policy(&input.replace("field_type: string", "field_type: bool")).is_err());
        let delivery = input.replace("surface: api.response", "surface: dependency.response").replace("match: {api: GET /requests}", "match: {api: GET /requests, resource: {protocol: redis, endpoint: 'cache:6379'}, operation: GET, key: {prefix: 'request:'}}").replace("slot: body", "slot: value").replace("  proof:", "  delivery: {rebase_time: [/duration]}\n  proof:");
        assert!(parse_policy(&delivery).is_err());
    }
}
