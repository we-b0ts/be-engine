use super::*;
use crate::policy::{compile_policy, parse_policy};
use crate::value_contract::time::ClockPair;
use serde_json::json;

fn fixture(codec: &str) -> crate::policy::CompiledPolicy {
    let policy = format!(
        r#"format: traffic-policy/v1
rules:
- id: delivery-clock
  surface: dependency.response
  match:
    resource: {{protocol: redis, endpoint: 'cache.test:6379'}}
    operation: GET
    key: {{exact: session}}
  slot: value
  codec: {codec}
  contract:
    /time: {{kind: time, format: unix_seconds, relation: preserve_offset, anchor: case.request_start}}
  delivery: {{rebase_time: [/time]}}
  proof: {{source: 'fixture.rs:clock', fact: 'Expiry preserves its offset from the request'}}
"#
    );
    compile_policy(&parse_policy(&policy).unwrap()).unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        case: ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}

#[test]
fn delivery_decodes_source_once_and_keeps_json_and_pb_delivery_strict() {
    for (codec, original, expected) in [
        (
            "json",
            br#"{ "time":1000,"stable":7 }"#.to_vec(),
            br#"{"stable":7,"time":2000}"#.to_vec(),
        ),
        (
            "{kind: protobuf, fields: {/time: {field_path: [1], field_type: uint64}}}",
            vec![8, 0xe8, 7, 0x18, 0x87, 0],
            vec![8, 0xd0, 15, 0x18, 0x87, 0],
        ),
    ] {
        let compiled = fixture(codec);
        let rules = compiled.rules.iter().collect::<Vec<_>>();
        let (delivery, decodes) = crate::value_codec::measured_decodes(|| {
            Delivery::prepare(&original, &rules, clocks()).unwrap()
        });
        assert_eq!(decodes, 1);
        assert_eq!(delivery.validation().time_validations["delivery-clock"], 1);
        let rendered = delivery.render(clocks().case.target.unwrap()).unwrap();
        assert_eq!(rendered, expected);
        assert_eq!(delivery.original, original);
        assert!(Delivery::prepare(&original, &rules, Default::default()).is_err());
    }
}

#[test]
fn one_decode_self_validation_still_rejects_missing_invalid_and_duplicate_source_fields() {
    let json = fixture("json");
    let rules = json.rules.iter().collect::<Vec<_>>();
    for source in [
        br#"{"stable":7}"#.as_slice(),
        br#"{"time":"1000"}"#,
        br#"{"time":1000,"time":1001}"#,
        b"truncated",
    ] {
        assert!(Delivery::prepare(source, &rules, clocks()).is_err());
    }
    let pb = fixture("{kind: protobuf, fields: {/time: {field_path: [1], field_type: uint64}}}");
    let rules = pb.rules.iter().collect::<Vec<_>>();
    for source in [&[][..], &[8, 0xe8], &[8, 1, 8, 2], &[10, 1, 1]] {
        assert!(Delivery::prepare(source, &rules, clocks()).is_err());
    }
}

#[test]
#[ignore = "manual fixture comparing previous triple-decode preparation with decoded reuse"]
fn delivery_preparation_benchmark() {
    use std::{hint::black_box, time::Instant};
    let compiled = fixture("json");
    let rules = compiled.rules.iter().collect::<Vec<_>>();
    let source = serde_json::to_vec(&json!({
        "time": 1000,
        "stable": (0..256).map(|id| json!({"id":id,"data":"unchanged".repeat(16)})).collect::<Vec<_>>()
    }))
    .unwrap();
    let source_clocks = AnchorClocks {
        case: ClockPair {
            source: clocks().case.source,
            target: clocks().case.source,
        },
        ..Default::default()
    };
    let iterations = 100;
    let start = Instant::now();
    let (_, legacy_decodes) = crate::value_codec::measured_decodes(|| {
        for _ in 0..iterations {
            let codec = merged_codec(&rules).unwrap();
            let decoded = crate::value_codec::CodecView::decode(&codec, &source).unwrap();
            assert!(crate::value_contract::json::pointer_observed(
                &decoded.logical,
                "/time"
            ));
            let check = compare(&source, &source, &rules, source_clocks).unwrap();
            assert!(check.passed());
            black_box((decoded, check));
        }
    });
    let legacy = start.elapsed();
    let start = Instant::now();
    let (_, reused_decodes) = crate::value_codec::measured_decodes(|| {
        for _ in 0..iterations {
            black_box(Delivery::prepare(&source, &rules, clocks()).unwrap());
        }
    });
    let reused = start.elapsed();
    assert_eq!(legacy_decodes, iterations * 3);
    assert_eq!(reused_decodes, iterations);
    eprintln!(
        "delivery preparation: payload_bytes={} iterations={iterations} previous_ms={:.3} reused_ms={:.3} previous_decodes={legacy_decodes} reused_decodes={reused_decodes}",
        source.len(),
        legacy.as_secs_f64() * 1000.0,
        reused.as_secs_f64() * 1000.0
    );
}
