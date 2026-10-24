use super::*;
use crate::policy::{compile_policy, parse_policy};
use crate::value_contract::time::ClockPair;
use serde_json::json;

fn fixture(codec: &str) -> crate::policy::CompiledPolicy {
    let policy = format!(
        r#"format: traffic-policy/v2
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
    /time: {{kind: time, format: unix_seconds, relation: preserve_offset}}
  delivery: {{rebase_time: [/time]}}
  proof: {{source: 'fixture.rs:clock', fact: 'Expiry preserves its offset from the request'}}
"#
    );
    compile_policy(&parse_policy(&policy).unwrap()).unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
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
        let rendered = delivery
            .render(clocks().dependency.target.unwrap())
            .unwrap();
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
fn response_owned_wildcard_times_are_independent_unless_the_clock_is_explicit() {
    let document = json!({"format":"traffic-policy/v2","responses":{"items":{
        "api":"GET /items","proof":{"source":"items.py:create","fact":"Each item owns an independently generated timestamp"},
        "body":{"codec":"json","fields":{"/items/*/at":{"relative_time":"unix_seconds"}}}
    }}});
    let source = br#"{"items":[{"at":1010,"id":1},{"at":1010,"id":2}]}"#;
    let target = br#"{"items":[{"at":2010,"id":1},{"at":2011,"id":2}]}"#;
    for explicit in [false, true] {
        let mut document = document.clone();
        if explicit {
            document["responses"]["items"]["body"]["fields"]["/items/*/at"]["clock_group"] =
                json!("same-event");
        }
        let policy = compile_policy(&parse_policy(&document.to_string()).unwrap()).unwrap();
        let rules = policy.rules.iter().collect::<Vec<_>>();
        let compared = compare(source, target, &rules, clocks()).unwrap();
        assert_eq!(compared.passed(), !explicit, "{:?}", compared.differences);
        assert!(
            !compare(
                source,
                br#"{"items":[{"at":2010,"id":1},{"at":2011,"id":3}]}"#,
                &rules,
                clocks()
            )
            .unwrap()
            .passed()
        );
    }
}

#[test]
fn nullable_owned_timestamps_keep_null_exact_and_validate_nonnull_values() {
    let document = json!({"format":"traffic-policy/v2","responses":{"task":{
        "api":"GET /task","proof":{"source":"task.py:model","fact":"Completion is nullable datetime across terminal statuses"},
        "body":{"codec":"json","fields":{"/completedAt":{"kind":"conditional","when":{"relative_pointer":".","not_in":[null]},"contract":{"relative_time":"unix_seconds"}}}}
    }}});
    let policy = compile_policy(&parse_policy(&document.to_string()).unwrap()).unwrap();
    let rules = policy.rules.iter().collect::<Vec<_>>();
    for (source, target, passed) in [
        (
            json!({"completedAt":null}),
            json!({"completedAt":null}),
            true,
        ),
        (
            json!({"completedAt":1010}),
            json!({"completedAt":2010}),
            true,
        ),
        (
            json!({"completedAt":null}),
            json!({"completedAt":2010}),
            false,
        ),
        (
            json!({"completedAt":1010}),
            json!({"completedAt":null}),
            false,
        ),
        (
            json!({"completedAt":"broken"}),
            json!({"completedAt":"broken"}),
            false,
        ),
        (json!({"completedAt":null}), json!({}), false),
    ] {
        let result = compare(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(&target).unwrap(),
            &rules,
            clocks(),
        )
        .unwrap();
        assert_eq!(
            result.passed(),
            passed,
            "{source} -> {target}: {:?}",
            result.differences
        );
    }
}

#[test]
#[ignore = "manual resource-field Replay comparison throughput and decode-count benchmark"]
fn schema_wildcard_replay_benchmark() {
    use std::{hint::black_box, time::Instant};
    let policy = crate::policy::parse_and_compile_policy(&json!({
        "format":"traffic-policy/v2","responses":{"items":{
            "api":"GET /items","proof":{"source":"items.py:clock","fact":"Each item has its own generated time"},
            "body":{"codec":"json","fields":{"/items/*/at":{"relative_time":"unix_seconds"}}}
        }}
    }).to_string()).unwrap();
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let payload = |target| {
        serde_json::to_vec(&json!({"items":(0..2048).map(|id| json!({
        "id":id,"at":if target { 2010 + id % 2 } else { 1010 },"stable":"x".repeat(256)
    })).collect::<Vec<_>>()}))
        .unwrap()
    };
    let source = payload(false);
    let target = payload(true);
    let iterations = 32;
    let started = Instant::now();
    let (_, decodes) = crate::value_codec::measured_decodes(|| {
        for _ in 0..iterations {
            let result = compare(&source, &target, &rules, clocks()).unwrap();
            assert!(result.passed(), "{:?}", result.differences);
            black_box(result);
        }
    });
    assert_eq!(decodes, iterations * 2);
    eprintln!(
        "schema field Replay: items=2048 bytes={} iterations={iterations} decodes={decodes} elapsed_ms={:.3}",
        source.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );
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
        dependency: ClockPair {
            source: clocks().dependency.source,
            target: clocks().dependency.source,
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
