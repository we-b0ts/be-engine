use super::*;
use crate::replay::{
    RedisTimeRead, redis_delivered_time_copies, redis_time_position, redis_time_write_proofs,
};
use crate::value_contract::{encoded, time_copies::TimeCopyStore};

fn prepare(
    runtime: &RequestContracts,
    command: &str,
    keys: &[&str],
    source: &[u8],
) -> super::super::time_copies::PreparedRedisTimeRead {
    prepare_at(
        runtime,
        command,
        keys,
        source,
        DateTime::from_timestamp(1000, 0),
    )
}

fn prepare_at(
    runtime: &RequestContracts,
    command: &str,
    keys: &[&str],
    source: &[u8],
    completed: Option<DateTime<Utc>>,
) -> super::super::time_copies::PreparedRedisTimeRead {
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, command);
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    runtime
        .prepare_redis_time_read(&context, &args(keys), &args(keys), source, completed)
        .unwrap()
        .unwrap()
}

#[test]
fn copied_time_requires_the_read_to_precede_the_write_on_both_sides() {
    for (source_completed, target_completed) in [
        (None, 2000),
        (DateTime::from_timestamp(1001, 0), 2000),
        (DateTime::from_timestamp(1000, 0), 2001),
    ] {
        let runtime = runtime("string", false, false);
        let body = r#"{"at":100,"stable":"x"}"#;
        let wire = bulk(body);
        let prepared = prepare_at(&runtime, "GET", &["session:1"], &wire, source_completed);
        runtime
            .commit_redis_time_read(
                &prepared,
                None,
                &wire,
                DateTime::from_timestamp(target_completed, 0).unwrap(),
            )
            .unwrap();
        assert!(
            preview(&runtime, "SET", &["session:1", body], &["session:1", body]).is_err(),
            "an unknown or future read cannot prove a copied historical time"
        );
    }
}

#[test]
fn historical_redis_time_needs_a_completed_read_of_the_same_physical_value() {
    for (container, field, read, keys, write, before, after, wire) in [
        (
            "string",
            false,
            "GET",
            vec!["session:1"],
            "SET",
            vec!["session:1", r#"{"at":100,"stable":"x"}"#],
            vec!["session:1", r#"{"at":555,"stable":"x"}"#],
            bulk(r#"{"at":100,"stable":"x"}"#),
        ),
        (
            "hash",
            true,
            "HGET",
            vec!["session:1", "selected"],
            "HMSET",
            vec!["session:1", "selected", r#"{"at":100,"stable":"x"}"#],
            vec!["session:1", "selected", r#"{"at":555,"stable":"x"}"#],
            bulk(r#"{"at":100,"stable":"x"}"#),
        ),
        (
            "list",
            false,
            "LRANGE",
            vec!["session:1", "0", "-1"],
            "RPUSH",
            vec!["session:1", r#"{"at":100,"stable":"x"}"#],
            vec!["session:1", r#"{"at":555,"stable":"x"}"#],
            array(&[bulk(r#"{"at":100,"stable":"x"}"#)]),
        ),
    ] {
        let runtime = runtime(container, field, false);
        assert!(
            preview(&runtime, write, &before, &before).is_err(),
            "no equality fallback without a read"
        );
        let prepared = prepare(&runtime, read, &keys, &wire);
        assert!(
            preview(&runtime, write, &before, &after).is_err(),
            "a pending read has not reached the wire"
        );
        let delivered = String::from_utf8(wire.clone())
            .unwrap()
            .replace("100", "555")
            .into_bytes();
        let (_, decodes) = crate::value_codec::measured_decodes(|| {
            runtime
                .commit_redis_time_read(
                    &prepared,
                    None,
                    &delivered,
                    DateTime::from_timestamp(2000, 0).unwrap(),
                )
                .unwrap()
        });
        assert_eq!(decodes, 1, "changed payloads decode once after delivery");
        assert!(
            preview(&runtime, write, &before, &after).is_ok(),
            "{read}/{write}"
        );
        let bad = after
            .iter()
            .map(|value| value.replace("555", "777"))
            .collect::<Vec<_>>();
        let bad = bad.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(preview(&runtime, write, &before, &bad).is_err());
        let wrong_key = before
            .iter()
            .map(|value| value.replace("session:1", "session:2"))
            .collect::<Vec<_>>();
        let wrong_after = after
            .iter()
            .map(|value| value.replace("session:1", "session:2"))
            .collect::<Vec<_>>();
        assert!(
            preview(
                &runtime,
                write,
                &wrong_key.iter().map(String::as_str).collect::<Vec<_>>(),
                &wrong_after.iter().map(String::as_str).collect::<Vec<_>>()
            )
            .is_err()
        );
        runtime.begin_case("case");
        assert!(
            preview(&runtime, write, &before, &after).is_err(),
            "a fresh case discards previous read provenance"
        );
    }
}

#[test]
fn unchanged_read_decodes_once_and_new_times_stay_relative() {
    let runtime = runtime("string", false, false);
    let source = r#"{"at":100,"other_at":90,"stable":"x"}"#;
    let wire = bulk(source);
    let (prepared, decodes) = crate::value_codec::measured_decodes(|| {
        let prepared = prepare(&runtime, "GET", &["session:1"], &wire);
        runtime
            .commit_redis_time_read(
                &prepared,
                None,
                &wire,
                DateTime::from_timestamp(2000, 0).unwrap(),
            )
            .unwrap();
        prepared
    });
    assert_eq!(
        decodes, 1,
        "the actual unchanged response reuses compact Source temporal leaves"
    );
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", source],
            &["session:1", source]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", r#"{"at":1010}"#],
            &["session:1", r#"{"at":2010}"#]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", r#"{"at":1010}"#],
            &["session:1", r#"{"at":1010}"#]
        )
        .is_err()
    );
    runtime
        .commit_redis_time_read(
            &prepared,
            None,
            &bulk(&source.replace("100", "500")),
            DateTime::from_timestamp(2001, 0).unwrap(),
        )
        .unwrap();
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", source],
            &["session:1", source]
        )
        .is_err(),
        "inconsistent delivered mappings are ambiguous"
    );
}

#[test]
fn a_hash_read_does_not_prove_the_same_timestamp_in_another_hash_field() {
    let runtime = runtime("hash", false, false);
    let source = r#"{"at":100}"#;
    let delivered = r#"{"at":555}"#;
    let prepared = prepare(&runtime, "HGET", &["session:1", "first"], &bulk(source));
    runtime
        .commit_redis_time_read(
            &prepared,
            None,
            &bulk(delivered),
            DateTime::from_timestamp(2000, 0).unwrap(),
        )
        .unwrap();
    assert!(
        preview(
            &runtime,
            "HSET",
            &["session:1", "first", source],
            &["session:1", "first", delivered]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "HMSET",
            &["session:1", "second", source],
            &["session:1", "second", delivered]
        )
        .is_err()
    );
}

#[test]
fn copied_values_still_enforce_explicit_clock_relationships() {
    let runtime = runtime_with_clock_group("string", false, false, Some("copied-clock"));
    let source = r#"{"at":100,"other_at":90}"#;
    let target = r#"{"at":555,"other_at":444}"#;
    let prepared = prepare(&runtime, "GET", &["session:1"], &bulk(source));
    runtime
        .commit_redis_time_read(
            &prepared,
            None,
            &bulk(target),
            DateTime::from_timestamp(2000, 0).unwrap(),
        )
        .unwrap();
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", source],
            &["session:1", target]
        )
        .is_err(),
        "delivered copy pairs cannot break an explicit same-clock interval"
    );
}

#[test]
fn two_thousand_array_times_use_linear_proof_lookup_without_redecoding_payloads() {
    let policy=crate::policy::parse_and_compile_policy(&json!({"format":"traffic-policy/v2","resources":{"cache":{
        "protocol":"redis","endpoint":"cache.test:6379","database":0,
        "proof":{"source":"cache.py:history","fact":"The stored item clocks preserve temporal semantics across reads and writes"},
        "keys":[{"key":{"prefix":"session:"},"container":"string","value":{"codec":"json","fields":{
            "/items/*/at":{"relative_time":"unix_seconds"},"/items/*/other_at":{"relative_time":"unix_seconds"}}}}]
    }}}).to_string()).unwrap();
    let response_rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == crate::policy::Surface::DependencyResponse)
        .collect::<Vec<_>>();
    let request_rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == crate::policy::Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let raw=json!({"items":(0..1000).map(|i|json!({"at":100+i,"other_at":200+i,"stable":i})).collect::<Vec<_>>()}).to_string();
    let wire = bulk(&raw);
    let keys = args(&["session:1"]);
    let mut store = TimeCopyStore::default();
    let clocks = crate::value_contract::time::ClockPair {
        source: DateTime::from_timestamp(1000, 0),
        target: DateTime::from_timestamp(2000, 0),
    };
    store.set_record_clocks(clocks);
    store.set_lookup_clocks(clocks);
    let (count, decodes) = crate::value_codec::measured_decodes(|| {
        redis_delivered_time_copies(
            RedisTimeRead {
                host: "cache.test",
                port: 6379,
                database: 0,
                command: "GET",
                source_args: &keys,
                target_args: &keys,
                source_response: &wire,
                delivered_response: &wire,
            },
            &response_rules,
            &mut |source_position,
                  target_position,
                  source_pattern,
                  target_pattern,
                  source,
                  target,
                  time| {
                store.record_batch(
                    "case",
                    vec![
                        crate::value_contract::time_copies::TimeCopyRecord::new_time(
                            time,
                            source_position,
                            target_position,
                            source_pattern,
                            target_pattern,
                            source,
                            target,
                        )?,
                    ],
                )
            },
        )
        .unwrap()
    });
    assert_eq!(count, 2000);
    assert_eq!(decodes, 1);
    let write_args = args(&["session:1", &raw]);
    let values = redis_field_values("SET", &write_args, None).unwrap();
    let position = redis_time_position("cache.test", 6379, 0, &values[0]);
    let ((proof_count, passed), decodes) = crate::value_codec::measured_decodes(|| {
        let decoded = request_rules[0].codec_plan.decode(raw.as_bytes()).unwrap();
        let proofs =
            redis_time_write_proofs(&store, "case", position, position, &decoded, &request_rules)
                .unwrap();
        let clocks = crate::value_contract::json::AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: DateTime::from_timestamp(1000, 0),
                target: DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        (
            proofs.len(),
            encoded::compare_decoded_with_time_copies(
                &decoded,
                &decoded,
                &request_rules,
                clocks,
                &proofs,
            )
            .unwrap()
            .passed(),
        )
    });
    assert_eq!(
        proof_count, 2000,
        "one lookup per Source leaf, no Source/Target Cartesian product"
    );
    assert!(passed);
    assert_eq!(decodes, 1);
}
