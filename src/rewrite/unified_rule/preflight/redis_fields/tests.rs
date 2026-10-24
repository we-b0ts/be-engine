use super::*;
use crate::policy::{CompiledPolicy, compile_policy, parse_policy};
use serde_json::json;

fn policy(container: &str, hash: bool, delivery: bool) -> CompiledPolicy {
    let mut value = json!({"format":"traffic-policy/v2","resources":{"cache":{
        "protocol":"redis","endpoint":"cache.test:6379","database":0,
        "proof":{"source":"cache.py:1-20","fact":"Stored event time follows the request clock and members are a set; keys and other state remain exact"},
        "keys":[{"key":{"prefix":"session:"},"container":container,
            "value":{"codec":"json","fields":{"/at":{"relative_time":"unix_seconds"},"/members":"unordered"}}}]
    }}});
    if hash {
        value["resources"]["cache"]["keys"][0]["hash_field"] = json!({"prefix":"selected:"});
    }
    if delivery {
        value["resources"]["cache"]["keys"][0]["value"]["delivery"] =
            json!({"rebase_time":["/at"]});
    }
    compile_policy(&parse_policy(&value.to_string()).unwrap()).unwrap()
}

fn rules(policy: &CompiledPolicy, surface: Surface) -> Vec<&CompiledRule> {
    policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == surface)
        .collect()
}

fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}
fn bytes(values: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&args(values)).unwrap()
}
fn capture_bytes(value: &[u8]) -> Value {
    json!({"encoding":"utf8","data":std::str::from_utf8(value).unwrap(),"truncated":false})
}
fn event(command: &str, values: &[&str], response: &[u8]) -> Value {
    json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,"database":0,
        "command":command,"args":args(values).iter().map(|value|capture_bytes(value)).collect::<Vec<_>>(),
        "response":capture_bytes(response),"replay_safe":true,"outcome":"response"})
}
fn clocks() -> AnchorClocks {
    let pair = ClockPair {
        source: DateTime::from_timestamp(1000, 0),
        target: DateTime::from_timestamp(2000, 0),
    };
    AnchorClocks {
        case: pair,
        dependency: pair,
        delivery: pair,
    }
}
fn bulk(value: &str, padded: bool) -> Vec<u8> {
    format!(
        "${}{}\r\n{value}\r\n",
        if padded { "000" } else { "" },
        value.len()
    )
    .into_bytes()
}
fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = format!("*{}\r\n", values.len()).into_bytes();
    for value in values {
        raw.extend(value);
    }
    raw
}
const SOURCE: &str = r#"{"at":1010,"members":[1,2],"stable":"exact"}"#;
const TARGET: &str = r#"{"at":2010,"members":[2,1],"stable":"exact"}"#;

#[test]
fn mset_hash_and_list_fields_generalize_across_commands_without_repeated_payload_decodes() {
    for (container, hash, commands, before, after) in [
        (
            "string",
            false,
            vec!["MSET"],
            vec![
                "outside",
                "opaque",
                "session:1",
                SOURCE,
                "session:2",
                SOURCE,
            ],
            vec![
                "outside",
                "opaque",
                "session:1",
                TARGET,
                "session:2",
                TARGET,
            ],
        ),
        (
            "hash",
            true,
            vec!["HSET", "HMSET"],
            vec![
                "session:1",
                "other",
                "opaque",
                "selected:a",
                SOURCE,
                "selected:b",
                SOURCE,
            ],
            vec![
                "session:1",
                "other",
                "opaque",
                "selected:a",
                TARGET,
                "selected:b",
                TARGET,
            ],
        ),
        (
            "list",
            false,
            vec!["RPUSH", "LPUSH"],
            vec!["session:1", SOURCE, SOURCE],
            vec!["session:1", TARGET, TARGET],
        ),
    ] {
        let policy = policy(container, hash, false);
        let rules = rules(&policy, Surface::DependencyRequest);
        assert!(
            rules
                .iter()
                .all(|rule| rule.rule.selector.operation.is_none())
        );
        for command in commands {
            let event = event(command, &before, b"+OK\r\n");
            let selected = super::super::dependency::selected_rules(&rules, &event).unwrap();
            assert_eq!(selected.len(), 1);
            let (checked, decodes) = crate::value_codec::measured_decodes(|| {
                source(
                    Surface::DependencyRequest,
                    &event,
                    &bytes(&before),
                    &selected,
                    clocks(),
                )
            });
            assert_eq!(checked.unwrap().len(), 1);
            assert_eq!(
                decodes, 2,
                "Source self-validation decodes each of two selected values once"
            );
            let (checked, decodes) = crate::value_codec::measured_decodes(|| {
                pair(
                    Surface::DependencyRequest,
                    &event,
                    &bytes(&before),
                    &bytes(&after),
                    &selected,
                    clocks(),
                )
            });
            assert_eq!(checked.unwrap(), 1);
            assert_eq!(
                decodes, 4,
                "two fields share each Source/Target payload decode"
            );
        }
    }
}

#[test]
fn ttl_options_indices_keys_hash_fields_and_unselected_values_remain_exact() {
    for (container, hash, command, before, after) in [
        (
            "string",
            false,
            "SETEX",
            vec!["session:1", "90", SOURCE],
            vec!["session:1", "91", TARGET],
        ),
        (
            "string",
            false,
            "SET",
            vec!["session:1", SOURCE, "EX", "90"],
            vec!["session:1", TARGET, "PX", "90"],
        ),
        (
            "string",
            false,
            "MSET",
            vec!["outside", "opaque", "session:1", SOURCE],
            vec!["outside", "changed", "session:1", TARGET],
        ),
        (
            "string",
            false,
            "MSET",
            vec!["outside", "opaque", "session:1", SOURCE],
            vec!["changed", "opaque", "session:1", TARGET],
        ),
        (
            "string",
            false,
            "SET",
            vec!["session:1", SOURCE],
            vec!["session:2", TARGET],
        ),
        (
            "hash",
            true,
            "HSET",
            vec!["session:1", "other", "opaque", "selected:a", SOURCE],
            vec!["session:1", "other", "changed", "selected:a", TARGET],
        ),
        (
            "hash",
            true,
            "HSET",
            vec!["session:1", "selected:a", SOURCE],
            vec!["session:1", "selected:b", TARGET],
        ),
        (
            "list",
            false,
            "LSET",
            vec!["session:1", "-1", SOURCE],
            vec!["session:1", "0", TARGET],
        ),
        (
            "list",
            false,
            "RPUSH",
            vec!["session:1", SOURCE, SOURCE],
            vec!["session:1", TARGET],
        ),
    ] {
        let policy = policy(container, hash, false);
        let rules = rules(&policy, Surface::DependencyRequest);
        assert!(
            pair(
                Surface::DependencyRequest,
                &event(command, &before, b"+OK\r\n"),
                &bytes(&before),
                &bytes(&after),
                &rules,
                clocks()
            )
            .is_err(),
            "{command}"
        );
    }
    let policy = policy("string", false, false);
    let rules = rules(&policy, Surface::DependencyRequest);
    let outside = bytes(&["outside", TARGET]);
    assert_eq!(
        pair(
            Surface::DependencyRequest,
            &event("SET", &["session:1", SOURCE], b"+OK\r\n"),
            &bytes(&["session:1", SOURCE]),
            &outside,
            &rules,
            clocks()
        )
        .unwrap(),
        0
    );
}

#[test]
fn derived_responses_use_source_clocks_once_and_preserve_bulk_and_array_framing() {
    for (container, hash, command, keys, original) in [
        (
            "string",
            false,
            "GET",
            vec!["session:1"],
            bulk(SOURCE, true),
        ),
        (
            "string",
            false,
            "MGET",
            vec!["session:1", "outside", "session:2"],
            array(&[
                bulk(SOURCE, true),
                bulk("opaque", false),
                b"$-1\r\n".to_vec(),
            ]),
        ),
        (
            "hash",
            true,
            "HGETALL",
            vec!["session:1"],
            array(&[
                bulk("other", false),
                bulk("opaque", false),
                bulk("selected:a", false),
                bulk(SOURCE, true),
            ]),
        ),
        (
            "list",
            false,
            "LRANGE",
            vec!["session:1", "0", "-1"],
            array(&[bulk(SOURCE, true), b"$-1\r\n".to_vec()]),
        ),
    ] {
        let policy = policy(container, hash, true);
        let rules = rules(&policy, Surface::DependencyResponse);
        let event = event(command, &keys, &original);
        let target = String::from_utf8(original.clone())
            .unwrap()
            .replace("1010", "2010")
            .into_bytes();
        let (checked, decodes) = crate::value_codec::measured_decodes(|| {
            pair(
                Surface::DependencyResponse,
                &event,
                &original,
                &target,
                &rules,
                clocks(),
            )
        });
        assert_eq!(checked.unwrap(), 1, "{command}");
        assert_eq!(
            decodes, 1,
            "Source validation and delivery reuse one decode for {command}"
        );
        assert!(
            pair(
                Surface::DependencyResponse,
                &event,
                &original,
                &String::from_utf8(target.clone())
                    .unwrap()
                    .replace("$000", "$")
                    .into_bytes(),
                &rules,
                clocks()
            )
            .is_err()
        );
        assert!(
            pair(
                Surface::DependencyResponse,
                &event,
                &original,
                &String::from_utf8(target)
                    .unwrap()
                    .replace("[1,2]", "[2,1]")
                    .into_bytes(),
                &rules,
                clocks()
            )
            .is_err(),
            "unordered comparison does not authorize rewriting a delivered array"
        );
    }
}

#[test]
fn nil_and_error_have_no_value_permission_and_compare_only_reads_do_not_rewrite() {
    let policy = policy("string", false, false);
    let rules = rules(&policy, Surface::DependencyResponse);
    for raw in [b"$-1\r\n".as_slice(), b"_\r\n", b"-ERR unavailable\r\n"] {
        let event = event("GET", &["session:1"], raw);
        assert!(selects(rules[0], &event).unwrap());
        let (checked, decodes) = crate::value_codec::measured_decodes(|| {
            source(Surface::DependencyResponse, &event, raw, &rules, clocks())
        });
        assert!(checked.unwrap().is_empty());
        assert_eq!(decodes, 0);
        assert_eq!(
            pair(
                Surface::DependencyResponse,
                &event,
                raw,
                raw,
                &rules,
                clocks()
            )
            .unwrap(),
            0
        );
        assert!(
            pair(
                Surface::DependencyResponse,
                &event,
                raw,
                &bulk(SOURCE, false),
                &rules,
                clocks()
            )
            .is_err()
        );
    }
    let original = bulk(SOURCE, true);
    let event = event("GET", &["session:1"], &original);
    assert_eq!(
        pair(
            Surface::DependencyResponse,
            &event,
            &original,
            &original,
            &rules,
            clocks()
        )
        .unwrap(),
        1
    );
    assert!(
        pair(
            Surface::DependencyResponse,
            &event,
            &original,
            &bulk(&SOURCE.replace("1010", "2010"), true),
            &rules,
            clocks()
        )
        .is_err()
    );
    let mut unrelated = event;
    unrelated["target_host"] = json!("unrelated.test");
    unrelated["args"] = Value::Null;
    assert!(
        super::super::dependency::selected_rules(&rules, &unrelated)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn absent_keys_skip_response_parsing_and_delivery_needs_its_own_observed_pointer() {
    let compiled = policy("hash", true, true);
    let rules = rules(&compiled, Surface::DependencyResponse);
    for (command, args) in [
        ("HGET", vec!["outside", "selected:a"]),
        ("HGET", vec!["session:1", "unselected"]),
        ("HMGET", vec!["session:1", "other", "still-other"]),
    ] {
        let mut unrelated = event(command, &args, b"malformed and opaque RESP");
        unrelated["response"] = Value::Null;
        let (selected, decodes) = crate::value_codec::measured_decodes(|| {
            super::super::dependency::selected_rules(&rules, &unrelated)
        });
        assert!(selected.unwrap().is_empty(), "{command}");
        assert_eq!(decodes, 0);
    }
    let missing = bulk(r#"{"members":[1,2],"stable":"exact"}"#, true);
    let event = event("HGET", &["session:1", "selected:a"], &missing);
    let error = source(
        Surface::DependencyResponse,
        &event,
        &missing,
        &rules,
        clocks(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("was not observed"));
}
