use super::*;
use serde_json::json;

#[path = "identity_tests.rs"]
mod identity_tests;
#[path = "time_copy_tests.rs"]
mod time_copy_tests;

fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

fn runtime(container: &str, field: bool, delivery: bool) -> RequestContracts {
    runtime_with_clock_group(container, field, delivery, None)
}

fn runtime_with_clock_group(
    container: &str,
    field: bool,
    delivery: bool,
    clock_group: Option<&str>,
) -> RequestContracts {
    let raw = format!(
        r#"format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    proof: {{source: app/cache.rs:1-20, fact: 'The stored timestamp preserves its relative clock and all other bytes remain contractual'}}
    keys:
      - key: {{prefix: 'session:'}}
        container: {container}
        {hash_field}
        value:
          codec: json
          fields:
            /at: {{relative_time: unix_seconds}}
            /other_at: {{relative_time: unix_seconds}}
          {delivery}
"#,
        hash_field = if field {
            "hash_field: {exact: selected}"
        } else {
            ""
        },
        delivery = if delivery {
            "delivery: {rebase_time: [/at]}"
        } else {
            ""
        },
    );
    let raw = if let Some(group) = clock_group {
        raw.replace(
            "{relative_time: unix_seconds}",
            &format!("{{relative_time: unix_seconds, clock_group: {group}}}"),
        )
    } else {
        raw
    };
    let policy = crate::policy::parse_policy(&raw).unwrap();
    let mut runtime = RequestContracts::default();
    runtime
        .configure_compiled(Some(Arc::new(
            crate::policy::compile_policy(&policy).unwrap(),
        )))
        .unwrap();
    runtime.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            source_uri: String::new(),
            source_input_error: None,
            method: "POST".into(),
            path: "/sessions".into(),
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            dir: PathBuf::new(),
            conditions: Default::default(),
            source_body: None,
        },
    );
    runtime
}

fn preview(
    runtime: &RequestContracts,
    command: &str,
    source: &[&str],
    actual: &[&str],
) -> Result<Decision> {
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, command);
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    runtime
        .preview_unified_redis(&context, &args(source), &args(actual))
        .expect("field selected")
}

#[test]
fn string_fields_follow_set_setex_psetex_and_each_mset_key() {
    let runtime = runtime("string", false, false);
    let a = r#"{"at":1010,"stable":"a"}"#;
    let b = r#"{"at":2010,"stable":"a"}"#;
    for command in ["SETEX", "PSETEX"] {
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "90", a],
                &["session:1", "90", b]
            )
            .is_ok()
        );
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "90", a],
                &["session:1", "91", b]
            )
            .is_err()
        );
    }
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", a, "PX", "90", "NX"],
            &["session:1", b, "PX", "90", "NX"]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "SET",
            &["session:1", a, "PX", "90"],
            &["session:1", b, "EX", "90"]
        )
        .is_err()
    );
    assert!(
        preview(
            &runtime,
            "MSET",
            &["outside", "exact", "session:1", a, "session:2", a],
            &["outside", "exact", "session:1", b, "session:2", b]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "MSET",
            &["outside", "exact", "session:1", a],
            &["outside", "changed", "session:1", b]
        )
        .is_err()
    );
    assert!(
        preview(
            &runtime,
            "MSET",
            &["outside", "exact", "session:1", a],
            &["outside", "exact", "session:2", b]
        )
        .is_err()
    );
}

#[test]
fn hash_fields_select_values_without_relaxing_field_names_or_other_values() {
    let runtime = runtime("hash", true, false);
    let a = r#"{"at":1010,"stable":"a"}"#;
    let b = r#"{"at":2010,"stable":"a"}"#;
    for command in ["HSET", "HMSET"] {
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "other", "exact", "selected", a],
                &["session:1", "other", "exact", "selected", b]
            )
            .is_ok()
        );
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "other", "exact", "selected", a],
                &["session:1", "other", "changed", "selected", b]
            )
            .is_err()
        );
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", "selected", a],
                &["session:1", "other", b]
            )
            .is_err()
        );
    }
}

#[test]
fn list_fields_follow_push_and_set_preserving_indices_order_and_count() {
    let runtime = runtime("list", false, false);
    let a = r#"{"at":1010,"stable":"a"}"#;
    let b = r#"{"at":2010,"stable":"a"}"#;
    let c = r#"{"at":1011,"stable":"b"}"#;
    let d = r#"{"at":2011,"stable":"b"}"#;
    for command in ["LPUSH", "RPUSH"] {
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", a, c],
                &["session:1", b, d]
            )
            .is_ok()
        );
        assert!(
            preview(
                &runtime,
                command,
                &["session:1", a, c],
                &["session:1", d, b]
            )
            .is_err()
        );
        assert!(preview(&runtime, command, &["session:1", a, c], &["session:1", b]).is_err());
    }
    assert!(
        preview(
            &runtime,
            "LSET",
            &["session:1", "-1", a],
            &["session:1", "-1", b]
        )
        .is_ok()
    );
    assert!(
        preview(
            &runtime,
            "LSET",
            &["session:1", "-1", a],
            &["session:1", "0", b]
        )
        .is_err()
    );
}

fn bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{value}\r\n", value.len()).into_bytes()
}

fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = format!("*{}\r\n", values.len()).into_bytes();
    for value in values {
        raw.extend(value);
    }
    raw
}

#[test]
fn read_carriers_preserve_key_hash_field_and_list_element_identity() {
    let raw = array(&[bulk("a"), b"$-1\r\n".to_vec(), bulk("c")]);
    let keys = args(&["first", "second", "third"]);
    let values = redis_field_values("MGET", &keys, Some(&raw)).unwrap();
    assert_eq!(
        values.iter().map(|v| v.key.to_vec()).collect::<Vec<_>>(),
        args(&["first", "second", "third"])
    );
    assert_eq!(values[0].payload, Some(b"a".as_slice()));
    assert!(values[1].payload.is_none());
    assert_eq!(values[2].payload, Some(b"c".as_slice()));
    assert!(redis_field_values("MGET", &args(&["first"]), Some(&raw)).is_err());
    let raw = array(&[bulk("selected"), bulk("a"), bulk("other"), bulk("b")]);
    let keys = args(&["session:1"]);
    let values = redis_field_values("HGETALL", &keys, Some(&raw)).unwrap();
    assert_eq!(values[0].hash_field, Some(b"selected".as_slice()));
    assert_eq!(values[1].hash_field, Some(b"other".as_slice()));
    let keys = args(&["session:1", "0", "-1"]);
    let raw = array(&[bulk("a"), bulk("b")]);
    let values = redis_field_values("LRANGE", &keys, Some(&raw)).unwrap();
    assert_eq!(values.len(), 2);
    assert!(values[0].response.as_ref().unwrap().end <= values[1].response.as_ref().unwrap().start);
    for raw in [b"$-1\r\n".as_slice(), b"_\r\n", b"-ERR unavailable\r\n"] {
        let keys = args(&["session:1", "0"]);
        let values = redis_field_values("LINDEX", &keys, Some(raw)).unwrap();
        assert!(values[0].payload.is_none());
    }
}

#[test]
fn response_delivery_rebases_only_selected_hash_values_and_preserves_nil_and_order() {
    let runtime = runtime("hash", true, true);
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let source = r#"{"at":1010,"stable":"selected"}"#;
    let selected_frame = format!("$000{}\r\n{source}\r\n", source.len()).into_bytes();
    let original = array(&[
        bulk("other"),
        bulk("exact"),
        bulk("selected"),
        selected_frame,
    ]);
    let prepared = runtime
        .prepare_redis_delivery(
            "case",
            &target,
            0,
            None,
            "HGETALL",
            &args(&["session:1"]),
            &original,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let rendered = prepared
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let keys = args(&["session:1"]);
    let values = redis_field_values("HGETALL", &keys, Some(&rendered)).unwrap();
    assert_eq!(values[0].payload, Some(b"exact".as_slice()));
    let selected: Value = serde_json::from_slice(values[1].payload.as_ref().unwrap()).unwrap();
    assert_eq!(selected, json!({"at":2010,"stable":"selected"}));
    let selected_start = redis_field_values("HGETALL", &args(&["session:1"]), Some(&original))
        .unwrap()[1]
        .response
        .as_ref()
        .unwrap()
        .start;
    assert_eq!(&rendered[..selected_start], &original[..selected_start]);
    assert!(rendered[selected_start..].starts_with(format!("$000{}\r\n", source.len()).as_bytes()));
    assert!(
        runtime
            .prepare_redis_delivery(
                "case",
                &target,
                0,
                None,
                "HGET",
                &args(&["session:1", "selected"]),
                b"$-1\r\n",
                None,
                None,
                None,
                uuid::Uuid::new_v4(),
                2,
            )
            .is_none()
    );
}

#[test]
fn malformed_arities_frames_and_nonstorage_commands_cannot_expose_fields() {
    for (command, values) in [
        ("MSET", vec!["key"]),
        ("HSET", vec!["key", "field"]),
        ("LSET", vec!["key", "0"]),
    ] {
        assert!(redis_field_values(command, &args(&values), None).is_err());
    }
    for command in ["PUBLISH", "EVALSHA", "ZADD", "APPEND"] {
        assert!(
            redis_field_values(command, &args(&["key", "value"]), None)
                .unwrap()
                .is_empty()
        );
    }
    for raw in [
        b"$4\r\nabc\r\n".as_slice(),
        b"$1\r\nx\r\n:1\r\n",
        b"*1\r\n:1\r\n",
        b"*999999999\r\n",
    ] {
        assert!(redis_field_values("MGET", &args(&["session:1"]), Some(raw)).is_err());
    }
}

#[test]
fn large_list_decodes_once_per_value_and_unrelated_resources_decode_nothing() {
    let runtime = runtime("list", false, false);
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "RPUSH");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    let mut source = vec![b"session:1".to_vec()];
    let mut actual = source.clone();
    for index in 0..128 {
        let payload = "x".repeat(4096);
        source.push(
            serde_json::to_vec(&json!({"at":1010+index,"other_at":1010+index,"stable":payload}))
                .unwrap(),
        );
        actual.push(
            serde_json::to_vec(&json!({"at":2010+index,"other_at":2010+index,"stable":payload}))
                .unwrap(),
        );
    }
    let (result, decodes) = crate::value_codec::measured_decodes(|| {
        runtime.preview_unified_redis(&context, &source, &actual)
    });
    result.unwrap().unwrap();
    assert_eq!(
        decodes, 256,
        "two time fields share each Source/Target decode"
    );
    let target = TargetKey {
        host: "unrelated.test".into(),
        port: 6379,
    };
    context.target = &target;
    let (result, decodes) = crate::value_codec::measured_decodes(|| {
        runtime.preview_unified_redis(&context, &source, &actual)
    });
    assert!(result.is_none());
    assert_eq!(decodes, 0);
    assert!(
        redis_field_values("PUBLISH", &source, None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn source_scan_counts_only_observed_values_and_keeps_null_unavailable() {
    let runtime = runtime("string", false, false);
    let capture = |bytes: &[u8]| json!({"encoding":"utf8","data":std::str::from_utf8(bytes).unwrap(),"truncated":false});
    let source = args(&["session:1", "session:2"]);
    let response = array(&[
        bulk(r#"{"at":1010,"other_at":1010,"stable":"exact"}"#),
        b"$-1\r\n".to_vec(),
    ]);
    let event = json!({"event_type":"redis_exchange", "replay_safe":true,
        "command":"MGET","target_host":"cache.test","target_port":6379,"database":0,
        "connection_id":"source-lane","sequence":1,
        "request_started_at":"1970-01-01T00:16:40Z","timestamp":"1970-01-01T00:16:40Z",
        "args":source.iter().map(|value|capture(value)).collect::<Vec<_>>(),"response":capture(&response)});
    let (result, decodes) =
        crate::value_codec::measured_decodes(|| runtime.observe_unified_source("case", &event));
    result.unwrap();
    assert_eq!(
        decodes, 1,
        "one complete value is decoded once for both fields"
    );
    assert_eq!(runtime.unavailable_value_slots().values().sum::<usize>(), 1);
    assert_eq!(
        runtime
            .reports()
            .iter()
            .filter(|report| report.applicable)
            .count(),
        1
    );
    let mut event = event;
    event["target_host"] = json!("unrelated.test");
    let (result, decodes) =
        crate::value_codec::measured_decodes(|| runtime.observe_unified_source("case", &event));
    result.unwrap();
    assert_eq!(decodes, 0);
}

#[test]
fn contextual_native_owner_keeps_identity_and_clock_semantics_before_global_fields() {
    let mut runtime = runtime("string", false, false);
    let policy = crate::policy::parse_policy(r#"format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    proof: {source: app/cache.rs:1-20, fact: 'Stored session timestamps preserve the request-relative clock'}
    keys:
    - key: {prefix: 'session:'}
      container: string
      value:
        codec: json
        fields:
          /at: {relative_time: unix_seconds}
rules:
- id: contextual-set
  match:
    api: POST /sessions
    resource: cache
    key: {kind: affix, prefix: 'session:', suffix: ''}
  effect:
    kind: redis_sequence
    key:
      kind: capture
      binding: session-id
      template: 'session:{value}'
      format: {kind: hex, bytes: 4}
    commands:
    - operation: SET
      arguments:
        1:
          kind: json
          fields:
            /at: {field_ref: {resource: cache, key: 0, pointer: /at}, clock_group: creation}
            /nonce: {kind: random, format: hex, length: 8}
  proof: {source: app/cache.rs:1-20, fact: 'Creation captures the key identity and a fresh nonce while preserving the generated clock'}
"#).unwrap();
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    let projection =
        crate::replay::policy::native_projection::project_native(&compiled.native).unwrap();
    runtime.rules = Arc::new(projection.document.dependency_rules);
    runtime
        .configure_compiled(Some(Arc::new(compiled)))
        .unwrap();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    let source = args(&[
        "session:aaaaaaaa",
        r#"{"at":1010,"nonce":"cccccccc","stable":"exact"}"#,
    ]);
    let actual = args(&[
        "session:bbbbbbbb",
        r#"{"at":2010,"nonce":"dddddddd","stable":"exact"}"#,
    ]);
    assert!(
        runtime
            .preview_unified_redis(&context, &source, &actual)
            .unwrap()
            .is_err()
    );
    let decision = runtime
        .preview_redis_context(&context, &source, &actual)
        .unwrap()
        .unwrap();
    assert!(decision.ids.iter().any(|id| id == "contextual-set"));
    assert!(decision.ids.iter().any(|id| id.starts_with("schema:")));
    assert_eq!(
        decision.ids.len(),
        2,
        "native and resource fields both evaluate"
    );
    let mut changed = actual;
    changed[1] = br#"{"at":2010,"nonce":"dddddddd","stable":"changed"}"#.to_vec();
    assert!(
        runtime
            .preview_redis_context(&context, &source, &changed)
            .unwrap()
            .is_err()
    );
    assert!(
        preview(
            &runtime,
            "SETEX",
            &["session:1", "90", r#"{"at":1010}"#],
            &["session:1", "90", r#"{"at":2010}"#]
        )
        .is_ok()
    );
}

#[test]
fn mget_delivery_preserves_unselected_value_and_nil_without_claiming_compare_only_reads() {
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let keys = args(&["session:1", "outside", "session:2"]);
    let original = array(&[
        bulk(r#"{"at":1010,"stable":"exact"}"#),
        bulk("opaque"),
        b"$-1\r\n".to_vec(),
    ]);
    let runtime = runtime("string", false, true);
    let (prepared, decodes) = crate::value_codec::measured_decodes(|| {
        runtime.prepare_redis_delivery(
            "case",
            &target,
            0,
            None,
            "MGET",
            &keys,
            &original,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
    });
    let prepared = prepared.unwrap().unwrap();
    assert_eq!(
        decodes, 1,
        "unselected opaque bytes and nil are not decoded"
    );
    let rendered = prepared
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let values = redis_field_values("MGET", &keys, Some(&rendered)).unwrap();
    assert_eq!(values[1].payload, Some(b"opaque".as_slice()));
    assert!(values[2].payload.is_none());
    let selected: Value = serde_json::from_slice(values[0].payload.unwrap()).unwrap();
    assert_eq!(selected, json!({"at":2010,"stable":"exact"}));
    let runtime = self::runtime("string", false, false);
    assert!(
        runtime
            .prepare_redis_delivery(
                "case",
                &target,
                0,
                None,
                "MGET",
                &keys,
                &original,
                DateTime::from_timestamp(1000, 0),
                DateTime::from_timestamp(2000, 0),
                DateTime::from_timestamp(1000, 0),
                uuid::Uuid::new_v4(),
                2,
            )
            .is_none(),
        "comparison-only schema must not become a delivery owner"
    );
}

#[test]
fn implicit_list_clocks_are_independent_while_explicit_shared_clocks_preserve_copies() {
    let source = &["session:1", r#"{"at":1010}"#, r#"{"at":1010}"#];
    let actual = &["session:1", r#"{"at":2010}"#, r#"{"at":2011}"#];
    let implicit = runtime("list", false, false);
    let (result, decodes) =
        crate::value_codec::measured_decodes(|| preview(&implicit, "RPUSH", source, actual));
    result.unwrap();
    assert_eq!(
        decodes, 4,
        "independent elements retain one Source and Target decode each"
    );
    let explicit = runtime_with_clock_group("list", false, false, Some("shared-event"));
    let (result, decodes) =
        crate::value_codec::measured_decodes(|| preview(&explicit, "RPUSH", source, actual));
    assert!(
        result.is_err(),
        "an explicit clock still preserves copies across elements"
    );
    assert_eq!(decodes, 4);
    assert!(
        preview(
            &explicit,
            "RPUSH",
            &["session:1", r#"{"at":1010,"other_at":1010}"#],
            &["session:1", r#"{"at":2010,"other_at":2011}"#],
        )
        .is_err(),
        "explicit same-value clock relationships remain checked"
    );
    assert!(
        preview(
            &explicit,
            "RPUSH",
            &["session:1", r#"{"at":1010,"other_at":1015}"#],
            &["session:1", r#"{"at":2010,"other_at":2015}"#],
        )
        .is_ok()
    );
}
