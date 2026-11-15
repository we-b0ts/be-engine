use super::*;
use serde_json::json;

#[path = "size_tests.rs"]
mod size_tests;

#[path = "automatic_tests.rs"]
mod automatic_tests;
#[path = "identity_tests.rs"]
mod identity_tests;
#[path = "scalar_tests.rs"]
mod scalar_tests;
#[path = "time_copy_tests.rs"]
mod time_copy_tests;

fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

fn runtime() -> RequestContracts {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /at: {kind: time, formats: [unix_seconds]}
    /other_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap();
    let mut runtime = RequestContracts::default();
    runtime
        .configure_compiled(Some(Arc::new(compiled)))
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
            dependencies_path: PathBuf::new(),
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
        .preview_redis_context(&context, &args(source), &args(actual))
        .expect("global Redis value selected")
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
fn global_json_values_follow_redis_carriers_and_keep_native_arguments_exact() {
    let runtime = runtime();
    let a = r#"{"at":1010,"stable":"checked"}"#;
    let b = r#"{"at":2010,"stable":"checked"}"#;
    for (command, source, target) in [
        ("SET", vec!["key", a], vec!["key", b]),
        ("SETEX", vec!["key", "30", a], vec!["key", "30", b]),
        ("PSETEX", vec!["key", "30000", a], vec!["key", "30000", b]),
        (
            "MSET",
            vec!["first", a, "second", a],
            vec!["first", b, "second", b],
        ),
        ("HSET", vec!["hash", "field", a], vec!["hash", "field", b]),
        (
            "HMSET",
            vec!["hash", "first", a, "second", a],
            vec!["hash", "first", b, "second", b],
        ),
        ("RPUSH", vec!["list", a, a], vec!["list", b, b]),
        ("LPUSH", vec!["list", a], vec!["list", b]),
        ("LSET", vec!["list", "1", a], vec!["list", "1", b]),
        ("PUBLISH", vec!["channel", a], vec!["channel", b]),
    ] {
        assert!(
            preview(&runtime, command, &source, &target).is_ok(),
            "{command}"
        );
    }
    for (command, source, target) in [
        (
            "SET",
            vec!["key", a, "EX", "30"],
            vec!["key", b, "EX", "31"],
        ),
        ("HSET", vec!["hash", "field", a], vec!["hash", "other", b]),
        ("LSET", vec!["list", "1", a], vec!["list", "2", b]),
        ("PUBLISH", vec!["channel", a], vec!["other", b]),
    ] {
        assert!(
            preview(&runtime, command, &source, &target).is_err(),
            "{command}"
        );
    }
    assert!(
        preview(
            &runtime,
            "SET",
            &["key", a],
            &["key", r#"{"at":2010,"stable":"wrong"}"#]
        )
        .is_err()
    );
}

#[test]
fn opaque_and_optional_redis_values_keep_strict_bytes_and_presence() {
    let runtime = runtime();
    for (source, target, passed) in [
        ("opaque", "opaque", true),
        ("opaque", "changed", false),
        ("{}", "{}", true),
        ("{}", r#"{"at":2000}"#, false),
        (r#"{"at":null}"#, r#"{"at":null}"#, true),
        (r#"{"at":null}"#, "{}", false),
    ] {
        assert_eq!(
            preview(&runtime, "SET", &["key", source], &["key", target]).is_ok(),
            passed,
            "{source} -> {target}"
        );
    }
}

#[test]
fn global_read_delivery_preserves_opaque_values_nil_and_array_order() {
    let runtime = runtime();
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let raw = array(&[
        bulk("opaque"),
        b"$-1\r\n".to_vec(),
        bulk(
            r#"{ "mcpServers":{"zeta":{"url":"z"},"alpha":{"baseUrl":"a"}}, "at":1010,"stable":true }"#,
        ),
    ]);
    let keys = args(&["first", "missing", "third"]);
    let delivery = runtime
        .prepare_redis_delivery(
            "case",
            "case",
            &host,
            0,
            None,
            "MGET",
            &keys,
            &keys,
            &raw,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let bytes = delivery
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let values = redis_field_values("MGET", &keys, Some(&bytes)).unwrap();
    assert_eq!(values[0].payload, Some(b"opaque".as_slice()));
    assert!(values[1].payload.is_none());
    assert_eq!(
        crate::json_value::parse(values[2].payload.unwrap()).unwrap(),
        json!({"mcpServers":{"zeta":{"url":"z"},"alpha":{"baseUrl":"a"}},"at":2010,"stable":true})
    );
    assert_eq!(
        values[2].payload.unwrap(),
        br#"{ "mcpServers":{"zeta":{"url":"z"},"alpha":{"baseUrl":"a"}}, "at":2010,"stable":true }"#
    );
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
fn malformed_arities_frames_and_nonstorage_commands_cannot_expose_fields() {
    for (command, values) in [
        ("MSET", vec!["key"]),
        ("HSET", vec!["key", "field"]),
        ("LSET", vec!["key", "0"]),
    ] {
        assert!(redis_field_values(command, &args(&values), None).is_err());
    }
    for command in ["PUBLISH", "ZADD", "APPEND"] {
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
