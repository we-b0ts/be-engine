use super::*;
use serde_json::json;

pub(super) fn identity_rule() -> Value {
    json!({"id":"block","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"writer"},"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"writer"}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:1","fact":"Source writes the generated block id, reads that same key and appends using the returned id"}})
}

fn policy(rules: Vec<Value>) -> crate::policy::CompiledPolicy {
    crate::policy::compile_policy(
        &serde_json::from_value(json!({"format":"traffic-policy/v2","rules":rules})).unwrap(),
    )
    .unwrap()
}

fn runtime(rules: Vec<Value>) -> RequestContracts {
    let root = tempfile::tempdir().unwrap();
    let requests = BTreeMap::from([(
        "case".into(),
        (
            root.path().into(),
            json!({
                "method":"POST","uri":"/tasks","timestamp":"1970-01-01T00:16:40Z",
                "body":{"encoding":"utf8","data":"{}","truncated":false}
            }),
        ),
    )]);
    super::super::super::matcher::ReplayPolicyRuntime::from_source_policy(
        &policy(rules),
        root.path(),
        &requests,
    )
    .unwrap()
    .request_contracts
}

fn target() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}
fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values.iter().map(|v| v.as_bytes().to_vec()).collect()
}
fn bulk(value: &[u8]) -> Vec<u8> {
    wire::encode(&redis_protocol::resp2::types::OwnedFrame::BulkString(
        value.into(),
    ))
    .unwrap()
}
fn context<'a>(target: &'a TargetKey, command: &'a str, sequence: u64) -> RedisRequestContext<'a> {
    RedisRequestContext {
        case: "case",
        target,
        database: 0,
        username: Some("writer"),
        command,
        recorded_at: DateTime::from_timestamp(1000 + sequence as i64, 0),
        actual_at: DateTime::from_timestamp(2000 + sequence as i64, 0),
        connection_id: Some(uuid::Uuid::nil()),
        sequence: Some(sequence),
        observation_id: None,
    }
}

#[test]
fn read_back_requires_explicit_permission_a_committed_successful_write_and_case_identity() {
    let target = target();
    let runtime = runtime(vec![identity_rule()]);
    let source = args(&["current:7", "old"]);
    let actual = args(&["current:7", "new"]);
    let write = context(&target, "SET", 1);
    let read = context(&target, "GET", 2);
    let read_args = args(&["current:7"]);
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );
    let pending = runtime
        .preview_redis_read_back_write(&write, &source, &actual, b"+OK\r\n", write.recorded_at)
        .unwrap();
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );
    runtime.commit_redis_read_back_write(pending).unwrap();
    let prepared = runtime
        .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
        .unwrap()
        .unwrap();
    assert_eq!(prepared.response, bulk(b"new"));
    assert!(runtime.read_back_report().is_empty());
    runtime
        .commit_redis_read_back(&prepared, Utc::now())
        .unwrap();
    runtime
        .validate_read_back_coverage(&BTreeSet::from(["block".into()]))
        .unwrap();
    let report = serde_json::to_string(&runtime.read_back_report()).unwrap();
    assert!(!report.contains("\"old\"") && !report.contains("\"new\""));
    assert_eq!(runtime.read_back_report()[0].source_write_sequence, 1);
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"unseen"))
            .is_err()
    );
    let mut another = context(&target, "GET", 2);
    another.case = "another-case";
    assert!(
        runtime
            .prepare_redis_read_back(&another, &read_args, &read_args, &bulk(b"old"))
            .unwrap()
            .is_none()
    );
    let mut another = context(&target, "GET", 2);
    another.database = 1;
    assert!(
        runtime
            .prepare_redis_read_back(&another, &read_args, &read_args, &bulk(b"old"))
            .unwrap()
            .is_none()
    );
    let mut another = context(&target, "GET", 2);
    another.username = Some("reader");
    assert!(
        runtime
            .prepare_redis_read_back(&another, &read_args, &read_args, &bulk(b"old"))
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .prepare_redis_read_back(
                &context(&target, "GET", 1),
                &read_args,
                &read_args,
                &bulk(b"old")
            )
            .is_err()
    );
    let changed = args(&["current:7", "other"]);
    assert!(
        runtime
            .preview_redis_read_back_write(&write, &source, &changed, b"+OK\r\n", write.recorded_at)
            .is_err()
    );
    runtime.begin_case("case");
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );

    let runtime = super::tests::runtime(vec![identity_rule()]);
    let failed = runtime
        .preview_redis_read_back_write(
            &write,
            &source,
            &actual,
            b"-ERR write rejected\r\n",
            write.recorded_at,
        )
        .unwrap();
    runtime.commit_redis_read_back_write(failed).unwrap();
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, b"$-1\r\n")
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .validate_read_back_coverage(&BTreeSet::from(["block".into()]))
            .is_err()
    );
    let mut definition = identity_rule();
    definition["effect"]
        .as_object_mut()
        .unwrap()
        .remove("read_back");
    let runtime = super::tests::runtime(vec![definition]);
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn timestamp_read_back_preserves_the_written_instant_and_unselected_fields() {
    let mut definition = identity_rule();
    definition["match"]
        .as_object_mut()
        .unwrap()
        .remove("operation");
    definition["effect"] = json!({"kind":"redis_sequence","commands":[{"operation":"SET","arguments":{"1":{"kind":"json","fields":{
        "/started_at":{"relative_time":"rfc3339"},"/last_activity_at":{"relative_time":"rfc3339"}
    }}}}],"read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,"json_pointers":["/started_at"]}]});
    let runtime = runtime(vec![definition]);
    let target = target();
    let write = context(&target, "SET", 1);
    let left = r#"{"started_at":"1970-01-01T00:16:41Z","last_activity_at":"1970-01-01T00:16:41Z","user":7}"#;
    let right = r#"{"started_at":"1970-01-01T00:33:21Z","last_activity_at":"1970-01-01T00:33:21Z","user":7}"#;
    let pending = runtime
        .preview_redis_read_back_write(
            &write,
            &args(&["current:7", left]),
            &args(&["current:7", right]),
            b"+OK\r\n",
            write.recorded_at,
        )
        .unwrap();
    runtime.commit_redis_read_back_write(pending).unwrap();
    let read = context(&target, "GET", 30); // A much later read must not shift started_at again.
    let read_args = args(&["current:7"]);
    let prepared = runtime
        .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(left.as_bytes()))
        .unwrap()
        .unwrap();
    let redis_protocol::resp2::types::OwnedFrame::BulkString(payload) =
        wire::frame(&prepared.response).unwrap()
    else {
        panic!()
    };
    let value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(value["started_at"], "1970-01-01T00:33:21Z");
    assert_eq!(value["last_activity_at"], "1970-01-01T00:16:41Z");
    assert_eq!(value["user"], 7);
}

#[test]
fn read_back_keeps_authenticated_users_keys_and_cross_connection_causality_separate() {
    let mut definition = identity_rule();
    definition["match"]["resource"]
        .as_object_mut()
        .unwrap()
        .remove("username");
    definition["effect"]["references"][0]["resource"]
        .as_object_mut()
        .unwrap()
        .remove("username");
    let runtime = runtime(vec![definition]);
    let target = target();
    let write = context(&target, "SET", 1);
    let read_args = args(&["current:7"]);
    let pending = runtime
        .preview_redis_read_back_write(
            &write,
            &args(&["current:7", "old"]),
            &args(&["current:7", "new"]),
            b"+OK\r\n",
            write.recorded_at,
        )
        .unwrap();
    runtime.commit_redis_read_back_write(pending).unwrap();
    let mut read = context(&target, "GET", 2);
    read.username = Some("reader");
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );
    read.username = Some("writer");
    assert!(
        runtime
            .prepare_redis_read_back(
                &read,
                &args(&["current:8"]),
                &args(&["current:8"]),
                &bulk(b"old")
            )
            .is_err()
    );
    read.connection_id = Some(uuid::Uuid::new_v4());
    read.recorded_at = DateTime::from_timestamp(1000, 0);
    assert!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .is_err()
    );
    read.recorded_at = DateTime::from_timestamp(1002, 0);
    assert_eq!(
        runtime
            .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
            .unwrap()
            .unwrap()
            .response,
        bulk(b"new")
    );
}

#[test]
fn read_back_retains_an_earlier_completion_on_an_independent_writer_connection() {
    let runtime = runtime(vec![identity_rule()]);
    let target = target();
    let source = args(&["current:7", "old"]);
    let actual = args(&["current:7", "new"]);
    let first = context(&target, "SET", 1);
    let pending = runtime
        .preview_redis_read_back_write(
            &first,
            &source,
            &actual,
            b"+OK\r\n",
            DateTime::from_timestamp(1010, 0),
        )
        .unwrap();
    runtime.commit_redis_read_back_write(pending).unwrap();
    let mut second = context(&target, "SET", 2);
    second.connection_id = Some(uuid::Uuid::new_v4());
    let pending = runtime
        .preview_redis_read_back_write(
            &second,
            &source,
            &actual,
            b"+OK\r\n",
            DateTime::from_timestamp(1002, 0),
        )
        .unwrap();
    runtime.commit_redis_read_back_write(pending).unwrap();
    let mut read = context(&target, "GET", 3);
    read.connection_id = Some(uuid::Uuid::new_v4());
    let read_args = args(&["current:7"]);
    let result = runtime
        .prepare_redis_read_back(&read, &read_args, &read_args, &bulk(b"old"))
        .unwrap()
        .unwrap();
    assert_eq!(result.response, bulk(b"new"));
    assert_eq!(
        result.reports[0].source_write_connection,
        second.connection_id.unwrap()
    );
}

#[test]
fn read_back_lrange_translates_conditional_ids_and_copies_without_changing_other_elements() {
    use redis_protocol::resp2::types::OwnedFrame;
    let mut definition = identity_rule();
    definition["match"]["operation"] = json!("RPUSH");
    definition["match"]["key"] = json!({"kind":"numeric","prefix":"blocks:"});
    definition["effect"]["capture"] = json!({"kind":"redis_argument","index":1,"json_pointer":"/id",
        "when":{"relative_pointer":"../type","equals":"text"},
        "copies":[{"pointer":"/_content_key","template":"content:{value}"}]});
    definition["effect"]["read_back"] = json!([{"operation":"LRANGE","write_operation":"RPUSH","argument_index":1,
        "json_pointers":["/id","/_content_key"]}]);
    let runtime = runtime(vec![definition]);
    let target = target();
    let write = context(&target, "RPUSH", 1);
    let source_text =
        json!({"id":"old","type":"text","_content_key":"content:old","status":"streaming"})
            .to_string();
    let target_text =
        json!({"id":"new","type":"text","_content_key":"content:new","status":"streaming"})
            .to_string();
    let thinking = json!({"id":"thinking-stable","type":"thinking","_content_key":"content:thinking-stable","status":"streaming"}).to_string();
    let source_args = args(&["blocks:7", &source_text, &thinking]);
    let target_args = args(&["blocks:7", &target_text, &thinking]);
    let pending = runtime
        .preview_redis_read_back_write(
            &write,
            &source_args,
            &target_args,
            b":2\r\n",
            write.recorded_at,
        )
        .unwrap();
    runtime.commit_redis_read_back_write(pending).unwrap();
    let response = wire::encode(&OwnedFrame::Array(vec![
        OwnedFrame::BulkString(source_text.as_bytes().into()),
        OwnedFrame::BulkString(thinking.as_bytes().into()),
    ]))
    .unwrap();
    let read_args = args(&["blocks:7", "0", "-1"]);
    let prepared = runtime
        .prepare_redis_read_back(
            &context(&target, "LRANGE", 2),
            &read_args,
            &read_args,
            &response,
        )
        .unwrap()
        .unwrap();
    let OwnedFrame::Array(result) = wire::frame(&prepared.response).unwrap() else {
        panic!()
    };
    let OwnedFrame::BulkString(text) = &result[0] else {
        panic!()
    };
    let value: Value = serde_json::from_slice(text).unwrap();
    assert_eq!(value["id"], "new");
    assert_eq!(value["_content_key"], "content:new");
    assert_eq!(value["status"], "streaming");
    assert_eq!(
        result[1],
        OwnedFrame::BulkString(thinking.as_bytes().into())
    );
}

#[test]
fn read_back_compiler_rejects_unowned_fields_operations_and_duplicate_native_owners() {
    let mut resource_rule = identity_rule();
    resource_rule["match"]
        .as_object_mut()
        .unwrap()
        .remove("api");
    let document: crate::policy::TrafficPolicy =
        serde_json::from_value(json!({"format":"traffic-policy/v2","rules":[resource_rule]}))
            .unwrap();
    assert!(crate::policy::compile_policy(&document).is_ok());
    for mutate in 0..4 {
        let mut definition = identity_rule();
        match mutate {
            0 => definition["effect"]["read_back"][0]["json_pointers"] = json!(["/secret"]),
            1 => definition["effect"]["read_back"][0]["operation"] = json!("MGET"),
            2 => definition["effect"]["read_back"][0]["argument_index"] = json!(2),
            _ => {
                definition["match"].as_object_mut().unwrap().remove("key");
            }
        }
        let document: crate::policy::TrafficPolicy =
            serde_json::from_value(json!({"format":"traffic-policy/v2","rules":[definition]}))
                .unwrap();
        assert!(crate::policy::compile_policy(&document).is_err());
    }
    let definition = identity_rule();
    let mut overlap = definition.clone();
    overlap["id"] = json!("duplicate");
    let document: crate::policy::TrafficPolicy =
        serde_json::from_value(json!({"format":"traffic-policy/v2","rules":[definition,overlap]}))
            .unwrap();
    assert!(crate::policy::compile_policy(&document).is_err());
}
