//! Native identity/time planning followed by a finite Redis replay over TCP.
use super::*;
use crate::DynamicValueRedisTimeRule;
use serde_json::json;

const ERROR: &[u8] = b"-ERR no recorded Redis dependency matched\r\n";
fn item(stamp: i64) -> String {
    json!({"id":format!("item-{stamp}"),"timestamp":stamp,
        "content_key":format!("cache:payload:7:item-{stamp}"),"owner":7,"status":"open"})
    .to_string()
}
fn inbound(mode: &str) -> String {
    json!({"method":"POST","uri":"/items","timestamp":"1970-01-01T00:16:40Z",
        "body":{"encoding":"utf8","truncated":false,"data":json!({"mode":mode}).to_string()}})
    .to_string()
}

#[tokio::test]
async fn redis_joint_time_plans_from_failure_then_replays_nil_capture_references_and_finite_consumption()
 {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    let case = local.join("recordings/run/case");
    std::fs::create_dir_all(&case).unwrap();
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    std::fs::write(case.join("request.json"), inbound("generated")).unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let connection = Uuid::new_v4();
    let source = item(1000000);
    let records = [
        redis_dependency(connection, 1, "current:7", b"$-1\r\n"),
        redis_hash_dependency(connection, 2, "RPUSH", &["items:7", &source], b":1\r\n"),
        redis_hash_dependency(
            connection,
            3,
            "SET",
            &["current:7", "item-1000000", "EX", "3600"],
            b"+OK\r\n",
        ),
        redis_hash_dependency(
            connection,
            4,
            "APPEND",
            &["cache:payload:7:item-1000000", "hello"],
            b":5\r\n",
        ),
        redis_hash_dependency(
            connection,
            5,
            "EXPIRE",
            &["cache:payload:7:item-1000000", "3600"],
            b":1\r\n",
        ),
    ];
    let immutable = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let dependencies = case.join("dependencies.jsonl");
    std::fs::write(&dependencies, &immutable).unwrap();
    let policy = temp.path().join(".traffic-e2e/policy.yaml");
    crate::replay::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
    state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .request_begin("case")
        .unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    redis_value_tests::request(&mut client, &["GET", "current:7"], b"$-1\r\n").await;
    redis_value_tests::request(
        &mut client,
        &["RPUSH", "items:7", &item(Utc::now().timestamp_millis())],
        ERROR,
    )
    .await;
    let report = temp.path().join("replay.json");
    {
        let mut replay = state.lock().await;
        replay.finalized_at = Some(Utc::now());
        std::fs::write(
            &report,
            serde_json::to_vec(&replay.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let identity = json!({
        "kind":"dynamic_value","id":"item-identity","api":"/items","targets":[{"host":"redis.internal","port":6379}],
        "when":{"request_body_json":{"/mode":{"equals":"generated"}}},
        "capture":{"protocol":"redis","target":{"host":"redis.internal","port":6379},"database":0,
            "command":"RPUSH","key":{"prefix":"items:","numeric":true},"argument_index":1,"json_pointer":"/id",
            "references":[{"json_pointer":"/content_key","template":"cache:payload:{key_middle}:{value}"}],
            "derived_from":{"json_pointer":"/timestamp","prefix":"item-"}},
        "source_evidence":"Item:create generates its ID from current milliseconds and reuses it in bounded payload references"
    });
    let time: DynamicValueRedisTimeRule =
        serde_json::from_value(json!({"id":"item-time","method":"POST",
        "time_values":[{"json_pointer":"/timestamp","format":"unix_milliseconds"}],
        "source_evidence":"Item:create stores the current request-relative millisecond timestamp"}))
        .unwrap();
    crate::replay::install_dependency_rule_fixture(&policy, identity.clone()).unwrap();
    let fields = time
        .time_values
        .iter()
        .map(|field| {
            (
                field.json_pointer.clone(),
                json!({"time":"preserve_relative","format":field.format}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    crate::replay::install_dependency_rule_fixture(&policy,json!({
        "id":time.id,"protocol":"redis","target":identity["capture"]["target"],
        "case":{"method":time.method,"path":identity["api"]},"when":identity["when"],
        "source_evidence":time.source_evidence,"redis":{"database":0,"key":identity["capture"]["key"],
            "commands":[{"command":"RPUSH","argument_values":{"1":{"json":fields}}}]}
    })).unwrap();
    for mode in ["forwarded", "generated"] {
        std::fs::write(case.join("request.json"), inbound(mode)).unwrap();
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
        state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        redis_value_tests::request(&mut client, &["GET", "current:7"], b"$-1\r\n").await;
        let stamp = Utc::now().timestamp_millis();
        let actual = item(stamp);
        redis_value_tests::request(
            &mut client,
            &["RPUSH", "items:7", &actual],
            if mode == "generated" {
                b":1\r\n"
            } else {
                ERROR
            },
        )
        .await;
        if mode == "generated" {
            let id = format!("item-{stamp}");
            let payload = format!("cache:payload:7:{id}");
            redis_value_tests::request(
                &mut client,
                &["SET", "current:7", &id, "EX", "3600"],
                b"+OK\r\n",
            )
            .await;
            redis_value_tests::request(&mut client, &["APPEND", &payload, "hello"], b":5\r\n")
                .await;
            redis_value_tests::request(&mut client, &["EXPIRE", &payload, "3600"], b":1\r\n").await;
            {
                let replay = state.lock().await;
                let report = replay.snapshot_report();
                assert_eq!(report.protocols.redis.matched_count, 5);
                assert!(!report.is_dirty());
                let usage = replay.replay_policy.as_ref().unwrap().report();
                assert!(usage.unused_applicable_dependency_rule_ids.is_empty());
                assert!(usage.dependency_rules.iter().all(|rule| rule.matches == 1));
            }
            redis_value_tests::request(&mut client, &["RPUSH", "items:7", &actual], ERROR).await;
            assert_eq!(
                state
                    .lock()
                    .await
                    .snapshot_report()
                    .protocols
                    .redis
                    .matched_count,
                5
            );
        } else {
            assert_eq!(
                state
                    .lock()
                    .await
                    .snapshot_report()
                    .protocols
                    .redis
                    .matched_count,
                1
            );
        }
        task.abort();
    }
    assert_eq!(std::fs::read_to_string(dependencies).unwrap(), immutable);
}

#[tokio::test]
async fn conditional_redis_capture_replays_mixed_blocks_times_references_and_finite_consumption() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join(".traffic-e2e/local/recordings/run/case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(case.join("request.json"), inbound("generated")).unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let connection = Uuid::new_v4();
    let text = |time| {
        json!({"type":"text","id":format!("text-{time}"),"timestamp":time,
        "content_key":format!("content:text-{time}"),"content":""})
        .to_string()
    };
    let thinking =
        json!({"type":"thinking","id":"thinking-abcdef123456","timestamp":1000000}).to_string();
    let tool = json!({"type":"tool","id":"toolu_recorded","timestamp":1000000}).to_string();
    let records = [
        redis_hash_dependency(connection, 1, "RPUSH", &["blocks:7", &thinking], b":1\r\n"),
        redis_hash_dependency(connection, 2, "RPUSH", &["blocks:7", &tool], b":2\r\n"),
        redis_hash_dependency(
            connection,
            3,
            "RPUSH",
            &["blocks:7", &text(1000000)],
            b":3\r\n",
        ),
        redis_hash_dependency(
            connection,
            4,
            "SET",
            &["current:7", "text-1000000", "EX", "300"],
            b"+OK\r\n",
        ),
        redis_hash_dependency(
            connection,
            5,
            "APPEND",
            &["content:text-1000000", "hello"],
            b":5\r\n",
        ),
        redis_hash_dependency(
            connection,
            6,
            "EXPIRE",
            &["content:text-1000000", "300"],
            b":1\r\n",
        ),
    ];
    let original = records.iter().map(|v| format!("{v}\n")).collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    let resource = json!({"protocol":"redis","endpoint":"redis.internal:6379","database":0});
    let proof = json!({"source":"blocks.py:create","fact":"Text ID derives from its wall-clock millisecond timestamp, while thinking and tool IDs have independent provenance"});
    let identity = json!({"id":"text","match":{"api":"POST /items","resource":resource,"operation":"RPUSH","key":{"kind":"exact","value":"blocks:7"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1,"json_pointer":"/id",
        "when":{"relative_pointer":"../type","equals":"text"},"derived_from":{"pointer":"/timestamp","prefix":"text-"},
        "copies":[{"pointer":"/content_key","template":"content:{value}"}]},"references":[{"resource":resource}]},"proof":proof});
    let time = json!({"id":"clock","match":{"api":"POST /items","resource":resource,"key":{"kind":"exact","value":"blocks:7"}},
        "effect":{"kind":"redis_sequence","commands":[{"operation":"RPUSH","arguments":{"1":{"kind":"json","fields":{
            "/timestamp":{"kind":"time","format":"unix_milliseconds","relation":"preserve_offset"}}}}}]},"proof":proof});
    let policy = temp.path().join(".traffic-e2e/policy.yaml");
    std::fs::write(
        &policy,
        serde_yaml::to_string(&json!({"format":"traffic-policy/v1","rules":[identity,time]}))
            .unwrap(),
    )
    .unwrap();
    let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy)).await;
    state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .request_begin("case")
        .unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let live_time = Utc::now().timestamp_millis();
    let live_thinking =
        json!({"type":"thinking","id":"thinking-abcdef123456","timestamp":live_time}).to_string();
    let live_tool = json!({"type":"tool","id":"toolu_recorded","timestamp":live_time}).to_string();
    redis_value_tests::request(
        &mut client,
        &["RPUSH", "blocks:7", &live_thinking],
        b":1\r\n",
    )
    .await;
    redis_value_tests::request(&mut client, &["RPUSH", "blocks:7", &live_tool], b":2\r\n").await;
    redis_value_tests::request(
        &mut client,
        &["RPUSH", "blocks:7", &text(live_time)],
        b":3\r\n",
    )
    .await;
    let id = format!("text-{live_time}");
    let content = format!("content:{id}");
    redis_value_tests::request(
        &mut client,
        &["SET", "current:7", &id, "EX", "300"],
        b"+OK\r\n",
    )
    .await;
    redis_value_tests::request(&mut client, &["APPEND", &content, "hello"], b":5\r\n").await;
    redis_value_tests::request(&mut client, &["EXPIRE", &content, "300"], b":1\r\n").await;
    assert_eq!(
        state
            .lock()
            .await
            .snapshot_report()
            .protocols
            .redis
            .matched_count,
        6
    );
    assert!(!state.lock().await.snapshot_report().is_dirty());
    // A successful conditional match never makes the Source exchange reusable.
    redis_value_tests::request(&mut client, &["RPUSH", "blocks:7", &text(live_time)], ERROR).await;
    assert_eq!(
        state
            .lock()
            .await
            .snapshot_report()
            .protocols
            .redis
            .matched_count,
        6
    );
    task.abort();
    assert_eq!(
        std::fs::read_to_string(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
