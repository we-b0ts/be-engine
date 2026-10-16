//! Native identity/time planning followed by a finite Redis replay over TCP.
use super::*;
use crate::{
    DynamicValueRedisTimeRule, DynamicValueRuleFeedback, plan_dynamic_value_redis_time_rule,
};
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
    let temp = tempfile::tempdir().unwrap();
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
    let identity=serde_json::from_value(json!({
        "id":"item-identity","api":"/items","targets":[{"host":"redis.internal","port":6379}],
        "when":{"request_body_json":{"/mode":{"equals":"generated"}}},
        "capture":{"protocol":"redis","target":{"host":"redis.internal","port":6379},"database":0,
            "command":"RPUSH","key":{"prefix":"items:","numeric":true},"argument_index":1,"json_pointer":"/id",
            "references":[{"json_pointer":"/content_key","template":"cache:payload:{key_middle}:{value}"}],
            "derived_from":{"json_pointer":"/timestamp","prefix":"item-"}},
        "source_evidence":"Item:create generates its ID from current milliseconds and reuses it in bounded payload references"
    })).unwrap();
    let time: DynamicValueRedisTimeRule =
        serde_json::from_value(json!({"id":"item-time","method":"POST",
        "time_values":[{"json_pointer":"/timestamp","format":"unix_milliseconds"}],
        "source_evidence":"Item:create stores the current request-relative millisecond timestamp"}))
        .unwrap();
    let plan = plan_dynamic_value_redis_time_rule(
        DynamicValueRuleFeedback {
            policy_path: policy.clone(),
            rule: identity,
            replay_report: report,
        },
        time,
    )
    .unwrap();
    assert_eq!(plan.report().matching_cases, 1);
    plan.apply().unwrap();
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
