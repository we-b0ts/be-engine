//! A real RESP capture can be authored from fingerprints, then correlate later keys.
use super::*;
use crate::{DynamicValueRuleFeedback, plan_dynamic_value_rule};
use redis_value_tests::{request, spawn};
use serde_json::json;

#[tokio::test]
async fn redis_capture_plan_apply_replay_preserves_options_references_and_finite_calls() {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    let lane = Uuid::new_v4();
    let set = redis_hash_dependency(
        lane,
        1,
        "SET",
        &["anchor", "source-name", "EX", "60"],
        b"+OK\r\n",
    );
    let delete = redis_hash_dependency(lane, 2, "DEL", &["cache:source-name:fixed"], b":1\r\n");
    let dependencies = case.join("dependencies.jsonl");
    std::fs::write(&dependencies, format!("{set}\n{delete}\n")).unwrap();
    let original = std::fs::read(&dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/items"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("verification.yaml");
    std::fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let (addr, state, task) = spawn(&case, Some(policy.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &["SET", "anchor", "target-name", "EX", "60"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    let report = temp.path().join("replay.json");
    {
        let mut state = state.lock().await;
        state.finalized_at = Some(Utc::now());
        let bytes = serde_json::to_vec(&state.snapshot_report()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("target-name"));
        std::fs::write(&report, bytes).unwrap();
    }
    task.abort();
    let rule = serde_json::from_value(json!({"id":"name","api":"/items","targets":[{"host":"redis.internal","port":6379}],"capture":{"protocol":"redis","target":{"host":"redis.internal","port":6379},"database":0,"command":"SET","key":"anchor","argument_index":1},"source_evidence":"Generator:create chooses a random name used in the later cache key"})).unwrap();
    plan_dynamic_value_rule(DynamicValueRuleFeedback {
        policy_path: policy.clone(),
        rule,
        replay_report: report,
    })
    .unwrap()
    .apply()
    .unwrap();
    let yaml = std::fs::read_to_string(&policy).unwrap();
    assert!(yaml.contains("kind: dynamic_value"));
    assert!(!yaml.contains("dynamic_values:"));
    let (addr, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &["SET", "anchor", "target-name", "EX", "61"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    request(
        &mut client,
        &["DEL", "cache:target-name:fixed"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    request(
        &mut client,
        &["SET", "anchor", "target-name", "EX", "60"],
        b"+OK\r\n",
    )
    .await;
    request(
        &mut client,
        &["DEL", "cache:wrong-name:fixed"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    request(&mut client, &["DEL", "cache:target-name:fixed"], b":1\r\n").await;
    request(
        &mut client,
        &["DEL", "cache:target-name:fixed"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    let state = state.lock().await;
    assert!(
        state
            .unused_exchanges(crate::replay::ReplaySource::Case)
            .is_empty()
    );
    assert_eq!(
        state
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .dynamic_bindings
            .len(),
        1
    );
    assert_eq!(std::fs::read(dependencies).unwrap(), original);
    task.abort();
}
