//! A real RESP capture can be authored from fingerprints, then correlate later keys.
use super::*;
use crate::{DynamicValueRuleFeedback, plan_dynamic_value_rule};
use redis_value_tests::{request, spawn};
use serde_json::json;

#[tokio::test]
async fn redis_capture_plan_apply_replay_preserves_options_references_and_finite_calls() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
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
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
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
    crate::replay::policy::test_fixture::install_dynamic_value(DynamicValueRuleFeedback {
        policy_path: policy.clone(),
        rule,
        replay_report: report,
    })
    .unwrap();
    let yaml = crate::recorder::test_io::read_to_string_sync(&policy).unwrap();
    assert!(yaml.contains("kind: identity"));
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

#[tokio::test]
async fn redis_prefix_capture_plans_from_exact_witnesses_and_replays_multiple_keys() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    let lane = Uuid::new_v4();
    let records = [
        redis_hash_dependency(
            lane,
            1,
            "SET",
            &["task:1", "source-one", "EX", "60"],
            b"+OK\r\n",
        ),
        redis_hash_dependency(
            lane,
            2,
            "SET",
            &["task:2", "source-two", "EX", "60"],
            b"+OK\r\n",
        ),
        redis_hash_dependency(lane, 3, "DEL", &["cache:source-one"], b":1\r\n"),
        redis_hash_dependency(lane, 4, "DEL", &["cache:source-two"], b":1\r\n"),
    ];
    let dependencies = case.join("dependencies.jsonl");
    std::fs::write(
        &dependencies,
        records
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let original = std::fs::read(&dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/items"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let (addr, state, task) = spawn(&case, Some(policy.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    request(
        &mut client,
        &["SET", "task:1", "target-one", "EX", "60"],
        error,
    )
    .await;
    request(
        &mut client,
        &["SET", "task:2", "target-two", "EX", "60"],
        error,
    )
    .await;
    let report_path = temp.path().join("replay.json");
    let report = {
        let mut state = state.lock().await;
        state.finalized_at = Some(Utc::now());
        serde_json::to_value(state.snapshot_report()).unwrap()
    };
    task.abort();
    assert!(!report.to_string().contains("target-one"));
    let candidates = report["replay_policy"]["dynamic_capture_candidates"]
        .as_array()
        .unwrap();
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate["capture"]["key"].is_string())
    );
    let rule: crate::DynamicValueRule = serde_json::from_value(json!({
        "id":"name","api":"/items","targets":[{"host":"redis.internal","port":6379}],
        "capture":{"protocol":"redis","target":{"host":"redis.internal","port":6379},
            "database":0,"command":"SET","key":{"prefix":"task:","numeric":true},"argument_index":1},
        "source_evidence":"Generator:create produces a random name under a task ID key, then uses that name in cache references"
    })).unwrap();
    let feedback = || DynamicValueRuleFeedback {
        policy_path: policy.clone(),
        rule: rule.clone(),
        replay_report: report_path.clone(),
    };
    let original_policy = std::fs::read(&policy).unwrap();
    // A broad rule still requires an exact, immutable same-case capture witness.
    for (field, value) in [
        ("key", json!({"prefix":"task:"})),
        ("key", json!("task:99")),
        ("database", json!(1)),
        ("argument_index", json!(2)),
        ("json_pointer", json!("/other")),
    ] {
        let mut changed = report.clone();
        changed["replay_policy"]["dynamic_capture_candidates"] = json!([candidates[0].clone()]);
        changed["replay_policy"]["dynamic_capture_candidates"][0]["capture"][field] = value;
        std::fs::write(&report_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(plan_dynamic_value_rule(feedback()).is_err(), "{field}");
        assert_eq!(std::fs::read(&policy).unwrap(), original_policy);
    }
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let retired_error = plan_dynamic_value_rule(feedback()).err().unwrap();
    assert!(
        retired_error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(std::fs::read(&dependencies).unwrap(), original);
    crate::replay::policy::test_fixture::install_dynamic_value(feedback()).unwrap();
    let saved = crate::recorder::test_io::read_to_string_sync(&policy).unwrap();
    assert!(saved.contains("prefix: 'task:'") || saved.contains("prefix: task:"));
    assert!(saved.contains("kind: numeric"));
    let (addr, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    for values in [
        vec!["SET", "task:3", "target-one", "EX", "60"],
        vec!["SET", "task:x", "target-one", "EX", "60"],
        vec!["SET", "other:1", "target-one", "EX", "60"],
        vec!["SET", "task:1", "target-one", "EX", "61"],
        vec!["DEL", "cache:target-one"],
    ] {
        request(&mut client, &values, error).await;
    }
    request(
        &mut client,
        &["SET", "task:1", "target-one", "EX", "60"],
        b"+OK\r\n",
    )
    .await;
    request(
        &mut client,
        &["SET", "task:2", "target-one", "EX", "60"],
        error,
    )
    .await;
    request(
        &mut client,
        &["SET", "task:2", "target-two", "EX", "60"],
        b"+OK\r\n",
    )
    .await;
    request(&mut client, &["DEL", "cache:target-two"], error).await;
    request(&mut client, &["DEL", "cache:target-one"], b":1\r\n").await;
    request(&mut client, &["DEL", "cache:target-two"], b":1\r\n").await;
    request(
        &mut client,
        &["SET", "task:1", "target-one", "EX", "60"],
        error,
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
        2
    );
    assert_eq!(std::fs::read(&dependencies).unwrap(), original);
    task.abort();
}
