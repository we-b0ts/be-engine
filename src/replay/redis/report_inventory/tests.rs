use super::*;
use serde_json::{Value, json};

fn fixture() -> RedisReplayState {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let rule: crate::BackgroundDependencyRuleConfig = serde_json::from_value(json!({
        "name":"snapshot-seed","protocol":"redis","ports":[6379],"command":"GET","keys":["snapshot"],
        "initial_load_timeout_ms":60000,"source_evidence":"Source keeps this process-owned read as a reusable snapshot"
    })).unwrap();
    for (index, key) in ["snapshot", "once", "failed"].into_iter().enumerate() {
        let mut record = json!({"connection_id":Uuid::new_v4(),"sequence":1,"target_host":"redis.test","target_port":6379,
            "resp_version":2,"database":0,"username":null,"command":"GET",
            "args":[{"encoding":"utf8","data":key}],"response_kind":"bulk_string",
            "response":{"encoding":"utf8","data":"$1\r\nx\r\n"},"replay_safe":true});
        if index == 0 {
            record["cache_snapshot_rule"] = "snapshot-seed".into();
            record["global_dependency_reason"] = "background_rule".into();
        }
        state
            .register_exchange(
                serde_json::from_value(record).unwrap(),
                ReplaySource::Global,
                None,
                &mut targets,
                std::slice::from_ref(&rule),
            )
            .unwrap();
    }
    state.freeze_global_report_layout();
    state.initialize_global_report_usage(3);
    state
}

fn request(state: &mut RedisReplayState, key: &str) -> MatchedRedisExchange {
    state
        .match_redis(
            None,
            &TargetKey {
                host: "redis.test".into(),
                port: 6379,
            },
            TargetConnection::default(),
            2,
            0,
            None,
            "GET",
            &[key.as_bytes().to_vec()],
        )
        .unwrap()
}

fn equivalent(state: &RedisReplayState, report: &std::path::Path, rows: &[Row]) {
    let mut extras = Vec::new();
    state
        .visit_global_report_extras(&mut |row| {
            extras.push(row);
            Ok(())
        })
        .unwrap();
    let (count, actual) = crate::replay::report::global_evidence::regular::tests::protocol_snapshot(
        report,
        "redis",
        state.global_report_layout(),
        rows,
        state.global_report_snapshot().unwrap(),
        extras,
    );
    let mut expected: Vec<Value> = Vec::new();
    state
        .visit_global_regular_unused(&mut |row| {
            expected.push(row);
            Ok(())
        })
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(count, state.global_unused_count());
}

#[test]
fn cached_global_reports_follow_real_reusable_completion_and_failed_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let mut state = fixture();
    let mut rows = Vec::new();
    state
        .visit_global_report_rows(&mut |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
    equivalent(&state, &report, &rows);
    for _ in 0..2 {
        let matched = request(&mut state, "snapshot");
        state.complete_exchange(&matched);
        assert!(state.exchanges[0].status.is_available());
        assert!(state.exchanges[0].matched_once);
        equivalent(&state, &report, &rows);
        assert_eq!(state.global_unused_count(), 2);
    }
    let matched = request(&mut state, "once");
    state.complete_exchange(&matched);
    equivalent(&state, &report, &rows);
    assert_eq!(state.global_unused_count(), 1);
    let matched = request(&mut state, "failed");
    state.fail_exchange(&matched, "fixture response delivery failed".into());
    equivalent(&state, &report, &rows);
    assert_eq!(state.global_unused_count(), 1);
}
