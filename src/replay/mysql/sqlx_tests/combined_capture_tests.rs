//! A real MySQL client plans and replays one generated identity plus request time.
use super::*;

const SQL: &str = "INSERT INTO items (name, created_at, owner_id) VALUES (?, ?, ?)";
const SOURCE: &str = "task-pending-123e4567e89b42d3a456426614174000";
const TARGET: &str = "task-pending-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa";

#[tokio::test]
async fn combined_capture_from_real_unmatched_insert_then_fresh_replay_is_finite() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut source = exchange(&format!("INSERT INTO items (name, created_at, owner_id) VALUES ('{SOURCE}', '2020-01-01 00:00:00', 7)"),json!({"status":"ok","affected_rows":1,"last_insert_id":9}));
        source["parse_warnings"] = json!([]);
        let empty = "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n";
        let (temp,addr,runtime,task) = fixture_with_policy(std::slice::from_ref(&source),Some(empty)).await;
        let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&path).unwrap();
        let mut client = connect(addr,&temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        assert!(sqlx::query(SQL).bind(TARGET).bind(chrono::Utc::now().naive_utc()).bind(7_i64).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let replay_report = temp.path().join("replay.json");
        {
            let mut state = runtime.state.lock().await;
            state.finalized_at = Some(chrono::Utc::now());
            std::fs::write(&replay_report,serde_json::to_vec(&state.snapshot_report()).unwrap()).unwrap();
        }
        let rule = serde_json::from_value(json!({"id":"generated-name","api":"/users","targets":[{"host":"127.0.0.1","port":3306}],
            "capture":{"protocol":"mysql","target":{"host":"127.0.0.1","port":3306},"database":"appdb","sql":SQL,"value_index":0},
            "source_evidence":"NameFactory:create generates task-pending-{uuid.uuid4().hex} per new item"})).unwrap();
        let time = serde_json::from_value(json!({"id":"created-at","time_values":[{"value_index":1}],"source_evidence":"ItemModel:created_at defaults to datetime.utcnow()"})).unwrap();
        crate::replay::policy::test_fixture::install_joint_mysql(crate::DynamicValueRuleFeedback {
            policy_path:temp.path().join("policy.yaml"),rule,replay_report,
        },time).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(),original);
        let policy = crate::recorder::test_io::read_to_string_sync(temp.path().join("policy.yaml")).unwrap();
        task.abort();
        let (fresh,addr,runtime,task) = fixture_with_policy(&[source],Some(&policy)).await;
        let mut client = connect(addr,&fresh.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        assert!(sqlx::query(SQL).bind(TARGET).bind(chrono::Utc::now().naive_utc()).bind(8_i64).execute(&mut client).await.is_err());
        assert!(runtime.state.lock().await.replay_policy.as_ref().unwrap().report().dynamic_bindings.is_empty());
        let now = chrono::Utc::now().naive_utc();
        assert_eq!(sqlx::query(SQL).bind(TARGET).bind(now).bind(7_i64).execute(&mut client).await.unwrap().rows_affected(),1);
        assert!(sqlx::query(SQL).bind(TARGET).bind(now).bind(7_i64).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,1);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.dynamic_bindings.len(),1);
        assert_eq!(report.dependency_rules[0].time_validations,1);
        task.abort();
    }).await.expect("combined MySQL capture Replay timed out");
}

#[tokio::test]
async fn combined_table_capture_replays_two_shards_without_cross_table_consumption() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let sources = [1,2].map(|shard| {
            let mut source = exchange(&format!("INSERT INTO items_{shard:04} (name, created_at, owner_id) VALUES ('source-{shard}', '2020-01-01 00:00:00', {})",shard+6),json!({"status":"ok","affected_rows":1,"last_insert_id":shard}));
            source["parse_warnings"]=json!([]);
            source
        });
        let empty = "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n";
        let (temp,addr,runtime,task) = fixture_with_policy(&sources,Some(empty)).await;
        let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&path).unwrap();
        let mut client = connect(addr,&temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let first = SQL.replace("items","items_0001");
        let second = SQL.replace("items","items_0002");
        assert!(sqlx::query(&first).bind("target-1").bind(chrono::Utc::now().naive_utc()).bind(7_i64).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let replay_report = temp.path().join("replay.json");
        {
            let mut state = runtime.state.lock().await;
            state.finalized_at = Some(chrono::Utc::now());
            std::fs::write(&replay_report,serde_json::to_vec(&state.snapshot_report()).unwrap()).unwrap();
        }
        let rule = serde_json::from_value(json!({"id":"sharded-name","api":"/users","targets":[{"host":"127.0.0.1","port":3306}],
            "capture":{"protocol":"mysql","target":{"host":"127.0.0.1","port":3306},"database":"appdb","sql":SQL.replace("items","{{table}}"),"table_series":{"prefix":"items_","start":0,"end":2,"width":4},"value_index":0},
            "source_evidence":"ItemStore shards by user_id % 3 into items_{shard:04d} and allocates a new opaque name"})).unwrap();
        let time = serde_json::from_value(json!({"id":"sharded-created-at","time_values":[{"value_index":1}],"source_evidence":"ItemModel:created_at defaults to datetime.utcnow()"})).unwrap();
        crate::replay::policy::test_fixture::install_joint_mysql(crate::DynamicValueRuleFeedback{policy_path:temp.path().join("policy.yaml"),rule,replay_report},time).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(),original);
        let policy = crate::recorder::test_io::read_to_string_sync(temp.path().join("policy.yaml")).unwrap();
        task.abort();
        let (fresh,addr,runtime,task) = fixture_with_policy(&sources,Some(&policy)).await;
        let mut client = connect(addr,&fresh.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        // The recorded first write must not match a different allowed shard;
        // the real second write has another stable owner and remains finite.
        assert!(sqlx::query(&second).bind("target-1").bind(chrono::Utc::now().naive_utc()).bind(7_i64).execute(&mut client).await.is_err());
        assert!(runtime.state.lock().await.replay_policy.as_ref().unwrap().report().dynamic_bindings.is_empty());
        for (sql,name,owner) in [(&first,"target-1",7_i64),(&second,"target-2",8_i64)] {
            assert_eq!(sqlx::query(sql).bind(name).bind(chrono::Utc::now().naive_utc()).bind(owner).execute(&mut client).await.unwrap().rows_affected(),1);
        }
        assert!(sqlx::query(&first).bind("target-1").bind(chrono::Utc::now().naive_utc()).bind(7_i64).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,2);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.dynamic_bindings.len(),2);
        assert_eq!(report.dependency_rules[0].time_validations,2);
        task.abort();
        assert_eq!(std::fs::read(&path).unwrap(),original);
    }).await.expect("sharded combined MySQL capture Replay timed out");
}
