use super::*;
use sqlx::Executor;

fn policy(_surface: &str, _operation: &str, _sql: &str, _slot: &str, _delivery: bool) -> String {
    "format: traffic-policy/v2\njson:\n  fields:\n    /members: {kind: unordered}\n    /time: {kind: time, formats: [unix_microseconds]}\n".into()
}

fn payload(micros: i64, members: Value) -> String {
    json!({"members":members,"time":micros+1_000_000,"stable":"checked"}).to_string()
}

#[tokio::test]
async fn sql_json_contract_preserves_statement_and_finite_consumption_over_tls() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let sql = "UPDATE widgets SET payload=? WHERE id=?";
        let mut write = exchange(sql, json!({"status":"ok","affected_rows":1}));
        write["command"] = json!("COM_STMT_EXECUTE");
        write["connection_id"] = json!(uuid::Uuid::new_v4());
        write["query_sequence"] = json!(1);
        write["params"] = json!([{"kind":"string","value":payload(1_577_836_800_000_000,json!(["a","b","a"]))},{"kind":"integer","value":7}]);
        let (temp, addr, runtime, task) = fixture_with_policy(&[write], Some(&policy("dependency.request", "COM_STMT_EXECUTE", sql, "{sql_value: 0}", false))).await;
        let original = std::fs::read(temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")).unwrap();
        let good = payload(Utc::now().timestamp_micros(),json!(["a","a","b"]));
        let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        for (body, id, valid) in [(good.replace("checked","changed"),7,false),(good.clone(),8,false),(good.clone(),7,true),(good,7,false)] {
            let result = sqlx::query(sql).bind(body).bind(id).execute(&mut client).await;
            if valid { assert_eq!(result.unwrap().rows_affected(),1); } else { assert!(result.is_err()); }
        }
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,1);
        assert_eq!(state.mysql.events.unmatched_queries.len(),3);
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.global_formats.iter().find(|r| r.id=="global.json").unwrap().time_validations,1);
        assert_eq!(std::fs::read(temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")).unwrap(),original);
        task.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn mysql_json_wildcard_times_preserve_array_shape_members_and_finite_consumption() {
    let start = 1_577_836_800_i64;
    let sql = "UPDATE widgets SET payload=? WHERE id=?";
    for count in [1, 2, 6] {
        let payload = |time: i64| json!({"blocks":(0..count).map(|i| json!({"id":format!("fixed-{i}"),"timestamp":time+i,"stable":7})).collect::<Vec<_>>(),"status":"done"});
        let mut record = exchange(sql, json!({"status":"ok","affected_rows":1}));
        record["timestamp"] = json!(chrono::DateTime::from_timestamp(start, 0).unwrap());
        record["duration_ms"] = json!(0);
        record["command"] = json!("COM_STMT_EXECUTE");
        record["connection_id"] = json!(uuid::Uuid::new_v4());
        record["query_sequence"] = json!(1);
        record["params"] = json!([{"kind":"string","value":payload(start).to_string()},{"kind":"integer","value":7}]);
        let policy = "format: traffic-policy/v2\njson:\n  fields:\n    /blocks/*/timestamp: {kind: time, formats: [unix_seconds]}\n";
        let (temp, addr, runtime, task) = fixture_with_policy(&[record], Some(policy)).await;
        let observed = Utc::now();
        runtime.state.lock().await.mysql.observed_at_for_test = Some(observed);
        let good = payload(observed.timestamp());
        let mut business = good.clone();
        business["status"] = json!("changed");
        let mut shape = good.clone();
        shape["blocks"].as_array_mut().unwrap().pop();
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        for (body, valid) in [
            (business, false),
            (shape, false),
            (good.clone(), true),
            (good, false),
        ] {
            let result = sqlx::query(sql)
                .bind(body.to_string())
                .bind(7_i64)
                .execute(&mut client)
                .await;
            assert_eq!(result.is_ok(), valid, "block count {count}: {result:?}");
        }
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 3);
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(
            report
                .global_formats
                .iter()
                .find(|r| r.id == "global.json")
                .unwrap()
                .time_validations,
            count as usize
        );
        task.abort();
    }
}

#[tokio::test]
async fn sql_json_response_changes_only_explicit_delivery_time() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let sql = "SELECT payload FROM widgets WHERE id=7";
        let source = payload(1_577_836_800_000_000, json!(["a", "b", "a"]));
        let mut record = exchange(
            sql,
            result(
                json!([{"name":"payload","family":"string","sql_type":"VARCHAR"}]),
                json!([[{"kind":"string","value":source}]]),
            ),
        );
        record["connection_id"] = json!(uuid::Uuid::new_v4());
        record["query_sequence"] = json!(1);
        let (temp, addr, runtime, task) = fixture_with_policy(
            &[record],
            Some(&policy(
                "dependency.response",
                "COM_QUERY",
                "SELECT payload FROM widgets WHERE id=?",
                "{sql_column: payload}",
                true,
            )),
        )
        .await;
        let original = std::fs::read(
            temp.path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl"),
        )
        .unwrap();
        // This SQL request starts far from the API clock; only its own observation rebases delivery.
        let dependency_start =
            chrono::DateTime::from_timestamp(2_000_000_000, 123_456_000).unwrap();
        runtime.state.lock().await.mysql.observed_at_for_test = Some(dependency_start);
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let row = (&mut client).fetch_one(sql).await.unwrap();
        let body: Value = serde_json::from_str(row.get::<&str, _>("payload")).unwrap();
        assert_eq!(
            body["time"],
            json!(dependency_start.timestamp_micros() + 1_000_000)
        );
        assert_eq!(body["members"], json!(["a", "b", "a"]));
        assert_eq!(body["stable"], "checked");
        assert!((&mut client).fetch_one(sql).await.is_err());
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")
            )
            .unwrap(),
            original
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finalized_evidence_waits_for_actual_dependency_delivery() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let sql = "SELECT id FROM widgets WHERE id=7";
        let mut record = exchange(
            sql,
            result(
                json!([{"name":"id","family":"integer","sql_type":"BIGINT"}]),
                json!([[{"kind":"integer","value":7}]]),
            ),
        );
        record["duration_ms"] = json!(500);
        let (temp, addr, runtime, server) = fixture_with_policy(&[record], None).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let query = tokio::spawn(async move {
            (&mut client).fetch_one(sql).await.unwrap();
            client.close().await.unwrap();
        });
        loop {
            if runtime
                .state
                .lock()
                .await
                .mysql
                .exchanges
                .iter()
                .any(|e| e.status == ReplayExchangeStatus::Responding)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let request = |command: &str, case_id| crate::replay::control::ReplayControlRequest {
            command: command.into(),
            case_id,
            fail_on_dirty: false,
            fail_on_incomplete: false,
            identity_pairs: Vec::new(),
            derived_input: None,
        };
        let (ended, _) = crate::replay::control::handle_control_request(
            request("end", Some("case-id".into())),
            runtime.state.clone(),
            Some(temp.path().join("finished-replay.json")),
            None,
        )
        .await;
        assert_eq!(ended["ok"], true);
        let (pending, _) = crate::replay::control::handle_control_request(
            request("finalize", None),
            runtime.state.clone(),
            Some(temp.path().join("finished-replay.json")),
            None,
        )
        .await;
        assert_eq!(pending["ok"], false);
        assert!(runtime.state.lock().await.finalized_at.is_none());
        query.await.unwrap();
        let (finished, _) = crate::replay::control::handle_control_request(
            request("finalize", None),
            runtime.state.clone(),
            Some(temp.path().join("finished-replay.json")),
            None,
        )
        .await;
        assert_eq!(finished["ok"], true);
        let (reopened, _) = crate::replay::control::handle_control_request(
            request("begin", Some("case-id".into())),
            runtime.state.clone(),
            Some(temp.path().join("finished-replay.json")),
            None,
        )
        .await;
        assert_eq!(reopened["ok"], false);
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn absent_sql_json_leaf_is_inactive_and_business_values_remain_exact() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let policy = "format: traffic-policy/v2\njson:\n  fields:\n    /updated_at: {kind: time, formats: [unix_seconds]}\n";
        let sql = "UPDATE settings SET json='{\"stable\":7}' WHERE id=7";
        let record = exchange(sql, json!({"status":"ok","affected_rows":1}));
        let (temp, addr, runtime, server) = fixture_with_policy(&[record], Some(policy)).await;
        let mut client = connect(
            addr,
            &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        ).await;
        assert!((&mut client).execute("UPDATE settings SET json='{\"stable\":8}' WHERE id=7").await.is_err());
        assert_eq!((&mut client).execute(sql).await.unwrap().rows_affected(), 1);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        let report = state.replay_policy.as_ref().unwrap().report();
        let rule = report.global_formats.iter().find(|rule| rule.id == "global.json").unwrap();
        assert!(!rule.applicable);
        assert_eq!(rule.validations, 0);
        assert!(report.unused_applicable_dependency_rule_ids.is_empty());
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        server.abort();
    }).await.unwrap();
}
