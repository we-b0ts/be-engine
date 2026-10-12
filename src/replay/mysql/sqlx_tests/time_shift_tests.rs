use super::*;
use sqlx::Executor;

#[tokio::test]
async fn mysql_time_shift_delivers_relative_expiry_through_tls_text_and_prepared_protocols() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let sql = "SELECT expires_at,owner FROM leases WHERE id=7 FOR UPDATE";
        let response = result(json!([
            {"name":"expires_at","family":"datetime","sql_type":"DATETIME","scale":6},
            {"name":"owner","family":"string","sql_type":"VARCHAR"}
        ]),json!([[{"kind":"datetime","value":"2020-01-01 00:05:00.123456"},{"kind":"string","value":"stable"}]]));
        let records = [exchange(sql,response.clone()),exchange(sql,response.clone()),
            exchange("SELECT expires_at,owner FROM leases WHERE id=7",response)];
        let rule = json!({"id":"lease-expiry","protocol":"mysql","case":{"method":"GET","path":"/users"},
            "target":{"host":"127.0.0.1","port":3306},"source_evidence":"lease.py:acquire stores UTC now plus the lease duration",
            "mysql":{"database":"appdb","sql":"SELECT expires_at,owner FROM leases WHERE id=? FOR UPDATE",
            "response_time_shift":{"expires_at":{"time":"preserve_relative","format":"mysql_datetime"}}}});
        let mut projection_rule = rule.clone();
        projection_rule["id"] = json!("lease-expiry-projection");
        projection_rule["mysql"]["sql"] = json!("SELECT expires_at,owner FROM leases WHERE id=?");
        let policy = serde_yaml::to_string(&json!({"version":3,"expected_response":"assertions_only","dependency_rules":[rule,projection_rule]})).unwrap();
        let (temp,addr,runtime,task) = fixture_with_policy(&records,Some(&policy)).await;
        let before = chrono::Utc::now().naive_utc();
        let mut client = connect(addr,&temp.path().join("case-id/.replay/ca.pem")).await;
        let text = client.fetch_one(sql).await.unwrap();
        assert!(sqlx::query("SELECT expires_at,owner FROM leases WHERE id=? FOR UPDATE")
            .bind(8_i64).fetch_one(&mut client).await.is_err());
        let prepared = sqlx::query("SELECT expires_at,owner FROM leases WHERE id=? FOR UPDATE").bind(7_i64).fetch_one(&mut client).await.unwrap();
        for row in [text,prepared] {
            let expiry: chrono::NaiveDateTime = row.get("expires_at");
            assert!((expiry - before).num_seconds() >= 299);
            assert!((expiry - before).num_seconds() <= 301);
            assert_eq!(row.get::<String,_>("owner"),"stable");
        }
        let projected = client.fetch_one("SELECT owner FROM leases WHERE id=7").await.unwrap();
        assert_eq!(projected.get::<String,_>("owner"), "stable");
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,3);
        let report = state.replay_policy.as_ref().unwrap().report();
        let usage = report.dependency_rules.iter().find(|rule| rule.id == "lease-expiry").unwrap();
        assert_eq!(usage.matches,2);
        assert!(state.mysql.exchanges.iter().all(|exchange| exchange.record.response.rows[0][0].value == Some(json!("2020-01-01 00:05:00.123456"))));
        drop(state);
        client.close().await.unwrap();
        task.abort();
    }).await.unwrap();
}
