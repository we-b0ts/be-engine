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
        let policy = r#"format: traffic-policy/v2
mysql:
  database: appdb
  tables:
    leases:
      pattern: leases
      fields:
        expires_at: {kind: time, formats: [{format: sql_datetime, utc_offset: '+00:00'}]}
"#;
        let (temp,addr,runtime,task) = fixture_with_policy(&records,Some(policy)).await;
        let before = chrono::Utc::now().naive_utc();
        let mut client = connect(addr,&temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
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
        let usage = report.global_formats.iter().find(|format| format.id == "global.mysql").unwrap();
        assert_eq!(usage.validations, 2);
        assert_eq!(usage.time_validations, 2);
        assert!(state.mysql.exchanges.iter().all(|exchange| exchange.record.response.rows[0][0].value == Some(json!("2020-01-01 00:05:00.123456"))));
        drop(state);
        client.close().await.unwrap();
        task.abort();
    }).await.unwrap();
}
