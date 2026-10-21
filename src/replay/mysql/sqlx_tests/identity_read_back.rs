//! Real TLS proves write -> selected identity read-back -> strict dependent write.
use super::*;
use sqlx::Executor;

fn policy() -> String {
    r#"format: traffic-policy/v1
rules:
- id: block
  match:
    api: GET /users
    resource: &mysql {protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}
    operation: COM_QUERY
    sql: INSERT INTO blocks (name) VALUES (?)
  effect:
    kind: identity
    value_type: string
    capture: {kind: mysql_value, index: 0}
    references: [{resource: *mysql}]
    mysql_read_back:
    - resource: *mysql
      sql: SELECT payload FROM {{table}} WHERE id=?
      table_series: {prefix: results_, start: 0, end: 2, width: 4}
      column: payload
      json_pointers: [/blocks/*/id, /blocks/*/key]
      templates: {'/blocks/*/key': 'content:{value}'}
      proof: {source: 'store.py:read', fact: 'Source reads the persisted blocks before copying their identities into Task JSON'}
  proof: {source: 'store.py:create', fact: 'Source generates a block identity reused in later JSON writes'}
- id: read-clock
  surface: dependency.response
  match:
    api: GET /users
    resource: *mysql
    operation: COM_QUERY
    sql: SELECT payload FROM {{table}} WHERE id=?
    table_series: {prefix: results_, start: 0, end: 2, width: 4}
  slot: {sql_column: payload}
  codec: json
  contract: {/changed_at: {kind: time, format: unix_microseconds, relation: preserve_offset}}
  delivery: {rebase_time: [/changed_at]}
  proof: {source: 'store.py:read_clock', fact: 'Source observes the request clock in this independent field'}
- id: write-clock
  match:
    api: GET /users
    resource: *mysql
    operation: COM_QUERY
    sql: UPDATE tasks SET payload=? WHERE id=?
  effect:
    kind: mysql_values
    values:
      0: {kind: json, fields: {/changed_at: {relative_time: unix_microseconds}}}
  proof: {source: 'store.py:write_clock', fact: 'Source updates the Task audit clock for this write'}
"#.into()
}

fn payload(micros: i64) -> String {
    json!({"blocks":[{"id":"old","key":"content:old","stable":7}],"changed_at":micros,"stable":"checked"}).to_string()
}

#[tokio::test]
async fn mysql_identity_read_back_composes_json_time_delivery_and_finite_writes_over_tls() {
    tokio::time::timeout(Duration::from_secs(25),async {
        let mut capture = exchange("INSERT INTO blocks (name) VALUES ('old')",json!({"status":"ok","affected_rows":1}));
        let mut read = exchange("SELECT payload FROM results_0001 WHERE id=7",result(json!([{"name":"payload","column":"payload","table":"results_0001","family":"text","sql_type":"LONGTEXT","nullable":false}]),json!([[{"kind":"string","value":payload(1_577_836_801_000_000)}]])));
        read["timestamp"] = json!("2020-01-01T00:00:01Z");
        let mut write = exchange(&format!("UPDATE tasks SET payload='{}' WHERE id=7",payload(1_577_836_802_000_000)),json!({"status":"ok","affected_rows":1}));
        write["timestamp"] = json!("2020-01-01T00:00:02Z");
        for (index,record) in [&mut capture,&mut read,&mut write].into_iter().enumerate() {
            record["connection_id"] = json!("01234567-89ab-4def-8123-456789abcdef");
            record["query_sequence"] = json!(index+1);
        }
        let (temp,addr,runtime,task) = fixture_with_policy(&[capture,read,write],Some(&policy())).await;
        let case = temp.path().join(".traffic-e2e/local/recordings/case-id");
        let immutable = std::fs::read(case.join("dependencies.jsonl")).unwrap();
        let mut client = connect(addr,&case.join(".replay/ca.pem")).await;
        client.execute("INSERT INTO blocks (name) VALUES ('new')").await.unwrap();
        assert!(sqlx::query("SELECT payload FROM results_0001 WHERE id=?").bind(8_i64).fetch_one(&mut client).await.is_err());
        let row = sqlx::query("SELECT payload FROM results_0001 WHERE id=?").bind(7_i64).fetch_one(&mut client).await.unwrap();
        let mut value: Value = serde_json::from_str(row.get::<String,_>(0).as_str()).unwrap();
        assert_eq!(value["blocks"][0]["id"],"new");
        assert_eq!(value["blocks"][0]["key"],"content:new");
        assert_eq!(value["blocks"][0]["stable"],7);
        assert_eq!(value["stable"],"checked");
        assert!((value["changed_at"].as_i64().unwrap()-Utc::now().timestamp_micros()).abs()<5_000_000);
        value["changed_at"] = json!(Utc::now().timestamp_micros());
        for scenario in ["id","key","business","clock","predicate"] {
            let mut bad = value.clone();
            match scenario {
                "id" => bad["blocks"][0]["id"] = json!("old"),
                "key" => bad["blocks"][0]["key"] = json!("content:other"),
                "business" => bad["blocks"][0]["stable"] = json!(8),
                "clock" => bad["changed_at"] = json!(Utc::now().timestamp_micros()-10_000_000),
                _ => (),
            }
            assert!(sqlx::query("UPDATE tasks SET payload=? WHERE id=?").bind(bad.to_string()).bind(if scenario=="predicate" {8_i64}else{7_i64}).execute(&mut client).await.is_err(),"{scenario}");
        }
        assert_eq!(sqlx::query("UPDATE tasks SET payload=? WHERE id=?").bind(value.to_string()).bind(7_i64).execute(&mut client).await.unwrap().rows_affected(),1);
        assert!(sqlx::query("UPDATE tasks SET payload=? WHERE id=?").bind(value.to_string()).bind(7_i64).execute(&mut client).await.is_err());
        assert!(sqlx::query("SELECT payload FROM results_0001 WHERE id=?").bind(7_i64).fetch_one(&mut client).await.is_err());
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,3);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.mysql_identity_read_backs.len(),1);
        assert_eq!(report.dynamic_bindings.len(),1);
        assert_eq!(std::fs::read(case.join("dependencies.jsonl")).unwrap(),immutable);
        task.abort();
    }).await.expect("SQL identity read-back TLS flow timed out");
}
