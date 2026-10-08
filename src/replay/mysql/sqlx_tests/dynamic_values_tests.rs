//! Real TLS/prepared SQL and RESP share one case-local generated identity.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POLICY: &str = r#"
version: 3
expected_response: assertions_only
dependency_rules:
  - kind: dynamic_value
    id: generated-name
    api: /users
    targets:
      - {host: 127.0.0.1, port: 3306}
      - {host: redis.internal, port: 6379}
    capture:
      protocol: mysql
      target: {host: 127.0.0.1, port: 3306}
      database: appdb
      sql: SELECT count(*) FROM kinds WHERE name=?
      value_index: 0
    source_evidence: "NameFactory:create generates a random name reused in storage and cache keys"
  - id: created-at
    protocol: mysql
    mysql:
      database: appdb
      sql: INSERT INTO kinds(name,json,created_at) VALUES(?,?,?)
      sql_values: {2: {time: replay_now, tolerance: 5s}}
"#;

#[tokio::test]
async fn capture_then_sql_json_and_redis_key_preserve_fixed_values_times_and_consumption() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let redis = json!({"event_type":"redis_exchange", "connection_id":uuid::Uuid::new_v4(),
            "sequence":1,"target_host":"redis.internal","target_port":6379,"resp_version":2,
            "database":0,"command":"DEL","args":[{"encoding":"utf8","data":"cache:old-name:fixed"}],
            "response_kind":"integer","response":{"encoding":"utf8","data":":1\r\n"},"replay_safe":true});
        let records = [
            exchange("SELECT count(*) FROM kinds WHERE name='old-name'", result(
                json!([{"name":"count(*)","family":"integer","sql_type":"BIGINT"}]),
                json!([[{"kind":"integer","value":0}]]))),
            exchange("INSERT INTO kinds(name,json,created_at) VALUES('old-name','{\"name\":\"old-name\",\"stable\":1}','2020-01-01 00:00:00')", json!({"status":"ok","affected_rows":1})),
            redis,
        ];
        let (temp,_,runtime,task) = fixture_with_policy(&records,Some(POLICY)).await;
        task.abort();
        let (addr,mysql_task) = endpoint_listener(runtime.clone(),false).await;
        let dependencies = temp.path().join("case-id/dependencies.jsonl");
        let immutable = std::fs::read(&dependencies).unwrap();
        let mut client = connect(addr,&temp.path().join("case-id/.replay/ca.pem")).await;
        let count = sqlx::query("SELECT count(*) FROM kinds WHERE name=?").bind("new-name").fetch_one(&mut client).await.unwrap();
        assert_eq!(count.get::<i64,_>(0),0);
        let insert = "INSERT INTO kinds(name,json,created_at) VALUES(?,?,?)";
        let now = chrono::Utc::now().naive_utc();
        for payload in [r#"{"name":"wrong-name","stable":1}"#, r#"{"name":"new-name","stable":2}"#] {
            assert!(sqlx::query(insert).bind("new-name").bind(payload).bind(now).execute(&mut client).await.is_err());
        }
        assert_eq!(sqlx::query(insert).bind("new-name").bind(r#"{"stable":1,"name":"new-name"}"#).bind(now).execute(&mut client).await.unwrap().rows_affected(),1);
        assert!(sqlx::query(insert).bind("new-name").bind(r#"{"name":"new-name","stable":1}"#).bind(now).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let (redis_addr,redis_task) = endpoint_listener(runtime.clone(),true).await;
        let mut redis = tokio::net::TcpStream::connect(redis_addr).await.unwrap();
        for (key,expected) in [("other:new-name:fixed",b"-ERR no recorded Redis dependency matched\r\n".as_slice()),("cache:wrong-name:fixed",b"-ERR no recorded Redis dependency matched\r\n".as_slice()),("cache:new-name:fixed",b":1\r\n".as_slice()),("cache:new-name:fixed",b"-ERR no recorded Redis dependency matched\r\n".as_slice())] {
            redis.write_all(format!("*2\r\n$3\r\nDEL\r\n${}\r\n{key}\r\n",key.len()).as_bytes()).await.unwrap();
            let mut response = vec![0;expected.len()];
            redis.read_exact(&mut response).await.unwrap();
            assert_eq!(response,expected);
        }
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,2);
        assert_eq!(state.mysql.events.unmatched_queries.len(),3);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert_eq!(state.replay_policy.as_ref().unwrap().report().dependency_rules[0].time_validations,1);
        assert_eq!(std::fs::read(dependencies).unwrap(),immutable);
        mysql_task.abort(); redis_task.abort();
    }).await.expect("cross-protocol dynamic replay timed out");
}

async fn endpoint_listener(
    runtime: Arc<ReplayRuntime>,
    redis: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let runtime = runtime.clone();
            tokio::spawn(async move {
                if redis {
                    let target = runtime
                        .state
                        .lock()
                        .await
                        .targets
                        .iter()
                        .find(|target| target.port == 6379)
                        .unwrap()
                        .clone();
                    crate::replay::redis::handle_connection(stream, target, runtime.state.clone())
                        .await
                        .unwrap();
                } else {
                    crate::replay::mysql::handle_connection(
                        stream,
                        peer,
                        Some(TargetKey {
                            host: "127.0.0.1".into(),
                            port: 3306,
                        }),
                        runtime.state.clone(),
                        runtime.ca.clone(),
                    )
                    .await
                    .unwrap();
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn sql_time_planner_uses_only_committed_same_case_identity_proofs() {
    tokio::time::timeout(Duration::from_secs(20),async {
        let mut capture = exchange("SELECT count(*) FROM kinds WHERE name='old-name'",result(json!([{"name":"count(*)","family":"integer","sql_type":"BIGINT"}]),json!([[{"kind":"integer","value":0}]])));
        capture["parse_warnings"] = json!([]);
        let mut insert = exchange("INSERT INTO kinds(name,json,created_at) VALUES('old-name','{\"name\":\"old-name\",\"stable\":1}','2020-01-01 00:00:00')",json!({"status":"ok","affected_rows":1}));
        insert["parse_warnings"] = json!([]);
        let policy = POLICY.split("  - id: created-at").next().unwrap().to_owned();
        let (temp,addr,runtime,task) = fixture_with_policy(&[capture,insert],Some(&policy)).await;
        let mut client = connect(addr,&temp.path().join("case-id/.replay/ca.pem")).await;
        sqlx::query("SELECT count(*) FROM kinds WHERE name=?").bind("new-name").fetch_one(&mut client).await.unwrap();
        assert!(sqlx::query("INSERT INTO kinds(name,json,created_at) VALUES(?,?,?)").bind("new-name").bind(r#"{"stable":1,"name":"new-name"}"#).bind(chrono::Utc::now().naive_utc()).execute(&mut client).await.is_err());
        client.close().await.unwrap();
        let report = temp.path().join("replay.json");
        {
            let mut state = runtime.state.lock().await;state.finalized_at = Some(chrono::Utc::now());
            std::fs::write(&report,serde_json::to_vec(&state.snapshot_report()).unwrap()).unwrap();
        }
        let feedback = || crate::MysqlTimeRuleFeedback {
            policy_path:temp.path().join("policy.yaml"),replay_report_path:report.clone(),api:"GET /users".into(),rule_id:"insert-time".into(),
            selector: crate::MysqlTimeSelector {target_host:"127.0.0.1".into(),target_port:3306,database:"appdb".into(),username:"root".into(),sql:"INSERT INTO kinds(name,json,created_at) VALUES(?,?,?)".into(),time_values:vec![crate::MysqlTimeValueSelector {value_index:2,json_pointer:None,tolerance:"5s".into(),offset:"0s".into(),format:"%Y-%m-%d %H:%M:%S%.f".into(),timezone:"+00:00".into()}]},
            source_evidence:"Storage:create writes datetime.utcnow()".into(),
        };
        let bytes = std::fs::read(&report).unwrap();
        let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(tampered["replay_policy"]["dynamic_bindings"].as_array().unwrap().len(),1);
        tampered["replay_policy"]["dynamic_bindings"][0]["target_fingerprint"] = json!("invalid");
        std::fs::write(&report,tampered.to_string()).unwrap();
        assert!(crate::plan_mysql_time_rule(feedback()).is_err());
        std::fs::write(&report,bytes).unwrap();
        crate::plan_mysql_time_rule(feedback()).unwrap().apply().unwrap();
        assert!(std::fs::read_to_string(temp.path().join("policy.yaml")).unwrap().contains("insert-time"));
        task.abort();
    }).await.expect("SQL-time identity evidence test timed out");
}
