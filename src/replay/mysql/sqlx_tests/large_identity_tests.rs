//! Bound identities must not reduce the supported size of an otherwise exact write.
use super::*;
use sqlx::Executor;

const UPDATE: &str = "UPDATE attachments SET image=?, storage_key=?, status=? WHERE id=?";
const POLICY: &str = r#"format: traffic-policy/v3
rules:
- id: storage-key
  match:
    api: GET /users
    resource: {protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}
    operation: COM_QUERY
    sql: SELECT id FROM attachments WHERE storage_key=?
  effect:
    kind: identity
    value_type: string
    capture: {kind: mysql_value, index: 0}
    references:
    - resource: {protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}
  proof: {source: 'upload.py:allocate', fact: 'Source generates a fresh storage key and copies it to the ready write'}
"#;

#[tokio::test]
async fn large_identity_write_keeps_blob_status_predicate_and_consumption_exact() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let image = "a".repeat(580_000);
        for source_prepared in [false, true] {
            for target_prepared in [false, true] {
                let text = format!("UPDATE attachments SET image='{image}', storage_key='source-key', status='ready' WHERE id=7");
                let mut write = exchange(&text, json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(UPDATE);
                    write["params"] = json!([
                        {"kind":"string","value":image},
                        {"kind":"string","value":"source-key"},
                        {"kind":"string","value":"ready"},
                        {"kind":"integer","value":7}
                    ]);
                }
                let lookup = exchange("SELECT id FROM attachments WHERE storage_key='source-key'", result(
                    json!([{"name":"id","family":"integer","sql_type":"BIGINT"}]),json!([])));
                let (temp,addr,runtime,task) = fixture_with_policy(&[lookup,write],Some(POLICY)).await;
                let path=temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original=std::fs::read(&path).unwrap();
                let mut client=connect(addr,&path.parent().unwrap().join(".replay/ca.pem")).await;
                (&mut client).fetch_all("SELECT id FROM attachments WHERE storage_key='target-key'").await.unwrap();
                for attempt in 0..5 {
                    let image=if attempt==0 {format!("{}b",&image[..image.len()-1])} else {image.clone()};
                    let status=if attempt==1 {"failed"} else {"ready"};
                    let id=if attempt==2 {8_i64} else {7};
                    let result=if target_prepared {
                        sqlx::query(UPDATE).bind(&image).bind("target-key").bind(status).bind(id).execute(&mut client).await
                    } else {
                        client.execute(format!("UPDATE attachments SET image='{image}', storage_key='target-key', status='{status}' WHERE id={id}").as_str()).await
                    };
                    if attempt==3 {assert_eq!(result.unwrap().rows_affected(),1);} else {assert!(result.is_err());}
                }
                client.close().await.unwrap();
                let state=runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count,2);
                assert_eq!(state.mysql.events.unmatched_queries.len(),4);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                assert_eq!(std::fs::read(path).unwrap(),original);
                task.abort();
            }
        }
    }).await.unwrap();
}
