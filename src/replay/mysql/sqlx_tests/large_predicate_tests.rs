use super::*;
use sqlx::Executor;

fn id_result() -> Value {
    result(
        json!([{"name":"kinds_id","table":"kinds","column":"id","family":"integer","sql_type":"BIGINT"}]),
        json!([[{"kind":"integer","value":7}]]),
    )
}

#[tokio::test]
async fn large_or_with_empty_names_uses_real_prepare_execute_and_projection_mapping() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for policy in [false, true] {
            for source_prepared in [false, true] {
                for target_prepared in [false, true] {
                    // 79 groups, including an empty name and a repeated row.
                    let rows = (0..79).map(|i| {
                        let i = i.min(77);
                        (i as i64, if i == 0 { String::new() } else { format!("n{i}") })
                    }).collect::<Vec<_>>();
                    let source_groups = rows.iter().map(|(id,name)| {
                        if source_prepared { "kinds.user_id=? AND kinds.name=? AND kinds.namespace=?".to_owned() }
                        else { format!("kinds.user_id={id} AND kinds.name='{name}' AND kinds.namespace='default'") }
                    }).collect::<Vec<_>>().join(" OR ");
                    let kind = if source_prepared { "?" } else { "'Model'" };
                    let source_sql = format!("SELECT kinds.id AS kinds_id FROM kinds WHERE kinds.kind={kind} AND kinds.is_active IS true AND ({source_groups})");
                    let mut record = exchange(&source_sql, id_result());
                    if source_prepared {
                        record["command"] = json!("COM_STMT_EXECUTE");
                        let mut params = vec![mysql_json("string", json!("Model"))];
                        for (id,name) in &rows {
                            params.extend([mysql_json("integer", json!(id)),mysql_json("string", json!(name)),mysql_json("string", json!("default"))]);
                        }
                        record["params"] = serde_json::to_value(params).unwrap();
                    }
                    let (temp, addr, runtime, task) = fixture(&[record], policy).await;
                    let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                    let original = std::fs::read(&path).unwrap();
                    let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                    for attempt in 0..3 {
                        // First execution substitutes NULL for the empty string;
                        // a later correct execution must still use this evidence.
                        let target_groups = rows.iter().rev().map(|(id,name)| {
                            if target_prepared { "k.name=? AND k.namespace=? AND k.user_id=?".to_owned() }
                            else { let name = if attempt == 0 && name.is_empty() { "NULL".to_owned() } else { format!("'{name}'") };
                                format!("k.name={name} AND k.namespace='default' AND k.user_id={id}") }
                        }).collect::<Vec<_>>().join(" OR ");
                        let kind = if target_prepared { "?" } else { "'Model'" };
                        let target_sql = format!("SELECT k.id AS id FROM kinds k WHERE k.kind={kind} AND k.is_active IS TRUE AND ({target_groups})");
                        let response = if target_prepared {
                            let mut query = sqlx::query(&target_sql).bind("Model");
                            for (id,name) in rows.iter().rev() {
                                let name = if attempt == 0 && name.is_empty() { None } else { Some(name.as_str()) };
                                query = query.bind(name).bind("default").bind(*id);
                            }
                            query.fetch_all(&mut client).await
                        } else { (&mut client).fetch_all(target_sql.as_str()).await };
                        if attempt == 1 { assert_eq!(response.unwrap()[0].get::<i64,_>("id"),7); }
                        else { assert!(response.is_err(), "wrong value or exhausted evidence"); }
                    }
                    client.close().await.unwrap();
                    let state = runtime.state.lock().await;
                    assert_eq!(state.mysql.events.matched_query_count,1);
                    assert_eq!(state.mysql.events.unmatched_queries.len(),2);
                    assert!(state.mysql.events.metadata_warnings.is_empty(), "{:?}",state.mysql.events.metadata_warnings);
                    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                    assert_eq!(std::fs::read(path).unwrap(),original);
                    task.abort();
                }
            }
        }
    }).await.expect("large OR SQLx replay timed out");
}

#[tokio::test]
async fn five_tuple_in_with_is_true_matches_literal_and_bound_prepared_statements() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for bound in [false,true] {
            let source = "SELECT kinds.id AS kinds_id FROM kinds WHERE kinds.kind='Team' AND (kinds.name,kinds.namespace,kinds.user_id) IN (('深度研究','default',3780),('knowledge','default',0),('chat','default',0),('个案策划','default',3529),('task','default',0)) AND kinds.is_active IS true";
            let (temp,addr,runtime,task) = fixture(&[exchange(source,id_result())],false).await;
            let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
            let row = if bound {
                sqlx::query("SELECT id FROM kinds WHERE is_active IS TRUE AND (name,namespace,user_id) IN ((?,?,?),(?,?,?),(?,?,?),(?,?,?),(?,?,?)) AND kind=?")
                    .bind("chat").bind("default").bind(0_i64)
                    .bind("个案策划").bind("default").bind(3529_i64)
                    .bind("深度研究").bind("default").bind(3780_i64)
                    .bind("knowledge").bind("default").bind(0_i64)
                    .bind("task").bind("default").bind(0_i64).bind("Team")
                    .fetch_one(&mut client).await.unwrap()
            } else {
                // The reported failure is EXECUTE with inline literals and no parameters.
                sqlx::query("SELECT id FROM kinds WHERE kind='Team' AND (name,namespace,user_id) IN (('chat','default',0),('个案策划','default',3529),('深度研究','default',3780),('knowledge','default',0),('task','default',0)) AND is_active IS TRUE")
                    .fetch_one(&mut client).await.unwrap()
            };
            assert_eq!(row.get::<i64,_>("id"),7);
            client.close().await.unwrap();
            let state=runtime.state.lock().await;
            assert!(state.mysql.events.unmatched_queries.is_empty());
            assert!(state.mysql.events.metadata_warnings.is_empty());
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            task.abort();
        }
    }).await.expect("five-tuple IS TRUE SQLx replay timed out");
}
