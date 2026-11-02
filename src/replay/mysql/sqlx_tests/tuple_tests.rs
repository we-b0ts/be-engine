use super::*;
use sqlx::{Column, Executor};

#[tokio::test]
async fn sqlx_tuple_in_matches_all_protocol_pairs_with_projection_and_fresh_bindings() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for policy in [false, true] {
            for source_prepared in [false, true] {
                for target_prepared in [false, true] {
                    let source = |tenant| {
                        let sql = if source_prepared {
                            "SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE tasks.tenant=? AND (tasks.kind,tasks.namespace) IN ((?,?),(?,?),(?,?)) ORDER BY tasks_id LIMIT 1".to_owned()
                        } else {
                            format!("SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE tasks.tenant={tenant} AND (tasks.kind,tasks.namespace) IN ((3,'C'),(1,'A'),(2,'B')) ORDER BY tasks_id LIMIT 1")
                        };
                        let mut record = exchange(&sql, result(
                            json!([
                                {"name":"tasks_id","table":"tasks","column":"id","family":"integer","sql_type":"BIGINT"},
                                {"name":"tasks_title","table":"tasks","column":"title","family":"string","sql_type":"VARCHAR"}
                            ]),
                            json!([[{"kind":"integer","value":tenant},{"kind":"string","value":"标题"}]])));
                        if source_prepared {
                            record["command"] = json!("COM_STMT_EXECUTE");
                            record["params"] = json!([
                                {"kind":"integer","value":tenant},
                                {"kind":"integer","value":3}, {"kind":"string","value":"C"},
                                {"kind":"integer","value":1}, {"kind":"string","value":"A"},
                                {"kind":"integer","value":2}, {"kind":"string","value":"B"}
                            ]);
                        }
                        record
                    };
                    let (temp, addr, runtime, task) = fixture(&[source(7), source(8)], policy).await;
                    let capture = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                    let original = std::fs::read(&capture).unwrap();
                    let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                    let target = "SELECT t.title AS title,t.id AS id FROM tasks t WHERE (t.kind,t.namespace) IN ((?,?),(?,?),(?,?)) AND t.tenant=? ORDER BY id LIMIT 1";
                    let mut compilations = 0;
                    for (attempt, tenant) in [7_i64,999,8,8].into_iter().enumerate() {
                        let response = if target_prepared {
                            sqlx::query(target).bind(2_i64).bind("B").bind(3_i64).bind("C")
                                .bind(1_i64).bind("A").bind(tenant).fetch_all(&mut client).await
                        } else {
                            let sql = format!("SELECT t.title AS title,t.id AS id FROM tasks t WHERE (t.kind,t.namespace) IN ((2,'B'),(3,'C'),(1,'A')) AND t.tenant={tenant} ORDER BY id LIMIT 1");
                            (&mut client).fetch_all(sql.as_str()).await
                        };
                        if attempt == 1 || attempt == 3 {
                            assert!(response.is_err(), "wrong values and exhausted evidence must fail");
                            client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                        } else {
                            let response = response.unwrap();
                            assert_eq!(response[0].columns().iter().map(|c| c.name()).collect::<Vec<_>>(), ["title","id"]);
                            assert_eq!(response[0].get::<String,_>("title"), "标题");
                            assert_eq!(response[0].get::<i64,_>("id"), tenant);
                        }
                        let count = runtime.state.lock().await.mysql.sql_cache.compilations;
                        if target_prepared && attempt == 2 { assert_eq!(count, compilations); }
                        compilations = count;
                    }
                    client.close().await.unwrap();
                    let state = runtime.state.lock().await;
                    assert_eq!(state.mysql.events.matched_query_count, 2);
                    assert_eq!(state.mysql.events.unmatched_queries.len(), 2);
                    assert!(state.mysql.events.metadata_warnings.is_empty(), "{:?}", state.mysql.events.metadata_warnings);
                    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                    assert_eq!(std::fs::read(capture).unwrap(), original);
                    task.abort();
                }
            }
        }
    }).await.expect("SQLx tuple IN replay timed out");
}

#[tokio::test]
async fn sqlx_tuple_prepare_is_injective_and_execute_checks_row_pairing() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let source = "SELECT id FROM tasks WHERE tenant=7 AND (kind,uid) IN ((1,2),(3,2))";
        let record = exchange(
            source,
            result(
                json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                json!([[{"kind":"integer","value":1}]]),
            ),
        );
        let (temp, addr, runtime, task) = fixture(&[record], true).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let target = "SELECT id FROM tasks WHERE (kind,uid) IN ((?,2),(1,?)) AND tenant=?";
        assert!(
            sqlx::query(target)
                .bind(1_i32)
                .bind(3_i32)
                .bind(7_i32)
                .fetch_one(&mut client)
                .await
                .is_err()
        );
        client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let row = sqlx::query(target)
            .bind(3_i32)
            .bind(2_i32)
            .bind(7_i32)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(row.get::<i32, _>(0), 1);
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
        assert!(state.mysql.events.metadata_warnings.is_empty());
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sqlx_workspace_reference_tuples_match_nine_and_eighteen_row_permutations() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for count in [9,18] {
            let tuples = (0..count).map(|i| format!("(7,'default','workspace-{i}')")).collect::<Vec<_>>().join(",");
            let source = format!("SELECT id FROM task_resources_0007 WHERE kind='Workspace' AND is_active=1 AND (user_id,namespace,name) IN ({tuples})");
            let record = exchange(&source, result(
                json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                json!([[{"kind":"integer","value":42}]])));
            let (temp,addr,runtime,task) = fixture(&[record], true).await;
            let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
            let target = format!("SELECT id FROM task_resources_0007 WHERE kind=? AND is_active=? AND (user_id,namespace,name) IN ({})", vec!["(?,?,?)";count].join(","));
            let mut query = sqlx::query(&target).bind("Workspace").bind(1_i32);
            for i in (0..count).rev() {
                query = query.bind(7_i32).bind("default").bind(format!("workspace-{i}"));
            }
            let row = query.fetch_one(&mut client).await.unwrap();
            assert_eq!(row.get::<i32,_>(0), 42);
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert!(state.mysql.events.metadata_warnings.is_empty());
            task.abort();
        }
    }).await.unwrap();
}
