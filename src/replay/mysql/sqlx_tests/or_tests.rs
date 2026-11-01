use super::*;
use sqlx::Executor;

#[tokio::test]
async fn sqlx_or_groups_match_all_protocol_pairs_with_aliases_tuples_and_cached_rebinding() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for policy in [false, true] {
            for source_prepared in [false, true] {
                for target_prepared in [false, true] {
                    let source = |tenant: i64| {
                        let sql = if source_prepared {
                            "SELECT DISTINCT teams.id AS teams_id FROM teams WHERE teams.tenant=? AND ((teams.namespace=? AND teams.name=?) OR (teams.namespace=? AND teams.name=?) OR (teams.namespace,teams.name) IN ((?,?),(?,?)))".to_owned()
                        } else {
                            format!("SELECT DISTINCT teams.id AS teams_id FROM teams WHERE teams.tenant={tenant} AND ((teams.namespace='default' AND teams.name='a') OR (teams.namespace='shared' AND teams.name='b') OR (teams.namespace,teams.name) IN (('x','c'),('y','d')))")
                        };
                        let mut record = exchange(&sql, result(
                            json!([{"name":"teams_id","table":"teams","column":"id","family":"integer","sql_type":"BIGINT"}]),
                            json!([[{"kind":"integer","value":tenant}]]),
                        ));
                        if source_prepared {
                            record["command"] = json!("COM_STMT_EXECUTE");
                            let mut params = vec![mysql_json("integer", json!(tenant))];
                            params.extend(["default", "a", "shared", "b", "x", "c", "y", "d"].map(|v| mysql_json("string", json!(v))));
                            record["params"] = serde_json::to_value(params).unwrap();
                        }
                        record
                    };
                    let (temp, addr, runtime, task) = fixture(&[source(7), source(8)], policy).await;
                    let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                    let original = std::fs::read(&path).unwrap();
                    let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                    let target = "SELECT DISTINCT t.id AS id FROM teams t WHERE ((t.namespace,t.name) IN ((?,?),(?,?)) OR (t.name=? AND t.namespace=?) OR (t.name=? AND t.namespace=?)) AND t.tenant=?";
                    let mut compiled = 0;
                    for (attempt, tenant, name) in [(0,7,"b"), (1,8,"wrong"), (2,8,"b"), (3,8,"b")] {
                        let response = if target_prepared {
                            sqlx::query(target).bind("y").bind("d").bind("x").bind("c").bind(name).bind("shared").bind("a").bind("default").bind(tenant as i64).fetch_all(&mut client).await
                        } else {
                            let sql = format!("SELECT DISTINCT t.id AS id FROM teams t WHERE ((t.namespace,t.name) IN (('y','d'),('x','c')) OR (t.name='{name}' AND t.namespace='shared') OR (t.name='a' AND t.namespace='default')) AND t.tenant={tenant}");
                            (&mut client).fetch_all(sql.as_str()).await
                        };
                        if attempt == 1 || attempt == 3 {
                            assert!(response.is_err(), "wrong branch values and exhausted recordings must fail");
                            client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                        } else {
                            assert_eq!(response.unwrap()[0].get::<i64, _>("id"), tenant as i64);
                        }
                        let now = runtime.state.lock().await.mysql.sql_cache.compilations;
                        // The failed lookup also warms remaining source SQL.
                        if target_prepared && attempt > 1 {
                            assert_eq!(now, compiled, "cached template must rebind every execution");
                        }
                        compiled = now;
                    }
                    client.close().await.unwrap();
                    let state = runtime.state.lock().await;
                    assert_eq!(state.mysql.events.matched_query_count, 2);
                    assert_eq!(state.mysql.events.unmatched_queries.len(), 2);
                    assert!(state.mysql.events.metadata_warnings.is_empty(), "{:?}", state.mysql.events.metadata_warnings);
                    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                    assert_eq!(std::fs::read(path).unwrap(), original);
                    task.abort();
                }
            }
        }
    }).await.expect("OR protocol compatibility timed out");
}

#[tokio::test]
async fn sqlx_nested_exists_in_lists_match_text_recording_with_prepared_target() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let source = "SELECT kinds.id AS kinds_id FROM kinds \
            WHERE kinds.id IN (3,1,2) AND (\
              coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = '' \
              OR EXISTS (SELECT 1 FROM resource_members \
                WHERE resource_members.resource_id = kinds.id \
                  AND resource_members.entity_id IN ('dept-b','dept-a') \
                  AND resource_members.role IN ('Owner','Maintainer','Developer'))\
            )";
        let record = exchange(
            source,
            result(
                json!([{"name":"kinds_id","table":"kinds","column":"id","family":"integer","sql_type":"BIGINT"}]),
                json!([[{"kind":"integer","value":77}]]),
            ),
        );
        let (temp, addr, runtime, task) = fixture(&[record], false).await;
        let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let target = "SELECT kinds.id AS kinds_id FROM kinds \
            WHERE kinds.id IN (?,?,?) AND (\
              coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = '' \
              OR EXISTS (SELECT 1 FROM resource_members \
                WHERE resource_members.resource_id = kinds.id \
                  AND resource_members.entity_id IN (?,?) \
                  AND resource_members.role IN ('Developer','Owner','Maintainer'))\
            )";
        let wrong = sqlx::query(target)
            .bind(2_i64)
            .bind(3_i64)
            .bind(1_i64)
            .bind("dept-a")
            .bind("dept-c")
            .fetch_all(&mut client)
            .await;
        assert!(wrong.is_err());
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let rows = sqlx::query(target)
            .bind(2_i64)
            .bind(3_i64)
            .bind(1_i64)
            .bind("dept-a")
            .bind("dept-b")
            .fetch_all(&mut client)
            .await
            .unwrap();
        assert_eq!(rows[0].get::<i64, _>("kinds_id"), 77);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        task.abort();
    })
    .await
    .expect("nested EXISTS IN replay timed out");
}
