use super::*;
use sqlx::{Column, Executor};

fn rows(value: i64) -> Value {
    result(
        json!([
            {"name":"tasks_id","table":"tasks","column":"id","family":"integer","sql_type":"BIGINT"},
            {"name":"tasks_title","table":"tasks","column":"title","family":"string","sql_type":"VARCHAR"}
        ]),
        json!([[{"kind":"integer","value":value},{"kind":"string","value":"标题"}]]),
    )
}

#[tokio::test]
async fn sqlx_predicate_orders_match_all_protocol_pairs_and_cached_parameter_rebinding() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for policy in [false, true] {
            for source_prepared in [false, true] {
                for target_prepared in [false, true] {
                    let source = |tenant| {
                        let sql = if source_prepared {
                            "SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE tasks.tenant=? AND tasks.id IN (?,?,?) AND tasks.title IN (?,?) ORDER BY tasks_id LIMIT 1".to_owned()
                        } else {
                            format!("SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE tasks.tenant={tenant} AND tasks.id IN (3,1,2) AND tasks.title IN ('标题','AbC') ORDER BY tasks_id LIMIT 1")
                        };
                        let mut record = exchange(&sql, rows(tenant));
                        if source_prepared {
                            record["command"] = json!("COM_STMT_EXECUTE");
                            record["params"] = json!([
                                {"kind":"integer","value":tenant}, {"kind":"integer","value":3},
                                {"kind":"integer","value":1}, {"kind":"integer","value":2},
                                {"kind":"string","value":"标题"}, {"kind":"string","value":"AbC"}
                            ]);
                        }
                        record
                    };
                    let records = [source(7), source(8)];
                    let (temp, addr, runtime, task) = fixture(&records, policy).await;
                    let capture = temp.path().join("case-id/dependencies.jsonl");
                    let original = std::fs::read(&capture).unwrap();
                    let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
                    // The target uses its normal parameter binding, pool/session
                    // state, and column mapping. It never receives the fixture.
                    let target = "SELECT t.title AS title,t.id AS id FROM tasks t WHERE t.title IN (?,?) AND (t.id IN (?,?,?) AND t.tenant=?) ORDER BY id LIMIT 1";
                    let mut compiled = 0;
                    for (attempt, tenant) in [7_i64, 999, 8, 8].into_iter().enumerate() {
                        let response = if target_prepared {
                            sqlx::query(target).bind("AbC").bind("标题").bind(2_i64).bind(3_i64).bind(1_i64).bind(tenant).fetch_all(&mut client).await
                        } else {
                            let sql = format!("SELECT t.title AS title,t.id AS id FROM tasks t WHERE t.title IN ('AbC','标题') AND (t.id IN (2,3,1) AND t.tenant={tenant}) ORDER BY id LIMIT 1");
                            (&mut client).fetch_all(sql.as_str()).await
                        };
                        if attempt == 1 || attempt == 3 {
                            assert!(response.is_err(), "wrong values or exhausted evidence must fail");
                        } else {
                            let response = response.unwrap();
                            assert_eq!(response[0].columns().iter().map(|c| c.name()).collect::<Vec<_>>(), ["title", "id"]);
                            assert_eq!(response[0].get::<String, _>("title"), "标题");
                            assert_eq!(response[0].get::<i64, _>("id"), tenant);
                        }
                        let state = runtime.state.lock().await;
                        let now = state.mysql.sql_cache.compilations;
                        if target_prepared && attempt == 2 { assert_eq!(compiled, now, "cached SQL must be rebound without recompilation"); }
                        compiled = now;
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
    }).await.expect("SQLx predicate replay timed out");
}

#[tokio::test]
async fn predicate_cache_preserves_identity_case_precedence_and_finite_consumption() {
    let source = "SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE id IN (3,1,2) AND tenant=7";
    let exact = "SELECT tasks.id AS tasks_id,tasks.title AS tasks_title FROM tasks WHERE tenant=7 AND id IN (1,2,3)";
    let (_temp, _addr, runtime, task) = fixture(
        &[exchange(source, rows(1)), exchange(exact, rows(2))],
        false,
    )
    .await;
    let mut state = runtime.state.lock().await;
    let source = &state.mysql.exchanges[0].identity;
    let identity = ReplaySessionIdentity {
        target: Some(source.target.clone()),
        database: source.database.clone(),
        username: source.username.clone(),
    };
    // Warm the AST cache before testing isolation, including metadata lookups.
    let target = "SELECT id AS id,title AS title FROM tasks WHERE tenant=? AND id IN (?,?,?)";
    assert_eq!(state.statement_metadata(&identity, target).columns.len(), 2);
    for field in ["host", "port", "database", "username", "case"] {
        let mut wrong = identity.clone();
        match field {
            "host" => wrong.target.as_mut().unwrap().host = "other".into(),
            "port" => wrong.target.as_mut().unwrap().port = 3307,
            "database" => wrong.database = Some("other".into()),
            "username" => wrong.username = Some("other".into()),
            "case" => state.active_case_id = Some("other-case".into()),
            _ => unreachable!(),
        }
        assert!(
            state
                .match_exchange(&wrong, "COM_QUERY", Some(exact), None)
                .is_none(),
            "{field}"
        );
        assert!(
            state.statement_metadata(&wrong, target).columns.is_empty(),
            "{field}"
        );
        state.active_case_id = Some("case-id".into());
    }
    let matched = state
        .match_exchange(&identity, "COM_QUERY", Some(exact), None)
        .unwrap();
    assert_eq!(
        matched.index, 1,
        "exact candidate must precede semantic candidate"
    );
    state.complete_exchange(&matched);
    // Global exact matching must not outrank Case semantic matching.
    state.mysql.exchanges[1].source = ReplaySource::Global;
    state.mysql.exchanges[1].case_id = None;
    state.mysql.exchanges[1].status = ReplayExchangeStatus::Available;
    let matched = state
        .match_exchange(&identity, "COM_QUERY", Some(exact), None)
        .unwrap();
    assert_eq!(matched.index, 0);
    state.complete_exchange(&matched);
    let matched = state
        .match_exchange(&identity, "COM_QUERY", Some(exact), None)
        .unwrap();
    assert_eq!(matched.source, ReplaySource::Global);
    state.complete_exchange(&matched);
    assert!(
        state
            .match_exchange(&identity, "COM_QUERY", Some(exact), None)
            .is_none()
    );
    task.abort();
}

#[tokio::test]
async fn sqlx_predicate_prepare_keeps_fixed_values_and_execute_checks_remaining_values() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let sql = "SELECT id FROM tasks WHERE id IN (1,2,NULL) AND tenant=7";
        let response = result(
            json!([{"name":"id","family":"integer","sql_type":"BIGINT"}]),
            json!([[{"kind":"integer","value":1}]]),
        );
        let (temp, addr, runtime, task) = fixture(&[exchange(sql, response)], false).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let target = "SELECT id FROM tasks WHERE tenant=? AND id IN (?,1,NULL)";
        assert!(
            sqlx::query(target)
                .bind(7_i64)
                .bind(3_i64)
                .fetch_one(&mut client)
                .await
                .is_err()
        );
        let row = sqlx::query(target)
            .bind(7_i64)
            .bind(2_i64)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(row.get::<i64, _>(0), 1);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
        assert!(state.mysql.events.metadata_warnings.is_empty());
        task.abort();
    })
    .await
    .expect("SQLx partial IN list replay timed out");
}

#[tokio::test]
async fn predicate_equivalence_cannot_bypass_selected_dynamic_parameter_validation() {
    let sql = "SELECT id FROM tasks WHERE tenant=? AND id IN (?,?)";
    let mut record = exchange(
        sql,
        result(
            json!([{"name":"id","family":"integer","sql_type":"BIGINT"}]),
            json!([]),
        ),
    );
    record["command"] = json!("COM_STMT_EXECUTE");
    record["params"] = json!([{"kind":"integer","value":7}, {"kind":"integer","value":1}, {"kind":"integer","value":2}]);
    let (temp, _addr, runtime, task) = fixture(&[record], true).await;
    let policy_path = temp.path().join("checked-policy.yaml");
    crate::replay::write_policy_fixture(
        &policy_path,
        r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: validated-tenant
    protocol: mysql
    target:
      host: 127.0.0.1
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      database: appdb
      username: root
      sql: 'SELECT id FROM tasks WHERE tenant=? AND id IN (?,?)'
      params:
        0:
          bind: tenant_id
          validate: uuid_v4
"#,
    )
    .unwrap();
    let mut state = runtime.state.lock().await;
    state.replay_policy =
        Some(crate::replay::policy::ReplayPolicyRuntime::load(&policy_path, &state.cases).unwrap());
    let source = &state.mysql.exchanges[0].identity;
    let identity = ReplaySessionIdentity {
        target: Some(source.target.clone()),
        database: source.database.clone(),
        username: source.username.clone(),
    };
    let params = [
        mysql_json("integer", json!(7)),
        mysql_json("integer", json!(2)),
        mysql_json("integer", json!(1)),
    ];
    assert!(
        state
            .match_exchange(&identity, "COM_STMT_EXECUTE", Some(sql), Some(&params))
            .is_none()
    );
    assert!(state.mysql.exchanges[0].status.is_available());
    state.replay_policy = None;
    assert!(
        state
            .match_exchange(&identity, "COM_STMT_EXECUTE", Some(sql), Some(&params))
            .is_some()
    );
    task.abort();
}
