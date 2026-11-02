use super::*;
use sqlx::{Column, Executor};

#[tokio::test]
async fn sqlx_projects_orm_columns_for_text_and_cached_prepared_queries() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for policy in [false, true] {
            let response = result(json!([
                {"name":"subtasks_0640_id","table":"subtasks_0640","column":"id","family":"integer","sql_type":"BIGINT","unsigned":true},
                {"name":"subtasks_0640_unused","table":"subtasks_0640","column":"unused","family":"string","sql_type":"VARCHAR"},
                {"name":"subtasks_0640_title","table":"subtasks_0640","column":"title","family":"string","sql_type":"VARCHAR"},
                {"name":"subtasks_0640_missing","table":"subtasks_0640","column":"missing","family":"string","sql_type":"VARCHAR"},
                {"name":"subtasks_0640_payload","table":"subtasks_0640","column":"payload","family":"binary","sql_type":"VARBINARY"}
            ]), json!([[{"kind":"integer","value":18446744073709551615_u64},
                {"kind":"string","value":"unused"}, {"kind":"string","value":"AbC 中文"},
                {"kind":"null"}, {"kind":"bytes","raw":{"encoding":"base64","data":"AP8="}}]]));
            let source_sql = |id| format!("SELECT subtasks_0640.id AS subtasks_0640_id, subtasks_0640.unused AS subtasks_0640_unused, subtasks_0640.title AS subtasks_0640_title, subtasks_0640.missing AS subtasks_0640_missing, subtasks_0640.payload AS subtasks_0640_payload FROM subtasks_0640 WHERE subtasks_0640.id={id} ORDER BY subtasks_0640_id DESC LIMIT 1");
            let mut empty = response.clone();
            empty["rows"] = json!([]);
            let records = [exchange(&source_sql(1), response.clone()), exchange(&source_sql(2), empty), exchange(&source_sql(3), response)];
            let (temp, addr, runtime, task) = fixture(&records, policy).await;
            let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
            let original = std::fs::read(&path).unwrap();
            let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
            let sql = "SELECT t.payload AS data, t.missing AS optional, t.id AS task_id, t.title AS title FROM subtasks_0640 AS t WHERE t.id=? ORDER BY task_id DESC LIMIT 1";
            let row = sqlx::query(sql).bind(1_u64).fetch_one(&mut client).await.unwrap();
            assert_eq!(row.columns().iter().map(|c| c.name()).collect::<Vec<_>>(), ["data", "optional", "task_id", "title"]);
            assert_eq!(row.get::<Vec<u8>, _>(0), [0, 255]);
            assert_eq!(row.get::<Option<String>, _>(1), None);
            assert_eq!(row.get::<u64, _>("task_id"), u64::MAX);
            assert_eq!(row.get::<String, _>("title"), "AbC 中文");
            assert!(sqlx::query(sql).bind(2_u64).fetch_optional(&mut client).await.unwrap().is_none());
            // Executor on a bare str exercises COM_QUERY rather than SQLx prepare.
            let rows = (&mut client).fetch_all("SELECT title AS heading, id AS task_id FROM subtasks_0640 WHERE id=3 ORDER BY task_id DESC LIMIT 1").await.unwrap();
            assert_eq!(rows[0].columns().len(), 2);
            assert_eq!(rows[0].get::<String, _>("heading"), "AbC 中文");
            assert_eq!(rows[0].get::<u64, _>(1), u64::MAX);
            client.close().await.unwrap();
            let state = runtime.state.lock().await;
            assert_eq!(state.mysql.events.matched_query_count, 3);
            assert_eq!(state.mysql.events.matched_queries.iter().map(|q| q.command.as_str()).collect::<Vec<_>>(), ["COM_STMT_EXECUTE", "COM_STMT_EXECUTE", "COM_QUERY"]);
            assert!(state.mysql.events.unmatched_queries.is_empty());
            assert!(state.mysql.events.metadata_warnings.is_empty());
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.mysql.exchanges[0].record.response.columns.len(), 5);
            assert_eq!(std::fs::read(path).unwrap(), original);
            task.abort();
        }
    }).await.expect("SQLx projection replay timed out");
}

#[tokio::test]
async fn sqlx_count_and_constant_aliases_preserve_values_and_conditions() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let value = |name, number| {
            result(
                json!([{"name":name,"family":"integer","sql_type":"BIGINT"}]),
                json!([[{"kind":"integer","value":number}]]),
            )
        };
        let records = [
            exchange(
                "SELECT COUNT(*) AS n FROM tasks WHERE status='RUNNING'",
                value("n", 42),
            ),
            exchange(
                "SELECT 1 AS present FROM tasks WHERE id=1 LIMIT 1",
                value("present", 1),
            ),
            exchange(
                "SELECT COUNT(*) FROM tasks WHERE id=2",
                value("COUNT(*)", 7),
            ),
        ];
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        for invalid in [
            "SELECT COUNT(*) AS total FROM tasks WHERE status='DONE'",
            "SELECT COUNT(id) AS total FROM tasks WHERE status='RUNNING'",
            "SELECT id AS total FROM tasks WHERE status='RUNNING'",
            "SELECT 2 AS present FROM tasks WHERE id=1 LIMIT 1",
        ] {
            assert!((&mut client).fetch_all(invalid).await.is_err(), "{invalid}");
            client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
        }
        let count = sqlx::query("SELECT count(*) AS total FROM tasks t WHERE t.status=?")
            .bind("RUNNING")
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(count.get::<i64, _>("total"), 42);
        let present = (&mut client)
            .fetch_all("SELECT 1 FROM tasks t WHERE t.id=1 LIMIT 1")
            .await
            .unwrap();
        assert_eq!(present[0].get::<i64, _>("1"), 1);
        let count = sqlx::query("SELECT count(*) FROM tasks WHERE id=?")
            .bind(2_u64)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(count.get::<i64, _>("count(*)"), 7);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.unmatched_queries.len(), 4);
        assert_eq!(state.mysql.events.matched_query_count, 3);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        task.abort();
    })
    .await
    .expect("SQLx expression replay timed out");
}

#[tokio::test]
async fn projection_keeps_scope_identity_exact_precedence_and_single_consumption() {
    let response = |names: &[&str]| {
        result(
            json!(
                names
                    .iter()
                    .map(|name| json!({"name":name,"family":"integer","sql_type":"BIGINT"}))
                    .collect::<Vec<_>>()
            ),
            json!([]),
        )
    };
    let sql = "SELECT id FROM tasks WHERE uid=1";
    let records = [
        exchange(
            "SELECT id AS tasks_id, uid FROM tasks WHERE uid=1",
            response(&["tasks_id", "uid"]),
        ),
        exchange(sql, response(&["id"])),
    ];
    let (_temp, _addr, runtime, task) = fixture(&records, false).await;
    let mut state = runtime.state.lock().await;
    let source = &state.mysql.exchanges[0].identity;
    let identity = ReplaySessionIdentity {
        target: Some(source.target.clone()),
        database: source.database.clone(),
        username: source.username.clone(),
    };
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
                .match_exchange(&wrong, "COM_QUERY", Some(sql), None)
                .is_none(),
            "{field}"
        );
        assert!(
            state
                .statement_metadata(&wrong, "SELECT id AS alias FROM tasks WHERE uid=?")
                .columns
                .is_empty(),
            "{field}"
        );
        state.active_case_id = Some("case-id".into());
    }
    let exact = state
        .match_exchange(&identity, "COM_QUERY", Some(sql), None)
        .unwrap();
    assert_eq!(exact.index, 1);
    assert!(exact.claim.publish_wire());
    assert!(state.complete_exchange(&exact));
    let projected = state
        .match_exchange(&identity, "COM_QUERY", Some(sql), None)
        .unwrap();
    assert_eq!(projected.index, 0);
    assert_eq!(projected.record.response.columns.len(), 1);
    assert!(projected.claim.publish_wire());
    assert!(state.complete_exchange(&projected));
    assert!(
        state
            .match_exchange(&identity, "COM_QUERY", Some(sql), None)
            .is_none()
    );
    assert_eq!(state.mysql.events.matched_query_count, 2);
    // A Global candidate remains available across cases, and is still finite.
    state.mysql.exchanges[0].source = ReplaySource::Startup;
    state.mysql.exchanges[0].case_id = None;
    state.mysql.invalidate_scope_index();
    state.mysql.exchanges[0].status = ReplayExchangeStatus::Available;
    state.active_case_id = Some("other-case".into());
    let global = state
        .match_exchange(&identity, "COM_QUERY", Some(sql), None)
        .unwrap();
    assert_eq!(global.source, ReplaySource::Startup);
    assert!(global.claim.publish_wire());
    assert!(state.complete_exchange(&global));
    assert!(
        state
            .match_exchange(&identity, "COM_QUERY", Some(sql), None)
            .is_none()
    );
    state.mysql.exchanges[0].status = ReplayExchangeStatus::Available;
    state.mysql.exchanges[0].record.command = "COM_STMT_EXECUTE".into();
    state.mysql.exchanges[0].record.sql =
        Some("SELECT id AS tasks_id, uid FROM tasks WHERE uid=?".into());
    state.mysql.exchanges[0].record.params = Some(vec![mysql_json("integer", json!(1))]);
    let prepared = "SELECT id FROM tasks WHERE uid=?";
    assert!(
        state
            .match_exchange(
                &identity,
                "COM_STMT_EXECUTE",
                Some(prepared),
                Some(&[mysql_json("integer", json!(2))])
            )
            .is_none()
    );
    let rebound = state
        .match_exchange(
            &identity,
            "COM_STMT_EXECUTE",
            Some(prepared),
            Some(&[mysql_json("integer", json!(1))]),
        )
        .unwrap();
    assert_eq!(rebound.record.response.columns.len(), 1);
    assert!(rebound.claim.publish_wire());
    assert!(state.complete_exchange(&rebound));
    task.abort();
}
