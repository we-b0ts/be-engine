//! Driver controls retain finite recorded failures before builtin responses.
use super::*;

async fn assert_recorded_control_failure(sql: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        for policy in [false, true] {
            let records = [
                exchange(
                    "SELECT id FROM unrelated_business WHERE id=7",
                    result(
                        json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                        json!([[{"kind":"integer","value":7}]]),
                    ),
                ),
                exchange(
                    sql,
                    json!({"status":"error","error_code":1644,
                        "error_message":"finite recorded control failure"}),
                ),
            ];
            let (temp, address, runtime, task) = fixture(&records, policy).await;
            let ca = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
            let mut client = connect(address, &ca).await;
            assert_eq!(
                runtime
                    .state
                    .lock()
                    .await
                    .protocols
                    .mysql
                    .events
                    .matched_query_count,
                0
            );

            let error = sqlx::raw_sql(sql).execute(&mut client).await.unwrap_err();
            let database = error
                .as_database_error()
                .unwrap()
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>();
            assert_eq!(database.number(), 1644, "{sql}, policy={policy}");
            assert_eq!(database.message(), "finite recorded control failure");
            client.close().await.unwrap();

            let state = runtime.state.lock().await;
            assert!(state.protocols.mysql.exchanges[1].status.is_consumed());
            assert!(state.protocols.mysql.exchanges[0].status.is_available());
            assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
            assert!(state.protocols.mysql.events.unmatched_queries.is_empty());
            assert!(
                state
                    .protocols
                    .mysql
                    .events
                    .builtin_queries
                    .iter()
                    .all(|query| {
                        query.sql.as_deref().map(normalize_sql) != Some(normalize_sql(sql))
                    })
            );
            task.abort();
        }
    })
    .await
    .expect("recorded control failure test timed out");
}

#[tokio::test]
async fn recorded_begin_error_is_consumed_before_builtin_success() {
    assert_recorded_control_failure("BEGIN").await;
}

#[tokio::test]
async fn recorded_setup_error_is_consumed_before_builtin_success() {
    assert_recorded_control_failure("SET NAMES utf8mb4").await;
}

#[tokio::test]
async fn ordinary_commit_only_associates_same_end_evidence() {
    let mut rollback = exchange("ROLLBACK", json!({"status":"ok"}));
    rollback["connection_id"] = json!(uuid::Uuid::new_v4());
    rollback["query_sequence"] = json!(1);
    let mut commit = exchange("COMMIT", json!({"status":"ok"}));
    commit["connection_id"] = json!(uuid::Uuid::new_v4());
    commit["query_sequence"] = json!(2);
    let (temp, address, runtime, task) = fixture_with_policy(
        &[rollback, commit],
        Some("format: traffic-policy/v3\nrules: []\n"),
    )
    .await;
    let ca = temp
        .path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
    let mut client = connect(address, &ca).await;
    sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
    client.close().await.unwrap();
    let state = runtime.state.lock().await;
    assert!(state.protocols.mysql.exchanges[0].status.is_available());
    assert!(state.protocols.mysql.exchanges[1].status.is_consumed());
    let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
    owner.seal_witnesses().unwrap();
    let witnesses = owner.witness_manifest().unwrap().witnesses().unwrap();
    let sequences = witnesses
        .iter()
        .filter_map(|witness| {
            (witness.metadata.surface == crate::policy::Surface::DependencyRequest
                && witness.target_sha256.is_some())
            .then_some(witness.metadata.source.sequence)
            .flatten()
        })
        .collect::<Vec<_>>();
    assert_eq!(sequences, [2]);
    task.abort();
}

#[tokio::test]
async fn recorded_prepare_failure_takes_precedence_over_cached_metadata() {
    let sql = "SELECT id FROM tasks WHERE id=?";
    let mut failure = exchange(
        sql,
        json!({"status":"error","error_code":1644,
        "error_message":"recorded prepare failure"}),
    );
    failure["command"] = json!("COM_STMT_PREPARE");
    let (temp, address, runtime, task) = fixture(&[failure], false).await;
    let ca = temp
        .path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
    let mut client = connect(address, &ca).await;
    let error = sqlx::query(sql)
        .bind(1_i64)
        .fetch_one(&mut client)
        .await
        .unwrap_err();
    let database = error
        .as_database_error()
        .unwrap()
        .downcast_ref::<sqlx::mysql::MySqlDatabaseError>();
    assert_eq!(database.number(), 1644);
    assert!(
        runtime.state.lock().await.protocols.mysql.exchanges[0]
            .status
            .is_consumed()
    );
    task.abort();
}

#[tokio::test]
async fn first_pass_accepts_in_list_order_without_reordering_boolean_terms() {
    let records = [
        "SELECT id FROM tasks WHERE name IN ('A','B','C') AND (flag=1 OR flag=2)",
        "SELECT id FROM tasks WHERE (flag=2 OR flag=1) AND name IN ('C','B','A')",
        "SELECT id FROM tasks WHERE (flag=2 OR flag=1) AND name IN ('A','B','C')",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, sql)| {
        let mut record = exchange(
            sql,
            result(
                json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                json!([[{"kind":"integer","value":index}]]),
            ),
        );
        record["connection_id"] = json!(uuid::Uuid::new_v4());
        record["query_sequence"] = json!(index + 1);
        record
    })
    .collect::<Vec<_>>();
    let (temp, address, runtime, task) = fixture(&records, false).await;
    let ca = temp
        .path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
    let mut client = connect(address, &ca).await;
    let row = sqlx::query("SELECT id FROM tasks WHERE (flag=2 OR flag=1) AND name IN (?,?,?)")
        .bind("A")
        .bind("B")
        .bind("C")
        .fetch_one(&mut client)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), 1);
    client.close().await.unwrap();
    let state = runtime.state.lock().await;
    assert!(state.protocols.mysql.exchanges[0].status.is_available());
    assert!(state.protocols.mysql.exchanges[1].status.is_consumed());
    assert!(state.protocols.mysql.exchanges[2].status.is_available());
    task.abort();
}

#[tokio::test]
async fn proven_cross_table_select_is_filtered_before_request_evidence() {
    let records = [
        "SELECT id FROM different_table WHERE id=7",
        "SELECT id FROM first_table UNION SELECT id FROM second_table",
        "SELECT id FROM requested_table WHERE id=7",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, sql)| {
        let mut record = exchange(
            sql,
            result(
                json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                json!([[{"kind":"integer","value":7}]]),
            ),
        );
        record["connection_id"] = json!(uuid::Uuid::new_v4());
        record["query_sequence"] = json!(index + 1);
        record
    })
    .collect::<Vec<_>>();
    let (temp, address, runtime, task) =
        fixture_with_policy(&records, Some("format: traffic-policy/v3\nrules: []\n")).await;
    let ca = temp
        .path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
    let mut client = connect(address, &ca).await;
    let row = sqlx::query("SELECT id FROM requested_table WHERE id=?")
        .bind(7_i64)
        .fetch_one(&mut client)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), 7);
    client.close().await.unwrap();

    let state = runtime.state.lock().await;
    assert_eq!(
        state.protocols.mysql.events.matched_queries[0].source_query_sequence,
        Some(3)
    );
    let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
    owner.seal_witnesses().unwrap();
    let witnesses = owner.witness_manifest().unwrap().witnesses().unwrap();
    let sequences = witnesses
        .iter()
        .filter_map(|witness| {
            (witness.metadata.surface == crate::policy::Surface::DependencyRequest
                && witness.target_sha256.is_some())
            .then_some(witness.metadata.source.sequence)
            .flatten()
        })
        .collect::<std::collections::BTreeSet<_>>();
    // The ambiguous SELECT remains available to the original evidence path.
    assert_eq!(sequences, [2, 3].into());
    task.abort();
}
