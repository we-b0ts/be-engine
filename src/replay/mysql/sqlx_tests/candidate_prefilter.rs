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
                runtime.state.lock().await.mysql.events.matched_query_count,
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
            assert!(state.mysql.exchanges[1].status.is_consumed());
            assert!(state.mysql.exchanges[0].status.is_available());
            assert_eq!(state.mysql.events.matched_query_count, 1);
            assert!(state.mysql.events.unmatched_queries.is_empty());
            assert!(state.mysql.events.builtin_queries.iter().all(|query| {
                query.sql.as_deref().map(normalize_sql) != Some(normalize_sql(sql))
            }));
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
        state.mysql.events.matched_queries[0].source_query_sequence,
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
