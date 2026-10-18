use super::*;

#[tokio::test]
async fn derived_counts_and_joined_exists_match_normal_prepared_clients() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for policy in [false, true] {
            for (count, join) in [(true, false), (true, true), (false, true)] {
                let join = if join {
                    " JOIN namespaces ON namespaces.name=kinds.namespace"
                } else {
                    ""
                };
                let inner = format!(
                    "SELECT kinds.id AS value FROM kinds{join} \
                    WHERE kinds.id IN (2,1) AND (kinds.owner_id=7 OR EXISTS (\
                    SELECT 1 FROM members WHERE members.kind_id=kinds.id \
                    AND members.entity_id IN ('b','a')))"
                );
                let source = if count {
                    format!("SELECT count(*) AS value FROM ({inner}) AS items")
                } else {
                    format!("{inner} ORDER BY kinds.id DESC LIMIT 10")
                };
                let target = source
                    .replace("IN (2,1)", "IN (?,?)")
                    .replace("IN ('b','a')", "IN (?,?)");
                let records = [exchange(
                    &source,
                    result(
                        json!([{"name":"value","family":"integer","sql_type":"INT"}]),
                        json!([[{"kind":"integer","value":3}]]),
                    ),
                )];
                let (temp, addr, runtime, task) = fixture(&records, policy).await;
                let capture = temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original = std::fs::read(&capture).unwrap();
                let mut client = connect(
                    addr,
                    &temp
                        .path()
                        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
                )
                .await;
                let row = sqlx::query(&target)
                    .bind(1_i32)
                    .bind(2_i32)
                    .bind("a")
                    .bind("b")
                    .fetch_one(&mut client)
                    .await
                    .unwrap();
                assert_eq!(row.get::<i32, _>("value"), 3);
                let state = runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count, 1);
                assert!(state.mysql.events.unmatched_queries.is_empty());
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                assert_eq!(std::fs::read(capture).unwrap(), original);
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}
