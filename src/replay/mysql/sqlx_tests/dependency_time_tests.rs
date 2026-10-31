//! Per-write clocks remain independent when a batch runs faster than Source.
use super::*;
use sqlx::Executor;

const SQL: &str = "UPDATE tasks SET deleted=?, updated_at=?, payload=? WHERE id=?";

fn policy() -> String {
    format!(
        r#"format: traffic-policy/v3
rules:
- id: write-clock
  match:
    api: GET /users
    resource: {{protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}}
    operation: COM_QUERY
    sql: {SQL:?}
  effect:
    kind: mysql_values
    values:
      1: {{relative_time: sql_datetime}}
      2:
        kind: json
        fields:
          /changed_at_us: {{relative_time: unix_microseconds}}
  proof: {{source: 'store.py:delete', fact: 'Each iteration obtains now and copies the same clock into its audit fields'}}
"#
    )
}

fn records(count: u64) -> Vec<Value> {
    (1..=count)
        .map(|id| {
            let clock =
                chrono::DateTime::from_timestamp(1_577_836_800 + id as i64, 123_456_000).unwrap();
            let payload = payload(clock);
            let sql = format!(
                "UPDATE tasks SET deleted=1, updated_at='{}', payload='{payload}' WHERE id={id}",
                clock.format("%Y-%m-%d %H:%M:%S%.6f")
            );
            let mut record = exchange(&sql, json!({"status":"ok","affected_rows":1}));
            record["timestamp"] = json!(clock + chrono::TimeDelta::milliseconds(1));
            record["duration_ms"] = json!(1);
            record["connection_id"] = json!("01234567-89ab-4def-8123-456789abcdef");
            record["query_sequence"] = json!(id);
            record
        })
        .collect()
}

fn payload(clock: chrono::DateTime<Utc>) -> String {
    json!({"changed_at_us":clock.timestamp_micros(),"stable":7}).to_string()
}

fn now() -> chrono::DateTime<Utc> {
    chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
}

async fn prepared(
    client: &mut MySqlConnection,
    id: i64,
    clock: chrono::DateTime<Utc>,
    payload: String,
) -> Result<sqlx::mysql::MySqlQueryResult, sqlx::Error> {
    sqlx::query(SQL)
        .bind(1_i64)
        .bind(clock.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
        .bind(payload)
        .bind(id)
        .execute(client)
        .await
}

#[tokio::test]
async fn dependency_request_time_supports_faster_batches_over_tls_text_and_prepared_writes() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let source = records(50);
        let (temp, addr, runtime, task) = fixture_with_policy(&source, Some(&policy())).await;
        let case = temp.path().join(".traffic-e2e/local/recordings/case-id");
        let original = std::fs::read(case.join("dependencies.jsonl")).unwrap();
        let mut client = connect(addr, &case.join(".replay/ca.pem")).await;

        // Failure does not consume the next write, bind an identity or waive
        // stable JSON/predicate checks. A stale clock still fails the fixed 5s bound.
        let current = now();
        assert!(
            prepared(&mut client, 999, current, payload(current))
                .await
                .is_err()
        );
        assert!(
            prepared(
                &mut client,
                1,
                current,
                payload(current).replace("\"stable\":7", "\"stable\":8")
            )
            .await
            .is_err()
        );
        let stale = current - chrono::TimeDelta::seconds(10);
        assert!(
            prepared(&mut client, 1, stale, payload(stale))
                .await
                .is_err()
        );

        for id in 1..=50 {
            let clock = now();
            let result = if id % 2 == 0 {
                prepared(&mut client, id, clock, payload(clock)).await
            } else {
                client.execute(format!(
                    "UPDATE tasks SET deleted=1, updated_at='{}', payload='{}' WHERE id={id}",
                    clock.format("%Y-%m-%d %H:%M:%S%.6f"), payload(clock)
                ).as_str()).await
            };
            assert_eq!(result.unwrap().rows_affected(), 1, "iteration {id}");
        }
        let clock = now();
        assert!(
            prepared(&mut client, 50, clock, payload(clock))
                .await
                .is_err()
        );
        client.close().await.unwrap();

        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 50);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 4);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let policy = state.replay_policy.as_ref().unwrap();
        let usage = policy.report();
        let usage = usage
            .dependency_rules
            .iter()
            .find(|r| r.id == "write-clock")
            .unwrap();
        assert_eq!(usage.matches, 50);
        assert_eq!(usage.time_validations, 100);
        let manifest = policy.request_contracts.witness_manifest().unwrap();
        assert!(manifest.complete);
        assert_eq!(manifest.omitted, 0);
        let witnesses = manifest.witnesses().unwrap();
        assert!(witnesses.iter().any(|w| {
            w.metadata.clocks.dependency.source != w.metadata.clocks.case.source
                && w.metadata.clocks.dependency.target.is_some()
                && w.target_sha256.is_some()
        }));
        assert_eq!(
            std::fs::read(case.join("dependencies.jsonl")).unwrap(),
            original
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[test]
fn mysql_time_contracts_reject_configured_clocks_and_render_without_anchors() {
    for anchor in [
        "case.request_start",
        "dependency.request_start",
        "dependency.response_delivery",
        "arbitrary",
    ] {
        let raw = policy().replace(
            "relative_time: sql_datetime",
            &format!("relative_time: sql_datetime, anchor: {anchor}"),
        );
        assert!(crate::policy::parse_policy(&raw).is_err(), "{anchor}");
    }
    let document = crate::policy::parse_policy(&policy()).unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let projection =
        crate::replay::policy::native_projection::project_native(&compiled.native).unwrap();
    let encoded = serde_yaml::to_string(&projection.document).unwrap();
    assert!(!encoded.contains("anchor:"));
    let restored: crate::replay::policy::ReplayPolicyDocument =
        serde_yaml::from_str(&encoded).unwrap();
    assert_eq!(
        serde_json::to_value(&projection.document).unwrap(),
        serde_json::to_value(restored).unwrap()
    );
}
