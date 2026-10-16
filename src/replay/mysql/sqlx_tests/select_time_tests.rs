//! SELECT time rules through ordinary SQLx text/prepared clients over TLS.
use super::*;
use sqlx::{Column, Executor};

const COUNT: &str = "SELECT count(*) AS total FROM errors WHERE created_at>? AND project_id=?";
const LIST: &str = "SELECT id FROM errors WHERE created_at>? AND project_id=? ORDER BY id LIMIT 10";

fn policy() -> String {
    format!(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n{}",
        [COUNT, LIST].iter().enumerate().map(|(i, sql)| format!(
            "  - id: select-time-{i}\n    protocol: mysql\n    mysql:\n      database: appdb\n      sql: {sql:?}\n      sql_values: {{0: {{time: replay_now, offset: -24h, tolerance: 5s}}}}\n"
        )).collect::<String>()
    )
}

#[tokio::test]
async fn select_sql_time_matches_counts_and_rows_across_text_and_prepared_protocols() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_prepared in [false, true] {
            for target_mode in 0..4 {
                let records = [COUNT, LIST]
                    .iter()
                    .enumerate()
                    .map(|(i, template)| {
                        let sql = template
                            .replacen('?', "'2019-12-31 00:00:00'", 1)
                            .replacen('?', "7", 1);
                        let mut read = exchange(
                            &sql,
                            result(
                                json!([{"name":if i == 0 {"total"} else {"id"},"family":"integer","sql_type":"BIGINT"}]),
                                json!([[{"kind":"integer","value":42}]]),
                            ),
                        );
                        if source_prepared {
                            read["command"] = json!("COM_STMT_EXECUTE");
                            read["sql"] = json!(template);
                            read["params"] = json!([
                                {"kind":"datetime","value":"2019-12-31 00:00:00"},
                                {"kind":"integer","value":7}
                            ]);
                        }
                        read
                    })
                    .collect::<Vec<_>>();
                let (temp, addr, runtime, task) =
                    fixture_with_policy(&records, Some(&policy())).await;
                let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                for template in [COUNT, LIST] {
                    for attempt in 0..4 {
                        let cutoff = if attempt == 0 {
                            chrono::NaiveDateTime::parse_from_str(
                                "2019-12-31 00:00:00",
                                "%Y-%m-%d %H:%M:%S",
                            )
                            .unwrap()
                        } else {
                            (chrono::Utc::now() - chrono::Duration::hours(24)).naive_utc()
                        };
                        let id = if attempt == 1 { 8_i64 } else { 7 };
                        let sql = template
                            .replacen(
                                '?',
                                &format!("'{}'", cutoff.format("%Y-%m-%d %H:%M:%S%.6f")),
                                1,
                            )
                            .replacen('?', &id.to_string(), 1);
                        let rows = match target_mode {
                            0 => (&mut client).fetch_all(sql.as_str()).await,
                            1 => sqlx::query(&sql).fetch_all(&mut client).await,
                            2 => {
                                sqlx::query(template)
                                    .bind(cutoff)
                                    .bind(id)
                                    .fetch_all(&mut client)
                                    .await
                            }
                            _ => {
                                let mixed = template.replacen('?', &format!("'{}'", cutoff.format("%Y-%m-%d %H:%M:%S%.6f")), 1);
                                sqlx::query(&mixed).bind(id).fetch_all(&mut client).await
                            }
                        };
                        if attempt == 2 {
                            let rows = rows.unwrap();
                            assert_eq!(rows.len(), 1);
                            assert_eq!(rows[0].get::<i64, _>(0), 42);
                            assert_eq!(
                                rows[0].columns()[0].name(),
                                if template == COUNT { "total" } else { "id" }
                            );
                        } else {
                            assert!(
                                rows.is_err(),
                                "stale cutoff, changed project and exhausted evidence must fail"
                            );
                        }
                    }
                }
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count, 2);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                let report = state.replay_policy.as_ref().unwrap().report();
                assert!(
                    report
                        .dependency_rules
                        .iter()
                        .all(|rule| rule.matches == 1 && rule.time_validations == 1)
                );
                assert_eq!(std::fs::read(path).unwrap(), original);
                task.abort();
            }
        }
    })
    .await
    .expect("SELECT time replay timed out");
}
