use super::*;
use sqlx::{Column, Executor};

// Exact SQL shape from models/unified case 84279845; fixture rows are synthetic.
const SOURCE: &str = "SELECT DISTINCT resource_members.entity_id AS resource_members_entity_id 
FROM resource_members 
WHERE resource_members.resource_type = 'Namespace' AND resource_members.entity_type = 'org_department' AND resource_members.entity_id IS NOT NULL AND resource_members.status = 'approved'";
const TARGET: &str = "SELECT DISTINCT resource_members.entity_id AS entity_id FROM resource_members WHERE resource_type = 'Namespace' AND entity_type = 'org_department' AND entity_id IS NOT NULL AND status = 'approved'";

fn departments(values: &[&str]) -> Value {
    result(
        json!([{"name":"resource_members_entity_id", "table":"resource_members", "column":"entity_id", "family":"string", "sql_type":"VARCHAR"}]),
        json!(
            values
                .iter()
                .map(|v| json!([{"kind":"string", "value":v}]))
                .collect::<Vec<_>>()
        ),
    )
}

#[tokio::test]
async fn sqlx_distinct_real_query_shape_matches_without_text_protocol_emulation() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for policy in [false, true] {
            let records = [
                exchange(SOURCE, departments(&["dept-1", "研发"])),
                exchange(SOURCE, departments(&[])),
            ];
            let (temp, addr, runtime, task) = fixture(&records, policy).await;
            let capture = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
            let before = std::fs::read(&capture).unwrap();
            let mut client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
            let rows = sqlx::query(TARGET).fetch_all(&mut client).await.unwrap();
            assert_eq!(
                rows.iter()
                    .map(|r| r.get::<String, _>("entity_id"))
                    .collect::<Vec<_>>(),
                ["dept-1", "研发"]
            );
            assert_eq!(rows[0].columns()[0].name(), "entity_id");
            assert!(
                sqlx::query(TARGET)
                    .fetch_all(&mut client)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                sqlx::query(TARGET).fetch_all(&mut client).await.is_err(),
                "recorded evidence is finite"
            );
            client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
            client.close().await.unwrap();
            let state = runtime.state.lock().await;
            assert_eq!(state.protocols.mysql.events.matched_query_count, 2);
            assert!(
                state
                    .protocols
                    .mysql
                    .events
                    .matched_queries
                    .iter()
                    .all(|q| q.command == "COM_STMT_EXECUTE")
            );
            assert!(
                state.protocols.mysql.events.metadata_warnings.is_empty(),
                "{:?}",
                state.protocols.mysql.events.metadata_warnings
            );
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(std::fs::read(capture).unwrap(), before);
            task.abort();
        }
    })
    .await
    .expect("DISTINCT real query replay timed out");
}

#[tokio::test]
async fn sqlx_distinct_protocol_pairs_rebind_cached_values_and_reorder_predicates() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_prepared in [false, true] {
            for target_prepared in [false, true] {
                let records = ["Namespace", "KnowledgeBase"].map(|resource_type| {
                    let mut record = if source_prepared {
                        exchange("SELECT DISTINCT resource_members.entity_id AS resource_members_entity_id FROM resource_members WHERE resource_members.resource_type = ? AND resource_members.entity_type = ? AND resource_members.entity_id IS NOT NULL AND resource_members.status = ?", departments(&[resource_type]))
                    } else {
                        exchange(&SOURCE.replace("'Namespace'", &format!("'{resource_type}'")), departments(&[resource_type]))
                    };
                    if source_prepared {
                        record["command"] = json!("COM_STMT_EXECUTE");
                        record["params"] = json!([
                            {"kind":"string","value":resource_type},
                            {"kind":"string","value":"org_department"},
                            {"kind":"string","value":"approved"}
                        ]);
                    }
                    record
                });
                let (temp, addr, runtime, task) = fixture(&records, false).await;
                let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                let target = "SELECT DISTINCT r.entity_id AS entity_id FROM resource_members r WHERE r.status = ? AND (r.entity_id IS NOT NULL AND r.entity_type = ?) AND r.resource_type = ?";
                let mut compilations = 0;
                for (i, resource_type) in ["Namespace", "WRONG", "KnowledgeBase"].into_iter().enumerate() {
                    let rows = if target_prepared {
                        sqlx::query(target).bind("approved").bind("org_department").bind(resource_type).fetch_all(&mut client).await
                    } else {
                        let sql = format!("SELECT DISTINCT r.entity_id AS entity_id FROM resource_members r WHERE r.status = 'approved' AND (r.entity_id IS NOT NULL AND r.entity_type = 'org_department') AND r.resource_type = '{resource_type}'");
                        (&mut client).fetch_all(sql.as_str()).await
                    };
                    if i == 1 { assert!(rows.is_err());
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await; }
                    else { assert_eq!(rows.unwrap()[0].get::<String, _>("entity_id"), resource_type); }
                    let count = runtime.state.lock().await.protocols.mysql.sql_cache.compilations;
                    // The failed lookup warms any remaining source templates.
                    if target_prepared && i == 2 { assert_eq!(count, compilations, "bind new values without reparsing"); }
                    compilations = count;
                }
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.protocols.mysql.events.matched_query_count, 2);
                assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
                assert!(state.protocols.mysql.events.metadata_warnings.is_empty(), "{:?}", state.protocols.mysql.events.metadata_warnings);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                task.abort();
            }
        }
    }).await.expect("DISTINCT protocol replay timed out");
}
