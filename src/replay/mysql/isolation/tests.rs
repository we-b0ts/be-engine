use super::*;
use crate::replay::dependencies::DependencyRecord;
use serde_json::json;

pub(in crate::replay::mysql) fn record(sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    json!({"event_type":"mysql_exchange","connection_id":Uuid::from_u128(91),"query_sequence":sequence,
        "timestamp":"2020-01-01T00:00:00Z","duration_ms":0,
        "target_host":"127.0.0.1","target_port":3306,"database":"appdb","username":"root",
        "command":"COM_QUERY","sql":sql,"server_status_before":before,"outcome":"response",
        "response":{"status":"ok","server_status":after,"affected_rows":0,"last_insert_id":0}})
}

pub(in crate::replay::mysql) fn baseline() -> Value {
    let mut value = record(1, "SELECT @@transaction_isolation", 0, 0);
    value["response"] = json!({"status":"resultset","server_status":0,
        "columns":[{"name":"@@transaction_isolation","family":"string","sql_type":"VARCHAR"}],
        "rows":[[{"kind":"string","value":"REPEATABLE-READ"}]]});
    value
}

pub(in crate::replay::mysql) fn records() -> Vec<Value> {
    let mut read = record(10, "SELECT id FROM items WHERE id=1", 0, 1);
    read["response"] = json!({"status":"resultset","server_status":1,
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":1}]]});
    let mut write = record(11, "UPDATE items SET value=2 WHERE id=1", 1, 1);
    write["response"]["affected_rows"] = json!(1);
    vec![
        record(
            8,
            "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
            0,
            0,
        ),
        record(9, "COMMIT", 0, 0),
        read,
        write,
        record(12, "COMMIT", 1, 0),
        record(13, "ROLLBACK", 0, 0),
        record(
            14,
            "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
            0,
            0,
        ),
    ]
}

fn decoded(values: Vec<Value>) -> Vec<DependencyRecord> {
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect()
}

#[test]
fn isolation_profiles_require_the_original_baseline_closed_scope_and_complete_wire_sequence() {
    for scenario in [
        "valid",
        "same-baseline",
        "same-baseline-missing-reset",
        "same-baseline-empty-scope",
        "missing-baseline",
        "wrong-baseline",
        "missing-reset",
        "gap",
        "active-setting",
        "failed-setting",
        "truncated-read",
        "failed-write",
        "second-transaction",
        "foreign-resource",
        "duplicate-sequence",
        "wrong-reset",
        "pooled",
        "pooled-missing-clock",
        "pooled-future-probe",
        "pooled-foreign-resource",
    ] {
        let mut registry = Registry::default();
        if scenario != "missing-baseline" {
            let mut base = baseline();
            if scenario == "wrong-baseline" {
                base["response"]["rows"][0][0]["value"] = json!("READ-UNCOMMITTED");
            }
            if scenario.starts_with("same-baseline") {
                base["response"]["rows"][0][0]["value"] = json!("READ-COMMITTED");
            }
            if scenario == "pooled-future-probe" {
                base["timestamp"] = json!("2020-01-01T00:00:02Z");
            }
            registry.prepare(&decoded(vec![base]), ReplaySource::Startup, None);
        }
        let mut rows = records();
        if scenario.starts_with("same-baseline") {
            rows[6]["sql"] = json!("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
        }
        if scenario.starts_with("pooled") {
            for row in &mut rows {
                row["connection_id"] = json!(Uuid::from_u128(92));
                row["timestamp"] = json!("2020-01-01T00:00:01Z");
                if scenario == "pooled-missing-clock" {
                    row.as_object_mut().unwrap().remove("timestamp");
                }
                if scenario == "pooled-foreign-resource" {
                    row["database"] = json!("other");
                }
            }
        }
        match scenario {
            "missing-reset" | "same-baseline-missing-reset" => {
                rows.pop();
            }
            "same-baseline-empty-scope" => {
                rows = vec![
                    rows[0].clone(),
                    record(9, "COMMIT", 0, 0),
                    record(
                        10,
                        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
                        0,
                        0,
                    ),
                ];
            }
            "gap" => rows[2]["query_sequence"] = json!(42),
            "active-setting" => rows[0]["server_status_before"] = json!(1),
            "failed-setting" => rows[0]["response"]["status"] = json!("error"),
            "truncated-read" => rows[2]["response"]["rows_truncated"] = json!(true),
            "failed-write" => rows[3]["response"]["error_code"] = json!(1205),
            "second-transaction" => {
                rows[5] = record(13, "UPDATE items SET value=3 WHERE id=1", 0, 1);
            }
            "foreign-resource" => rows[3]["database"] = json!("other"),
            "duplicate-sequence" => rows.push(rows[2].clone()),
            "wrong-reset" => {
                rows[6]["sql"] = json!("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            }
            _ => {}
        }
        let plans = registry.prepare(&decoded(rows), ReplaySource::Case, Some("case"));
        assert_eq!(
            plans.len(),
            usize::from(matches!(scenario, "valid" | "pooled" | "same-baseline")),
            "{scenario}"
        );
        if let Some(plan) = plans.first() {
            assert_eq!(plan.required, BTreeSet::from([2, 3, 4]));
            assert_eq!((plan.setup, plan.end, plan.reset), (0, 4, 6));
        }
    }
}
