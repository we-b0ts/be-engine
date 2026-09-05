use super::*;
use serde_json::json;

fn exchange(sequence: u64, sql: &str) -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":Uuid::nil(),
        "query_sequence":sequence, "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "response":{"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0}})
}

fn optional(records: &[Value]) -> BTreeSet<usize> {
    optional_rollbacks(
        &records
            .iter()
            .cloned()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn only_redundant_rollback_after_successful_end_is_optional() {
    for end in ["COMMIT", "ROLLBACK"] {
        let records = [
            exchange(10, end),
            exchange(11, " rollback; "),
            exchange(12, "ROLLBACK"),
        ];
        assert_eq!(optional(&records), [1, 2].into());
        // File order is not the physical connection order.
        assert_eq!(
            optional(&[records[2].clone(), records[0].clone(), records[1].clone()]),
            [0, 2].into()
        );
    }
}

#[test]
fn first_rollback_reads_writes_locks_and_chain_remain_required() {
    assert!(optional(&[exchange(10, "ROLLBACK")]).is_empty());
    for previous in [
        "BEGIN",
        "SELECT id FROM users",
        "SELECT id FROM users FOR UPDATE",
        "UPDATE users SET id=2",
        "ROLLBACK TO SAVEPOINT s",
        "COMMIT AND CHAIN",
        "ROLLBACK AND CHAIN",
        "COMMIT; BEGIN",
        "CALL finish_transaction()",
    ] {
        assert!(
            optional(&[exchange(10, previous), exchange(11, "ROLLBACK")]).is_empty(),
            "{previous}"
        );
    }
    assert!(optional(&[exchange(10, "ROLLBACK"), exchange(11, "COMMIT")]).is_empty());
}

#[test]
fn incomplete_or_failed_evidence_never_authorizes_rollback_omission() {
    let pair = [exchange(10, "COMMIT"), exchange(11, "ROLLBACK")];
    for index in 0..2 {
        for (field, value) in [
            ("connection_id", json!(Uuid::new_v4())),
            ("connection_id", Value::Null),
            ("query_sequence", Value::Null),
            ("query_sequence", json!(20)),
            ("target_host", json!("other.internal")),
            ("database", json!("other")),
            ("username", json!("other")),
            ("command", json!("COM_STMT_EXECUTE")),
            ("parse_warnings", json!(["incomplete"])),
            ("outcome", json!("client_terminated")),
            ("params", json!([{"kind":"integer", "value":1}])),
        ] {
            let mut records = pair.clone();
            records[index][field] = value;
            assert!(optional(&records).is_empty(), "{index}: {field}");
        }
        for (field, value) in [
            ("status", json!("error")),
            ("server_status", Value::Null),
            ("server_status", json!(1)),
            ("server_status", json!(8)),
            ("server_status", json!(0x2001)),
            ("error_code", json!(1205)),
            ("rows_truncated", json!(true)),
            ("affected_rows", Value::Null),
            ("affected_rows", json!(1)),
            ("last_insert_id", json!(42)),
        ] {
            let mut records = pair.clone();
            records[index]["response"][field] = value;
            assert!(optional(&records).is_empty(), "{index}: response.{field}");
        }
    }
    assert!(optional(&[pair[0].clone(), pair[0].clone(), pair[1].clone()]).is_empty());
    let mut missing_sequence = exchange(12, "BEGIN");
    missing_sequence["query_sequence"] = Value::Null;
    assert!(optional(&[pair[0].clone(), pair[1].clone(), missing_sequence]).is_empty());
}
