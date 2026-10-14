use super::*;
use serde_json::{Value, json};

fn control(seq: u64, sql: &str, before: u16, after: u16) -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":Uuid::nil(),
        "query_sequence":seq, "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "server_status_before":before,
        "response":{"status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0}})
}

fn records() -> Vec<Value> {
    let mut read = control(5, "SELECT id FROM users WHERE id=1", 0, 1);
    read["response"] = json!({"status":"resultset", "server_status":1,
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":1}]]});
    vec![
        control(3, "SET AUTOCOMMIT = 0", 2, 0),
        read,
        control(6, "ROLLBACK", 1, 0),
        control(7, "ROLLBACK", 0, 0),
        control(8, "SET SESSION AUTOCOMMIT=1", 0, 2),
    ]
}

fn optional(records: &[Value]) -> BTreeMap<usize, OptionalSessionExchange> {
    super::super::classify(
        &records
            .iter()
            .cloned()
            .map(|record| serde_json::from_value(record).unwrap())
            .collect::<Vec<_>>(),
        ReplaySource::Global,
        &mut super::super::ReadPrefixes::default(),
    )
}

fn setups(records: &[Value]) -> Vec<usize> {
    optional(records)
        .into_iter()
        .filter_map(|(index, kind)| (kind == OptionalSessionExchange::Autocommit).then_some(index))
        .collect()
}

#[test]
fn cold_read_session_allows_setup_gap_and_keeps_distinct_evidence() {
    let records = records();
    assert_eq!(setups(&records), vec![0, 4]);
    assert_eq!(
        optional(&records).get(&2),
        Some(&OptionalSessionExchange::Rollback)
    );
    assert_eq!(
        optional(&records).get(&3),
        Some(&OptionalSessionExchange::Rollback)
    );
    assert!(
        !optional(&records).contains_key(&1),
        "reads remain required"
    );
    let reordered = [
        records[1].clone(),
        records[4].clone(),
        records[2].clone(),
        records[0].clone(),
        records[3].clone(),
    ];
    assert_eq!(setups(&reordered), vec![1, 3]);
}

#[test]
fn enabling_autocommit_can_end_a_proven_read_span() {
    let mut records = records();
    records.truncate(3);
    records[2] = control(6, "SET AUTOCOMMIT=1", 1, 2);
    assert_eq!(setups(&records), vec![0, 2]);
    // A session that stays in autocommit mode needs no closing ROLLBACK.
    records.truncate(2);
    records[0] = control(3, "SET AUTOCOMMIT=1", 2, 2);
    records[1]["server_status_before"] = json!(2);
    records[1]["response"]["server_status"] = json!(2);
    assert_eq!(setups(&records), vec![0]);
}

#[test]
fn setup_does_not_hide_writes_locks_explicit_transactions_or_unknown_sql() {
    for sql in [
        "UPDATE users SET id=2",
        "SELECT id FROM users FOR UPDATE",
        "BEGIN",
        "CALL business()",
        "SELECT GET_LOCK('x',1) FROM users",
        "SET autocommit=0,sql_mode=''",
        "SET GLOBAL autocommit=0",
    ] {
        let mut records = records();
        records.insert(2, control(6, sql, 1, 1));
        for (index, record) in records.iter_mut().enumerate().skip(3) {
            record["query_sequence"] = json!(index + 4);
        }
        assert!(setups(&records).is_empty(), "{sql}");
    }
    assert!(setups(&[control(3, "SET AUTOCOMMIT=1", 1, 2)]).is_empty());
    assert!(
        setups(&records()[..2]).is_empty(),
        "unclosed implicit reads"
    );
    let mut records = records();
    records.push(control(9, "UPDATE users SET id=2", 2, 2));
    assert!(
        setups(&records).is_empty(),
        "later writes also keep setup required"
    );
}

#[test]
fn incomplete_and_inconsistent_setup_evidence_stays_required() {
    for index in 0..records().len() {
        for (field, value) in [
            ("connection_id", Value::Null),
            ("connection_id", json!(Uuid::new_v4())),
            ("query_sequence", Value::Null),
            ("database", json!("other")),
            ("username", json!("other")),
            ("server_status_before", Value::Null),
            ("server_status_before", json!(9)),
            ("parse_warnings", json!(["incomplete"])),
            ("outcome", json!("client_terminated")),
        ] {
            if index == 4 && field == "connection_id" {
                // A reset on another connection cannot invalidate an already
                // completed read-only session on this connection.
                continue;
            }
            let mut records = records();
            records[index][field] = value;
            // A different physical connection may still classify independently;
            // the original cold setup must never borrow its missing read/end.
            assert!(!setups(&records).contains(&0), "{index}: {field}");
        }
    }
    for index in [0, 4] {
        for (field, value) in [
            ("status", json!("error")),
            ("server_status", Value::Null),
            ("server_status", json!(9)),
            ("affected_rows", json!(1)),
            ("last_insert_id", json!(1)),
            ("error_code", json!(1205)),
            ("rows_truncated", json!(true)),
        ] {
            let mut records = records();
            records[index]["response"][field] = value;
            assert!(setups(&records).is_empty(), "{index}: {field}");
        }
    }
    let mut records = records();
    records[2]["query_sequence"] = json!(9);
    assert!(setups(&records).is_empty(), "gap inside read transaction");
    let mut records = self::records();
    records.push(records[1].clone());
    assert!(setups(&records).is_empty(), "duplicate sequence");
}
