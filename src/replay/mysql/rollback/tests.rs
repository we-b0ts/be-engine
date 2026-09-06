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

fn read(sequence: u64, before: u16) -> Value {
    let mut record = exchange(sequence, "SELECT id FROM users WHERE id=1");
    record["server_status_before"] = json!(before);
    record["response"] = json!({"status":"resultset", "server_status":1,
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":1}]]});
    record
}

fn cleanup(sequence: u64) -> Value {
    let mut record = exchange(sequence, "ROLLBACK");
    record["server_status_before"] = json!(1);
    record
}

#[test]
fn implicit_read_only_session_cleanup_is_optional_with_complete_status_evidence() {
    let records = [
        read(116, 0),
        read(117, 1),
        cleanup(118),
        exchange(119, "ROLLBACK"),
    ];
    assert_eq!(optional(&records), [2, 3].into());
    assert_eq!(
        optional(&[records[2].clone(), records[0].clone(), records[1].clone()]),
        [0].into()
    );
    let mut prepared = read(116, 0);
    prepared["command"] = json!("COM_STMT_EXECUTE");
    prepared["sql"] = json!("SELECT id FROM users WHERE id=?");
    prepared["params"] = json!([{"kind":"integer","value":1}]);
    assert_eq!(optional(&[prepared, cleanup(117)]), [1].into());
}

#[test]
fn successful_prepare_preserves_read_proof_but_failed_prepare_does_not() {
    let mut prepare = exchange(117, "SELECT id FROM users WHERE id=?");
    prepare["command"] = json!("COM_STMT_PREPARE");
    prepare["server_status_before"] = json!(1);
    prepare["response"] = json!({"status":"stmt_prepare"});
    let mut records = [read(116, 0), prepare, read(118, 1), cleanup(119)];
    assert_eq!(optional(&records), [3].into());
    records[1]["response"]["status"] = json!("error");
    assert!(optional(&records).is_empty());
}

#[test]
fn implicit_cleanup_needs_known_start_contiguous_reads_and_successful_end() {
    let pair = [read(116, 0), cleanup(117)];
    for (index, field, value) in [
        (0, "server_status_before", Value::Null),
        (0, "server_status_before", json!(1)),
        (0, "server_status_before", json!(0x2001)),
        (0, "parse_warnings", json!(["incomplete"])),
        (0, "outcome", json!("client_terminated")),
        (1, "server_status_before", Value::Null),
        (1, "server_status_before", json!(0)),
        (1, "database", json!("other")),
        (1, "connection_id", json!(Uuid::new_v4())),
        (1, "query_sequence", json!(118)),
        (1, "sql", json!("ROLLBACK AND CHAIN")),
    ] {
        let mut records = pair.clone();
        records[index][field] = value;
        assert!(optional(&records).is_empty(), "{index} {field}");
    }
    for (index, field, value) in [
        (0, "server_status", Value::Null),
        (0, "server_status", json!(9)),
        (0, "rows_truncated", json!(true)),
        (0, "rows", json!([[]])),
        (0, "error_code", json!(1205)),
        (1, "server_status", json!(1)),
        (1, "status", json!("error")),
        (1, "affected_rows", json!(1)),
    ] {
        let mut records = pair.clone();
        records[index]["response"][field] = value;
        assert!(optional(&records).is_empty(), "{index} response.{field}");
    }
    // A read-only-looking suffix cannot hide earlier writes, locks, or BEGIN.
    for sql in [
        "BEGIN",
        "UPDATE users SET id=2",
        "SELECT id FROM users FOR UPDATE",
        "SAVEPOINT s",
    ] {
        let mut middle = exchange(117, sql);
        middle["server_status_before"] = json!(1);
        middle["response"]["server_status"] = json!(1);
        assert!(
            optional(&[read(116, 0), middle, read(118, 1), cleanup(119)]).is_empty(),
            "{sql}"
        );
    }
    assert!(optional(&[pair[0].clone(), pair[0].clone(), pair[1].clone()]).is_empty());
    // Separately loaded case/Global files do not establish a shared transaction.
    assert!(optional(&[read(116, 0)]).is_empty());
    assert!(optional(&[read(117, 1), cleanup(118)]).is_empty());
}

#[test]
fn read_effect_allowlist_rejects_locks_calls_and_vendor_tail_clauses() {
    for sql in [
        "SELECT u.id AS user_id FROM users u WHERE u.id IN (1,2) AND (u.active=1 OR u.name='a') ORDER BY u.id LIMIT 1",
        "SELECT * FROM users WHERE id=?",
        "SELECT id FROM users",
        "SELECT id FROM users WHERE id IS NOT NULL",
    ] {
        assert!(super::read::plain_select(sql), "{sql}");
    }
    for sql in [
        "BEGIN",
        "SELECT id FROM users FOR UPDATE",
        "SELECT id FROM users FOR SHARE",
        "SELECT id FROM users LOCK IN SHARE MODE",
        "SELECT id INTO OUTFILE '/tmp/x' FROM users",
        "SELECT GET_LOCK('lock',1) FROM users",
        "SELECT custom_function() FROM users",
        "SELECT id FROM users WHERE custom_function()=1",
        "SELECT id FROM users ORDER BY GET_LOCK('x',1)",
        "SELECT id FROM users LIMIT custom_function()",
        "SELECT @x:=id FROM users",
        "SELECT id FROM users WHERE id IN (SELECT id FROM users)",
        "SELECT id FROM users; UPDATE users SET id=1",
        "SELECT /*!50000 SQL_CALC_FOUND_ROWS */ id FROM users",
        "SELECT id FROM users SETTINGS x=custom_function()",
        "SELECT id FROM users FORMAT JSON",
        "SELECT id FROM users UNION SELECT id FROM users",
        "CALL read_users()",
        "SELECT id FROM users WHERE id =",
        "SELECT id FROM users WHERE id=1 FOR UPDATE NOWAIT",
    ] {
        assert!(!super::read::plain_select(sql), "{sql}");
    }
    assert!(!super::read::plain_select(&format!(
        "SELECT id FROM users WHERE {}id=1{}",
        "(".repeat(100),
        ")".repeat(100)
    )));
}
