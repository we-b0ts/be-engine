use super::*;
use serde_json::json;

mod complex_read_tests;
mod read_exclusions_tests;

fn exchange(sequence: u64, sql: &str) -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":Uuid::nil(),
        "query_sequence":sequence, "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "response":{"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0}})
}

fn optional(records: &[Value]) -> BTreeSet<usize> {
    classify(
        &records
            .iter()
            .cloned()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .filter_map(|(index, kind)| (kind == OptionalSessionExchange::Rollback).then_some(index))
    .collect()
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
fn boolean_tests_preserve_read_proof_only_for_pure_operands() {
    use super::read::{Effect, classify};
    for suffix in [
        "IS TRUE",
        "IS NOT TRUE",
        "IS FALSE",
        "IS NOT FALSE",
        "IS UNKNOWN",
        "IS NOT UNKNOWN",
    ] {
        let sql =
            format!("SELECT namespace.name FROM namespace WHERE namespace.is_active {suffix}");
        assert_eq!(classify(&sql), Effect::ReadOnly, "{sql}");
        for operand in ["GET_LOCK('x',1)", "@value"] {
            let sql = format!("SELECT id FROM users WHERE {operand} {suffix}");
            assert_ne!(classify(&sql), Effect::ReadOnly, "{sql}");
        }
    }
}

#[test]
fn interleaved_long_session_boolean_reads_allow_both_connections_cleanup() {
    // models/unified shape: main sequences 215..336, a short independent
    // session interleaved after 224, and 37 IS TRUE queries in the main span.
    // File offsets, MySQL exchange indices, and connection sequences differ.
    let mut records = Vec::new();
    for sequence in 215..335 {
        if sequence == 225 {
            let short = Uuid::new_v4();
            for mut record in [read(2109, 0), cleanup(2110), exchange(2111, "ROLLBACK")] {
                record["connection_id"] = json!(short);
                records.push(record);
            }
        }
        let mut record = read(
            sequence,
            if sequence == 215 {
                0
            } else if sequence == 217 {
                33
            } else {
                1
            },
        );
        if sequence == 216 || (227..=332).contains(&sequence) && (sequence - 227).is_multiple_of(3)
        {
            record["sql"] = json!(
                "SELECT namespace.name AS namespace_name FROM namespace WHERE namespace.is_active IS true"
            );
        }
        if sequence == 216 {
            record["response"]["server_status"] = json!(33);
        }
        if sequence == 224 {
            record["sql"] = json!(
                "SELECT DISTINCT resource_members.entity_id FROM resource_members WHERE resource_members.resource_type='Namespace'"
            );
        }
        records.push(record);
    }
    records.extend([cleanup(335), exchange(336, "ROLLBACK")]);
    assert_eq!(records.len(), 125);
    assert_eq!(optional(&records), [11, 12, 123, 124].into());
    // Consuming other traffic cannot authorize cleanup of excluded effects.
    records[1]["sql"] = json!("SELECT GET_LOCK('x',1) FROM namespace");
    assert_eq!(optional(&records), [11, 12, 124].into());
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
fn read_effect_exclusions_reject_locks_calls_and_vendor_tail_clauses() {
    for sql in [
        "SELECT id FROM users WHERE (id,name) IN ((1,'a'),(2,'b'))",
        "SELECT u.id AS user_id FROM users u WHERE u.id IN (1,2) AND (u.active=1 OR u.name='a') ORDER BY u.id LIMIT 1",
        "SELECT * FROM users WHERE id=?",
        "SELECT id FROM users",
        "SELECT id FROM users WHERE id IS NOT NULL",
    ] {
        assert_eq!(
            super::read::classify(sql),
            super::read::Effect::ReadOnly,
            "{sql}"
        );
    }
    for sql in [
        "SELECT id FROM users WHERE (id,name) IN ((1,'a'),(2,GET_LOCK('x',1)))",
        "BEGIN",
        "SELECT id FROM users FOR UPDATE",
        "SELECT id FROM users FOR SHARE",
        "SELECT id FROM users LOCK IN SHARE MODE",
        "SELECT id INTO OUTFILE '/tmp/x' FROM users",
        "SELECT GET_LOCK('x',1) FROM users",
        "SELECT id FROM users WHERE GET_LOCK('x',1)=1",
        "SELECT id FROM users ORDER BY GET_LOCK('x',1)",
        "SELECT id FROM users LIMIT GET_LOCK('x',1)",
        "SELECT DISTINCT GET_LOCK('x',1) FROM users",
        "SELECT id + GET_LOCK('x',1) FROM users",
        "SELECT id FROM users GROUP BY GET_LOCK('x',1)",
        "SELECT id FROM users GROUP BY id HAVING GET_LOCK('x',1)=1",
        "SELECT @x:=id FROM users",
        "SELECT id FROM users; UPDATE users SET id=1",
        "SELECT /*!50000 SQL_CALC_FOUND_ROWS */ id FROM users",
        "SELECT id FROM users SETTINGS x=GET_LOCK('x',1)",
        "SELECT id FROM users FORMAT JSON",
        "SELECT id FROM users UNION SELECT GET_LOCK('x',1) FROM users",
        "CALL read_users()",
        "SELECT id FROM users WHERE id =",
        "SELECT id FROM users WHERE id=1 FOR UPDATE NOWAIT",
    ] {
        assert_ne!(
            super::read::classify(sql),
            super::read::Effect::ReadOnly,
            "{sql}"
        );
    }
    assert_ne!(
        super::read::classify(&format!(
            "SELECT id FROM users WHERE {}id=1{}",
            "(".repeat(100),
            ")".repeat(100)
        )),
        super::read::Effect::ReadOnly
    );
}

#[test]
fn read_effect_accepts_a_batched_read_above_the_legacy_token_cap() {
    // A batched read that inlines a large id set stays read-only. Otherwise the
    // session cleanup allowance for such a request would depend on how wide the
    // source rendered its `IN (...)`, which is not a property of the statement.
    // This matches the widest recorded history read (recording 20260928050001,
    // 16,508 ids) while staying inside the bounded classifier budget.
    let ids = (0..16_508)
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT id FROM subtask_contexts WHERE subtask_contexts.subtask_id IN ({ids}) ORDER BY subtask_contexts.id ASC"
    );
    assert!(sql.len() > 64 * 1024, "size {}", sql.len());
    assert!(sql.len() < 1024 * 1024, "size {}", sql.len());
    assert_eq!(super::read::classify(&sql), super::read::Effect::ReadOnly);
}

#[test]
fn effect_classification_is_independent_of_query_matching_and_preserves_transaction_boundaries() {
    use super::read::{Effect, classify};
    for sql in [
        "UPDATE users SET id=2",
        "DELETE FROM users",
        "INSERT INTO users(id) VALUES(1)",
        "CALL do_work()",
        "SELECT id FROM users FOR UPDATE",
    ] {
        assert_eq!(classify(sql), Effect::StateChange, "{sql}");
    }
    for sql in [
        "SELECT GET_LOCK('x',1) FROM users",
        "SELECT @value FROM users",
        "invalid sql",
        // Unsupported MySQL grammar must remain unknown, never read-only.
        "SELECT id INTO OUTFILE '/tmp/x' FROM users",
    ] {
        assert_eq!(classify(sql), Effect::Unknown, "{sql}");
    }
    for sql in [
        "SELECT DISTINCT namespace, name FROM kinds WHERE (namespace='default' AND name='a') OR (namespace='shared' AND name='b')",
        "SELECT id + 1 FROM users WHERE id + 2 > 0 GROUP BY id HAVING id > 0 ORDER BY id + 1",
        "SELECT kinds.id AS kinds_id, kinds.user_id AS kinds_user_id, kinds.kind AS kinds_kind, kinds.name AS kinds_name, kinds.namespace AS kinds_namespace, kinds.json AS kinds_json, kinds.is_active AS kinds_is_active, kinds.created_at AS kinds_created_at, kinds.updated_at AS kinds_updated_at FROM kinds WHERE kinds.kind = 'Model' AND kinds.namespace = 'default' AND kinds.is_active = true AND kinds.user_id = 126",
    ] {
        assert_eq!(classify(sql), Effect::ReadOnly, "{sql}");
        let mut query = read(2109, 0);
        query["sql"] = json!(sql);
        let records = [query.clone(), cleanup(2110), exchange(2111, "ROLLBACK")];
        assert_eq!(optional(&records), [1, 2].into(), "{sql}");
        query["server_status_before"] = json!(1);
        assert!(
            optional(&[query.clone(), cleanup(2110)]).is_empty(),
            "unknown transaction start"
        );
        query["server_status_before"] = json!(0);
        query["response"]["rows_truncated"] = json!(true);
        assert!(
            optional(&[query, cleanup(2110)]).is_empty(),
            "incomplete response"
        );
    }
}
