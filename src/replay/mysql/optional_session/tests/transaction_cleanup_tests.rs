use super::*;

fn control(sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut record = exchange(sequence, sql);
    record["server_status_before"] = json!(before);
    record["response"]["server_status"] = json!(after);
    record
}

fn explicit(start: &str, end: &str, autocommit: u16) -> Vec<Value> {
    let mut query = read(11, autocommit | 1);
    query["response"]["server_status"] = json!(autocommit | 1);
    vec![
        control(10, start, autocommit, autocommit | 1),
        query,
        control(12, end, autocommit | 1, autocommit),
    ]
}

fn classify_global(records: &[Value]) -> BTreeMap<usize, OptionalSessionExchange> {
    classify_with_global(&[], records, ReplaySource::Startup)
}

fn classify_with_global(
    global: &[Value],
    records: &[Value],
    source: ReplaySource,
) -> BTreeMap<usize, OptionalSessionExchange> {
    let decode = |values: &[Value]| {
        values
            .iter()
            .cloned()
            .map(|value| serde_json::from_value(value).unwrap())
            .collect::<Vec<_>>()
    };
    let mut prefixes = ReadPrefixes::default();
    classify(&decode(global), ReplaySource::Startup, &mut prefixes);
    classify(&decode(records), source, &mut prefixes)
}

#[test]
fn explicit_read_transactions_allow_only_their_successful_end_to_be_omitted() {
    for start in ["BEGIN", " START TRANSACTION; "] {
        for (end, kind) in [
            ("COMMIT", OptionalSessionExchange::Commit),
            ("ROLLBACK", OptionalSessionExchange::Rollback),
        ] {
            for autocommit in [0, 2] {
                let records = explicit(start, end, autocommit);
                assert_eq!(classify_global(&records), BTreeMap::from([(2, kind)]));
                assert_eq!(
                    classify_with_global(&records[..2], &records[2..], ReplaySource::Case),
                    BTreeMap::from([(0, kind)])
                );
            }
        }
    }
}

#[test]
fn writes_locks_savepoints_unknown_sql_and_nested_begin_break_explicit_read_proof() {
    for sql in [
        "UPDATE users SET id=2",
        "SELECT id FROM users FOR UPDATE",
        "SELECT id FROM users FOR SHARE",
        "SELECT id FROM users LOCK IN SHARE MODE",
        "SELECT GET_LOCK('x',1) FROM users",
        "SELECT id INTO @x FROM users",
        "SAVEPOINT s",
        "ROLLBACK TO SAVEPOINT s",
        "RELEASE SAVEPOINT s",
        "CALL business()",
        "BEGIN",
    ] {
        for end in ["COMMIT", "ROLLBACK"] {
            let mut records = explicit("BEGIN", end, 0);
            let mut excluded = control(12, sql, 1, 1);
            if sql.starts_with("SELECT") {
                excluded["response"] = records[1]["response"].clone();
            }
            records[2]["query_sequence"] = json!(14);
            let mut later_read = records[1].clone();
            later_read["query_sequence"] = json!(13);
            records.insert(2, excluded);
            records.insert(3, later_read);
            assert!(classify_global(&records).is_empty(), "{sql}: {end}");
        }
    }
}

#[test]
fn explicit_read_proof_requires_complete_contiguous_consistent_evidence() {
    let records = explicit("BEGIN", "ROLLBACK", 0);
    for (index, field, value) in [
        (0, "server_status_before", json!(1)),
        (0, "server_status_before", Value::Null),
        (0, "sql", json!("BEGIN; SELECT 1")),
        (0, "parse_warnings", json!(["incomplete"])),
        (0, "outcome", json!("client_terminated")),
        (1, "query_sequence", json!(13)),
        (1, "query_sequence", Value::Null),
        (1, "database", json!("other")),
        (1, "connection_id", json!(Uuid::new_v4())),
        (1, "server_status_before", json!(0)),
        (2, "server_status_before", json!(0)),
        (2, "sql", json!("ROLLBACK AND CHAIN")),
        (2, "sql", json!("ROLLBACK TO SAVEPOINT s")),
    ] {
        let mut changed = records.clone();
        changed[index][field] = value;
        assert!(classify_global(&changed).is_empty(), "{index}: {field}");
    }
    for (index, field, value) in [
        (0, "server_status", json!(0)),
        (0, "server_status", json!(3)),
        (0, "status", json!("error")),
        (0, "affected_rows", json!(1)),
        (1, "rows_truncated", json!(true)),
        (1, "server_status", json!(9)),
        (2, "server_status", json!(1)),
        (2, "server_status", json!(2)),
        (2, "error_code", json!(1205)),
    ] {
        let mut changed = records.clone();
        changed[index]["response"][field] = value;
        assert!(
            classify_global(&changed).is_empty(),
            "{index}: response.{field}"
        );
    }
    let mut duplicate = records.clone();
    duplicate.push(records[1].clone());
    assert!(classify_global(&duplicate).is_empty());
}

#[test]
fn successful_prepare_and_ping_preserve_explicit_read_proof() {
    let mut records = explicit("BEGIN", "COMMIT", 0);
    records[2]["query_sequence"] = json!(14);
    let mut prepare = control(12, "SELECT id FROM users WHERE id=?", 1, 1);
    prepare["command"] = json!("COM_STMT_PREPARE");
    prepare["response"] = json!({"status":"stmt_prepare"});
    let mut ping = control(13, "", 1, 1);
    ping["command"] = json!("COM_PING");
    ping["sql"] = Value::Null;
    records.insert(2, prepare);
    records.insert(3, ping);
    assert_eq!(
        classify_global(&records),
        BTreeMap::from([(4, OptionalSessionExchange::Commit)])
    );
    for index in [2, 3] {
        let mut changed = records.clone();
        changed[index]["response"]["status"] = json!("error");
        assert!(classify_global(&changed).is_empty());
    }
}

#[test]
fn known_empty_commit_and_rollback_are_optional_independently_of_prior_transactions() {
    for flags in [0, 2] {
        let records = [
            control(10, "COMMIT", flags, flags),
            control(11, "ROLLBACK", flags, flags),
            control(12, "COMMIT", flags, flags),
        ];
        assert_eq!(
            classify_global(&records),
            BTreeMap::from([
                (0, OptionalSessionExchange::Commit),
                (1, OptionalSessionExchange::Rollback),
                (2, OptionalSessionExchange::Commit),
            ])
        );
        for record in &records {
            assert_eq!(classify_global(std::slice::from_ref(record)).len(), 1);
        }
    }
    let records = [
        control(10, "BEGIN", 0, 1),
        control(11, "UPDATE users SET id=2", 1, 1),
        control(12, "COMMIT", 1, 0),
        control(13, "COMMIT", 0, 0),
        control(14, "ROLLBACK", 0, 0),
    ];
    assert_eq!(
        classify_global(&records),
        BTreeMap::from([
            (3, OptionalSessionExchange::Commit),
            (4, OptionalSessionExchange::Rollback),
        ])
    );
}

#[test]
fn empty_ends_need_complete_status_identity_sequence_and_successful_plain_responses() {
    for sql in ["COMMIT", "ROLLBACK"] {
        let record = control(10, sql, 0, 0);
        for (field, value) in [
            ("connection_id", Value::Null),
            ("query_sequence", Value::Null),
            ("target_host", Value::Null),
            ("server_status_before", Value::Null),
            ("server_status_before", json!(1)),
            ("server_status_before", json!(8)),
            ("server_status_before", json!(0x2000)),
            ("sql", json!(format!("{sql} AND CHAIN"))),
            ("sql", json!(format!("{sql}; SELECT 1"))),
            ("parse_warnings", json!(["incomplete"])),
            ("outcome", json!("client_terminated")),
        ] {
            let mut changed = record.clone();
            changed[field] = value;
            assert!(classify_global(&[changed]).is_empty(), "{sql}: {field}");
        }
        for (field, value) in [
            ("server_status", Value::Null),
            ("server_status", json!(1)),
            ("server_status", json!(2)),
            ("server_status", json!(8)),
            ("server_status", json!(0x2000)),
            ("status", json!("error")),
            ("error_code", json!(1205)),
            ("affected_rows", json!(1)),
            ("last_insert_id", json!(1)),
            ("rows_truncated", json!(true)),
        ] {
            let mut changed = record.clone();
            changed["response"][field] = value;
            assert!(
                classify_global(&[changed]).is_empty(),
                "{sql}: response.{field}"
            );
        }
        assert!(classify_global(&[record.clone(), record]).is_empty());
    }
}

#[test]
fn empty_end_does_not_override_a_conflicting_local_or_global_predecessor() {
    let prior = read(10, 0);
    for sql in ["COMMIT", "ROLLBACK"] {
        let end = control(11, sql, 0, 0);
        assert!(classify_global(&[prior.clone(), end.clone()]).is_empty());
        assert!(
            classify_with_global(std::slice::from_ref(&prior), &[end], ReplaySource::Case)
                .is_empty()
        );
        let completed = control(10, "ROLLBACK", 1, 0);
        let conflicting = control(11, sql, 1, 0);
        assert!(classify_global(&[completed, conflicting]).is_empty());
    }
}
