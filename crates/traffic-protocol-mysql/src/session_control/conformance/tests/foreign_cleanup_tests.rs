use super::*;

fn records(values: &[Value]) -> Vec<DependencyRecord> {
    values
        .iter()
        .cloned()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect()
}

fn classify_case(global: &[Value], case: &[Value]) -> BTreeMap<usize, OptionalSessionExchange> {
    let mut prefixes = ReadPrefixes::default();
    classify(&records(global), ReplaySource::Startup, &mut prefixes);
    classify(&records(case), ReplaySource::Case, &mut prefixes)
}

fn commit(sequence: u64) -> Value {
    let mut end = cleanup(sequence);
    end["sql"] = json!("COMMIT");
    end
}

#[test]
fn foreign_cleanup_does_not_exempt_later_business_transaction_on_reused_connection() {
    for before in [0, 1] {
        let mut foreign = cleanup(19366);
        foreign["server_status_before"] = json!(before);
        let mut write = exchange(19369, "UPDATE users SET id=2 WHERE id=1");
        write["server_status_before"] = json!(0);
        write["response"]["server_status"] = json!(1);
        write["response"]["affected_rows"] = json!(1);
        for end in [commit(19370), cleanup(19370)] {
            // Physical sequence, not file order or other SQL in the case,
            // determines which transaction a boundary can belong to.
            let values = [
                write.clone(),
                end,
                foreign.clone(),
                exchange(19371, "ROLLBACK"),
            ];
            assert_eq!(
                classify_case(&[], &values),
                BTreeMap::from([
                    (2, OptionalSessionExchange::Rollback),
                    (3, OptionalSessionExchange::Rollback),
                ])
            );
        }
    }
}

#[test]
fn leading_rollback_needs_complete_identity_sequence_and_successful_plain_end() {
    for (field, value) in [
        ("connection_id", Value::Null),
        ("query_sequence", Value::Null),
        ("target_host", Value::Null),
        ("server_status_before", Value::Null),
        ("server_status_before", json!(9)),
        ("parse_warnings", json!(["incomplete"])),
        ("outcome", json!("client_terminated")),
        ("sql", json!("ROLLBACK AND CHAIN")),
        ("sql", json!("ROLLBACK TO SAVEPOINT s")),
        ("sql", json!("ROLLBACK; SELECT 1")),
        ("command", json!("COM_STMT_EXECUTE")),
    ] {
        let mut end = cleanup(118);
        end[field] = value;
        assert!(classify_case(&[], &[end]).is_empty(), "{field}");
    }
    for (field, value) in [
        ("status", json!("error")),
        ("server_status", Value::Null),
        ("server_status", json!(1)),
        ("server_status", json!(8)),
        ("affected_rows", json!(1)),
        ("last_insert_id", json!(1)),
        ("rows_truncated", json!(true)),
        ("error_code", json!(1205)),
    ] {
        let mut end = cleanup(118);
        end["response"][field] = value;
        assert!(classify_case(&[], &[end]).is_empty(), "response.{field}");
    }
    assert!(classify_case(&[], &[cleanup(118), cleanup(118)]).is_empty());
    assert!(
        classify_case(&[], &[commit(118)]).is_empty(),
        "unknown COMMIT is required"
    );
    assert!(
        classify_case(&[], &[read(116, 1), cleanup(118)]).is_empty(),
        "an earlier exchange on this connection blocks a leading-cleanup waiver even across a gap"
    );
}

#[test]
fn global_read_prefix_proves_commit_and_rollback_across_recording_buckets() {
    let global = [read(19364, 0), read(19365, 1)];
    for (end, kind) in [
        (commit(19366), OptionalSessionExchange::Commit),
        (cleanup(19366), OptionalSessionExchange::Rollback),
    ] {
        let mut other = read(1, 0);
        other["connection_id"] = json!(Uuid::new_v4());
        let values = [end, other, exchange(19367, "ROLLBACK")];
        assert_eq!(
            classify_case(&global, &values),
            BTreeMap::from([(0, kind), (2, OptionalSessionExchange::Rollback),])
        );
    }
    // The global file may contain later disconnected spans on this connection.
    // Retain each complete span's tail, not just the file's final read.
    let global = [
        read(19364, 0),
        read(19365, 1),
        read(19378, 0),
        read(19379, 1),
    ];
    assert_eq!(
        classify_case(&global, &[commit(19366)]).get(&0),
        Some(&OptionalSessionExchange::Commit)
    );
    assert_eq!(
        classify_case(&global, &[read(19366, 1), commit(19367)]).get(&1),
        Some(&OptionalSessionExchange::Commit)
    );
}

#[test]
fn global_commit_proof_rejects_gaps_writes_locks_and_incomplete_or_wrong_identity() {
    let global = [read(116, 0), read(117, 1)];
    for (index, field, value) in [
        (0, "server_status_before", Value::Null),
        (0, "server_status_before", json!(1)),
        (0, "sql", json!("UPDATE users SET id=2")),
        (0, "sql", json!("SELECT id FROM users FOR UPDATE")),
        (0, "sql", json!("SELECT GET_LOCK('x',1) FROM users")),
        (0, "query_sequence", json!(115)),
        (0, "query_sequence", Value::Null),
        (0, "connection_id", json!(Uuid::new_v4())),
        (0, "parse_warnings", json!(["incomplete"])),
        (1, "server_status_before", json!(0)),
        (1, "database", json!("other")),
    ] {
        let mut changed = global.clone();
        changed[index][field] = value;
        assert!(
            classify_case(&changed, &[commit(118)]).is_empty(),
            "{index}: {field}"
        );
    }
    for field in ["target_host", "database", "username"] {
        let mut changed = commit(118);
        changed[field] = json!("other");
        assert!(classify_case(&global, &[changed]).is_empty(), "{field}");
    }
    for index in 0..2 {
        let mut changed = global.clone();
        changed[index]["response"]["rows_truncated"] = json!(true);
        assert!(classify_case(&changed, &[commit(118)]).is_empty());
    }
    assert!(
        classify_case(
            &[global[0].clone(), global[0].clone(), global[1].clone()],
            &[commit(118)]
        )
        .is_empty()
    );
    assert!(classify_case(&global, &[commit(119)]).is_empty());
    let mut broken = commit(118);
    broken["server_status_before"] = json!(0);
    assert!(classify_case(&global, &[broken]).is_empty());
}

#[test]
fn case_loading_order_never_supplies_another_cases_missing_transaction_prefix() {
    let mut prefixes = ReadPrefixes::default();
    classify(&records(&[read(116, 0)]), ReplaySource::Case, &mut prefixes);
    assert!(
        classify(
            &records(&[read(117, 1), commit(118)]),
            ReplaySource::Case,
            &mut prefixes
        )
        .is_empty()
    );
    // Local complete read sessions use the same rule for COMMIT; writes do not.
    assert_eq!(
        classify_case(&[], &[read(116, 0), commit(117)]).get(&1),
        Some(&OptionalSessionExchange::Commit)
    );
}
