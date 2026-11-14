use super::*;

fn segmented_reads() -> Vec<Value> {
    let base = records();
    let mut records = vec![base[0].clone()];
    for index in 0..7 {
        let first_sequence = 5 + 4 * index;
        for (offset, template) in base[1..4].iter().enumerate() {
            let mut record = template.clone();
            record["query_sequence"] = json!(first_sequence + offset as u64);
            records.push(record);
        }
    }
    records
}

fn case_optional(records: &[Value]) -> BTreeMap<usize, OptionalSessionExchange> {
    optional_in(records, ReplaySource::Case)
}

fn case_setups(records: &[Value]) -> Vec<usize> {
    case_optional(records)
        .into_iter()
        .filter_map(|(index, kind)| (kind == OptionalSessionExchange::Autocommit).then_some(index))
        .collect()
}

#[test]
fn case_initialization_is_optional_across_seven_completed_read_sessions() {
    let records = segmented_reads();
    assert_eq!(records.len(), 22);
    assert_eq!(case_setups(&records), [0]);
    let optional = case_optional(&records);
    assert_eq!(optional.len(), 15);
    for index in 0..7 {
        assert!(
            !optional.contains_key(&(1 + index * 3)),
            "business reads stay required"
        );
    }
    assert!(
        setups(&records).is_empty(),
        "Global post-read gaps remain strict"
    );
    let mut reversed = records;
    reversed.reverse();
    assert_eq!(case_setups(&reversed), [21]);
}

#[test]
fn case_boundaries_accept_rollback_commit_and_server_completed_autocommit_reads() {
    for ending in ["ROLLBACK", "COMMIT", "SET AUTOCOMMIT=1"] {
        let mut records = records();
        records.truncate(3);
        records[2]["sql"] = json!(ending);
        let after = if ending == "SET AUTOCOMMIT=1" { 2 } else { 0 };
        records[2]["response"]["server_status"] = json!(after);
        let mut next = records[1].clone();
        next["query_sequence"] = json!(9);
        next["server_status_before"] = json!(after);
        next["response"]["server_status"] = json!(after);
        records.push(next);
        if after == 0 {
            records.push(control(10, "ROLLBACK", 0, 0));
        }
        let setups = case_setups(&records);
        assert!(setups.contains(&0), "{ending}");
        assert_eq!(setups.contains(&2), after == 2, "{ending}");
    }
    // A successful SELECT in autocommit mode already ends its transaction.
    let mut records = records();
    records.truncate(2);
    records[0] = control(3, "SET AUTOCOMMIT=1", 2, 2);
    records[1]["server_status_before"] = json!(2);
    records[1]["response"]["server_status"] = json!(2);
    let mut next = records[1].clone();
    next["query_sequence"] = json!(9);
    records.push(next);
    assert_eq!(case_setups(&records), [0]);
}

#[test]
fn case_gaps_inside_active_transactions_cannot_borrow_read_proof() {
    let mut before_end = segmented_reads();
    for record in &mut before_end[2..] {
        record["query_sequence"] = json!(record["query_sequence"].as_u64().unwrap() + 1);
    }
    assert!(
        case_setups(&before_end).is_empty(),
        "gap before transaction end"
    );
    let mut between_reads = records();
    for record in &mut between_reads[2..] {
        record["query_sequence"] = json!(record["query_sequence"].as_u64().unwrap() + 2);
    }
    let mut next_read = between_reads[1].clone();
    next_read["query_sequence"] = json!(7);
    next_read["server_status_before"] = json!(1);
    between_reads.insert(2, next_read);
    assert!(
        case_setups(&between_reads).is_empty(),
        "gap between active reads"
    );
    let mut records = segmented_reads();
    records.truncate(5);
    assert!(
        case_setups(&records).is_empty(),
        "the final read must finish inactive"
    );
}

#[test]
fn case_gaps_never_hide_writes_locks_or_explicit_transactions() {
    for sql in [
        "UPDATE users SET id=2",
        "SELECT id FROM users FOR UPDATE",
        "BEGIN",
        "CALL business()",
        "SELECT GET_LOCK('x',1) FROM users",
        "SET autocommit=0,sql_mode=''",
    ] {
        let mut records = segmented_reads();
        let mut statement = records[1].clone();
        statement["query_sequence"] = json!(8);
        statement["sql"] = json!(sql);
        statement["server_status_before"] = json!(0);
        statement["response"]["server_status"] = json!(0);
        if !sql.starts_with("SELECT") {
            statement["response"] =
                json!({"status":"ok","server_status":0,"affected_rows":1,"last_insert_id":0});
        }
        records.insert(4, statement);
        assert!(case_setups(&records).is_empty(), "{sql}");
    }
}

#[test]
fn case_gap_boundaries_require_complete_consistent_connection_and_status_evidence() {
    for (field, value) in [
        ("connection_id", Value::Null),
        ("connection_id", json!(Uuid::new_v4())),
        ("query_sequence", Value::Null),
        ("database", json!("other")),
        ("username", json!("other")),
        ("server_status_before", Value::Null),
        ("server_status_before", json!(1)),
        ("server_status_before", json!(2)),
        ("server_status_before", json!(8)),
        ("server_status_before", json!(0x2000)),
        ("parse_warnings", json!(["incomplete"])),
        ("outcome", json!("client_terminated")),
    ] {
        let mut records = segmented_reads();
        records[4][field] = value;
        assert!(case_setups(&records).is_empty(), "{field}");
    }
    for (field, value) in [
        ("status", json!("error")),
        ("server_status", Value::Null),
        ("server_status", json!(1)),
        ("server_status", json!(8)),
        ("rows_truncated", json!(true)),
        ("affected_rows", json!(1)),
    ] {
        let mut records = segmented_reads();
        records[3]["response"][field] = value;
        assert!(case_setups(&records).is_empty(), "{field}");
    }
}

#[test]
fn case_initialization_does_not_borrow_an_end_from_another_case_or_connection() {
    let records = records();
    assert!(case_setups(&records[..2]).is_empty());
    assert!(case_setups(&records[2..]).is_empty());
    let mut mixed = records[..3].to_vec();
    mixed[2]["connection_id"] = json!(Uuid::new_v4());
    assert!(case_setups(&mixed).is_empty());
    let mut first = super::super::super::ReadPrefixes::default();
    let prepare = |slice: &[Value]| {
        slice
            .iter()
            .cloned()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect::<Vec<_>>()
    };
    super::super::super::classify(&prepare(&records[2..]), ReplaySource::Case, &mut first);
    assert!(
        !super::super::super::classify(&prepare(&records[..2]), ReplaySource::Case, &mut first)
            .values()
            .any(|kind| *kind == OptionalSessionExchange::Autocommit)
    );
}
