use super::*;
use serde_json::json;

pub(crate) fn records() -> Vec<Value> {
    let control = |seq, sql, before, after| {
        json!({
            "event_type":"mysql_exchange", "connection_id":Uuid::nil(), "query_sequence":seq,
            "target_host":"127.0.0.1", "target_port":3306, "database":"appdb", "username":"root",
            "command":"COM_QUERY", "sql":sql, "server_status_before":before,
            "response":{"status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0}
        })
    };
    let read = |seq| {
        let mut r = control(seq, "SELECT id FROM users WHERE id=1", 0, 1);
        r["response"] = json!({"status":"resultset", "server_status":1,
            "columns":[{"name":"id", "family":"integer", "sql_type":"INT"}],
            "rows":[[{"kind":"integer", "value":1}]]});
        r
    };
    vec![
        control(3, "SET AUTOCOMMIT = 0", 2, 0),
        read(5),
        control(6, "UPDATE users SET active=1 WHERE id=1", 1, 1),
        control(7, "COMMIT", 1, 0),
        control(8, "ROLLBACK", 0, 0),
        read(9),
        control(10, "UPDATE users SET active=2 WHERE id=1", 1, 1),
        control(11, "COMMIT", 1, 0),
    ]
}

fn registry(values: &[Value]) -> Registry {
    let records: Vec<crate::replay::dependencies::DependencyRecord> = values
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    let plans = Registry::prepare(&records, &BTreeMap::new());
    let exchanges: Vec<_> = records
        .into_iter()
        .map(|r| {
            let crate::replay::dependencies::DependencyRecord::MysqlExchange(record) = r else {
                panic!()
            };
            ReplayExchange {
                source: ReplaySource::Case,
                case_id: Some("case".into()),
                identity: identity_from_exchange(&record).unwrap(),
                record: *record,
                optional_session: None,
                status: ReplayExchangeStatus::Available,
                timing: ReplayExchangeTiming::from_recorded(
                    0,
                    crate::DependencyExchangeOutcome::Response,
                ),
            }
        })
        .collect();
    let mapping = (0..exchanges.len()).map(|i| (i, i)).collect();
    let mut registry = Registry::default();
    let _ = registry.install(plans, &mapping, &exchanges);
    registry
}

fn segment(
    registry: &mut Registry,
    witness: &mut Witness,
    indices: &[usize],
    ending: &str,
) -> Vec<usize> {
    registry.observe(witness, "BEGIN", None, true);
    for &index in &indices[..indices.len() - 1] {
        registry.observe(witness, "UPDATE users SET active=1", Some(index), true);
    }
    registry.observe(witness, ending, indices.last().copied(), true)
}

#[test]
fn all_implicit_transactions_need_distinct_complete_target_transactions() {
    let mut r = registry(&records());
    let mut first = Witness::default();
    assert!(segment(&mut r, &mut first, &[1, 2, 3], "COMMIT").is_empty());
    assert_eq!(r.diagnostic(0).unwrap()["covered_transaction_count"], 1);
    let mut second = Witness::default();
    assert_eq!(segment(&mut r, &mut second, &[5, 6, 7], "COMMIT"), vec![0]);
    let diagnostic = r.diagnostic(0).unwrap();
    assert_eq!(diagnostic["reason"], "equivalent_write_transactions");
    assert_eq!(diagnostic["covered_transaction_count"], 2);
    assert_ne!(
        diagnostic["source_transactions"][0]["target_connection_id"],
        diagnostic["source_transactions"][1]["target_connection_id"]
    );
}

#[test]
fn missing_split_merged_reordered_or_different_end_cannot_satisfy_setup() {
    for (indices, ending) in [
        (vec![1, 3], "COMMIT"),
        (vec![2, 1, 3], "COMMIT"),
        (vec![1, 2, 3, 5, 6, 7], "COMMIT"),
        (vec![1, 2, 3], "ROLLBACK"),
        (vec![1, 2, 4], "COMMIT"),
    ] {
        let mut r = registry(&records());
        assert!(segment(&mut r, &mut Witness::default(), &indices, ending).is_empty());
        assert_ne!(
            r.diagnostic(0).unwrap()["reason"],
            "equivalent_write_transactions"
        );
    }
    let mut r = registry(&records());
    let mut unscoped = Witness::default();
    r.observe(&mut unscoped, "UPDATE users SET active=1", Some(2), true);
    assert!(segment(&mut r, &mut Witness::default(), &[1, 2, 3], "COMMIT").is_empty());
    assert_eq!(r.diagnostic(0).unwrap()["covered_transaction_count"], 0);
}

#[test]
fn nested_failed_and_foreign_connection_ends_cannot_supply_a_witness() {
    let mut values = records();
    values.truncate(4);
    for mode in ["nested", "failed", "foreign", "builtin"] {
        let mut r = registry(&values);
        let mut witness = Witness::default();
        r.observe(&mut witness, "BEGIN", None, true);
        r.observe(&mut witness, "SELECT id FROM users", Some(1), true);
        match mode {
            "nested" => {
                r.observe(&mut witness, "BEGIN", None, true);
            }
            "failed" => {
                r.observe(&mut witness, "UPDATE users", Some(2), false);
            }
            "builtin" => {
                r.observe(&mut witness, "SET autocommit=1", None, true);
            }
            _ => {}
        }
        r.observe(&mut witness, "UPDATE users", Some(2), true);
        let mut foreign = Witness::default();
        let end_witness = if mode == "foreign" {
            &mut foreign
        } else {
            &mut witness
        };
        assert!(
            r.observe(end_witness, "COMMIT", Some(3), true).is_empty(),
            "{mode}"
        );
    }
}

#[test]
fn rollback_is_a_distinct_supported_transaction_end() {
    let mut values = records();
    values.truncate(4);
    values[3]["sql"] = json!("ROLLBACK");
    let mut r = registry(&values);
    assert_eq!(
        segment(&mut r, &mut Witness::default(), &[1, 2, 3], "ROLLBACK"),
        vec![0]
    );
}

#[test]
fn strict_source_effects_require_coverage_without_granting_setup_omission() {
    let mut values = records();
    values.truncate(4);
    values[1]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    let mut r = registry(&values);
    assert!(r.requires_witness(3));
    assert!(segment(&mut r, &mut Witness::default(), &[1, 2, 3], "COMMIT").is_empty());
    let proof = r.diagnostic(0).unwrap();
    assert_eq!(proof["covered_transaction_count"], 1);
    assert_eq!(proof["reason"], "source_statement_effects_unsupported");
    assert_eq!(
        proof["source_transactions"][0]["strict_source_effects"],
        true
    );
    assert!(!r.requires_witness(3));
}

#[test]
fn transaction_order_is_required_but_pending_end_delivery_is_not_a_pool_race() {
    let mut r = registry(&records());
    assert!(segment(&mut r, &mut Witness::default(), &[5, 6, 7], "COMMIT").is_empty());
    assert_eq!(r.diagnostic(0).unwrap()["covered_transaction_count"], 0);

    let mut r = registry(&records());
    let mut first = Witness::default();
    let mut second = Witness::default();
    r.observe(&mut first, "BEGIN", None, true);
    r.observe(&mut first, "SELECT id FROM users", Some(1), true);
    r.observe(&mut first, "UPDATE users", Some(2), true);
    // First COMMIT is already admitted; its socket has not finished delivery bookkeeping.
    r.observe(&mut second, "BEGIN", None, true);
    r.observe_delivery(
        &mut second,
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql: "SELECT id FROM users",
            index: Some(5),
            successful: true,
            before: 3,
            after: 3,
        },
        |index| index == 3,
    );
    r.observe_delivery(
        &mut second,
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql: "UPDATE users",
            index: Some(6),
            successful: true,
            before: 3,
            after: 3,
        },
        |index| index == 3,
    );
    assert!(r.observe(&mut second, "COMMIT", Some(7), true).is_empty());
    assert_eq!(r.diagnostic(0).unwrap()["covered_transaction_count"], 1);
    assert_eq!(r.observe(&mut first, "COMMIT", Some(3), true), vec![0]);
}

#[test]
fn duplicate_end_identity_cannot_leave_a_partial_omission_proof() {
    let mut values = records();
    values.push(values[3].clone());
    let r = registry(&values);
    assert!(r.requirements[0].transactions.is_empty());
    assert_eq!(
        r.diagnostic(0).unwrap()["reason"],
        "source_sequence_ambiguous"
    );
}

#[test]
fn incomplete_or_unsupported_source_never_grants_omission() {
    let base = records();
    let mut variants = Vec::new();
    let mut change = |index: usize, field: &str, value: Value| {
        let mut records = base.clone();
        records[index][field] = value;
        variants.push(records);
    };
    change(1, "server_status_before", Value::Null);
    change(2, "query_sequence", json!(50));
    change(2, "query_sequence", json!(5));
    change(2, "database", json!("other"));
    change(2, "sql", json!("ALTER TABLE users ADD x INT"));
    change(2, "sql", json!("CALL business()"));
    change(2, "sql", json!("UPDATE users SET active=@value"));
    change(
        2,
        "sql",
        json!("UPDATE users SET active=1; DELETE FROM users"),
    );
    change(2, "parse_warnings", json!(["incomplete"]));
    change(
        2,
        "response",
        json!({"status":"error", "server_status":1,"error_code":1205}),
    );
    variants.push(base[..3].to_vec());
    for values in variants {
        let r = registry(&values);
        assert!(
            r.requirements[0].blocked
                || r.requirements[0].source_reason.is_some()
                || r.requirements[0]
                    .transactions
                    .iter()
                    .any(|t| t.strict || !t.autocommit_eligible()),
            "{values:?}"
        );
    }
}

#[test]
fn diagnostics_focus_the_selected_transaction_after_the_first_eight() {
    let base = records();
    let mut values = vec![base[0].clone()];
    values[0]["query_sequence"] = json!(1);
    for transaction in 0..10 {
        for (offset, original) in [1, 2, 3].into_iter().enumerate() {
            let mut record = base[original].clone();
            record["query_sequence"] = json!(2 + transaction * 3 + offset);
            values.push(record);
        }
    }
    let r = registry(&values);
    let selected = r.diagnostic(30).unwrap();
    assert_eq!(
        selected["source_transactions"][0]["last_query_sequence"],
        31
    );
    assert_eq!(selected["source_transactions"].as_array().unwrap().len(), 8);
    assert_eq!(selected["omitted_transactions"], 2);
    assert_eq!(
        r.diagnostic(0).unwrap()["source_transactions"][0]["last_query_sequence"],
        4
    );
}

#[test]
fn an_unclosed_tail_cannot_erase_a_preceding_multi_write_obligation() {
    let mut values = records();
    values.truncate(4);
    let mut extra = values[2].clone();
    extra["query_sequence"] = json!(7);
    extra["sql"] = json!("UPDATE users SET active=2 WHERE id=1");
    values[3]["query_sequence"] = json!(8);
    values.insert(3, extra);
    let mut tail = records()[5].clone();
    tail["query_sequence"] = json!(9);
    values.push(tail);
    let mut r = registry(&values);
    assert!(r.requires_witness(4));
    assert_eq!(
        r.diagnostic(4).unwrap()["reason"],
        "source_transaction_unclosed"
    );
    let observation = r.observe_delivery(
        &mut Witness::default(),
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql: "UPDATE users SET active=1 WHERE id=1",
            index: Some(2),
            successful: true,
            before: 2,
            after: 2,
        },
        |_| false,
    );
    assert!(observation.violation.is_some());
    assert_eq!(
        r.diagnostic(4).unwrap()["reason"],
        "target_transaction_missing"
    );
}

#[test]
fn failed_update_status_requires_a_consecutive_end_and_never_a_failed_rollback() {
    for gap in [false, true] {
        let mut values = records();
        values = vec![values[2].clone(), values[3].clone()];
        values[0]["query_sequence"] = json!(1);
        values[0]["server_status_before"] = json!(0);
        values[0]["response"] =
            json!({"status":"error","error_code":1205,"error_message":"update failed"});
        values[1]["query_sequence"] = json!(if gap { 3 } else { 2 });
        values[1]["sql"] = json!("ROLLBACK");
        values[1]["server_status_before"] = json!(0);
        let r = registry(&values);
        if gap {
            assert!(r.requirements[0].transactions.is_empty());
            assert!(r.requirements[0].source_reason.is_some());
        } else {
            assert!(r.requirements[0].transactions[0].autocommit_eligible());
        }
        values[1]["response"] =
            json!({"status":"error","error_code":2013,"error_message":"rollback failed"});
        let r = registry(&values);
        assert!(r.requirements[0].transactions.is_empty());
        assert!(r.requirements[0].source_reason.is_some());
    }
}
