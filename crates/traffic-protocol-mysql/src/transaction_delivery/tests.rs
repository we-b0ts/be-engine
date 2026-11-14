use super::*;
use serde_json::json;
mod error_rollback;
mod implicit_native;
mod member_comparison;
mod prefix;

use super::test_support::records;
use crate::session_identity::{DependencyIdentity, identity_from_exchange};
type Witness = super::Witness<TestEvidence>;
type RecordedMysqlExchange = crate::recorded::RecordedMysqlExchange<TestEvidence>;

#[derive(Debug, Clone)]
struct TestEvidence;
impl RecordSource for TestEvidence {
    fn load<T: serde::de::DeserializeOwned>(&self) -> anyhow::Result<T> {
        anyhow::bail!("inline fixture has no external evidence")
    }
}

struct ReplayExchange {
    record: RecordedMysqlExchange,
    identity: DependencyIdentity,
    source: ReplaySource,
    case_id: Option<String>,
    optional_session: Option<OptionalSessionExchange>,
}

impl SessionContext for [ReplayExchange] {
    type Evidence = TestEvidence;

    fn exchange(&self, index: usize) -> SourceExchange<'_, TestEvidence> {
        let exchange = &self[index];
        SourceExchange {
            record: &exchange.record,
            identity: &exchange.identity,
            source: exchange.source,
            case_id: exchange.case_id.as_deref(),
            optional_session: exchange.optional_session,
        }
    }

    fn available(&self, _index: usize) -> bool {
        true
    }
    fn admitted(&self, _index: usize) -> bool {
        false
    }
    fn delivered(&self, _index: usize) -> bool {
        false
    }
}

fn registry(values: &[Value]) -> Registry {
    registry_with_exchanges(values).0
}

fn registry_with_exchanges(values: &[Value]) -> (Registry, Vec<ReplayExchange>) {
    let records: Vec<RecordedMysqlExchange> = values
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    let mut registry = Registry::default();
    let plans = registry.prepare(
        records.iter().enumerate(),
        &BTreeMap::new(),
        ReplaySource::Case,
    );
    let exchanges: Vec<_> = records
        .into_iter()
        .map(|record| ReplayExchange {
            source: ReplaySource::Case,
            case_id: Some("case".into()),
            identity: identity_from_exchange(&record).unwrap(),
            record,
            optional_session: None,
        })
        .collect();
    let mapping = (0..exchanges.len()).map(|i| (i, i)).collect();
    let _ = registry.install(plans, &mapping, exchanges.as_slice());
    (registry, exchanges)
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
fn fast_dispatch_defers_only_coverage_for_future_transactions() {
    let mut values = records();
    let at = |seconds| DateTime::from_timestamp(seconds, 0).unwrap();
    for value in &mut values {
        value["request_started_at"] = json!(at(value["query_sequence"].as_i64().unwrap()));
    }
    let (mut registry, exchanges) = registry_with_exchanges(&values);
    assert!(!registry.can_defer_setup(0, at(8), |i| exchanges[i].record.request_started_at));
    let mut first = Witness::default();
    assert!(segment(&mut registry, &mut first, &[1, 2, 3], "COMMIT").is_empty());
    assert!(registry.can_defer_setup(0, at(8), |i| exchanges[i].record.request_started_at));
    assert!(!registry.can_defer_setup(0, at(10), |i| exchanges[i].record.request_started_at));
    assert!(!registry.can_defer_setup(0, at(11), |i| exchanges[i].record.request_started_at));

    let mut second = Witness::default();
    assert_eq!(
        segment(&mut registry, &mut second, &[5, 6, 7], "COMMIT"),
        vec![0]
    );
}

#[test]
fn fast_dispatch_uses_the_proven_prefix_before_a_later_source_status_gap() {
    let at = |seconds| DateTime::from_timestamp(seconds, 0).unwrap();
    let mut values = records();
    // After the first committed transaction and its idle rollback, the
    // selected scope skips a read on the same physical connection.
    values[5]["query_sequence"] = 11.into();
    values[5]["server_status_before"] = 1.into();
    values[6]["query_sequence"] = 12.into();
    values[7]["query_sequence"] = 13.into();
    for value in &mut values {
        let sequence = value["query_sequence"].as_i64().unwrap();
        value["request_started_at"] = json!(at(sequence));
        value["timestamp"] = json!(at(sequence));
    }
    let (mut registry, exchanges) = registry_with_exchanges(&values);
    assert_eq!(
        registry.diagnostic(0).unwrap()["reason"],
        "source_status_discontinuous"
    );
    assert!(!registry.can_defer_setup(0, at(7), |i| exchanges[i].record.request_started_at));
    assert!(segment(&mut registry, &mut Witness::default(), &[1, 2, 3], "COMMIT").is_empty());
    assert!(registry.can_defer_setup(0, at(7), |i| exchanges[i].record.request_started_at));
    assert!(!registry.can_defer_setup(0, at(8), |i| exchanges[i].record.request_started_at));
    assert_eq!(
        registry.diagnostic(0).unwrap()["reason"],
        "source_status_discontinuous",
        "dispatch cannot certify final omission"
    );

    values[6]["request_started_at"] = json!(at(6));
    let (mut reversed, exchanges) = registry_with_exchanges(&values);
    assert!(segment(&mut reversed, &mut Witness::default(), &[1, 2, 3], "COMMIT").is_empty());
    assert!(!reversed.can_defer_setup(0, at(7), |i| exchanges[i].record.request_started_at));
}

#[test]
fn fast_dispatch_stops_at_the_start_of_a_later_incomplete_transaction() {
    let at = |seconds| DateTime::from_timestamp(seconds, 0).unwrap();
    let mut values = records();
    // The second implicit transaction has a missing read between its
    // first SELECT and its later UPDATE, while the first one is complete.
    values[6]["query_sequence"] = 11.into();
    values[7]["query_sequence"] = 12.into();
    for value in &mut values {
        let sequence = value["query_sequence"].as_i64().unwrap();
        value["request_started_at"] = json!(at(sequence));
        value["timestamp"] = json!(at(sequence));
    }
    let (mut registry, exchanges) = registry_with_exchanges(&values);
    assert_eq!(
        registry.diagnostic(0).unwrap()["reason"],
        "source_sequence_gap"
    );
    assert!(segment(&mut registry, &mut Witness::default(), &[1, 2, 3], "COMMIT").is_empty());
    assert!(registry.can_defer_setup(0, at(8), |i| exchanges[i].record.request_started_at));
    assert!(!registry.can_defer_setup(0, at(9), |i| exchanges[i].record.request_started_at));
    assert!(!registry.can_defer_setup(0, at(10), |i| exchanges[i].record.request_started_at));
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
    values[1]["sql"] = json!("SELECT @session_value FROM users WHERE id=1");
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
fn a_real_complete_locking_transaction_can_prove_default_autocommit_equivalence() {
    let mut values = records();
    values.truncate(4);
    values[1]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    let mut r = registry(&values);
    assert!(r.requires_witness(3));
    assert_eq!(
        segment(&mut r, &mut Witness::default(), &[1, 2, 3], "COMMIT"),
        vec![0]
    );
    let proof = r.diagnostic(0).unwrap();
    assert_eq!(proof["covered_transaction_count"], 1);
    assert_eq!(proof["reason"], "equivalent_write_transactions");
    assert_eq!(
        proof["source_transactions"][0]["strict_source_effects"],
        true
    );
    assert_eq!(
        proof["source_transactions"][0]["autocommit_eligible"],
        false
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

fn gap_records() -> (Vec<Value>, Vec<Value>) {
    let base = records();
    let mut case = base[1..4].to_vec();
    case[0]["query_sequence"] = json!(1);
    case[1]["query_sequence"] = json!(3);
    case[2]["query_sequence"] = json!(4);
    let mut global = case[0].clone();
    global["query_sequence"] = json!(2);
    global["server_status_before"] = json!(1);
    global["sql"] = json!("SELECT id FROM teams WHERE id=2");
    (case, vec![global])
}

fn scoped_plans(case: &[Value], global: &[Value]) -> Vec<source::Plan> {
    let decode = |values: &[Value]| {
        values
            .iter()
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .collect::<Vec<RecordedMysqlExchange>>()
    };
    let mut registry = Registry::default();
    let _ = registry.prepare(
        decode(global).iter().enumerate(),
        &BTreeMap::new(),
        ReplaySource::Startup,
    );
    registry.prepare(
        decode(case).iter().enumerate(),
        &BTreeMap::new(),
        ReplaySource::Case,
    )
}

#[test]
fn global_read_facts_only_complete_an_ordinary_prewrite_gap() {
    let (case, global) = gap_records();
    let plans = scoped_plans(&case, &global);
    assert!(plans[0].reason.is_none());
    assert!(plans[0].failed_ends.is_empty());
    assert_eq!(plans[0].transactions.len(), 1);
    assert_eq!(plans[0].transactions[0].write_count, 1);
    assert_eq!(plans[0].transactions[0].members, vec![0, 1, 2]);

    let mut variants = vec![Vec::new(), vec![global[0].clone(), global[0].clone()]];
    for (field, value) in [
        ("sql", json!("SELECT id FROM teams WHERE id=2 FOR UPDATE")),
        ("sql", json!("SELECT @@autocommit")),
        ("sql", json!("UPDATE teams SET active=1 WHERE id=2")),
        ("database", json!("another_database")),
        ("connection_id", json!(Uuid::from_u128(17))),
        ("server_status_before", json!(0)),
        ("server_status_before", Value::Null),
    ] {
        let mut changed = global.clone();
        changed[0][field] = value;
        variants.push(changed);
    }
    let mut truncated = global.clone();
    truncated[0]["response"]["rows_truncated"] = json!(true);
    variants.push(truncated);
    let mut missing_after = global.clone();
    missing_after[0]["response"]["server_status"] = Value::Null;
    variants.push(missing_after);
    let mut case_overlap = global.clone();
    case_overlap.push(case[0].clone());
    variants.push(case_overlap);
    for global in variants {
        let plans = scoped_plans(&case, &global);
        assert_eq!(plans[0].reason, Some("source_sequence_gap"));
        assert!(plans[0].transactions.is_empty());
        let rejected = &plans[0].failed_ends[0];
        assert_eq!(rejected.source_query_sequence, Some(4));
        assert_eq!(rejected.failure_query_sequence, Some(3));
        assert_eq!(rejected.missing_query_sequences, vec![2]);
    }
}

#[test]
fn global_reads_after_the_first_write_or_an_explicit_start_never_bridge() {
    let (case, global) = gap_records();
    for mode in ["write", "begin", "lock"] {
        let mut case = case.clone();
        if mode == "write" {
            case[0] = case[1].clone();
            case[0]["query_sequence"] = json!(1);
            case[0]["server_status_before"] = json!(0);
        } else if mode == "begin" {
            case[0]["sql"] = json!("BEGIN");
            case[0]["response"] = json!({"status":"ok","server_status":1,
                "affected_rows":0,"last_insert_id":0});
        } else {
            case[0]["sql"] = json!("SELECT id FROM users FOR UPDATE");
        }
        let plans = scoped_plans(&case, &global);
        assert_eq!(plans[0].reason, Some("source_sequence_gap"), "{mode}");
        assert!(plans[0].transactions.is_empty(), "{mode}");
    }
}

#[test]
fn an_unproven_span_keeps_its_end_diagnostic_and_recovers_later_complete_groups() {
    let (mut case, _) = gap_records();
    let mut later = case.clone();
    for (record, sequence) in later.iter_mut().zip([5, 6, 7]) {
        record["query_sequence"] = json!(sequence);
    }
    case.extend(later);
    let mut r = registry(&case);
    assert_eq!(r.requirements[0].transactions.len(), 1);
    assert_eq!(r.requirements[0].transactions[0].last_sequence, 7);
    let rejected = r.diagnostic(2).unwrap();
    assert_eq!(rejected["reason"], "source_sequence_gap");
    assert_eq!(
        rejected["source_proof_rejection"]["missing_query_sequences"],
        json!([2])
    );
    assert!(
        rejected["source_transactions"][0]
            .get("write_count")
            .is_none()
    );
    assert!(
        rejected["source_transactions"][0]
            .get("target_status_before")
            .is_none()
    );
    assert!(segment(&mut r, &mut Witness::default(), &[3, 4, 5], "COMMIT").is_empty());
    assert!(
        r.requirements[0].transactions[0]
            .witness
            .unwrap()
            .transaction
            .is_some()
    );
    assert_eq!(r.requirements[0].source_reason, Some("source_sequence_gap"));
}

#[test]
fn an_end_without_a_connection_has_a_rejection_instead_of_missing_diagnostics() {
    let mut values = vec![records()[3].clone()];
    values[0]["connection_id"] = Value::Null;
    let r = registry(&values);
    let proof = r.diagnostic(0).unwrap();
    assert_eq!(proof["reason"], "source_connection_missing");
    assert!(proof["source_transactions"][0]["source_connection_id"].is_null());
}

#[test]
fn a_large_unproven_gap_retains_only_bounded_missing_sequence_evidence() {
    let (mut case, global) = gap_records();
    case[1]["query_sequence"] = json!(u64::MAX - 1);
    case[2]["query_sequence"] = json!(u64::MAX);
    let plans = scoped_plans(&case, &global);
    assert!(plans[0].transactions.is_empty());
    let rejected = &plans[0].failed_ends[0];
    assert_eq!(rejected.reason, "source_sequence_gap");
    assert_eq!(
        rejected.missing_query_sequences,
        (2..10).collect::<Vec<_>>()
    );
    assert_eq!(rejected.omitted_missing_query_sequences, u64::MAX - 11);
}
