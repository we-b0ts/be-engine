use super::*;
use crate::{
    session_control::{SourceControl, classify_source_controls, prepare_source_transactions},
    transaction_source::GlobalReads,
};

fn verdicts(values: &[Value]) -> BTreeMap<usize, SourceControl> {
    let records = values
        .iter()
        .cloned()
        .map(|value| serde_json::from_value::<DependencyRecord>(value).unwrap())
        .collect::<Vec<_>>();
    classify_source_controls(records.iter().enumerate())
}

fn control(sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut value = exchange(sequence, sql);
    value["server_status_before"] = json!(before);
    value["response"]["server_status"] = json!(after);
    value
}

#[test]
fn read_rollback_and_pool_cleanup_have_distinct_verdicts_in_native_order() {
    let values = [control(63, "ROLLBACK", 0, 0), read(61, 0), cleanup(62)];
    assert_eq!(
        verdicts(&values),
        [
            (0, SourceControl::InactiveEnd),
            (2, SourceControl::ReadOnlyEnd)
        ]
        .into()
    );
    assert_eq!(
        verdicts(&values[..1]),
        [(0, SourceControl::InactiveEnd)].into()
    );
    assert!(verdicts(&values[2..]).is_empty(), "unknown active prefix");
    let mut corrupt = values.clone();
    corrupt[0]["server_status_before"] = Value::Null;
    assert_eq!(verdicts(&corrupt), [(2, SourceControl::ReadOnlyEnd)].into());
    corrupt = values.clone();
    corrupt[2]["server_status_before"] = json!(0);
    assert!(!verdicts(&corrupt).contains_key(&2), "contradictory status");
    corrupt[2]["query_sequence"] = json!(61);
    assert!(verdicts(&corrupt).is_empty(), "duplicated wire sequence");
}

#[test]
fn zero_row_writes_locking_reads_and_savepoints_retain_the_real_end() {
    for sql in [
        "UPDATE users SET id=2",
        "SELECT id FROM users FOR UPDATE",
        "SAVEPOINT x",
    ] {
        let mut strict = control(62, sql, 1, 1);
        if sql.starts_with("SELECT") {
            strict["response"] = read(62, 1)["response"].clone();
        }
        let values = [read(61, 0), strict, read(63, 1), cleanup(64)];
        assert!(verdicts(&values).is_empty(), "{sql}");
    }
}

#[test]
fn truncated_shape_and_discontinuous_identity_keep_active_cleanup_required() {
    let query = read(61, 0);
    let end = cleanup(62);
    for (field, value) in [
        ("rows_truncated", json!(true)),
        ("rows", json!([[]])),
        ("server_status", Value::Null),
    ] {
        let mut partial = query.clone();
        partial["response"][field] = value;
        assert!(verdicts(&[partial, end.clone()]).is_empty(), "{field}");
    }
    let mut different_schema = end.clone();
    different_schema["database"] = json!("other");
    assert!(verdicts(&[query.clone(), different_schema]).is_empty());
    let mut gap = end;
    gap["query_sequence"] = json!(63);
    assert!(verdicts(&[query, gap]).is_empty());
}

#[test]
fn mode_controls_require_independent_proof_of_their_safe_boundary() {
    let setup = control(60, "SET autocommit=0", 2, 0);
    let begin = control(61, "BEGIN", 0, 1);
    let end = control(63, "commit", 1, 0);
    let values = [setup.clone(), begin.clone(), read(62, 1), end.clone()];
    assert_eq!(
        verdicts(&values),
        [
            (0, SourceControl::AutocommitMode),
            (1, SourceControl::BeginMode),
            (3, SourceControl::ReadOnlyEnd)
        ]
        .into()
    );
    assert!(verdicts(&[begin.clone(), read(62, 1)]).is_empty());
    assert!(verdicts(&[control(61, "SET autocommit=0", 3, 1)]).is_empty());
    assert!(verdicts(&[control(61, "SET autocommit=1", 1, 2)]).is_empty());
    for sql in [
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET TRANSACTION READ ONLY",
        "SET @@session.tx_isolation='SERIALIZABLE'",
        "/*! SET TRANSACTION ISOLATION LEVEL SERIALIZABLE */",
    ] {
        let constraint = control(60, sql, 0, 0);
        assert!(
            verdicts(&[constraint, begin.clone(), read(62, 1), end.clone()]).is_empty(),
            "{sql}"
        );
    }
    assert!(
        verdicts(&[
            control(61, "START TRANSACTION WITH CONSISTENT SNAPSHOT", 0, 1),
            read(62, 1),
            end,
        ])
        .is_empty()
    );
}

#[test]
fn explicit_start_can_be_replaced_without_exempting_a_required_transaction_end() {
    for sql in ["UPDATE users SET id=2", "SELECT id FROM users FOR UPDATE"] {
        let begin = control(61, "BEGIN", 0, 1);
        let mut business = control(62, sql, 1, 1);
        if sql.starts_with("SELECT") {
            business["response"] = read(62, 1)["response"].clone();
        }
        let values = [begin, business, read(63, 1), cleanup(64)];
        let records =
            values.map(|value| serde_json::from_value::<DependencyRecord>(value).unwrap());
        let (controls, plans) = prepare_source_transactions(
            records.iter().enumerate(),
            ReplaySource::Unattributed,
            &GlobalReads::default(),
        );
        assert_eq!(controls, [(0, SourceControl::BeginMode)].into(), "{sql}");
        assert_eq!(plans[0].transactions[0].members, [0, 1, 2, 3], "{sql}");
        let (controls, _) = prepare_source_transactions(
            records[..3].iter().enumerate(),
            ReplaySource::Unattributed,
            &GlobalReads::default(),
        );
        assert!(controls.is_empty(), "unclosed {sql}");
    }
}
