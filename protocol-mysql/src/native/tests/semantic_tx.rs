use super::*;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::{DriverPrelude, EventSessionPreparation, ReplaySessionStep};
use uuid::Uuid;

const READ: &str = "SELECT id FROM items WHERE id=7";
const WRITE: &str = "UPDATE items SET seen=1 WHERE id=7";

fn record(sequence: u64, wire: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut value = event();
    let start = chrono::DateTime::from_timestamp(1_767_225_600 + sequence as i64, 0).unwrap();
    value["request_started_at"] = json!(start);
    value["timestamp"] = json!(start + chrono::TimeDelta::milliseconds(1));
    value["capture_complete"] = json!(true);
    value["capture"] = json!({
        "sequence":sequence,"exchange_id":Uuid::from_u128(sequence.into()),
        "process_epoch":Uuid::nil(),"phase":"runtime","started_at":start,
        "attribution":{"kind":"startup","process_epoch":Uuid::nil(),"initialization_unit":"session"},
        "protocol_ref":ProtocolRef::connection("mysql", Uuid::nil(), wire),
        "semantic_required":true,"effect_index":0,
    });
    value["query_sequence"] = json!(wire);
    value["sql"] = json!(sql);
    value["server_status_before"] = json!(before);
    if sql.starts_with("SELECT ") {
        value["response"]["server_status"] = json!(after);
    } else {
        value["response"] = json!({
            "status":"ok","server_status":after,"affected_rows":u64::from(sql == WRITE),
            "last_insert_id":0,
        });
    }
    value
}

fn plan(rows: &[Value]) -> EventSessionPreparation {
    Native
        .prepare_event_session(&rows.iter().enumerate().collect::<Vec<_>>())
        .unwrap()
}

#[test]
fn an_implicit_read_span_keeps_queries_and_omits_its_rollback() {
    let mut rows = [
        record(4198, 40, READ, 0, 1),
        record(4260, 41, "SELECT id FROM kinds WHERE id=6", 1, 1),
        record(19806, 42, "ROLLBACK", 1, 0),
    ];
    let prepared = plan(&rows);
    assert!(prepared.steps.is_empty());
    assert_eq!(
        prepared.driver_prelude,
        [(2, DriverPrelude::MysqlReadOnlyTransactionEnd)].into()
    );

    rows[1]["capture_complete"] = json!(false);
    let incomplete = plan(&rows);
    assert_eq!(incomplete.steps[&0], ReplaySessionStep::ImplicitStart);
    assert!(incomplete.driver_prelude.is_empty());
}

#[test]
fn ordinary_prefix_reads_can_move_before_begin_but_the_write_tail_stays_bound() {
    let rows = [
        record(10, 1, "BEGIN", 2, 3),
        record(20, 2, READ, 3, 3),
        record(30, 3, WRITE, 3, 3),
        record(40, 4, "SELECT seen FROM items WHERE id=7", 3, 3),
        record(50, 5, "ROLLBACK", 3, 2),
    ];
    let prepared = plan(&rows);
    assert_eq!(
        prepared.driver_prelude,
        [(0, DriverPrelude::MysqlTransactionBegin)].into()
    );
    assert!(!prepared.steps.contains_key(&1));
    assert_eq!(prepared.steps[&2], ReplaySessionStep::Start);
    assert_eq!(
        prepared.steps[&3],
        ReplaySessionStep::Continue {
            after: ProtocolRef::connection("mysql", Uuid::nil(), 3),
            end: false,
        }
    );
    assert_eq!(
        prepared.steps[&4],
        ReplaySessionStep::Continue {
            after: ProtocolRef::connection("mysql", Uuid::nil(), 4),
            end: true,
        }
    );
}

#[test]
fn only_a_single_committed_update_can_use_autocommit() {
    let rows = [
        record(10, 1, "BEGIN", 2, 3),
        record(20, 2, WRITE, 3, 3),
        record(40, 3, "COMMIT", 3, 2),
    ];
    let prepared = plan(&rows);
    assert_eq!(
        prepared.driver_prelude,
        [(0, DriverPrelude::MysqlTransactionBegin)].into()
    );
    assert_eq!(prepared.steps[&1], ReplaySessionStep::AutocommitWrite);
    assert_eq!(
        prepared.steps[&2],
        ReplaySessionStep::AutocommitCommit {
            after: ProtocolRef::connection("mysql", Uuid::nil(), 2),
        }
    );

    let mut rollback = rows.clone();
    rollback[2]["sql"] = json!("ROLLBACK");
    assert_eq!(plan(&rollback).steps[&1], ReplaySessionStep::Start);

    let connection = Uuid::from_u128(2);
    let mut competing = record(30, 1, READ, 2, 2);
    competing["connection_id"] = json!(connection);
    competing["capture"]["protocol_ref"] = json!(ProtocolRef::connection("mysql", connection, 1));
    let mut interleaved = rows.to_vec();
    interleaved.push(competing);
    let strict = plan(&interleaved);
    assert_eq!(strict.steps[&1], ReplaySessionStep::Start);
    assert!(matches!(
        strict.steps[&2],
        ReplaySessionStep::Continue { end: true, .. }
    ));

    let mut competing = record(15, 1, READ, 2, 2);
    competing["connection_id"] = json!(connection);
    competing["capture"]["protocol_ref"] = json!(ProtocolRef::connection("mysql", connection, 1));
    let mut overlapping = rows.to_vec();
    overlapping.push(competing.clone());
    assert_eq!(
        plan(&overlapping).steps[&1],
        ReplaySessionStep::AutocommitWrite
    );

    overlapping[3]["timestamp"] = rows[2]["timestamp"].clone();
    assert_eq!(plan(&overlapping).steps[&1], ReplaySessionStep::Start);
    overlapping[3]["timestamp"] = Value::Null;
    assert_eq!(plan(&overlapping).steps[&1], ReplaySessionStep::Start);

    overlapping[3]["target_host"] = json!("different.test");
    assert_eq!(
        plan(&overlapping).steps[&1],
        ReplaySessionStep::AutocommitWrite
    );
}

#[test]
fn the_semantic_projection_keeps_locking_reads_and_explicit_snapshot_constraints() {
    let locked = [
        record(10, 1, "BEGIN", 2, 3),
        record(20, 2, "SELECT id FROM items WHERE id=7 FOR UPDATE", 3, 3),
        record(30, 3, "ROLLBACK", 3, 2),
    ];
    let prepared = plan(&locked);
    assert!(prepared.driver_prelude.is_empty());
    assert_eq!(prepared.steps[&0], ReplaySessionStep::Start);
    assert!(matches!(
        prepared.steps[&1],
        ReplaySessionStep::Continue { end: false, .. }
    ));

    let snapshot = [
        record(
            10,
            1,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
            2,
            2,
        ),
        record(20, 2, "BEGIN", 2, 3),
        record(30, 3, READ, 3, 3),
        record(40, 4, "ROLLBACK", 3, 2),
    ];
    let prepared = plan(&snapshot);
    assert!(prepared.driver_prelude.is_empty());
    assert_eq!(prepared.steps[&1], ReplaySessionStep::Start);
}
