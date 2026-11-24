use super::*;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::DriverPrelude;
use uuid::Uuid;

fn startup() -> Vec<Value> {
    [
        "SET NAMES utf8mb4",
        "SET time_zone = '+00:00'",
        "SET AUTOCOMMIT = 0",
        "SET NAMES utf8mb4",
        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "COMMIT",
        "SELECT VERSION()",
        "SELECT DATABASE()",
        "SELECT @@transaction_isolation",
        "SELECT @@sql_mode",
        "SELECT @@lower_case_table_names",
        "ROLLBACK",
        "DESCRIBE migration_table",
        "ROLLBACK",
    ]
    .into_iter()
    .enumerate()
    .map(|(position, sql)| {
        let sequence = position as u64 + 1;
        let mut row = event();
        row["query_sequence"] = json!(sequence);
        row["sql"] = json!(sql);
        row["server_status_before"] = match position {
            0 => Value::Null,
            1 | 2 => json!(2),
            _ => json!(0),
        };
        let after = if position < 2 { 2 } else { 0 };
        if (6..=10).contains(&position) || position == 12 {
            row["response"]["server_status"] = json!(after);
        } else {
            row["response"] = json!({"status":"ok","server_status":after,"affected_rows":0,"last_insert_id":0});
        }
        row["capture"] = json!({
            "sequence":sequence*4,"exchange_id":Uuid::nil(),"process_epoch":Uuid::nil(),
            "phase":"startup","started_at":"2026-01-01T00:00:00Z",
            "attribution":{"kind":"startup","process_epoch":Uuid::nil(),"initialization_unit":"session"},
            "protocol_ref":ProtocolRef::connection("mysql", Uuid::nil(), sequence),
            "semantic_required":!matches!(position, 0 | 1 | 3),"effect_index":0,
        });
        row
    })
    .collect()
}

fn proven(rows: &[Value]) -> std::collections::BTreeMap<usize, DriverPrelude> {
    Native
        .prepare_event_session(&rows.iter().enumerate().collect::<Vec<_>>())
        .unwrap()
        .driver_prelude
}

#[test]
fn driver_proof_covers_only_the_complete_prefix_before_application_sql() {
    let rows = startup();
    let expected = [2, 4, 5, 6, 7, 8, 9, 10, 11]
        .map(|index| (index, DriverPrelude::MysqlSqlalchemyPymysql))
        .into();
    assert_eq!(proven(&rows), expected);
    assert!(proven(&rows[..12]).is_empty());
    let mut incomplete = rows.clone();
    incomplete.remove(7);
    assert!(proven(&incomplete).is_empty());

    let mut business_commit = rows.clone();
    business_commit[5]["server_status_before"] = json!(1);
    assert!(proven(&business_commit).is_empty());

    let mut business_read = rows;
    business_read[6]["sql"] = json!("SELECT name FROM application_table");
    assert!(proven(&business_read).is_empty());
}

#[test]
fn event_session_keeps_a_missing_table_error_as_a_matchable_application_event() {
    use traffic_protocol::connection::ReplaySessionStep;
    let mut rows = startup();
    rows[12]["sql"] = json!("DESCRIBE `schema`.`migration_table`");
    rows[12]["response"] =
        json!({"status":"error","error_code":1146,"error_message":"table is absent"});
    rows[13]["server_status_before"] = Value::Null;
    let prepare = |rows: &[Value]| {
        Native
            .prepare_event_session(&rows.iter().enumerate().collect::<Vec<_>>())
            .unwrap()
    };
    let ready = prepare(&rows);
    assert_eq!(ready.driver_prelude.len(), 10);
    assert!(!ready.driver_prelude.contains_key(&12));
    assert!(!ready.steps.contains_key(&12));
    assert_eq!(
        ready.driver_prelude[&13],
        DriverPrelude::MysqlIdleMetadataRollback
    );

    let mut cleanup_reports_active = rows.clone();
    cleanup_reports_active[13]["response"]["server_status"] = json!(1);
    assert!(!proven(&cleanup_reports_active).contains_key(&13));

    let mut wrong_lane_or_sequence = rows.clone();
    wrong_lane_or_sequence[13]["query_sequence"] = json!(15);
    assert!(!proven(&wrong_lane_or_sequence).contains_key(&13));

    rows[12]["server_status_before"] = json!(1);
    let active = prepare(&rows);
    assert_eq!(active.steps[&12], ReplaySessionStep::Unverified);
    assert!(!active.driver_prelude.contains_key(&13));
}

fn transaction_then_idle_rollback(terminal: &str, member_sql: &str) -> [Value; 3] {
    let [mut member, mut end] = locked_rollback_source();
    member["sql"] = json!(member_sql);
    if member_sql.starts_with("UPDATE") {
        member["response"] =
            json!({"status":"ok", "server_status":1,"affected_rows":1,"last_insert_id":0});
    }
    end["sql"] = json!(terminal);
    let mut cleanup = end.clone();
    cleanup["query_sequence"] = json!(30);
    cleanup["sql"] = json!("ROLLBACK");
    cleanup["server_status_before"] = json!(0);
    let mut rows = [member, end, cleanup];
    for (offset, row) in rows.iter_mut().enumerate() {
        let sequence = row["query_sequence"].as_u64().unwrap();
        row["capture_complete"] = json!(true);
        row["capture"] = json!({
            "sequence":sequence*4,"exchange_id":Uuid::from_u128(offset as u128 + 1),"process_epoch":Uuid::nil(),
            "phase":"startup","started_at":"2026-01-01T00:00:00Z",
            "attribution":{"kind":"startup","process_epoch":Uuid::nil(),"initialization_unit":"session"},
            "protocol_ref":ProtocolRef::connection("mysql", Uuid::nil(), sequence),
            "semantic_required":true,"effect_index":0,
        });
    }
    rows
}

#[test]
fn event_session_attests_clean_adjacent_idle_cleanup_but_keeps_the_real_terminal() {
    use traffic_protocol::connection::ReplaySessionStep;
    for (terminal, member) in [
        ("COMMIT", "UPDATE system_configs SET version=2 WHERE id=7"),
        (
            "ROLLBACK",
            "SELECT id FROM system_configs WHERE id=7 FOR UPDATE",
        ),
        ("ROLLBACK", "SELECT id FROM system_configs WHERE id=7"),
    ] {
        let rows = transaction_then_idle_rollback(terminal, member);
        let plan = Native
            .prepare_event_session(&rows.iter().enumerate().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(
            plan.driver_prelude,
            [(2, DriverPrelude::MysqlPostTransactionIdleRollback)].into()
        );
        assert!(matches!(
            plan.steps[&1],
            ReplaySessionStep::Continue { end: true, .. } | ReplaySessionStep::ReadOnlyEnd { .. }
        ));
        assert!(!plan.steps.contains_key(&2));
        assert!(proven(&rows[1..]).is_empty(), "missing transaction start");
    }
}

#[test]
fn idle_rollback_proof_ignores_only_index_diagnostics_before_the_real_terminal() {
    use traffic_protocol::connection::ReplaySessionStep;

    let rows = transaction_then_idle_rollback(
        "ROLLBACK",
        "SELECT id FROM system_configs ORDER BY version",
    );
    for previous in [0x11, 0x21, 0x31] {
        let mut captured = rows.clone();
        captured[0]["response"]["server_status"] = json!(previous);
        captured[1]["server_status_before"] = json!(previous);
        let plan = Native
            .prepare_event_session(&captured.iter().enumerate().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(
            plan.driver_prelude,
            [(2, DriverPrelude::MysqlPostTransactionIdleRollback)].into()
        );
        assert!(matches!(
            plan.steps[&1],
            ReplaySessionStep::Continue { end: true, .. } | ReplaySessionStep::ReadOnlyEnd { .. }
        ));
    }
    for invalid in [0x20, 0x23, 0x29, 0x61, 0x2021] {
        let mut captured = rows.clone();
        captured[0]["response"]["server_status"] = json!(invalid);
        captured[1]["server_status_before"] = json!(invalid);
        assert!(
            proven(&captured).is_empty(),
            "unexpected proof for {invalid:#x}"
        );
    }
}

#[test]
fn idle_rollback_exclusion_requires_an_unchanged_complete_adjacent_wire_control() {
    let rows =
        transaction_then_idle_rollback("COMMIT", "UPDATE system_configs SET version=2 WHERE id=7");
    for (field, value) in [
        ("connection_id", json!(Uuid::from_u128(7))),
        ("database", json!("other")),
        ("query_sequence", json!(31)),
        ("capture_complete", json!(false)),
        ("params", json!([])),
        ("parse_warnings", json!(["malformed packet"])),
        ("server_status_before", json!(1)),
        ("sql", json!("ROLLBACK AND CHAIN")),
        ("command", json!("COM_STMT_EXECUTE")),
    ] {
        let mut changed = rows.clone();
        changed[2][field] = value;
        assert!(
            proven(&changed).is_empty(),
            "unexpected proof with changed {field}"
        );
    }
    for (field, value) in [
        ("server_status", json!(0x40)),
        ("affected_rows", json!(1)),
        ("last_insert_id", json!(1)),
    ] {
        let mut changed = rows.clone();
        changed[2]["response"][field] = value;
        assert!(
            proven(&changed).is_empty(),
            "unexpected proof with changed {field}"
        );
    }
    let mut duplicate = rows.to_vec();
    duplicate.push(rows[2].clone());
    assert!(proven(&duplicate).is_empty());
    let mut interposed = rows[2].clone();
    interposed["sql"] = json!("SET @x=1");
    interposed["query_sequence"] = json!(30);
    let mut delayed = rows[2].clone();
    delayed["query_sequence"] = json!(31);
    delayed["capture"]["protocol_ref"] = json!(ProtocolRef::connection("mysql", Uuid::nil(), 31));
    delayed["capture"]["sequence"] = json!(124);
    assert!(proven(&[rows[0].clone(), rows[1].clone(), interposed, delayed]).is_empty());
}
