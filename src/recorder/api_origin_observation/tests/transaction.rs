use super::*;

fn rule() -> BackgroundDependencyRuleConfig {
    let mut rule = mysql_rule();
    if let BackgroundDependencyRuleConfig::Mysql {
        selector,
        include_transaction_boundaries,
        transaction_members,
        ..
    } = &mut rule
    {
        selector.sql = "UPDATE {{table}} SET state='done' WHERE id=?".into();
        *include_transaction_boundaries = true;
        transaction_members.push(serde_json::from_value(json!({
            "target_host": "db.test", "target_port": 3306, "database": "app", "username": "writer",
            "sql": "SELECT id FROM {{table}} WHERE kind='audit' LIMIT 1", "table_patterns": ["audit_*"]
        })).unwrap());
    }
    rule
}

fn begin(scope: &ApiOriginScope, connection: Uuid) {
    assert!(mysql(scope, connection, "BEGIN").is_none());
    let mut event = exchange("BEGIN", connection, 1);
    event.response.affected_rows = Some(0);
    event.response.server_status = Some(3);
    observe(scope, event);
}

fn anchor(scope: &ApiOriginScope, connection: Uuid, id: u64, sequence: u64) {
    let sql = format!("UPDATE jobs_0001 SET state='done' WHERE id={id}");
    assert_eq!(
        mysql(scope, connection, &sql),
        Some(SelectionScope::BoundIdentity)
    );
    let mut event = exchange(&sql, connection, sequence);
    event.server_status_before = Some(3);
    event.response.server_status = Some(3);
    observe(scope, event);
}

#[test]
fn a_confirmed_begin_anchor_and_member_can_select_the_real_terminal_request() {
    let scope = scope(&[rule()]);
    observe(&scope, insert(12));
    let connection = Uuid::new_v4();
    begin(&scope, connection);
    anchor(&scope, connection, 12, 2);
    let member = "SELECT id FROM audit_0001 WHERE kind='audit' LIMIT 1";
    assert_eq!(
        mysql(&scope, connection, member),
        Some(SelectionScope::BoundIdentity)
    );
    let mut event = exchange(member, connection, 3);
    event.server_status_before = Some(3);
    event.response.server_status = Some(3);
    event.response.status = "resultset".into();
    event.response.affected_rows = None;
    event.response.columns.push(crate::recorder::MysqlColumn {
        name: "id".into(),
        table: None,
        column: None,
        family: "integer".into(),
        sql_type: "BIGINT".into(),
        unsigned: None,
        bits: None,
        nullable: None,
        scale: None,
        column_type_code: 8,
        flags: None,
    });
    event.response.rows = vec![vec![MysqlValue {
        kind: "integer".into(),
        value: Some(1.into()),
        raw: None,
    }]];
    event.response.row_count = 1;
    observe(&scope, event);
    assert_eq!(
        mysql(&scope, connection, "COMMIT"),
        Some(SelectionScope::BoundIdentity)
    );
    assert!(mysql(&scope, connection, "COMMIT").is_none());
}

#[test]
fn terminals_without_a_real_begin_or_without_an_anchor_never_extend_the_window() {
    let scope = scope(&[rule()]);
    observe(&scope, insert(12));
    let connection = Uuid::new_v4();
    assert!(mysql(&scope, connection, "COMMIT").is_none());
    anchor(&scope, connection, 12, 2);
    assert!(mysql(&scope, connection, "ROLLBACK").is_none());
    begin(&scope, connection);
    assert!(mysql(&scope, connection, "COMMIT").is_none());
    let mut failed = exchange("BEGIN", connection, 1);
    failed.response.status = "error".into();
    failed.response.server_status = Some(3);
    observe(&scope, failed);
    anchor(&scope, connection, 12, 2);
    assert!(mysql(&scope, connection, "COMMIT").is_none());
}

#[test]
fn unrelated_statements_connections_and_sequence_gaps_cannot_inherit_an_anchor() {
    let scope = scope(&[rule()]);
    observe(&scope, insert(12));
    let connection = Uuid::new_v4();
    begin(&scope, connection);
    anchor(&scope, connection, 12, 2);
    assert!(mysql(&scope, Uuid::new_v4(), "COMMIT").is_none());
    assert!(mysql(&scope, connection, "SELECT 1").is_none());
    assert!(mysql(&scope, connection, "COMMIT").is_none());

    begin(&scope, connection);
    anchor(&scope, connection, 12, 3);
    assert!(mysql(&scope, connection, "COMMIT").is_none());
    begin(&scope, connection);
    anchor(&scope, connection, 12, 2);
    let mut failed = exchange(
        "SELECT id FROM audit_0001 WHERE kind='audit' LIMIT 1",
        connection,
        3,
    );
    failed.server_status_before = Some(3);
    failed.response.server_status = Some(3);
    failed.response.status = "error".into();
    observe(&scope, failed);
    assert!(mysql(&scope, connection, "COMMIT").is_none());
}

#[test]
fn later_identity_capture_cannot_turn_another_jobs_transaction_into_this_jobs_work() {
    let scope = scope(&[rule()]);
    let connection = Uuid::new_v4();
    begin(&scope, connection);
    let sql = "UPDATE jobs_0001 SET state='done' WHERE id=13";
    assert_eq!(
        mysql(&scope, connection, sql),
        Some(SelectionScope::SelectorOnly)
    );
    let mut event = exchange(sql, connection, 2);
    event.server_status_before = Some(3);
    event.response.server_status = Some(3);
    observe(&scope, event);
    observe(&scope, insert(12));
    assert!(mysql(&scope, connection, "COMMIT").is_none());
}
