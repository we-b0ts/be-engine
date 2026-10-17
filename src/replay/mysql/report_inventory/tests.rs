use super::*;
use serde_json::{Value, json};

fn control(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":connection,
        "query_sequence":sequence, "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "server_status_before":before,
        "response":{"status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0}})
}

fn read(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut record = control(connection, sequence, sql, before, after);
    record["response"] = json!({"status":"resultset", "server_status":after,
        "columns":[{"name":"id", "family":"integer", "sql_type":"INT"}],
        "rows":[[{"kind":"integer", "value":1}]]});
    record
}

async fn fixture(root: &Path) -> ReplayRuntime {
    let case = root.join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    let rollback = Uuid::new_v4();
    let commit = Uuid::new_v4();
    let auto = Uuid::new_v4();
    let records = [
        read(rollback, 1, "SELECT id FROM rollback_read", 0, 1),
        control(rollback, 2, "ROLLBACK", 1, 0),
        read(commit, 1, "SELECT id FROM commit_read", 0, 1),
        control(commit, 2, "COMMIT", 1, 0),
        control(auto, 1, "SET AUTOCOMMIT=0", 2, 0),
        read(auto, 2, "SELECT id FROM autocommit_read", 0, 1),
        control(auto, 3, "ROLLBACK", 1, 0),
        control(auto, 4, "SET AUTOCOMMIT=1", 0, 2),
        read(Uuid::new_v4(), 1, "SELECT id FROM required_read", 2, 2),
        control(Uuid::new_v4(), 1, "SET NAMES utf8mb4", 2, 2),
    ];
    std::fs::write(
        root.join("global-dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    crate::replay::write_test_recording_network_manifest(&case);
    ReplayRuntime::load(
        ReplayConfig {
            case_dir: case,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(root.join("report.json")),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.join("ca.pem")),
            ca_key_path: Some(root.join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap()
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.internal".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: Some("user".into()),
    }
}

fn rows(state: &ReplayState) -> Vec<Row> {
    let mut rows = Vec::new();
    state
        .visit_mysql_global_report_rows(&mut |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
    assert_eq!(rows.len(), 10);
    assert_eq!(rows.iter().filter(|row| row.visible).count(), 5);
    assert_eq!(state.mysql.global_report_usage().count(), Some(5));
    rows
}

fn equivalent(state: &ReplayState, report: &Path, rows: &[Row]) -> usize {
    let mut extras = Vec::new();
    state
        .visit_mysql_global_report_extras(&mut |row| {
            extras.push(row);
            Ok(())
        })
        .unwrap();
    let usage = state.mysql.global_report_usage();
    let (count, actual) = crate::replay::report::global_evidence::regular::tests::protocol_snapshot(
        report,
        "mysql",
        usage.layout().to_vec(),
        rows,
        usage.snapshot().unwrap(),
        extras,
    );
    let mut expected = Vec::new();
    state
        .visit_global_mysql_unused(&mut |row| {
            expected.push(row);
            Ok(())
        })
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(count, expected.len());
    assert_eq!(count, state.global_mysql_unused_count());
    count
}

#[tokio::test]
async fn cleanup_visibility_follows_real_reservations_and_delivery_outcomes() {
    for (end, kind) in [
        ("ROLLBACK", OptionalSessionExchange::Rollback),
        ("COMMIT", OptionalSessionExchange::Commit),
    ] {
        for fail in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let report = temp.path().join("report.json");
            let runtime = fixture(temp.path()).await;
            let mut state = runtime.state.lock().await;
            let baseline = rows(&state);
            assert_eq!(equivalent(&state, &report, &baseline), 5);
            let matched = state
                .match_exchange(&identity(), "COM_QUERY", Some(end), None)
                .unwrap();
            assert_eq!(
                state.mysql.exchanges[matched.index].optional_session,
                Some(kind)
            );
            assert_eq!(
                state.mysql.exchanges[matched.index].status,
                ReplayExchangeStatus::Responding
            );
            // Optional cleanup stays hidden while its recorded response is in flight.
            assert_eq!(equivalent(&state, &report, &baseline), 5);
            if fail {
                state.fail_exchange(&matched, &identity(), "fixture response delivery failed");
                assert_eq!(equivalent(&state, &report, &baseline), 6);
            } else {
                state.complete_exchange(&matched);
                assert_eq!(equivalent(&state, &report, &baseline), 5);
            }
        }
    }
}

#[tokio::test]
async fn autocommit_and_required_sql_use_their_native_visibility_transitions() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let runtime = fixture(temp.path()).await;
    let mut state = runtime.state.lock().await;
    let baseline = rows(&state);
    assert_eq!(equivalent(&state, &report, &baseline), 5);
    let setup = state
        .match_exchange(&identity(), "COM_QUERY", Some("SET AUTOCOMMIT=0"), None)
        .unwrap();
    assert_eq!(
        state.mysql.exchanges[setup.index].optional_session,
        Some(OptionalSessionExchange::Autocommit)
    );
    assert_eq!(equivalent(&state, &report, &baseline), 6);
    state.complete_exchange(&setup);
    assert_eq!(equivalent(&state, &report, &baseline), 5);

    let setup = state
        .match_exchange(&identity(), "COM_QUERY", Some("SET AUTOCOMMIT=1"), None)
        .unwrap();
    assert_eq!(
        state.mysql.exchanges[setup.index].optional_session,
        Some(OptionalSessionExchange::Autocommit)
    );
    assert_eq!(equivalent(&state, &report, &baseline), 6);
    state.fail_exchange(&setup, &identity(), "fixture setup delivery failed");
    assert_eq!(equivalent(&state, &report, &baseline), 6);

    let required = state
        .match_exchange(
            &identity(),
            "COM_QUERY",
            Some("SELECT id FROM required_read"),
            None,
        )
        .unwrap();
    assert!(
        state.mysql.exchanges[required.index]
            .optional_session
            .is_none()
    );
    assert_eq!(equivalent(&state, &report, &baseline), 6);
    state.complete_exchange(&required);
    assert_eq!(equivalent(&state, &report, &baseline), 5);

    let (source, index) = state
        .consume_builtin_exchange(&identity(), "COM_QUERY", Some("SET NAMES utf8mb4"))
        .unwrap();
    assert_eq!(source, ReplaySource::Global);
    assert!(state.mysql.exchanges[index].optional_session.is_none());
    assert_eq!(
        state.mysql.exchanges[index].status,
        ReplayExchangeStatus::Consumed
    );
    assert_eq!(equivalent(&state, &report, &baseline), 4);
}
