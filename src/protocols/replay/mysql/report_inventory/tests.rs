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
    fixture_with_case(root, "").await
}

async fn fixture_with_case(root: &Path, records: &str) -> ReplayRuntime {
    let case = root.join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(case.join("dependencies.jsonl"), records).unwrap();
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

#[tokio::test]
async fn shared_mysql_admission_observes_once_and_keeps_arrival_when_delivery_reverses() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".traffic-e2e/local/recording");
    std::fs::create_dir_all(&root).unwrap();
    crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
    let runtime = fixture(&root).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let actual = identity();
    let mut session = ReplaySession {
        control: crate::dependency::termination::ConnectionControl::new(&socket).unwrap(),
        request_started: tokio::time::Instant::now(),
        fast_response_timing: false,
        target: actual.target,
        database: actual.database,
        username: actual.username,
        next_statement_id: 1,
        status_flags: 2,
        statements: HashMap::new(),
        transaction_scope: Default::default(),
        savepoints: Default::default(),
        transaction_witness: Default::default(),
    };
    let first = super::super::admission::match_request(
        &runtime.state,
        &session,
        "COM_QUERY",
        Some("SELECT id FROM rollback_read"),
        None,
    )
    .await;
    let second = super::super::admission::match_request(
        &runtime.state,
        &session,
        "COM_QUERY",
        Some("SELECT id FROM required_read"),
        None,
    )
    .await;
    assert_eq!((first.event_index, second.event_index), (Some(0), Some(1)));
    assert!(first.observation_id.is_some() && second.observation_id.is_some());
    let first = first.matched.unwrap();
    let second = second.matched.unwrap();
    assert_ne!(first.record.connection_id, second.record.connection_id);
    {
        let mut state = runtime.state.lock().await;
        assert!(second.claim.publish_wire());
        assert!(state.complete_exchange(&second));
        assert!(first.claim.publish_wire());
        assert!(state.complete_exchange(&first));
        assert_eq!(
            state
                .protocols
                .mysql
                .events
                .matched_queries
                .iter()
                .map(|report| report.target_event_index)
                .collect::<Vec<_>>(),
            [Some(1), Some(0)]
        );
        assert_eq!(
            state
                .target_observations
                .manifest()
                .unwrap()
                .graph()
                .unwrap()
                .targets
                .len(),
            2
        );
    }
    let rejected = super::super::admission::match_request(
        &runtime.state,
        &session,
        "COM_QUERY",
        Some("SELECT missing FROM not_recorded"),
        None,
    )
    .await;
    assert!(rejected.matched.is_none());
    assert_eq!(rejected.event_index, Some(2));
    assert!(rejected.observation_id.is_some());
    let mut state = runtime.state.lock().await;
    assert_eq!(
        state
            .protocols
            .mysql
            .events
            .request_order
            .latest(rejected.case_id.as_deref()),
        Some(2)
    );
    assert_eq!(
        state
            .target_observations
            .manifest()
            .unwrap()
            .graph()
            .unwrap()
            .targets
            .len(),
        3
    );
    let before = (
        state.protocols.mysql.events.matched_query_count,
        state.protocols.mysql.events.builtin_query_count,
        state.protocols.mysql.events.unmatched_queries.len(),
    );
    state.finalized_at = Some(Utc::now());
    drop(state);
    let (mut output, _peer) = tokio::io::duplex(32);
    let error = handle_query(&mut output, runtime.state.clone(), &mut session, "SELECT 1")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("finalized"));
    let state = runtime.state.lock().await;
    assert_eq!(
        before,
        (
            state.protocols.mysql.events.matched_query_count,
            state.protocols.mysql.events.builtin_query_count,
            state.protocols.mysql.events.unmatched_queries.len()
        )
    );
    assert_eq!(
        state
            .protocols
            .mysql
            .events
            .request_order
            .latest(rejected.case_id.as_deref()),
        Some(2)
    );
    assert_eq!(
        state
            .target_observations
            .manifest()
            .unwrap()
            .graph()
            .unwrap()
            .targets
            .len(),
        3
    );
}

#[tokio::test]
async fn finite_delivery_requires_wire_and_commits_each_native_hook_once() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = fixture(temp.path()).await;
    let mut state = runtime.state.lock().await;
    let matched = state
        .match_exchange(
            &identity(),
            "COM_QUERY",
            Some("SELECT id FROM required_read"),
            None,
        )
        .unwrap();
    assert!(!state.complete_exchange(&matched));
    assert_eq!(state.protocols.mysql.events.matched_query_count, 0);
    assert!(matched.claim.publish_wire());
    let hooks = std::cell::Cell::new(0);
    assert!(
        state
            .finish_mysql_exchange(&matched, || {
                hooks.set(hooks.get() + 1);
                Ok(())
            })
            .unwrap()
    );
    assert!(
        !state
            .finish_mysql_exchange(&matched, || {
                hooks.set(hooks.get() + 1);
                Ok(())
            })
            .unwrap()
    );
    assert_eq!(hooks.get(), 1);
    assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
    state.fail_exchange(
        &matched,
        &identity(),
        "a consumed claim cannot be rolled back",
    );
    assert!(
        state.protocols.mysql.exchanges[matched.index]
            .status
            .is_consumed()
    );
    assert!(state.protocols.mysql.events.unmatched_queries.is_empty());
}

#[tokio::test]
async fn wire_success_with_native_commit_failure_remains_unconsumed_and_dirty() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = fixture(temp.path()).await;
    let mut state = runtime.state.lock().await;
    let matched = state
        .match_exchange(
            &identity(),
            "COM_QUERY",
            Some("SELECT id FROM required_read"),
            None,
        )
        .unwrap();
    assert!(matched.claim.publish_wire());
    assert!(
        state
            .finish_mysql_exchange(&matched, || anyhow::bail!(
                "synthetic native commit failure"
            ))
            .is_err()
    );
    assert_eq!(
        state.protocols.mysql.exchange_status(matched.index),
        Some(ReplayExchangeStatus::Failed)
    );
    assert_eq!(state.protocols.mysql.events.matched_query_count, 0);
    assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
    assert!(!state.complete_exchange(&matched));
}

#[tokio::test]
async fn cancelled_optional_delivery_is_required_in_native_and_sparse_global_views() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = fixture(temp.path()).await;
    let mut state = runtime.state.lock().await;
    let before = state.global_mysql_unused_count();
    let matched = state
        .match_exchange(&identity(), "COM_QUERY", Some("COMMIT"), None)
        .unwrap();
    assert_eq!(state.global_mysql_unused_count(), before);
    drop(matched.claim.guard());
    assert_eq!(
        state.protocols.mysql.exchange_status(matched.index),
        Some(ReplayExchangeStatus::Failed)
    );
    assert_eq!(state.global_mysql_unused_count(), before + 1);
    assert!(
        !state
            .protocols
            .mysql
            .permits_unstarted_omission(matched.index)
    );
    assert!(!state.complete_exchange(&matched));
}

#[tokio::test]
async fn unused_empty_history_query_retains_its_selection_in_ai_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let columns = (0..24)
        .map(|index| format!("subtasks.field_{index} AS subtasks_field_{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let body = "FROM subtasks WHERE subtasks.task_id = 42 \
                ORDER BY subtasks.message_id ASC, subtasks.created_at ASC";
    let sql = format!("SELECT {columns} {body}");
    let mut record = read(connection, 17, &sql, 0, 1);
    record["response"]["columns"] = Value::Array(
        (0..24)
            .map(|index| {
                json!({"name":format!("subtasks_field_{index}"),
                "family":"integer","sql_type":"INT"})
            })
            .collect(),
    );
    record["response"]["rows"] = json!([]);
    let runtime = fixture_with_case(temp.path(), &record.to_string()).await;
    let state = runtime.state.lock().await;
    let (index, exchange) = state
        .protocols
        .mysql
        .exchanges
        .iter()
        .enumerate()
        .find(|(_, exchange)| exchange.record.sql.as_deref() == Some(&sql))
        .unwrap();
    assert_eq!(exchange.record.result_row_count(), Some(0));
    let summary = serde_json::to_value(state.mysql_summary(index)).unwrap();
    assert_eq!(summary["row_count"], 0);
    assert_eq!(summary["sql_summary"]["select_body"]["preview"], body);
    assert!(
        !summary["sql_summary"]["preview"]
            .as_str()
            .unwrap()
            .contains("WHERE")
    );
    let report = json!({"unused_case_exchanges":[summary]});
    let evidence = crate::protocols::replay::report::evidence::build_dependency_evidence(&report);
    let representative = evidence.clusters[0].representative.as_ref().unwrap();
    let signature = representative
        .difference
        .expected
        .signature
        .as_ref()
        .unwrap();
    assert_eq!(signature["connection_id"], connection.to_string());
    assert_eq!(signature["query_sequence"], 17);
    assert_eq!(signature["index"], index);
    assert_eq!(signature["row_count"], 0);
    assert_eq!(signature["sql_summary"]["select_body"]["preview"], body);
    assert_eq!(signature["sql_summary"]["select_body"]["truncated"], false);
    assert_eq!(
        signature["sql_summary"]["fingerprint"],
        summary["sql_summary"]["fingerprint"]
    );
    assert_eq!(state.protocols.mysql.events.matched_query_count, 0);
    assert!(state.protocols.mysql.events.unmatched_queries.is_empty());
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
    assert_eq!(state.protocols.mysql.global_report_usage().count(), Some(5));
    rows
}

fn equivalent(state: &ReplayState, report: &Path, rows: &[Row]) -> usize {
    let mut extras = Vec::new();
    state
        .protocols
        .mysql
        .visit_global_report_range(true, &mut |row| {
            extras.push(row);
            Ok(())
        })
        .unwrap();
    let usage = state.protocols.mysql.global_report_usage();
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
                state.protocols.mysql.exchanges[matched.index].optional_session,
                Some(kind)
            );
            assert_eq!(
                state.protocols.mysql.exchanges[matched.index].status,
                ReplayExchangeStatus::Responding
            );
            // Optional cleanup stays hidden while its recorded response is in flight.
            assert_eq!(equivalent(&state, &report, &baseline), 5);
            if fail {
                state.fail_exchange(&matched, &identity(), "fixture response delivery failed");
                assert_eq!(equivalent(&state, &report, &baseline), 6);
            } else {
                assert!(matched.claim.publish_wire());
                assert!(state.complete_exchange(&matched));
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
        state.protocols.mysql.exchanges[setup.index].optional_session,
        Some(OptionalSessionExchange::Autocommit)
    );
    assert_eq!(equivalent(&state, &report, &baseline), 6);
    assert!(setup.claim.publish_wire());
    assert!(state.complete_exchange(&setup));
    assert_eq!(equivalent(&state, &report, &baseline), 5);

    let setup = state
        .match_exchange(&identity(), "COM_QUERY", Some("SET AUTOCOMMIT=1"), None)
        .unwrap();
    assert_eq!(
        state.protocols.mysql.exchanges[setup.index].optional_session,
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
        state.protocols.mysql.exchanges[required.index]
            .optional_session
            .is_none()
    );
    assert_eq!(equivalent(&state, &report, &baseline), 6);
    assert!(required.claim.publish_wire());
    assert!(state.complete_exchange(&required));
    assert_eq!(equivalent(&state, &report, &baseline), 5);

    let (source, index) = state
        .consume_builtin_exchange(&identity(), "COM_QUERY", Some("SET NAMES utf8mb4"))
        .unwrap();
    assert_eq!(source, ReplaySource::Startup);
    assert!(
        state.protocols.mysql.exchanges[index]
            .optional_session
            .is_none()
    );
    assert_eq!(
        state.protocols.mysql.exchanges[index].status,
        ReplayExchangeStatus::Consumed
    );
    assert_eq!(equivalent(&state, &report, &baseline), 4);
}
