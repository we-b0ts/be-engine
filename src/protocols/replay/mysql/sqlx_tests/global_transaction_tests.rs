//! Real TLS clients retain a Global transaction across Case admission boundaries.
use super::*;

const BACKGROUND_UPDATE: &str = "UPDATE jobs SET status='DONE' WHERE id=12";
const BUSINESS_UPDATE: &str = "UPDATE users SET active=0 WHERE id=7";

fn statement(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut record = exchange(
        sql,
        json!({"status":"ok", "server_status":after, "affected_rows":0,
            "last_insert_id":0, "columns":[], "rows":[], "rows_truncated":false}),
    );
    record["connection_id"] = json!(connection);
    record["query_sequence"] = json!(sequence);
    record["server_status_before"] = json!(before);
    record["outcome"] = json!("response");
    record["parse_warnings"] = json!([]);
    record["capture"] =
        serde_json::to_value(crate::dependency::observation::fixture_capture("process")).unwrap();
    if sql.starts_with("UPDATE") {
        record["response"]["affected_rows"] = json!(1);
    }
    record
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    background: Uuid,
    business: Uuid,
    originals: Vec<(PathBuf, Vec<u8>)>,
}

impl Fixture {
    fn new(boundary: bool, business_transaction: bool) -> Self {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join(".traffic-e2e/local/recordings");
        for case in ["case-a", "case-b"] {
            let path = root.join(case);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(
                path.join("request.json"),
                r#"{"method":"POST","uri":"/work","timestamp":"2020-01-01T00:00:00Z"}"#,
            )
            .unwrap();
            std::fs::write(path.join("expected-response.json"), "{}").unwrap();
        }
        if boundary {
            std::fs::write(
                root.join("recording-run.json"),
                r#"{"status":"completed","run_id":"global-transaction-sqlx"}"#,
            )
            .unwrap();
        }
        let background = Uuid::new_v4();
        let business = Uuid::new_v4();
        let mut case_b = vec![statement(background, 12, "COMMIT", 3, 2)];
        if business_transaction {
            case_b.extend([
                statement(business, 20, "BEGIN", 2, 3),
                statement(business, 21, BUSINESS_UPDATE, 3, 3),
                statement(business, 22, "COMMIT", 3, 2),
            ]);
        }
        let mut originals = Vec::new();
        for (relative, records) in [
            (
                "global-dependencies.jsonl",
                vec![statement(background, 10, "BEGIN", 2, 3)],
            ),
            (
                "case-a/dependencies.jsonl",
                vec![statement(background, 11, BACKGROUND_UPDATE, 3, 3)],
            ),
            ("case-b/dependencies.jsonl", case_b),
        ] {
            let path = root.join(relative);
            let raw = records
                .iter()
                .map(|record| record.to_string() + "\n")
                .collect::<String>()
                .into_bytes();
            std::fs::write(&path, &raw).unwrap();
            originals.push((path, raw));
        }
        crate::replay::write_test_recording_network_manifest(&root);
        Self {
            _temporary: temporary,
            root,
            background,
            business,
            originals,
        }
    }

    fn assert_immutable(&self) {
        for (path, original) in &self.originals {
            assert_eq!(&std::fs::read(path).unwrap(), original);
        }
    }

    fn append_global(&mut self, record: Value) {
        let path = self.root.join("global-dependencies.jsonl");
        let (_, original) = self
            .originals
            .iter_mut()
            .find(|(original, _)| original == &path)
            .unwrap();
        original.extend_from_slice((record.to_string() + "\n").as_bytes());
        std::fs::write(path, original).unwrap();
    }

    fn replace_records(&mut self, relative: &str, records: &[Value]) {
        let path = self.root.join(relative);
        let (_, original) = self
            .originals
            .iter_mut()
            .find(|(original, _)| original == &path)
            .unwrap();
        *original = records
            .iter()
            .map(|record| record.to_string() + "\n")
            .collect::<String>()
            .into_bytes();
        std::fs::write(path, original).unwrap();
    }

    async fn start(
        &self,
        lazy: bool,
        selected: &[&str],
    ) -> (SocketAddr, Arc<ReplayRuntime>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ReplayConfig {
            case_dir: self.root.clone(),
            selected_case_ids: selected.iter().map(|case| (*case).to_owned()).collect(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(self.ca_path()),
            ca_key_path: Some(self.root.join(".replay/ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        };
        let mut lifecycle = ReplayLifecycleConfig::default();
        lifecycle.dependency_loading.lazy_cases = lazy;
        lifecycle.case_dependency_post_response_window = Duration::ZERO;
        let runtime = Arc::new(
            ReplayRuntime::load_with_lifecycle(
                config,
                "127.0.0.1:0".parse().unwrap(),
                addr,
                lifecycle,
            )
            .await
            .unwrap(),
        );
        let serving = runtime.clone();
        let task = tokio::spawn(async move { serving.run_tcp(listener).await.unwrap() });
        (addr, runtime, task)
    }

    fn ca_path(&self) -> PathBuf {
        self.root.join(".replay/ca.pem")
    }
}

async fn control(runtime: &ReplayRuntime, command: &str, case: &str) -> Value {
    let request = crate::replay::control::ReplayControlRequest {
        command: command.into(),
        case_id: Some(case.into()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        parameters: Default::default(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    let response = match command {
        "begin" => crate::replay::control::begin_case(&request, runtime.state.clone()).await,
        "end" => crate::replay::control::end_case(&request, runtime.state.clone()).await,
        _ => unreachable!(),
    };
    assert_eq!(response["ok"], true, "{response}");
    response
}

fn wire_index(state: &ReplayState, connection: Uuid, sequence: u64) -> usize {
    let matches = state
        .protocols
        .mysql
        .exchanges
        .iter()
        .enumerate()
        .filter(|(_, exchange)| {
            exchange.record.connection_id == Some(connection)
                && exchange.record.query_sequence == Some(sequence)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "each recorded command is registered once");
    matches[0]
}

fn assert_provenance(state: &ReplayState, fixture: &Fixture) {
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    let members = report["global_mysql_transaction_exchanges"]
        .as_array()
        .unwrap();
    assert_eq!(members.len(), 2);
    for (sequence, case) in [(11, "case-a"), (12, "case-b")] {
        let row = members
            .iter()
            .find(|row| row["query_sequence"] == sequence)
            .unwrap();
        assert!(row.get("case_id").is_none());
        assert_eq!(row["original_case_id"], case);
        assert_eq!(
            row["dependencies_path"],
            fixture
                .root
                .join(case)
                .join("dependencies.jsonl")
                .to_str()
                .unwrap()
        );
        assert_eq!(row["line"], 1);
        assert_eq!(row["record_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(row["start_connection_id"], fixture.background.to_string());
        assert_eq!(row["start_query_sequence"], 10);
    }
}

#[tokio::test]
async fn unselected_case_members_are_global_once_and_cannot_steal_business_commit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            let fixture = Fixture::new(true, true);
            let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
            {
                let state = runtime.state.lock().await;
                assert!(!state.cases.contains_key("case-a"));
                for sequence in [10, 11, 12] {
                    let index = wire_index(&state, fixture.background, sequence);
                    assert_eq!(
                        state.protocols.mysql.exchanges[index].source,
                        if sequence == 10 {
                            ReplaySource::Startup
                        } else {
                            ReplaySource::Process
                        }
                    );
                }
                assert_provenance(&state, &fixture);
            }
            let mut background = connect(addr, &fixture.ca_path()).await;
            sqlx::raw_sql("BEGIN")
                .execute(&mut background)
                .await
                .unwrap();
            control(&runtime, "begin", "case-b").await;
            // Repeated lazy preparation must not duplicate promoted records.
            crate::replay::prepare_case_dependencies(runtime.state.clone(), "case-b")
                .await
                .unwrap();
            sqlx::query(BACKGROUND_UPDATE)
                .execute(&mut background)
                .await
                .unwrap();
            let mut business = connect(addr, &fixture.ca_path()).await;
            let mut transaction = business.begin().await.unwrap();
            assert_eq!(
                sqlx::query(BUSINESS_UPDATE)
                    .execute(&mut *transaction)
                    .await
                    .unwrap()
                    .rows_affected(),
                1
            );
            transaction.commit().await.unwrap();
            {
                let state = runtime.state.lock().await;
                let global_end = wire_index(&state, fixture.background, 12);
                let business_end = wire_index(&state, fixture.business, 22);
                assert!(
                    state.protocols.mysql.exchanges[global_end]
                        .status
                        .is_available()
                );
                assert!(
                    state.protocols.mysql.exchanges[business_end]
                        .status
                        .is_consumed()
                );
                assert!(!state.protocols.mysql.case_is_dirty("case-b"));
            }
            sqlx::raw_sql("COMMIT")
                .execute(&mut background)
                .await
                .unwrap();
            sqlx::raw_sql("COMMIT")
                .execute(&mut background)
                .await
                .unwrap();
            assert_eq!(control(&runtime, "end", "case-b").await["dirty"], false);
            // The finite promoted write has already been consumed.
            assert!(
                sqlx::query(BACKGROUND_UPDATE)
                    .execute(&mut background)
                    .await
                    .is_err()
            );
            {
                let state = runtime.state.lock().await;
                assert_eq!(state.protocols.mysql.events.matched_query_count, 6);
                assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
                assert!(
                    state.protocols.mysql.events.unmatched_queries[0]
                        .case_id
                        .is_none()
                );
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                assert!(state.unused_exchanges(ReplaySource::Startup).is_empty());
                for sequence in [10, 11, 12] {
                    let index = wire_index(&state, fixture.background, sequence);
                    assert!(state.protocols.mysql.exchanges[index].status.is_consumed());
                }
                assert_provenance(&state, &fixture);
            }
            fixture.assert_immutable();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn global_transaction_errors_stay_global_and_pool_reuse_restores_case_owner() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            // A rejected request closes its physical transaction. Each wire
            // form therefore has its own real transaction and Source inventory.
            for rejected in [Some(false), Some(true), None] {
                let fixture = Fixture::new(true, false);
                let (addr, runtime, task) = fixture.start(lazy, &[]).await;
                let mut background = connect(addr, &fixture.ca_path()).await;
                sqlx::raw_sql("BEGIN").execute(&mut background).await.unwrap();
                control(&runtime, "begin", "case-a").await;
                sqlx::query(BACKGROUND_UPDATE).execute(&mut background).await.unwrap();
                assert_eq!(control(&runtime, "end", "case-a").await["dirty"], false);
                control(&runtime, "begin", "case-b").await;
                if let Some(prepared) = rejected {
                    let sql = "UPDATE jobs SET status='UNKNOWN' WHERE id=99";
                    let error = if prepared {
                        sqlx::query(sql).execute(&mut background).await.unwrap_err()
                    } else {
                        sqlx::raw_sql(sql).execute(&mut background).await.unwrap_err()
                    };
                    assert!(error.as_database_error().is_none());
                    let state = runtime.state.lock().await;
                    assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
                    assert!(state.protocols.mysql.events.unmatched_queries[0].case_id.is_none());
                    assert!(!state.protocols.mysql.case_is_dirty("case-b"));
                    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                    let end = wire_index(&state, fixture.background, 12);
                    assert!(state.protocols.mysql.exchanges[end].status.is_available(), "EOF cannot consume the unexecuted Source COMMIT");
                    drop(state);
                    assert!(sqlx::raw_sql("COMMIT").execute(&mut background).await.is_err());
                    let mut business = connect(addr, &fixture.ca_path()).await;
                    assert!(sqlx::query(BUSINESS_UPDATE).execute(&mut business).await.is_err());
                    let state = runtime.state.lock().await;
                    assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 2);
                    assert_eq!(state.protocols.mysql.events.unmatched_queries[1].case_id.as_deref(), Some("case-b"));
                    assert!(state.protocols.mysql.case_is_dirty("case-b"));
                    assert!(state.protocols.mysql.exchanges[end].status.is_available());
                } else {
                    sqlx::raw_sql("COMMIT").execute(&mut background).await.unwrap();
                    assert!(sqlx::query(BACKGROUND_UPDATE).execute(&mut background).await.is_err());
                    let state = runtime.state.lock().await;
                    assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
                    assert_eq!(state.protocols.mysql.events.unmatched_queries[0].case_id.as_deref(), Some("case-b"),
                        "after a successful Global COMMIT the pooled connection uses the active Case");
                    assert!(state.unused_exchanges(ReplaySource::Startup).is_empty());
                    assert_eq!(state.protocols.mysql.events.matched_query_count, 3);
                    assert_provenance(&state, &fixture);
                }
                fixture.assert_immutable();
                task.abort();
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn missing_recording_run_boundary_does_not_promote_case_members() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            let fixture = Fixture::new(false, false);
            let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
            let mut background = connect(addr, &fixture.ca_path()).await;
            sqlx::raw_sql("BEGIN")
                .execute(&mut background)
                .await
                .unwrap();
            control(&runtime, "begin", "case-b").await;
            assert!(
                sqlx::query(BACKGROUND_UPDATE)
                    .execute(&mut background)
                    .await
                    .is_err()
            );
            assert!(
                sqlx::raw_sql("COMMIT")
                    .execute(&mut background)
                    .await
                    .is_err()
            );
            let state = runtime.state.lock().await;
            assert!(state.global_mysql_transactions().is_empty());
            let end = wire_index(&state, fixture.background, 12);
            assert_eq!(
                state.protocols.mysql.exchanges[end].source,
                ReplaySource::Case
            );
            assert!(state.protocols.mysql.exchanges[end].status.is_available());
            assert!(state.protocols.mysql.case_is_dirty("case-b"));
            assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
            fixture.assert_immutable();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn global_business_member_corrects_a_transaction_started_during_active_case() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            for reject in [false, true] {
                let fixture = Fixture::new(true, false);
                let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
                control(&runtime, "begin", "case-b").await;
                let mut background = connect(addr, &fixture.ca_path()).await;
                sqlx::raw_sql("BEGIN")
                    .execute(&mut background)
                    .await
                    .unwrap();
                sqlx::query(BACKGROUND_UPDATE)
                    .execute(&mut background)
                    .await
                    .unwrap();
                if reject {
                    let error = sqlx::query("UPDATE jobs SET status='UNKNOWN' WHERE id=99")
                        .execute(&mut background)
                        .await
                        .unwrap_err();
                    assert!(error.as_database_error().is_none());
                } else {
                    sqlx::raw_sql("COMMIT")
                        .execute(&mut background)
                        .await
                        .unwrap();
                }
                let state = runtime.state.lock().await;
                assert_eq!(
                    state.protocols.mysql.events.unmatched_queries.len(),
                    usize::from(reject)
                );
                if reject {
                    assert!(
                        state.protocols.mysql.events.unmatched_queries[0]
                            .case_id
                            .is_none()
                    );
                    let end = wire_index(&state, fixture.background, 12);
                    assert!(
                        state.protocols.mysql.exchanges[end].status.is_available(),
                        "rejected transaction leaves its Source COMMIT unused"
                    );
                } else {
                    assert!(state.unused_exchanges(ReplaySource::Startup).is_empty());
                }
                assert!(!state.protocols.mysql.case_is_dirty("case-b"));
                assert_eq!(
                    state.protocols.mysql.events.matched_query_count,
                    if reject { 2 } else { 3 }
                );
                fixture.assert_immutable();
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_global_implicit_commit_ends_transaction_owner_before_connection_reuse() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            let mut fixture = Fixture::new(true, false);
            let ddl_connection = Uuid::new_v4();
            let ddl = "CREATE TABLE archived_jobs (id BIGINT)";
            fixture.append_global(statement(ddl_connection, 1, ddl, 3, 2));
            let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
            let mut background = connect(addr, &fixture.ca_path()).await;
            sqlx::raw_sql("BEGIN")
                .execute(&mut background)
                .await
                .unwrap();
            control(&runtime, "begin", "case-b").await;
            sqlx::raw_sql(ddl).execute(&mut background).await.unwrap();
            {
                let state = runtime.state.lock().await;
                let index = wire_index(&state, ddl_connection, 1);
                assert_eq!(
                    state.protocols.mysql.exchanges[index].source,
                    ReplaySource::Startup
                );
                assert!(state.protocols.mysql.exchanges[index].status.is_consumed());
                assert!(
                    state
                        .global_mysql_transactions()
                        .iter()
                        .all(|row| row.exchange.index != index),
                    "the DDL is native Global evidence, outside the promoted transaction"
                );
                assert!(!state.protocols.mysql.case_is_dirty("case-b"));
            }
            assert!(
                sqlx::query("UPDATE missing_jobs SET status='DONE' WHERE id=99")
                    .execute(&mut background)
                    .await
                    .is_err()
            );
            let state = runtime.state.lock().await;
            assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
            assert_eq!(
                state.protocols.mysql.events.unmatched_queries[0]
                    .case_id
                    .as_deref(),
                Some("case-b")
            );
            assert!(state.protocols.mysql.case_is_dirty("case-b"));
            fixture.assert_immutable();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn conflicting_case_and_global_business_members_cannot_silently_change_owner() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            let fixture = Fixture::new(true, true);
            let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
            control(&runtime, "begin", "case-b").await;
            let mut business = connect(addr, &fixture.ca_path()).await;
            sqlx::raw_sql("BEGIN").execute(&mut business).await.unwrap();
            sqlx::query(BUSINESS_UPDATE)
                .execute(&mut business)
                .await
                .unwrap();
            // Source records prove different owners for these two writes on
            // the same active Target transaction. The second write is rejected.
            assert!(
                sqlx::query(BACKGROUND_UPDATE)
                    .execute(&mut business)
                    .await
                    .is_err()
            );
            let state = runtime.state.lock().await;
            for sequence in [20, 21] {
                let index = wire_index(&state, fixture.business, sequence);
                assert!(state.protocols.mysql.exchanges[index].status.is_consumed());
            }
            assert!(state.protocols.mysql.case_is_dirty("case-b"));
            assert!(
                state
                    .protocols
                    .mysql
                    .events
                    .dirty_case_ids
                    .contains("case-b"),
                "ownership conflict is attributed to the established business Case"
            );
            assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
            let conflict = &state.protocols.mysql.events.unmatched_queries[0];
            assert_eq!(conflict.case_id.as_deref(), Some("case-b"));
            assert!(
                conflict
                    .reason
                    .contains("conflicting Case and Global ownership")
            );
            fixture.assert_immutable();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_global_reads_skip_transaction_proof_preparation_and_preserve_case_replay() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for lazy in [false, true] {
            let mut fixture = Fixture::new(true, true);
            let read = |id| {
                let mut record = statement(
                    Uuid::new_v4(),
                    1,
                    &format!("SELECT id FROM users WHERE id={id}"),
                    2,
                    2,
                );
                record["response"] = json!({"status":"resultset", "server_status":2,
                    "columns":[{"name":"id", "family":"integer", "sql_type":"INT"}],
                    "rows":[[{"kind":"integer", "value":id}]]});
                record
            };
            fixture.replace_records("global-dependencies.jsonl", &[read(8)]);
            fixture.replace_records("case-a/dependencies.jsonl", &[]);
            fixture.replace_records(
                "case-b/dependencies.jsonl",
                &[
                    statement(fixture.business, 20, "BEGIN", 2, 3),
                    statement(fixture.business, 21, BUSINESS_UPDATE, 3, 3),
                    statement(fixture.business, 22, "COMMIT", 3, 2),
                    read(7),
                ],
            );
            let cache = crate::dependency_index::store::cache_directory(&fixture.root);
            // Existing API-origin preparation creates shared transaction facts
            // even without configured process rules. Preserve that baseline;
            // the new Global screening must avoid adding its own proof work.
            crate::api_trigger::prepare(&fixture.root, &[]).unwrap();
            let facts = cache.join("mysql-transactions-v1.json");
            let original_facts = crate::dependency_index::FileStamp::read(&facts).unwrap();
            let (addr, runtime, task) = fixture.start(lazy, &["case-b"]).await;
            assert_eq!(
                crate::dependency_index::FileStamp::read(&facts).unwrap(),
                original_facts,
                "ordinary Global reads do not rebuild existing transaction facts"
            );
            for name in [
                "mysql-global-transaction-proof-v2.json",
                "mysql-global-transaction-proof.lock",
            ] {
                assert!(
                    !cache.join(name).exists(),
                    "unexpected startup cache {name}"
                );
            }
            {
                let state = runtime.state.lock().await;
                assert!(!state.protocols.mysql.has_global_transaction_start);
                assert!(state.global_mysql_transactions().is_empty());
            }
            control(&runtime, "begin", "case-b").await;
            let mut business = connect(addr, &fixture.ca_path()).await;
            let mut transaction = business.begin().await.unwrap();
            sqlx::query(BUSINESS_UPDATE)
                .execute(&mut *transaction)
                .await
                .unwrap();
            transaction.commit().await.unwrap();
            let row = sqlx::query("SELECT id FROM users WHERE id=7")
                .fetch_one(&mut business)
                .await
                .unwrap();
            assert_eq!(row.get::<i32, _>("id"), 7);
            let state = runtime.state.lock().await;
            assert_eq!(state.protocols.mysql.events.matched_query_count, 4);
            assert!(!state.protocols.mysql.case_is_dirty("case-b"));
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert!(state.global_mysql_transactions().is_empty());
            fixture.assert_immutable();
            task.abort();
        }
    })
    .await
    .unwrap();
}
