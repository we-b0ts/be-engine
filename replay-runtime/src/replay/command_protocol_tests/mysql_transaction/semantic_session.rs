//! Replay sealed MySQL transaction plans through the streaming runtime and wire driver.

use super::*;
use anyhow::Result;
use traffic_model::{
    attribution::DependencyOwner,
    recording::{
        CaptureCoverage, CaptureMetadata, CapturePhase, MANIFEST_FILE, ProtocolRef,
        RecordingManifest, SESSION_RECORDING_SCHEMA, SemanticInventory, SourceArtifactIdentity,
    },
    session::SessionEvent,
    trace::{CaptureEvent, OutputKind, RecordedEvent},
};
use traffic_protocol::{DependencyProvider, connection::Endpoint};
use traffic_protocol_mysql::MysqlProvider;
use traffic_recording_store::writer::{
    JsonlBufferSettings, JsonlWriterPool, LedgerFiles, RecordKind, RowLayout, RowStamp,
};

struct SessionFixture {
    _directory: tempfile::TempDir,
    runtime: ReplayRuntime,
    stop: u64,
}

impl SessionFixture {
    async fn new(statements: &[(&str, u16, u16)]) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let stop = seal(directory.path(), statements).await?;
        let address = "127.0.0.1:0".parse().unwrap();
        let runtime = ReplayRuntime::load_session_for_test(MysqlReplayConfig {
            case_dir: directory.path().into(),
            selected_case_ids: Vec::new(),
            dns_listen: address,
            tcp_listen: address,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(directory.path().join("report.json")),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(directory.path().join("ca.pem")),
            ca_key_path: Some(directory.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        })
        .await?;
        let fixture = Self {
            _directory: directory,
            runtime,
            stop,
        };
        fixture.control("session_commit", 1).await;
        fixture.control("session_wait", 2).await;
        fixture.control("session_commit", 2).await;
        Ok(fixture)
    }

    async fn control(&self, command: &str, sequence: u64) -> Value {
        let request = serde_json::from_value::<ReplayControlRequest>(json!({
            "command": command, "sequence": sequence,
        }))
        .unwrap();
        let (response, _) = crate::replay::handle_control_request(
            request,
            self.runtime.state.clone(),
            self.runtime.report_path.clone(),
            None,
        )
        .await;
        if command != "session_status" {
            assert_eq!(response["ok"], true, "{command}: {response}");
        }
        response
    }

    async fn finish(&self) {
        for sequence in [self.stop, self.stop + 1] {
            self.control("session_wait", sequence).await;
            self.control("session_commit", sequence).await;
        }
        let response = self.control("session_status", 0).await;
        assert_eq!(response["session_events"]["complete"], true, "{response}");
        assert!(response["session_events"]["failure"].is_null());
    }
}

async fn seal(root: &Path, statements: &[(&str, u16, u16)]) -> Result<u64> {
    let epoch = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let owner = DependencyOwner::Startup {
        process_epoch: epoch,
        initialization_unit: "session".into(),
    };
    let mut ledger = LedgerFiles::initialize_for_mode(root, epoch, epoch, true).await?;
    let mut files = JsonlWriterPool::new(JsonlBufferSettings {
        capacity: 4096,
        flush_interval: Duration::from_secs(30),
    });
    ledger.note_session_target(
        "mysql",
        Endpoint {
            host: "mysql.test".into(),
            port: 3306,
        },
    );
    for (sequence, event) in [(1, SessionEvent::SourceStart), (2, SessionEvent::Ready)] {
        ledger
            .append_session_event(&mut files, &recorded(sequence, event))
            .await?;
    }

    let mut facts = MysqlProvider
        .evidence()
        .unwrap()
        .session_scope_facts()
        .unwrap();
    let mut sequence = 3;
    for (index, &statement) in statements.iter().enumerate() {
        let dependency_sequence = sequence;
        let query_sequence = (index + 1) as u64;
        let value = exchange(
            epoch,
            connection,
            &owner,
            dependency_sequence,
            query_sequence,
            statement,
        );
        facts.observe(&value)?;
        ledger
            .append_event(
                &mut files,
                &recorded(
                    sequence,
                    CaptureEvent::Started {
                        dependency_sequence,
                        phase: CapturePhase::Runtime,
                        observed_case: None,
                        admitted_case: None,
                    },
                ),
            )
            .await?;
        ledger.note_mandatory_protocol("mysql");
        ledger
            .append_dependency(
                &mut files,
                value,
                &owner,
                RecordKind::Exchange,
                &RowLayout::default(),
                None,
                RowStamp {
                    sequence: sequence + 1,
                    offset_micros: sequence + 1,
                },
            )
            .await?;
        for (output_sequence, event) in [
            (
                sequence + 2,
                CaptureEvent::OutputStarted {
                    dependency_sequence,
                    output: OutputKind::End,
                },
            ),
            (
                sequence + 3,
                CaptureEvent::Output {
                    dependency_sequence,
                    output: OutputKind::End,
                },
            ),
        ] {
            ledger
                .append_event(&mut files, &recorded(output_sequence, event))
                .await?;
        }
        sequence += 4;
    }
    let stop = sequence;
    for (sequence, event) in [
        (stop, SessionEvent::Stop),
        (stop + 1, SessionEvent::SourceExit { status: Some(0) }),
    ] {
        ledger
            .append_session_event(&mut files, &recorded(sequence, event))
            .await?;
    }
    ledger
        .append_event(&mut files, &recorded(stop + 2, CaptureEvent::Sealed))
        .await?;
    let files = ledger
        .seal_with_schedule(&mut files, facts.finish()?)
        .await?;
    let count = statements.len() as u64;
    let manifest = RecordingManifest {
        schema: SESSION_RECORDING_SCHEMA.into(),
        run_id: "mysql-transaction-session".into(),
        run_epoch: epoch,
        process_epochs: vec![epoch],
        capture_policy_identity: String::new(),
        source_artifact: SourceArtifactIdentity::Unavailable {
            reason: "fixture".into(),
        },
        sealed: true,
        capture_complete: true,
        coverage: CaptureCoverage {
            admitted: count,
            terminal: count,
            ..Default::default()
        },
        records: count,
        unattributed_records: 0,
        semantic_inventory: SemanticInventory {
            total_mandatory: count,
            by_owner_kind: [("startup".into(), count)].into(),
            ..Default::default()
        },
        inputs: Vec::new(),
        files,
    };
    std::fs::write(
        root.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest.archive())?,
    )?;
    let network = crate::recording_network::RecordingNetworkManifest::from_observations(
        ["mysql.test".to_owned()].into(),
        [crate::recording_network::RecordedEndpoint::new(
            "mysql.test",
            3306,
        )?]
        .into(),
    );
    std::fs::write(
        root.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        serde_json::to_vec(&network)?,
    )?;
    Ok(stop)
}

fn recorded<T>(sequence: u64, event: T) -> RecordedEvent<T> {
    RecordedEvent {
        sequence,
        offset_micros: sequence,
        event,
    }
}

fn exchange(
    epoch: Uuid,
    connection: Uuid,
    owner: &DependencyOwner,
    sequence: u64,
    query_sequence: u64,
    (sql, before, after): (&str, u16, u16),
) -> Value {
    let observed = chrono::Utc::now();
    let capture = CaptureMetadata {
        transformations: Vec::new(),
        exchange_id: Uuid::new_v4(),
        sequence,
        process_epoch: epoch,
        phase: CapturePhase::Runtime,
        observed_case: None,
        admitted_case: None,
        started_at: observed,
        protocol_ref: ProtocolRef::connection("mysql", connection, query_sequence),
        attribution: owner.clone(),
        matched_rule_id: None,
        matched_rule_ids: Vec::new(),
        effect_index: 0,
        semantic_required: true,
    };
    let response = if sql.starts_with("SELECT ") {
        json!({
            "status":"resultset", "server_status":after,
            "columns":[{"name":"id","family":"integer","sql_type":"INT","column_type_code":3}],
            "rows":[], "row_count":0,
        })
    } else {
        json!({"status":"ok", "server_status":after,
            "affected_rows":u64::from(sql == WRITE), "last_insert_id":0})
    };
    json!({
        "event_type":"mysql_exchange", "recording_id":epoch, "capture":capture,
        "capture_complete":true, "outcome":"response", "connection_id":connection,
        "query_sequence":query_sequence, "target_host":"mysql.test", "target_port":3306,
        "database":"app", "username":"reader", "command":"COM_QUERY", "sql":sql,
        "timestamp":observed, "request_started_at":observed, "server_status_before":before,
        "response":response,
    })
}

async fn update_status(client: &mut TcpStream) -> u16 {
    let response = query(client, WRITE).await.unwrap().payload;
    assert_eq!(&response[..3], &[0, 1, 0]);
    u16::from_le_bytes(response[3..5].try_into().unwrap())
}

#[tokio::test]
async fn semantic_session_matches_implicit_reads_over_two_autocommit_connections() -> Result<()> {
    let fixture =
        SessionFixture::new(&[(READ, 0, 1), (READ_AFTER_WRITE, 1, 1), ("ROLLBACK", 1, 0)]).await?;
    let (mut first, first_task) = connect_mysql(&fixture.runtime).await;
    let (mut second, second_task) = connect_mysql(&fixture.runtime).await;
    assert_eq!(select_status(&mut first, READ).await & 3, 2);
    assert_eq!(select_status(&mut second, READ_AFTER_WRITE).await & 3, 2);
    fixture.finish().await;
    drop((first, second));
    first_task.await??;
    second_task.await??;
    Ok(())
}

#[tokio::test]
async fn semantic_session_keeps_a_local_begin_ahead_of_a_later_strict_begin() -> Result<()> {
    const LOCKED_READ: &str = "SELECT id FROM notes WHERE id = 7 FOR UPDATE";
    let fixture = SessionFixture::new(&[
        (READ, 0, 1),
        ("ROLLBACK", 1, 0),
        ("BEGIN", 0, 1),
        (LOCKED_READ, 1, 1),
        ("ROLLBACK", 1, 0),
    ])
    .await?;
    let (mut client, task) = connect_mysql(&fixture.runtime).await;
    assert_eq!(ok_status(&mut client, "BEGIN").await & 3, 3);
    assert_eq!(select_status(&mut client, READ).await & 3, 3);
    assert_eq!(ok_status(&mut client, "ROLLBACK").await & 3, 2);
    assert_eq!(ok_status(&mut client, "BEGIN").await & 3, 3);
    assert_eq!(select_status(&mut client, LOCKED_READ).await & 3, 3);
    assert_eq!(ok_status(&mut client, "ROLLBACK").await & 3, 2);
    fixture.finish().await;
    drop(client);
    task.await??;
    Ok(())
}

#[tokio::test]
async fn semantic_session_matches_read_before_begin_and_keeps_write_tail() -> Result<()> {
    let fixture = SessionFixture::new(&[
        ("BEGIN", 2, 3),
        (READ, 3, 3),
        (WRITE, 3, 3),
        (READ_AFTER_WRITE, 3, 3),
        ("ROLLBACK", 3, 2),
    ])
    .await?;
    let (mut client, task) = connect_mysql(&fixture.runtime).await;
    assert_eq!(select_status(&mut client, READ).await & 3, 2);
    assert_eq!(ok_status(&mut client, "BEGIN").await & 3, 3);
    assert_eq!(update_status(&mut client).await & 3, 3);
    assert_eq!(select_status(&mut client, READ_AFTER_WRITE).await & 3, 3);
    assert_eq!(ok_status(&mut client, "ROLLBACK").await & 3, 2);
    fixture.finish().await;
    drop(client);
    task.await??;
    Ok(())
}

#[tokio::test]
async fn semantic_session_matches_one_committed_update_in_either_target_mode() -> Result<()> {
    for explicit in [false, true] {
        let fixture = SessionFixture::new(&[
            ("BEGIN", 2, 3),
            (WRITE, 3, 3),
            ("COMMIT", 3, 2),
            (READ, 2, 2),
        ])
        .await?;
        let (mut client, task) = connect_mysql(&fixture.runtime).await;
        if explicit {
            assert_eq!(ok_status(&mut client, "BEGIN").await & 3, 3);
        }
        assert_eq!(
            update_status(&mut client).await & 3,
            if explicit { 3 } else { 2 }
        );
        if explicit {
            assert_eq!(ok_status(&mut client, "COMMIT").await & 3, 2);
        }
        assert_eq!(select_status(&mut client, READ).await & 3, 2);
        fixture.finish().await;
        drop(client);
        task.await??;
    }
    Ok(())
}

#[tokio::test]
async fn semantic_session_requires_commit_after_explicit_single_update() -> Result<()> {
    let fixture = SessionFixture::new(&[("BEGIN", 2, 3), (WRITE, 3, 3), ("COMMIT", 3, 2)]).await?;
    let (mut client, task) = connect_mysql(&fixture.runtime).await;
    assert_eq!(ok_status(&mut client, "BEGIN").await & 3, 3);
    assert_eq!(update_status(&mut client).await & 3, 3);
    assert!(
        query(&mut client, "ROLLBACK")
            .await
            .is_none_or(|reply| reply.payload[0] == 0xff)
    );
    assert!(task.await?.is_err());
    let response = fixture.control("session_status", 0).await;
    assert_eq!(response["session_events"]["expected"]["sequence"], 11);
    assert!(!response["session_events"]["failure"].is_null());
    Ok(())
}

#[tokio::test]
async fn semantic_session_rejects_autocommitting_an_update_that_source_rolled_back() -> Result<()> {
    let fixture =
        SessionFixture::new(&[("BEGIN", 2, 3), (WRITE, 3, 3), ("ROLLBACK", 3, 2)]).await?;
    let (mut client, task) = connect_mysql(&fixture.runtime).await;
    assert!(
        query(&mut client, WRITE)
            .await
            .is_none_or(|reply| reply.payload[0] == 0xff)
    );
    assert!(task.await?.is_err());
    let response = fixture.control("session_status", 0).await;
    assert_eq!(response["session_events"]["expected"]["sequence"], 7);
    assert!(!response["session_events"]["failure"].is_null());
    Ok(())
}
