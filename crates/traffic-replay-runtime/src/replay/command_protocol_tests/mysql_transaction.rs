use super::*;
use crate::replay::test_support::{recording as fixtures, serve_native};
use crate::replay::{ReplayControlRequest, ReplayDependencyLoading, ReplayLifecycleConfig};
use serde_json::json;
use traffic_protocol_mysql::{MysqlPacket, read_packet, write_packet};

const READ: &str = "SELECT id FROM notes WHERE id = 7";
const WRITE: &str = "UPDATE notes SET seen = 1 WHERE id = 7";
const READ_AFTER_WRITE: &str = "SELECT seen FROM notes WHERE id = 7";

struct Fixture {
    _directory: tempfile::TempDir,
    runtime: ReplayRuntime,
    case: String,
}

impl Fixture {
    async fn new(exchanges: &[(&str, u16, u16)], lazy_cases: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let recorder = crate::Recorder::new(directory.path().join("recordings"))
            .await
            .unwrap();
        recorder
            .observe_accessed_endpoint("mysql.test", 3306)
            .await
            .unwrap();
        let case = crate::recorder::CaseContext {
            id: Uuid::new_v4(),
            rule_name: "mysql-transaction".into(),
            uri_group: None,
        };
        let connection = Uuid::new_v4();
        for (index, &(sql, before, after)) in exchanges.iter().enumerate() {
            let mut event = fixtures::native_event(&json!({
                "event_type": "mysql_exchange",
                "connection_id": connection,
                "query_sequence": index + 1,
                "target_host": "mysql.test",
                "target_port": 3306,
                "sql": sql,
            }));
            let crate::protocols::recording::events::RecorderEvent::MysqlExchange(exchange) =
                &mut event
            else {
                unreachable!();
            };
            exchange.server_status_before = Some(before);
            exchange.response.server_status = Some(after);
            if sql.starts_with("SELECT ") {
                exchange.response.status = "resultset".into();
                exchange.response.affected_rows = None;
                exchange.response.last_insert_id = None;
                exchange
                    .response
                    .columns
                    .push(traffic_protocol_mysql::semantic::MysqlColumn {
                        name: "value".into(),
                        database: None,
                        table: None,
                        column: None,
                        family: "integer".into(),
                        sql_type: "INT".into(),
                        unsigned: None,
                        bits: None,
                        nullable: None,
                        scale: None,
                        column_type_code: 3,
                        flags: None,
                    });
            }
            recorder
                .append_case_dependency(&case, &event, "fixture")
                .await
                .unwrap();
        }
        let completed_refs = (0..exchanges.len())
            .map(|position| {
                traffic_model::recording::ProtocolRef::connection(
                    "mysql",
                    connection,
                    u64::try_from(position).unwrap() + 1,
                )
            })
            .collect::<Vec<_>>();
        for (name, value) in [
            ("admission.json", json!({"fixture":true})),
            (
                "request.json",
                json!({"method":"GET","uri":"/mysql","timestamp":"1970-01-01T00:16:40Z"}),
            ),
            ("expected-response.json", json!({})),
            (
                "dependency-tail-observation.json",
                json!({
                    "version":1,
                    "request_timeout_ms":1000,
                    "outcome":"quiet",
                    "inventory_complete":true,
                    "completed_refs":completed_refs
                }),
            ),
        ] {
            recorder.write_case_json(&case, name, &value).await.unwrap();
        }
        recorder.publish_case(&case).await.unwrap();
        recorder.finish_run().await.unwrap();
        let address = "127.0.0.1:0".parse().unwrap();
        let runtime = ReplayRuntime::load_with_lifecycle(
            MysqlReplayConfig {
                case_dir: recorder.run_dir().as_ref().clone(),
                selected_case_ids: vec![],
                dns_listen: address,
                tcp_listen: address,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: Some(directory.path().join("report.json")),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(directory.path().join("ca.pem")),
                ca_key_path: Some(directory.path().join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            address,
            address,
            ReplayLifecycleConfig {
                case_dependency_post_response_window: Duration::ZERO,
                dependency_loading: ReplayDependencyLoading {
                    lazy_cases,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let fixture = Self {
            _directory: directory,
            runtime,
            case: case.id.to_string(),
        };
        fixture.control("begin").await;
        fixture.control("request_begin").await;
        fixture
    }

    async fn control(&self, name: &str) -> Value {
        let command: ReplayControlRequest = serde_json::from_value(json!({
            "command": name,
            "case_id": self.case,
            "fail_on_dirty": true,
        }))
        .unwrap();
        let (response, _) = crate::replay::handle_control_request(
            command,
            self.runtime.state.clone(),
            self.runtime.report_path.clone(),
            None,
        )
        .await;
        assert_eq!(response["ok"], true, "{name}: {response}");
        response
    }

    async fn connect(&self) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let target = crate::replay::ReplayTarget {
            host: "mysql.test".into(),
            port: 3306,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: crate::replay::ReplayProtocol::new(traffic_protocol::ProtocolId::new(
                "mysql",
            )),
        };
        let task = tokio::spawn(serve_native(server, target, self.runtime.state.clone()));
        assert_eq!(packet(&mut client).await.unwrap().payload[0], 10);
        let mut payload = vec![0; 32];
        payload[..4].copy_from_slice(&0x8208_u32.to_le_bytes());
        payload.extend_from_slice(b"reader\0\0app\0");
        write_packet(
            &mut client,
            &MysqlPacket {
                sequence_id: 1,
                payload,
            },
        )
        .await
        .unwrap();
        assert_eq!(packet(&mut client).await.unwrap().payload[0], 0);
        (client, task)
    }
}

async fn packet(client: &mut TcpStream) -> Option<MysqlPacket> {
    tokio::time::timeout(Duration::from_secs(3), read_packet(client))
        .await
        .expect("MySQL replay packet timed out")
        .unwrap()
}

async fn query(client: &mut TcpStream, sql: &str) -> Option<MysqlPacket> {
    let mut payload = vec![3];
    payload.extend_from_slice(sql.as_bytes());
    write_packet(
        client,
        &MysqlPacket {
            sequence_id: 0,
            payload,
        },
    )
    .await
    .unwrap();
    packet(client).await
}

async fn ok_status(client: &mut TcpStream, sql: &str) -> u16 {
    let response = query(client, sql).await.unwrap().payload;
    assert_eq!(&response[..3], &[0, 0, 0], "{sql}");
    u16::from_le_bytes(response[3..5].try_into().unwrap())
}

async fn select_status(client: &mut TcpStream, sql: &str) -> u16 {
    assert_eq!(query(client, sql).await.unwrap().payload, [1], "{sql}");
    let _column = packet(client).await.unwrap();
    let _column_end = packet(client).await.unwrap();
    let end = packet(client).await.unwrap().payload;
    assert_eq!(end[0], 0xfe);
    u16::from_le_bytes(end[3..5].try_into().unwrap())
}

#[tokio::test]
async fn mysql_native_replay_skips_proven_read_only_and_pool_cleanup_ends() {
    for lazy in [false, true] {
        let fixture = Fixture::new(
            &[
                ("SET autocommit = 0", 2, 0),
                (READ, 0, 1),
                ("ROLLBACK", 1, 0),
                ("ROLLBACK", 0, 0),
                (READ_AFTER_WRITE, 0, 1),
                ("COMMIT", 1, 0),
            ],
            lazy,
        )
        .await;
        let (mut client, task) = fixture.connect().await;
        assert_eq!(select_status(&mut client, READ).await & 3, 2);
        assert_eq!(select_status(&mut client, READ_AFTER_WRITE).await & 3, 2);
        assert_eq!(ok_status(&mut client, "ROLLBACK").await & 3, 2);
        drop(client);
        task.await.unwrap().unwrap();
        assert_eq!(fixture.control("end").await["dirty"], false);
    }
}

#[tokio::test]
async fn mysql_native_replay_zero_row_write_requires_same_connection_through_rollback() {
    for (begin, start_status, write_status, end_status) in
        [("BEGIN", 3, 3, 2), ("SET autocommit=0", 0, 1, 0)]
    {
        let fixture = Fixture::new(
            &[
                ("SET autocommit = 0", 2, 0),
                (READ, 0, 1),
                (WRITE, 1, 1),
                (READ_AFTER_WRITE, 1, 1),
                ("ROLLBACK", 1, 0),
            ],
            false,
        )
        .await;
        let (mut client, task) = fixture.connect().await;
        assert_eq!(select_status(&mut client, READ).await & 3, 2);
        assert_eq!(ok_status(&mut client, begin).await & 3, start_status);
        assert_eq!(ok_status(&mut client, WRITE).await & 3, write_status);
        assert_eq!(
            select_status(&mut client, READ_AFTER_WRITE).await & 3,
            write_status
        );
        assert_eq!(ok_status(&mut client, "ROLLBACK").await & 3, end_status);
        drop(client);
        task.await.unwrap().unwrap();
        assert_eq!(fixture.control("end").await["dirty"], false);
    }
}

#[tokio::test]
async fn mysql_native_replay_rejects_autocommit_write_foreign_continuation_and_wrong_end() {
    let fixture = Fixture::new(
        &[
            ("SET autocommit = 0", 2, 0),
            (WRITE, 0, 1),
            (READ_AFTER_WRITE, 1, 1),
            ("ROLLBACK", 1, 0),
        ],
        false,
    )
    .await;
    let (mut wrong, task) = fixture.connect().await;
    assert!(query(&mut wrong, WRITE).await.is_none());
    assert!(task.await.unwrap().is_err());

    let (mut owner, owner_task) = fixture.connect().await;
    assert_eq!(ok_status(&mut owner, "BEGIN").await & 3, 3);
    assert_eq!(ok_status(&mut owner, WRITE).await & 3, 3);

    let (mut wrong, task) = fixture.connect().await;
    assert_eq!(ok_status(&mut wrong, "BEGIN").await & 3, 3);
    assert!(query(&mut wrong, READ_AFTER_WRITE).await.is_none());
    assert!(task.await.unwrap().is_err());

    assert_eq!(select_status(&mut owner, READ_AFTER_WRITE).await & 3, 3);
    assert!(query(&mut owner, "COMMIT").await.is_none());
    assert!(owner_task.await.unwrap().is_err());
}
