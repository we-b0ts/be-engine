use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncWriteExt, DuplexStream};
use traffic_protocol::{
    connection::{
        NativeFuture, OutputIo, RequestHost, RequestSession, ResponseDelivery, ResponseFramer,
    },
    message::MessageEncoder,
};
use traffic_replay::{
    ReplaySource,
    exchange::{ExchangeInventory, ExchangeRules, MatchContext, Selection, SourceContext},
};

struct Host {
    inventory: ExchangeInventory,
    event_session: bool,
    delivered: Arc<AtomicUsize>,
}

impl RequestHost for Host {
    fn event_session(&self) -> bool {
        self.event_session
    }

    fn statement_metadata<'a>(
        &'a self,
        template: &'a dyn ProtocolMessage,
        session: &'a RequestSession,
    ) -> NativeFuture<'a, Option<Arc<dyn MessageEncoder>>> {
        Box::pin(async move {
            Ok(self.inventory.statement_metadata(
                traffic_protocol::ProtocolId::new("mysql"),
                &endpoint(),
                template,
                session,
                traffic_replay::SourceEvent {
                    sequence: 234,
                    dependency_sequence: 234,
                    kind: traffic_replay::EventKind::Request,
                    offset_micros: 0,
                },
            ))
        })
    }

    fn execute_in_session(
        &self,
        request: Arc<dyn ProtocolMessage>,
        session: RequestSession,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            let selected = self.inventory.select(
                MatchContext {
                    protocol: traffic_protocol::ProtocolId::new("mysql"),
                    endpoint: &endpoint(),
                    active_case: None,
                    request: request.as_ref(),
                    session: None,
                    lane: None,
                    request_session: Some(&session),
                    metadata: &(),
                },
                |_| (),
                |_, _| Ok(()),
            )?;
            let Selection::Matched(selected) = selected else {
                anyhow::bail!("unmatched prepared execution");
            };
            Ok(Box::new(Delivery(
                self.inventory.exchanges[selected.index]
                    .native
                    .response
                    .clone(),
                self.delivered.clone(),
            )) as Box<dyn ResponseDelivery>)
        })
    }

    fn execute(&self, _: Arc<dyn ProtocolMessage>) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        unreachable!("native MySQL requires connection state")
    }
}

struct Delivery(Arc<dyn MessageEncoder>, Arc<AtomicUsize>);
impl ResponseDelivery for Delivery {
    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let values = self
                .0
                .project()?
                .values
                .into_iter()
                .map(|(path, value)| (path, value.bytes))
                .collect();
            let mut output = framer.prepare_output(self.0.output(&values)?)?;
            traffic_replay::output::deliver(io, output.as_mut(), None).await?;
            self.1.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

fn endpoint() -> Endpoint {
    Endpoint {
        host: "db.test".into(),
        port: 3306,
    }
}

async fn socket(
    sql: &str,
    response: Value,
    event_session: bool,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<Result<()>>,
    Arc<AtomicUsize>,
) {
    let mut source = event();
    source["sql"] = json!(sql);
    source["server_status_before"] = json!(2);
    source["response"] = response;
    let exchange = Native.recorded_exchange(&source).unwrap().unwrap();
    let capture = serde_json::from_value(json!({
        "sequence":234, "started_at": "2030-01-01T00:00:00Z",
        "exchange_id":uuid::Uuid::nil(), "process_epoch":uuid::Uuid::nil(), "effect_index":0,
        "phase":"startup", "semantic_required":true, "protocol_ref": exchange.reference,
        "attribution":{"kind":"startup", "process_epoch":uuid::Uuid::nil(), "initialization_unit":"fixture"},
    }))
    .unwrap();
    let mut inventory = ExchangeInventory::default();
    inventory
        .register(
            traffic_protocol::ProtocolId::new("mysql"),
            exchange,
            SourceContext {
                source: ReplaySource::Startup,
                case_id: None,
                position: 0,
                capture: Some(capture),
            },
            ExchangeRules::default(),
        )
        .unwrap();
    inventory.seal();
    let delivered = Arc::new(AtomicUsize::new(0));
    let host = Arc::new(Host {
        inventory,
        event_session,
        delivered: delivered.clone(),
    });
    let info = ConnectionInfo {
        endpoint: endpoint(),
        client_addr: None,
        upstream_addr: None,
        max_frame_bytes: 16 * 1024,
    };
    let (mut client, server) = tokio::io::duplex(8192);
    let task = tokio::spawn(
        Native
            .server_session(info)
            .unwrap()
            .run(Box::new(server), host),
    );
    packet(&mut client).await;
    let mut login = vec![0; 32];
    login[..4].copy_from_slice(
        &(crate::types::CLIENT_PROTOCOL_41 | crate::CLIENT_CONNECT_WITH_DB).to_le_bytes(),
    );
    login.extend_from_slice(b"user\0\0app\0");
    crate::write_packet(
        &mut client,
        &crate::MysqlPacket {
            sequence_id: 1,
            payload: login,
        },
    )
    .await
    .unwrap();
    packet(&mut client).await;
    (client, task, delivered)
}

async fn packet(client: &mut DuplexStream) -> Vec<u8> {
    crate::read_packet(client).await.unwrap().unwrap().payload
}

async fn send(client: &mut DuplexStream, command: u8, payload: &[u8]) {
    let mut bytes = vec![command];
    bytes.extend_from_slice(payload);
    crate::write_packet(
        client,
        &crate::MysqlPacket {
            sequence_id: 0,
            payload: bytes,
        },
    )
    .await
    .unwrap();
}

async fn prepare(client: &mut DuplexStream, sql: &str, parameters: usize, columns: usize) -> u32 {
    send(client, 0x16, sql.as_bytes()).await;
    let first = packet(client).await;
    assert_eq!(first[0], 0);
    assert_eq!(
        u16::from_le_bytes(first[5..7].try_into().unwrap()) as usize,
        columns
    );
    assert_eq!(
        u16::from_le_bytes(first[7..9].try_into().unwrap()) as usize,
        parameters
    );
    for definitions in [parameters, columns] {
        if definitions > 0 {
            for _ in 0..definitions {
                packet(client).await;
            }
            assert_eq!(packet(client).await[0], 0xfe);
        }
    }
    u32::from_le_bytes(first[1..5].try_into().unwrap())
}

#[tokio::test]
async fn prepared_update_matches_exact_bound_values_and_only_execution_delivers() {
    let template = "UPDATE kinds SET json=?, updated_at=NOW() WHERE kinds.id=?";
    let document = format!(r#"{{"body":"{}"}}"#, "a".repeat(8240));
    let recorded =
        format!("UPDATE `kinds` SET `json`='{document}', `updated_at`=now() WHERE `kinds`.`id`=7");
    let response = json!({"status":"ok", "affected_rows":1, "last_insert_id":0, "server_status":2});
    for id in [7_i64, 8] {
        let (mut client, task, delivered) = socket(&recorded, response.clone(), true).await;
        let statement = prepare(&mut client, template, 2, 0).await;
        assert_eq!(delivered.load(Ordering::Relaxed), 0);
        let mut execute = statement.to_le_bytes().to_vec();
        execute.extend_from_slice(&[0, 1, 0, 0, 0, 0, 1, 0xfd, 0, 8, 0]);
        execute.extend(crate::values::lenenc_int(document.len() as u64));
        execute.extend_from_slice(document.as_bytes());
        execute.extend_from_slice(&id.to_le_bytes());
        send(&mut client, 0x17, &execute).await;
        if id == 7 {
            let ok = packet(&mut client).await;
            assert_eq!(&ok[..3], &[0, 1, 0]);
            send(&mut client, 0x19, &statement.to_le_bytes()).await;
            send(&mut client, 0x0e, &[]).await;
            assert_eq!(packet(&mut client).await[0], 0);
            client.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
            assert_eq!(delivered.load(Ordering::Relaxed), 1);
        } else {
            assert_eq!(
                task.await.unwrap().unwrap_err().to_string(),
                "unmatched prepared execution"
            );
            assert_eq!(delivered.load(Ordering::Relaxed), 0);
        }
    }
    let (mut client, task, delivered) = socket(&recorded, response, false).await;
    send(&mut client, 0x16, template.as_bytes()).await;
    assert_eq!(packet(&mut client).await[0], 0xff);
    assert!(task.await.unwrap().is_err());
    assert_eq!(delivered.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn text_source_rows_use_binary_encoding_for_prepared_target() {
    let mut response = event()["response"].clone();
    response["server_status"] = json!(2);
    let (mut client, task, delivered) =
        socket("SELECT id FROM items WHERE id=7", response, true).await;
    let statement = prepare(&mut client, "SELECT id FROM items WHERE id=?", 1, 1).await;
    let mut execute = statement.to_le_bytes().to_vec();
    execute.extend_from_slice(&[0, 1, 0, 0, 0, 0, 1, 8, 0]);
    execute.extend_from_slice(&7i64.to_le_bytes());
    send(&mut client, 0x17, &execute).await;
    assert_eq!(packet(&mut client).await, [1]);
    packet(&mut client).await;
    assert_eq!(packet(&mut client).await[0], 0xfe);
    assert_eq!(packet(&mut client).await, [0, 0, 7, 0, 0, 0]);
    assert_eq!(packet(&mut client).await[0], 0xfe);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(delivered.load(Ordering::Relaxed), 1);
}
