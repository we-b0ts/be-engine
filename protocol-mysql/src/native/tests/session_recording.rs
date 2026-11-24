use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use traffic_model::{recording::ProtocolRef, trace::OutputKind};
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{CaptureExchange, CaptureHost, CaptureOutput, Endpoint, NativeFuture, Operation},
};

use super::*;
use crate::MysqlPacket;

#[derive(Default)]
struct Sink {
    observations: Arc<Mutex<Vec<CaptureSnapshot>>>,
    failures: Mutex<Vec<&'static str>>,
}

struct Permit(Arc<Mutex<Vec<CaptureSnapshot>>>);
struct Receipt;

impl CaptureOutput for Receipt {
    fn commit(self: Box<Self>) {}
}

impl CaptureExchange for Permit {
    fn prepare_output(&self, _: OutputKind) -> Result<Box<dyn CaptureOutput>> {
        Ok(Box::new(Receipt))
    }

    fn complete(self: Box<Self>, event: CaptureSnapshot) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
            Ok(())
        })
    }
}

impl CaptureHost for Sink {
    fn begin(
        &self,
        _: ProtocolRef,
        _: Operation,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>> {
        Box::pin(async { Ok(Some(Box::new(Permit(self.observations.clone())) as Box<_>)) })
    }

    fn observe(&self, event: CaptureSnapshot) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.observations.lock().unwrap().push(event);
            Ok(())
        })
    }

    fn omit_builtin_maintenance(&self, _: Operation) -> bool {
        true
    }

    fn builtin_maintenance_failed(&self, name: &'static str) {
        self.failures.lock().unwrap().push(name);
    }
}

#[tokio::test]
async fn successful_ping_is_absent_and_preserves_native_exchange_adjacency() -> Result<()> {
    let (mut client, capture_client) = tokio::io::duplex(4096);
    let (capture_upstream, mut upstream) = tokio::io::duplex(4096);
    let sink = Arc::new(Sink::default());
    let info = ConnectionInfo {
        endpoint: Endpoint {
            host: "mysql.test".into(),
            port: 3306,
        },
        client_addr: None,
        upstream_addr: None,
        max_frame_bytes: 4096,
    };
    let capture = Native.capture_session(info)?;
    let worker = tokio::spawn(capture.run(
        Box::new(capture_client),
        Box::new(capture_upstream),
        sink.clone(),
    ));
    crate::write_packet(&mut upstream, &crate::response::handshake_packet(1)).await?;
    crate::read_packet(&mut client).await?.unwrap();
    let mut login = vec![0; 32];
    login[..4].copy_from_slice(&crate::types::CLIENT_PROTOCOL_41.to_le_bytes());
    login.extend_from_slice(b"user\0\0");
    crate::write_packet(
        &mut client,
        &MysqlPacket {
            sequence_id: 1,
            payload: login,
        },
    )
    .await?;
    crate::read_packet(&mut upstream).await?.unwrap();
    let ok = crate::response::ok_payload_with_status(0, 0, crate::types::SERVER_STATUS_AUTOCOMMIT);
    crate::write_packet(
        &mut upstream,
        &MysqlPacket {
            sequence_id: 2,
            payload: ok.clone(),
        },
    )
    .await?;
    crate::read_packet(&mut client).await?.unwrap();
    for input in [b"\x03SET @x=1".as_slice(), b"\x0e", b"\x03SET @x=2"] {
        crate::write_packet(
            &mut client,
            &MysqlPacket {
                sequence_id: 0,
                payload: input.to_vec(),
            },
        )
        .await?;
        assert_eq!(
            crate::read_packet(&mut upstream).await?.unwrap().payload,
            input
        );
        crate::write_packet(
            &mut upstream,
            &MysqlPacket {
                sequence_id: 1,
                payload: ok.clone(),
            },
        )
        .await?;
        assert_eq!(crate::read_packet(&mut client).await?.unwrap().payload, ok);
    }
    client.shutdown().await?;
    upstream.shutdown().await?;
    worker.await??;

    let observations = sink.observations.lock().unwrap();
    let exchanges: Vec<_> = observations
        .iter()
        .filter(|event| event.payload()["event_type"] == "mysql_exchange")
        .map(CaptureSnapshot::payload)
        .collect();
    assert_eq!(exchanges.len(), 2);
    assert_eq!(exchanges[0]["query_sequence"], 1);
    assert_eq!(exchanges[1]["query_sequence"], 2);
    assert_eq!(
        exchanges[1]["server_status_before"],
        crate::types::SERVER_STATUS_AUTOCOMMIT
    );
    assert!(
        observations
            .iter()
            .all(|event| event.payload()["command"] != "COM_PING")
    );
    assert!(sink.failures.lock().unwrap().is_empty());
    Ok(())
}
