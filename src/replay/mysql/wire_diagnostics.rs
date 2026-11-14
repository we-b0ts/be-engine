//! Native wire-envelope diagnostics installed by the MySQL connection adapter.
pub(super) use traffic_protocol_mysql::diagnostics::*;

#[cfg(test)]
mod tests {
    use super::super::MysqlPacket;
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Writer(Arc<Mutex<Vec<u8>>>);

    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_trace_correlates_envelopes_without_disclosing_payloads() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer(Arc::clone(&output));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        connection("127.0.0.1:12345".parse().unwrap(), async {
            request(
                &MysqlPacket {
                    sequence_id: 0,
                    payload: b"SELECT 'private-sql'".to_vec(),
                },
                "COM_QUERY",
            );
            response(
                &MysqlPacket {
                    sequence_id: 1,
                    payload: b"\0private-row".to_vec(),
                },
                Some(2),
            );
            flushed(true);
            request(
                &MysqlPacket {
                    sequence_id: 0,
                    payload: vec![0x0e],
                },
                "COM_PING",
            );
            client_eof();
        })
        .await;
        let trace = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(trace.contains("peer=127.0.0.1:12345"));
        assert!(trace.contains("request=1") && trace.contains("request=2"));
        assert!(trace.contains("payload_bytes=12") && trace.contains("leading_byte=Some(0)"));
        assert!(trace.contains("transport_flush") && trace.contains("client_eof"));
        assert!(!trace.contains("private-sql") && !trace.contains("private-row"));
        // The scope must not leak a preceding connection's request counter.
        connection("127.0.0.1:54321".parse().unwrap(), async {
            assert_eq!(request_number(), Some(0));
        })
        .await;
        assert!(request_number().is_none());

        async fn encoded_responses() -> Vec<u8> {
            use tokio::io::AsyncReadExt;
            let (mut writer, mut reader) = tokio::io::duplex(65536);
            let metadata = super::super::StatementMetadata::new(
                2,
                serde_json::from_value(serde_json::json!([
                    {"name":"private-column", "family":"integer", "sql_type":"INT"}
                ]))
                .unwrap(),
            );
            let response = serde_json::from_value(serde_json::json!({
                "status":"ok", "affected_rows":0, "last_insert_id":0
            }))
            .unwrap();
            super::super::write_response(
                &mut writer,
                &response,
                super::super::ResultRowEncoding::Text,
                3,
            )
            .await
            .unwrap();
            super::super::write_stmt_prepare_ok(&mut writer, 1, &metadata, 3)
                .await
                .unwrap();
            drop(writer);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        }
        let plain = encoded_responses().await;
        let traced = connection("127.0.0.1:54321".parse().unwrap(), encoded_responses()).await;
        assert_eq!(
            plain, traced,
            "wire diagnostics must not change response bytes"
        );
        let mut packets = traced.as_slice();
        let begin = super::super::read_packet(&mut packets)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(begin.payload.len(), 7);
        let prepare = super::super::read_packet(&mut packets)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepare.payload.len(), 12);
        let trace = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(!trace.contains("private-column"));
        assert!(
            trace.contains("prepare_ok_and_metadata") && trace.contains("status_flags=Some(3)")
        );
    }
}
