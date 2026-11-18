use super::*;
use serde_json::json;

fn recorded(status: &str) -> RecordedMysqlResponse {
    serde_json::from_value(json!({
        "status":status, "server_status":3, "affected_rows":2, "last_insert_id":9,
        "error_code":1205,"error_message":"fixture failure",
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":1}],[{"kind":"integer","value":2}]]
    }))
    .unwrap()
}

#[tokio::test]
async fn native_resultsets_expose_finite_headers_rows_and_the_real_protocol_end() {
    for encoding in [ResultRowEncoding::Text, ResultRowEncoding::Binary] {
        let response = recorded("resultset");
        let mut output = response_output(&response, encoding);
        assert_eq!(output.part_count(), 2);
        let mut boundaries = Vec::new();
        let mut complete = Vec::new();
        let mut wire = Vec::new();
        while let Some(chunk) = output.next().unwrap() {
            boundaries.push(chunk.boundary);
            complete.push(chunk.complete);
            wire.extend_from_slice(&chunk.bytes);
        }
        assert_eq!(
            boundaries,
            [
                OutputBoundary::Headers,
                OutputBoundary::Headers,
                OutputBoundary::Headers,
                OutputBoundary::Part,
                OutputBoundary::Part,
                OutputBoundary::End
            ]
        );
        assert_eq!(complete, [false, false, true, true, true, true]);
        let mut bytes = wire.as_slice();
        let mut packets = Vec::new();
        while let Some(packet) = crate::read_packet(&mut bytes).await.unwrap() {
            packets.push(packet);
        }
        assert_eq!(
            packets
                .iter()
                .map(|packet| packet.sequence_id)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(packets[2].payload, eof_payload_with_status(3));
        assert_eq!(packets[5].payload, eof_payload_with_status(3));
        for (packet, row) in packets[3..5].iter().zip(&response.rows) {
            let expected = match encoding {
                ResultRowEncoding::Text => text_row_payload(row).unwrap(),
                ResultRowEncoding::Binary => binary_row_payload(&response.columns, row).unwrap(),
            };
            assert_eq!(packet.payload, expected);
        }
    }
}

fn response_output(
    response: &RecordedMysqlResponse,
    encoding: ResultRowEncoding,
) -> ResponseOutput<'_> {
    super::response(response, encoding, 3)
}

#[tokio::test]
async fn ordinary_native_statuses_retain_one_complete_output_and_original_error_encoding() {
    for (status, leading) in [
        ("ok", 0),
        ("error", 255),
        ("unknown", 255),
        ("resultset", 255),
    ] {
        let mut response = recorded(status);
        response.columns.clear();
        let mut output = response_output(&response, ResultRowEncoding::Text);
        assert_eq!(output.part_count(), 0);
        let chunk = output.next().unwrap().unwrap();
        assert_eq!(chunk.boundary, OutputBoundary::End);
        assert!(chunk.complete);
        let packet = crate::read_packet(&mut chunk.bytes.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.sequence_id, 1);
        assert_eq!(packet.payload[0], leading);
        if status == "error" {
            assert_eq!(packet.payload, err_payload(1205, "fixture failure"));
        }
        assert!(output.next().unwrap().is_none());
    }
}
