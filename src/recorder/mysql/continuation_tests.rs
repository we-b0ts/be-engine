use super::*;
use crate::mysql::wire::continuation::{MAX_PACKET_PAYLOAD_LEN, write_message};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

fn column(name: &str, type_code: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in ["def", "appdb", "contexts", "contexts", name, name] {
        payload.push(value.len() as u8);
        payload.extend_from_slice(value.as_bytes());
    }
    payload.push(12);
    payload.extend_from_slice(&33_u16.to_le_bytes());
    payload.extend_from_slice(&u32::MAX.to_le_bytes());
    payload.push(type_code);
    payload.extend_from_slice(&[0; 5]);
    payload
}

fn lenenc(bytes: &[u8]) -> Vec<u8> {
    let mut payload = vec![0xfe];
    payload.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(bytes);
    payload
}

fn start(tracker: &mut MysqlQueryTracker, command: u8, sql: &[u8], sequence: u64) {
    let packet = MysqlPacket {
        sequence_id: 0,
        payload: [vec![command], sql.to_vec()].concat(),
    };
    tracker
        .start_query(
            Uuid::nil(),
            sequence,
            &parse_client_command(&packet).unwrap(),
            &packet,
            None,
        )
        .unwrap();
}

#[tokio::test]
async fn captures_complete_text_and_binary_large_rows_with_physical_debug_packets() {
    for binary in [false, true] {
        let mut tracker =
            MysqlQueryTracker::new(64 * 1024 * 1024, true, MysqlExchangeContext::default());
        if binary {
            start(&mut tracker, 0x16, b"SELECT id,image FROM contexts", 1);
            let mut prepared = vec![0];
            prepared.extend_from_slice(&7_u32.to_le_bytes());
            prepared.extend_from_slice(&2_u16.to_le_bytes());
            prepared.extend_from_slice(&[0; 5]);
            for (index, payload) in [
                prepared,
                column("id", 3),
                column("image", 252),
                vec![0xfe, 0, 0, 2, 0],
            ]
            .into_iter()
            .enumerate()
            {
                tracker
                    .observe_server_packet(&MysqlPacket {
                        sequence_id: index as u8 + 1,
                        payload,
                    })
                    .unwrap();
            }
            start(&mut tracker, 0x17, &[7, 0, 0, 0, 0, 1, 0, 0, 0], 2);
        } else {
            start(&mut tracker, 0x03, b"SELECT id,image FROM contexts", 1);
        }

        // The continuation starts with ERR-looking data, not a protocol marker.
        let prefix = if binary {
            [vec![0, 0], 42_i32.to_le_bytes().to_vec()].concat()
        } else {
            vec![2, b'4', b'2']
        };
        let mut image = vec![b'a'; 19_795_000];
        image[MAX_PACKET_PAYLOAD_LEN - prefix.len() - 9] = 0xff;
        let row = [prefix, lenenc(&image)].concat();
        let small = if binary {
            [vec![0, 0], 43_i32.to_le_bytes().to_vec(), lenenc(b"small")].concat()
        } else {
            [vec![2, b'4', b'3'], lenenc(b"small")].concat()
        };
        let mut wire = Vec::new();
        let mut sequence_id = 1;
        for payload in [
            vec![2],
            column("id", 3),
            column("image", 252),
            vec![0xfe, 0, 0, 2, 0],
            row,
            small,
            vec![0xfe, 0, 0, 2, 0],
        ] {
            sequence_id = write_message(
                &mut wire,
                &MysqlPacket {
                    sequence_id,
                    payload,
                },
            )
            .await
            .unwrap();
        }
        let mut input = wire.as_slice();
        let mut final_completion = None;
        while let Some(packet) = read_packet(&mut input).await.unwrap() {
            let completion = tracker.observe_server_packet(&packet).unwrap();
            if !completion.is_empty() {
                assert!(
                    input.is_empty(),
                    "continuation completed the response early"
                );
                final_completion = Some(completion);
            }
        }
        let (debug, exchange) = final_completion.unwrap().into_parts();
        let debug = debug.unwrap();
        assert_eq!(debug.status, "resultset");
        assert_eq!(debug.packet_count, 8);
        assert_eq!(debug.packets.as_ref().unwrap().len(), 8);
        assert_eq!(
            debug.packets.as_ref().unwrap()[4].payload_len,
            MAX_PACKET_PAYLOAD_LEN
        );
        assert_eq!(debug.packets.as_ref().unwrap()[5].sequence_id, 6);
        assert_eq!(debug.payload_bytes + 8 * 4, wire.len());
        let exchange = exchange.unwrap();
        assert!(
            exchange.parse_warnings.is_empty(),
            "{:?}",
            exchange.parse_warnings
        );
        assert_eq!(exchange.response.server_status, Some(2));
        assert_eq!(exchange.response.row_count, 2);
        assert_eq!(exchange.response.rows[0][0].value, Some(json!(42)));
        assert_eq!(exchange.response.rows[1][0].value, Some(json!(43)));
        let raw = exchange.response.rows[0][1].raw.as_ref().unwrap();
        assert_eq!(STANDARD.decode(&raw.data).unwrap(), image);
        assert!(!raw.truncated);
    }
}

#[test]
fn records_a_missing_continuation_as_a_parse_warning() {
    let mut tracker = MysqlQueryTracker::new(1024, false, MysqlExchangeContext::default());
    start(&mut tracker, 0x03, b"SELECT image FROM contexts", 1);
    tracker
        .observe_server_packet(&MysqlPacket {
            sequence_id: 1,
            payload: vec![1],
        })
        .unwrap();
    tracker
        .observe_server_packet(&MysqlPacket {
            sequence_id: 2,
            payload: vec![b'a'; MAX_PACKET_PAYLOAD_LEN],
        })
        .unwrap();
    let (_, exchange) = tracker.finish_active("incomplete").unwrap().into_parts();
    assert!(
        exchange
            .unwrap()
            .parse_warnings
            .iter()
            .any(|w| w.contains("continuation packet ended"))
    );
}

#[tokio::test]
async fn eof_looking_continuation_does_not_finish_the_resultset() {
    let mut tracker =
        MysqlQueryTracker::new(32 * 1024 * 1024, false, MysqlExchangeContext::default());
    start(&mut tracker, 0x03, b"SELECT image FROM contexts", 1);
    let mut image = vec![b'a'; MAX_PACKET_PAYLOAD_LEN - 4];
    let image_len = image.len();
    image[image_len - 5..].copy_from_slice(&[0xfe, 0, 0, 2, 0]);
    let mut wire = Vec::new();
    let mut sequence_id = 1;
    for payload in [
        vec![1],
        column("image", 252),
        vec![0xfe, 0, 0, 2, 0],
        lenenc(&image),
    ] {
        sequence_id = write_message(
            &mut wire,
            &MysqlPacket {
                sequence_id,
                payload,
            },
        )
        .await
        .unwrap();
    }
    let mut input = wire.as_slice();
    while let Some(packet) = read_packet(&mut input).await.unwrap() {
        assert!(tracker.observe_server_packet(&packet).unwrap().is_empty());
    }
    let eof = MysqlPacket {
        sequence_id,
        payload: vec![0xfe, 0, 0, 2, 0],
    };
    let (_, exchange) = tracker.observe_server_packet(&eof).unwrap().into_parts();
    let exchange = exchange.unwrap();
    assert!(exchange.parse_warnings.is_empty());
    assert_eq!(exchange.response.row_count, 1);
    assert_eq!(
        STANDARD
            .decode(&exchange.response.rows[0][0].raw.as_ref().unwrap().data)
            .unwrap(),
        image
    );
}
