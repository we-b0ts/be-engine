use super::*;

#[test]
fn aggregates_resultset_packets_into_one_response() {
    let mut tracker = MysqlResponseTracker::new(1024, true);
    tracker.start_query(Uuid::nil(), 7, "COM_STMT_EXECUTE".to_string(), None);

    assert!(
        observe_payload(&mut tracker, 1, &[1]).is_none(),
        "column-count packet should not finish the response"
    );
    assert!(
        observe_payload(&mut tracker, 2, b"column").is_none(),
        "column definition packet should not finish the response"
    );
    assert!(
        observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none(),
        "first EOF ends column definitions only"
    );
    assert!(
        observe_payload(&mut tracker, 4, &[0x00, b'r', b'o', b'w']).is_none(),
        "binary row payloads may start with 0x00 and must not finish as OK"
    );

    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
        .expect("second EOF should finish the response");
    assert_eq!(response.query_sequence, 7);
    assert_eq!(response.status, "resultset");
    assert_eq!(response.packet_count, 5);
    assert_eq!(response.payload_bytes, 21);
    assert_eq!(response.payload.original_len, 21);
    assert_eq!(response.payload.stored_len, 21);
    assert!(!response.payload.truncated);
    let packets = response.packets.expect("raw packets should be recorded");
    assert_eq!(packets[3].packet_kind, "result_or_data");
    assert_eq!(packets[3].payload.original_len, 4);
}

#[test]
fn response_payload_is_concatenated_and_truncated() {
    let mut tracker = MysqlResponseTracker::new(4, false);
    tracker.start_query(Uuid::nil(), 8, "COM_STMT_EXECUTE".to_string(), None);

    assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
    assert!(observe_payload(&mut tracker, 2, b"abc").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"row").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

    assert_eq!(response.payload_bytes, 17);
    assert_eq!(response.payload.original_len, 17);
    assert_eq!(response.payload.stored_len, 4);
    assert!(response.payload.truncated);
    assert!(response.packets.is_none());
}

#[test]
fn raw_packets_can_be_recorded_when_enabled() {
    let mut tracker = MysqlResponseTracker::new(4, true);
    tracker.start_query(Uuid::nil(), 9, "COM_STMT_EXECUTE".to_string(), None);

    assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
    assert!(observe_payload(&mut tracker, 2, b"abcdef").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"row").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

    let packets = response.packets.expect("raw packets should be recorded");
    assert_eq!(packets[1].payload_len, 6);
    assert_eq!(packets[1].payload.original_len, 6);
    assert_eq!(packets[1].payload.stored_len, 4);
    assert!(packets[1].payload.truncated);
}

#[test]
fn aggregates_stmt_prepare_until_expected_eofs() {
    let mut tracker = MysqlResponseTracker::new(1024, false);
    tracker.start_query(Uuid::nil(), 3, "COM_STMT_PREPARE".to_string(), None);

    let mut prepare_ok = vec![0x00];
    prepare_ok.extend_from_slice(&1_u32.to_le_bytes());
    prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
    prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
    prepare_ok.push(0);
    prepare_ok.extend_from_slice(&0_u16.to_le_bytes());

    assert!(observe_payload(&mut tracker, 1, &prepare_ok).is_none());
    assert!(observe_payload(&mut tracker, 2, b"param").is_none());
    assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
    assert!(observe_payload(&mut tracker, 4, b"column").is_none());
    let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
        .expect("stmt prepare should finish after param and column EOF packets");
    assert_eq!(response.status, "stmt_prepare");
    assert_eq!(response.packet_count, 5);
    assert!(response.packets.is_none());
}

fn observe_payload(
    tracker: &mut MysqlResponseTracker,
    sequence_id: u8,
    payload: &[u8],
) -> Option<MysqlResponseEvent> {
    let packet = MysqlPacket {
        sequence_id,
        payload: payload.to_vec(),
    };
    tracker.observe_packet(&packet, Some(&packet))
}
