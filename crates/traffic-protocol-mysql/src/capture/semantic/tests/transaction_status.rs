use super::*;

fn enqueue(tracker: &mut MysqlSemanticTracker, sequence: u64, command: u8, sql: &str) {
    let packet = MysqlPacket {
        sequence_id: 0,
        payload: [vec![command], sql.as_bytes().to_vec()].concat(),
    };
    tracker.start_query(
        Uuid::nil(),
        sequence,
        &parse_client_command(&packet).unwrap(),
        &packet,
        None,
    );
}

fn finish(
    tracker: &mut MysqlSemanticTracker,
    status: &str,
    packets: Vec<Vec<u8>>,
) -> MysqlExchangeEvent {
    for (index, payload) in packets.into_iter().enumerate() {
        tracker.observe_packet(&MysqlPacket {
            sequence_id: index as u8 + 1,
            payload,
        });
    }
    tracker.finish_active(status, None, None, Some(1)).unwrap()
}

fn ok(flags: u16) -> Vec<Vec<u8>> {
    vec![vec![0, 0, 0, flags as u8, (flags >> 8) as u8, 0, 0]]
}

fn resultset(final_eof: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut packets = vec![
        vec![1],
        column_def("id", MYSQL_TYPE_LONG),
        vec![0xfe, 0, 0, 0, 0],
        lenenc_bytes(b"1"),
    ];
    packets.extend(final_eof);
    packets
}

#[test]
fn pipelined_ping_read_and_rollback_capture_actual_status_transitions() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    // The ping is omitted from semantic dependencies, but its observed status
    // must still establish the first SELECT's transaction boundary.
    enqueue(&mut tracker, 115, 0x0e, "");
    enqueue(&mut tracker, 116, 0x03, "SELECT id FROM users");
    enqueue(&mut tracker, 117, 0x03, "ROLLBACK");
    let ping = finish(&mut tracker, "ok", ok(0));
    assert_eq!(ping.server_status_before, None);
    let read = finish(
        &mut tracker,
        "resultset",
        resultset(Some(vec![0xfe, 0, 0, 1, 0])),
    );
    assert_eq!(read.server_status_before, Some(0));
    assert_eq!(read.response.server_status, Some(1));
    let rollback = finish(&mut tracker, "ok", ok(0));
    assert_eq!(rollback.server_status_before, Some(1));
    assert_eq!(rollback.response.server_status, Some(0));
    let evidence = serde_json::to_value(read).unwrap();
    assert_eq!(evidence["server_status_before"], 0);
    assert_eq!(evidence["response"]["server_status"], 1);
}

#[test]
fn only_complete_final_eof_provides_resultset_status() {
    for (eof, expected) in [
        (Some(vec![0xfe, 0, 0, 1, 0]), Some(1)),
        (Some(vec![0xfe, 0, 0, 1, 0x20]), Some(0x2001)),
        (Some(vec![0xfe, 0, 0, 2]), None),
        (None, None),
    ] {
        let mut tracker = MysqlSemanticTracker::new(test_context());
        enqueue(&mut tracker, 1, 0x03, "SELECT id FROM users");
        let read = finish(&mut tracker, "resultset", resultset(eof));
        assert_eq!(read.response.server_status, expected);
        enqueue(&mut tracker, 2, 0x03, "ROLLBACK");
        assert_eq!(
            finish(&mut tracker, "ok", ok(0)).server_status_before,
            expected
        );
    }
}

#[test]
fn errors_gaps_and_no_response_commands_invalidate_previous_status() {
    for status in ["error", "incomplete", "client_terminated"] {
        let mut tracker = MysqlSemanticTracker::new(test_context());
        enqueue(&mut tracker, 1, 0x0e, "");
        finish(&mut tracker, "ok", ok(0));
        enqueue(&mut tracker, 2, 0x03, "SELECT id FROM users");
        finish(&mut tracker, status, vec![vec![0xff, 0x15, 0x04]]);
        enqueue(&mut tracker, 3, 0x03, "ROLLBACK");
        assert_eq!(finish(&mut tracker, "ok", ok(0)).server_status_before, None);
    }
    let mut tracker = MysqlSemanticTracker::new(test_context());
    enqueue(&mut tracker, 1, 0x0e, "");
    finish(&mut tracker, "ok", ok(0));
    enqueue(&mut tracker, 3, 0x03, "ROLLBACK");
    assert_eq!(finish(&mut tracker, "ok", ok(0)).server_status_before, None);
    let close = MysqlPacket {
        sequence_id: 0,
        payload: vec![0x19, 1, 0, 0, 0],
    };
    tracker.observe_no_response_command(&parse_client_command(&close).unwrap(), &close);
    enqueue(&mut tracker, 4, 0x03, "ROLLBACK");
    assert_eq!(finish(&mut tracker, "ok", ok(0)).server_status_before, None);
}

#[test]
fn prepare_preserves_known_status_but_pending_results_do_not() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    enqueue(&mut tracker, 1, 0x0e, "");
    finish(&mut tracker, "ok", ok(0));
    enqueue(&mut tracker, 2, 0x16, "SELECT id FROM users");
    let prepare = finish(&mut tracker, "stmt_prepare", vec![prepare_ok(9, 0, 0)]);
    assert_eq!(prepare.response.server_status, None);
    enqueue(&mut tracker, 3, 0x03, "SELECT id FROM users");
    assert_eq!(
        finish(
            &mut tracker,
            "resultset",
            resultset(Some(vec![0xfe, 0, 0, 9, 0]))
        )
        .server_status_before,
        Some(0)
    );
    enqueue(&mut tracker, 4, 0x03, "ROLLBACK");
    assert_eq!(finish(&mut tracker, "ok", ok(0)).server_status_before, None);
}
