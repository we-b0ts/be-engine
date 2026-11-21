use super::*;
use crate::parse_client_command;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use traffic_model::capture::BodyCapture;

mod transaction_status;

#[test]
fn semantic_exchange_retains_the_observed_request_clock_not_completion_minus_duration() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    let query = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x03], b"SELECT 1".to_vec()].concat(),
    };
    let command = parse_client_command(&query).unwrap();
    tracker.start_query(Uuid::nil(), 1, &command, &query, None);
    let observed = tracker.pending.front().unwrap().request_started_at;
    let exchange = tracker
        .finish_active("ok", None, None, Some(30_000))
        .unwrap();
    assert_eq!(exchange.request_started_at, observed);
    assert_ne!(
        exchange.timestamp - chrono::TimeDelta::seconds(30),
        observed
    );
    let serialized = serde_json::to_value(exchange).unwrap();
    assert_eq!(
        serialized["request_started_at"],
        serde_json::to_value(observed).unwrap()
    );
}

#[test]
fn column_origins_preserve_wire_schema_independently_of_connection_database() {
    let column = parse_column_definition(&column_def("updated_at", MYSQL_TYPE_DATETIME)).unwrap();
    assert_eq!(column.database.as_deref(), Some("test"));
    assert_eq!(column.table.as_deref(), Some("t"));
    assert_eq!(column.column.as_deref(), Some("updated_at"));
    let serialized = serde_json::to_value(column).unwrap();
    assert_eq!(serialized["database"], "test");
}

#[test]
fn rollback_ok_preserves_server_transaction_status_without_guessing_truncated_flags() {
    for (payload, expected) in [
        (vec![0, 0, 0, 0, 0, 0, 0], Some(0)),
        (vec![0, 0, 0, 2, 0, 0, 0], Some(2)),
        (vec![0, 0, 0, 1, 0, 0, 0], Some(1)),
        (vec![0, 0, 0, 1], None),
    ] {
        let mut tracker = MysqlSemanticTracker::new(test_context());
        let query = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"ROLLBACK".to_vec()].concat(),
        };
        let command = parse_client_command(&query).unwrap();
        tracker.start_query(Uuid::nil(), 1, &command, &query, None);
        tracker.observe_packet(&MysqlPacket {
            sequence_id: 1,
            payload,
        });
        let exchange = tracker.finish_active("ok", None, None, Some(1)).unwrap();
        assert_eq!(exchange.response.server_status, expected);
        let value = serde_json::to_value(exchange).unwrap();
        assert_eq!(
            value["response"]["server_status"],
            serde_json::to_value(expected).unwrap()
        );
    }
}

#[test]
fn parses_text_resultset_exchange() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    let query = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x03], b"select id, name".to_vec()].concat(),
    };
    let command = parse_client_command(&query).unwrap();
    tracker.start_query(Uuid::nil(), 1, &command, &query, None);

    tracker.observe_packet(&MysqlPacket {
        sequence_id: 1,
        payload: vec![2],
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 2,
        payload: column_def("id", MYSQL_TYPE_LONG),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 3,
        payload: column_def("name", MYSQL_TYPE_VAR_STRING),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 4,
        payload: vec![0xfe, 0, 0, 0, 0],
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 5,
        payload: [lenenc_bytes(b"42"), lenenc_bytes(b"alice")].concat(),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 6,
        payload: vec![0xfe, 0, 0, 0, 0],
    });

    let exchange = tracker
        .finish_active("resultset", None, None, Some(5))
        .expect("exchange");
    assert_eq!(exchange.command, "COM_QUERY");
    assert_eq!(exchange.sql.as_deref(), Some("select id, name"));
    assert_eq!(exchange.response.columns.len(), 2);
    assert_eq!(exchange.response.row_count, 1);
    assert_eq!(
        exchange.response.rows[0][0].value,
        Some(Value::Number(42.into()))
    );
    assert_eq!(
        exchange.response.rows[0][1].value,
        Some(Value::String("alice".to_string()))
    );
}

#[test]
fn changes_database_only_after_successful_init_db_response() {
    let mut context = test_context();
    context.database = Some("original".to_string());
    let mut tracker = MysqlSemanticTracker::new(context);
    let init_db = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x02], b"pluto".to_vec()].concat(),
    };
    let command = parse_client_command(&init_db).unwrap();
    tracker.start_query(Uuid::nil(), 1, &command, &init_db, None);
    assert_eq!(tracker.database(), Some("original"));

    let response = MysqlResponseEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::nil(),
        query_sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        status: "ok".to_string(),
        packet_count: 1,
        payload_bytes: 1,
        duration_ms: 1,
        error_code: None,
        error_message: None,
        payload: capture_body(&[0x00], 1024),
        packets: None,
    };
    let exchange = tracker.finish_from_response(&response).unwrap();
    assert_eq!(exchange.database.as_deref(), Some("original"));
    assert_eq!(tracker.database(), Some("pluto"));
}

#[test]
fn serializes_column_as_semantic_schema() {
    let column = parse_column_definition(&column_def_with_flags(
        "id",
        MYSQL_TYPE_LONG,
        MYSQL_FLAG_NOT_NULL | MYSQL_FLAG_UNSIGNED,
    ))
    .expect("column definition");
    let value = serde_json::to_value(&column).expect("column serializes");

    assert_eq!(value["name"], "id");
    assert_eq!(value["table"], "t");
    assert_eq!(value["column"], "id");
    assert_eq!(value["family"], "integer");
    assert_eq!(value["sql_type"], "INT");
    assert_eq!(value["unsigned"], true);
    assert_eq!(value["bits"], 32);
    assert_eq!(value["nullable"], false);
    assert!(value.get("flags").is_none());
    assert!(value.get("column_type_code").is_none());
    assert!(value.get("column_type").is_none());
}

#[test]
fn decodes_binary_charset_var_string_as_varbinary_schema() {
    let column = parse_column_definition(&column_def_with_charset_and_flags(
        "user_name",
        MYSQL_TYPE_VAR_STRING,
        MYSQL_CHARSET_BINARY,
        MYSQL_FLAG_NOT_NULL,
    ))
    .expect("column definition");
    let value = serde_json::to_value(&column).expect("column serializes");

    assert_eq!(value["name"], "user_name");
    assert_eq!(value["family"], "binary");
    assert_eq!(value["sql_type"], "VARBINARY");
    assert_eq!(value["nullable"], false);
}

#[test]
fn decodes_binary_flag_var_string_as_varbinary_schema() {
    let column = parse_column_definition(&column_def_with_charset_and_flags(
        "department_id",
        MYSQL_TYPE_VAR_STRING,
        33,
        MYSQL_FLAG_BINARY,
    ))
    .expect("column definition");
    let value = serde_json::to_value(&column).expect("column serializes");

    assert_eq!(value["name"], "department_id");
    assert_eq!(value["family"], "binary");
    assert_eq!(value["sql_type"], "VARBINARY");
    assert_eq!(value["nullable"], true);
}

#[test]
fn records_binary_charset_string_values_as_bytes() {
    let column = parse_column_definition(&column_def_with_charset_and_flags(
        "user_name",
        MYSQL_TYPE_VAR_STRING,
        MYSQL_CHARSET_BINARY,
        MYSQL_FLAG_NOT_NULL,
    ))
    .expect("column definition");

    let value = parse_text_value(b"alice", &column, 64);

    assert_eq!(value.kind, "bytes");
    assert!(value.value.is_none());
    assert_eq!(
        value.raw,
        Some(BodyCapture {
            encoding: "base64",
            original_len: 5,
            stored_len: 5,
            truncated: false,
            data: STANDARD.encode(b"alice")
        })
    );
}

#[test]
fn records_binary_flag_string_values_as_bytes() {
    let column = parse_column_definition(&column_def_with_charset_and_flags(
        "department_id",
        MYSQL_TYPE_VAR_STRING,
        33,
        MYSQL_FLAG_BINARY,
    ))
    .expect("column definition");

    let value = parse_text_value(b"0", &column, 64);

    assert_eq!(value.kind, "bytes");
    assert!(value.value.is_none());
    assert_eq!(
        value.raw,
        Some(BodyCapture {
            encoding: "base64",
            original_len: 1,
            stored_len: 1,
            truncated: false,
            data: STANDARD.encode(b"0")
        })
    );
}

#[test]
fn parses_prepare_and_execute_binary_resultset() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    let prepare = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x16], b"select name from user where id=?".to_vec()].concat(),
    };
    let command = parse_client_command(&prepare).unwrap();
    tracker.start_query(Uuid::nil(), 1, &command, &prepare, None);
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 1,
        payload: prepare_ok(9, 1, 1),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 2,
        payload: column_def("id", MYSQL_TYPE_LONG),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 3,
        payload: vec![0xfe, 0, 0, 0, 0],
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 4,
        payload: column_def("name", MYSQL_TYPE_VAR_STRING),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 5,
        payload: vec![0xfe, 0, 0, 0, 0],
    });
    let prepare_exchange = tracker
        .finish_active("stmt_prepare", None, None, Some(2))
        .unwrap();
    assert_eq!(prepare_exchange.statement_id, Some(9));

    let execute = MysqlPacket {
        sequence_id: 0,
        payload: stmt_execute_long_param(9, 42),
    };
    let command = parse_client_command(&execute).unwrap();
    tracker.start_query(Uuid::nil(), 2, &command, &execute, None);
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 1,
        payload: vec![1],
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 2,
        payload: column_def("name", MYSQL_TYPE_VAR_STRING),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 3,
        payload: vec![0xfe, 0, 0, 0, 0],
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 4,
        payload: [vec![0x00, 0x00], lenenc_bytes(b"alice")].concat(),
    });
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 5,
        payload: vec![0xfe, 0, 0, 0, 0],
    });

    let execute_exchange = tracker
        .finish_active("resultset", None, None, Some(3))
        .unwrap();
    assert_eq!(
        execute_exchange.sql.as_deref(),
        Some("select name from user where id=?")
    );
    assert_eq!(
        execute_exchange.params.unwrap()[0].value,
        Some(Value::Number(42.into()))
    );
    assert_eq!(
        execute_exchange.response.rows[0][0].value,
        Some(Value::String("alice".to_string()))
    );
}

#[test]
fn stmt_close_clears_prepared_statement_without_creating_exchange() {
    let mut tracker = MysqlSemanticTracker::new(test_context());
    let prepare = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x16], b"select name from user".to_vec()].concat(),
    };
    let command = parse_client_command(&prepare).unwrap();
    tracker.start_query(Uuid::nil(), 1, &command, &prepare, None);
    tracker.observe_packet(&MysqlPacket {
        sequence_id: 1,
        payload: prepare_ok(9, 0, 0),
    });
    tracker
        .finish_active("stmt_prepare", None, None, Some(1))
        .expect("prepare exchange");
    assert!(tracker.session.prepared_sql(9).is_some());

    let close = MysqlPacket {
        sequence_id: 0,
        payload: [vec![0x19], 9_u32.to_le_bytes().to_vec()].concat(),
    };
    let command = parse_client_command(&close).unwrap();
    tracker.observe_no_response_command(&command, &close);
    assert!(!tracker.session.prepared_sql(9).is_some());
    assert!(
        tracker
            .finish_active("incomplete", None, None, None)
            .is_none()
    );
}

fn prepare_ok(statement_id: u32, num_columns: u16, num_params: u16) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.extend_from_slice(&num_columns.to_le_bytes());
    payload.extend_from_slice(&num_params.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload
}

fn stmt_execute_long_param(statement_id: u32, value: u32) -> Vec<u8> {
    let mut payload = vec![0x17];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.push(0);
    payload.push(1);
    payload.push(MYSQL_TYPE_LONG);
    payload.push(0);
    payload.extend_from_slice(&value.to_le_bytes());
    payload
}

fn column_def(name: &str, type_code: u8) -> Vec<u8> {
    column_def_with_flags(name, type_code, 0)
}

fn column_def_with_flags(name: &str, type_code: u8, flags: u16) -> Vec<u8> {
    column_def_with_charset_and_flags(name, type_code, 33, flags)
}

fn column_def_with_charset_and_flags(
    name: &str,
    type_code: u8,
    charset: u16,
    flags: u16,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&lenenc_bytes(b"def"));
    payload.extend_from_slice(&lenenc_bytes(b"test"));
    payload.extend_from_slice(&lenenc_bytes(b"t"));
    payload.extend_from_slice(&lenenc_bytes(b"t"));
    payload.extend_from_slice(&lenenc_bytes(name.as_bytes()));
    payload.extend_from_slice(&lenenc_bytes(name.as_bytes()));
    payload.push(0x0c);
    payload.extend_from_slice(&charset.to_le_bytes());
    payload.extend_from_slice(&255_u32.to_le_bytes());
    payload.push(type_code);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0, 0]);
    payload
}

fn test_context() -> MysqlExchangeContext {
    MysqlExchangeContext {
        route_name: Some("mysql".to_string()),
        target_host: Some("mysql.internal".to_string()),
        target_port: Some(3306),
        target_addr: Some("mysql.internal:3306".to_string()),
        upstream_addr: Some("10.0.0.1:3306".to_string()),
        username: Some("root".to_string()),
        database: Some("appdb".to_string()),
    }
}

#[test]
fn captures_invalid_utf8_as_raw_base64() {
    let value = mysql_utf8_or_raw(&[0xff, 0x00], 8);
    assert_eq!(value.kind, "bytes");
    assert_eq!(
        value.raw,
        Some(BodyCapture {
            encoding: "base64",
            original_len: 2,
            stored_len: 2,
            truncated: false,
            data: STANDARD.encode([0xff, 0x00])
        })
    );
}
