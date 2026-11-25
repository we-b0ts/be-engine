use super::*;
use bytes::Bytes;
use serde_json::json;
use traffic_protocol::message::ProtocolMessage;

mod driver_prelude;
mod prepared_execution;
mod session_recording;
mod tuple_membership;

fn event() -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":uuid::Uuid::nil(), "query_sequence":1,
        "target_host":"db.test", "target_port":3306, "database":"app", "username":"user",
        "command":"COM_QUERY", "sql":"SELECT id FROM items WHERE id=7",
        "response":{"status":"resultset","columns":[{"name":"id","column":"id","table":"items","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":7}]]}})
}

#[test]
fn projection_retains_sql_order_and_exposes_values_without_policy_implementations() {
    let project = |sql: &str| {
        RequestMessage {
            command: "COM_QUERY".into(),
            sql: Some(sql.into()),
            params: None,
            database: None,
            username: None,
        }
        .project()
        .unwrap()
    };
    let source = project("SELECT * FROM t WHERE a=1 AND b IN (2,3)");
    assert_eq!(
        source.structure,
        project("select * from t where a=1 and b in (2,3)").structure
    );
    assert_ne!(
        source.structure,
        project("select * from t where b in (2,3) and a=1").structure
    );
    let reordered = project("select * from t where a=1 and b in (3,2)");
    assert_eq!(source.structure, reordered.structure);
    assert_ne!(
        source.values["/literals/1"].bytes,
        reordered.values["/literals/1"].bytes
    );
    assert_ne!(
        source.values["/literals/2"].bytes,
        reordered.values["/literals/2"].bytes
    );
}

#[test]
fn native_result_cells_can_be_selected_and_encoded_through_the_shared_value_port() {
    let exchange = Native.recorded_exchange(&event()).unwrap().unwrap();
    let mut values: std::collections::BTreeMap<String, Bytes> = exchange
        .response
        .project()
        .unwrap()
        .values
        .into_iter()
        .map(|(path, value)| (path, value.bytes))
        .collect();
    assert_eq!(
        exchange
            .response
            .locate(&json!({"kind":"field","table":"items","column":"id"}))
            .unwrap(),
        ["/rows/0/0"]
    );
    values.insert("/rows/0/0".into(), Bytes::from_static(b"99"));
    let bytes = exchange.response.encode(&values).unwrap();
    let response: response::ResponseMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response.response.rows[0][0].value, Some(json!(99)));
    assert_eq!(response.response.columns[0].sql_type, "INT");
}

#[test]
fn incomplete_capture_and_unimplemented_prepared_commands_fail_at_projection() {
    let mut record = event();
    record["response"]["rows_truncated"] = json!(true);
    assert!(Native.recorded_exchange(&record).is_err());
    record = event();
    record["response"].as_object_mut().unwrap().remove("rows");
    assert!(Native.recorded_exchange(&record).is_err());
    record = event();
    record["command"] = json!("COM_STMT_EXECUTE");
    assert!(Native.recorded_exchange(&record).is_err());
}

#[test]
fn string_carriers_expose_content_bytes_for_codec_recognition() {
    let document = r#"{"id":7,"stable":true}"#;
    let request = RequestMessage {
        command: "COM_QUERY".into(),
        sql: Some(format!("SELECT * FROM items WHERE payload='{document}'")),
        params: Some(vec![crate::values::mysql_json("string", json!(document))]),
        database: None,
        username: None,
    };
    let projection = request.project().unwrap();
    for path in ["/literals/0", "/params/0"] {
        assert_eq!(projection.values[path].bytes.as_ref(), document.as_bytes());
        assert_eq!(
            projection.values[path].scalar_encoding,
            traffic_protocol::message::ScalarEncoding::Utf8
        );
    }
    let mut record = event();
    record["response"]["rows"][0][0] = json!({"kind":"string","value":document});
    let exchange = Native.recorded_exchange(&record).unwrap().unwrap();
    let projection = exchange.response.project().unwrap();
    assert_eq!(
        projection.values["/rows/0/0"].bytes.as_ref(),
        document.as_bytes()
    );
    let delivered = r#"{"id":99,"stable":true}"#;
    let updates = std::collections::BTreeMap::from([("/rows/0/0".into(), Bytes::from(delivered))]);
    let envelope: response::ResponseMessage =
        serde_json::from_slice(&exchange.response.encode(&updates).unwrap()).unwrap();
    assert_eq!(envelope.response.rows[0][0].kind, "string");
    assert_eq!(envelope.response.rows[0][0].value, Some(json!(delivered)));
}

#[test]
fn ownership_projection_preserves_ordinary_reads_and_blocks_unproven_ends() {
    use traffic_model::attribution::DependencyScope;
    use traffic_protocol::connection::ReplaySessionStep;

    let mut read = event();
    read["server_status_before"] = json!(0);
    read["response"]["server_status"] = json!(1);
    assert!(
        Native
            .prepare_replay_scope(DependencyScope::Process, &[(0, &read)])
            .unwrap()
            .is_empty()
    );

    read["server_status_before"] = json!(1);
    let mut end = read.clone();
    end["query_sequence"] = json!(2);
    end["sql"] = json!("ROLLBACK");
    end["response"] = json!({
        "status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0
    });
    assert_eq!(
        Native
            .prepare_replay_scope(DependencyScope::Case, &[(0, &read), (1, &end)])
            .unwrap(),
        [
            (0, ReplaySessionStep::InTransaction),
            (1, ReplaySessionStep::Unverified)
        ]
        .into()
    );
}

#[test]
fn event_session_keeps_recorded_controls_and_read_only_transaction_receipts() {
    use traffic_model::attribution::DependencyScope;
    use traffic_protocol::connection::ReplaySessionStep;

    let control = |sequence, sql, before, after| {
        let mut record = event();
        record["query_sequence"] = json!(sequence);
        record["sql"] = json!(sql);
        record["server_status_before"] = json!(before);
        record["response"] = json!({
            "status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0
        });
        record
    };
    let begin = control(1, "BEGIN", 2, 3);
    let mut read = event();
    read["query_sequence"] = json!(2);
    read["server_status_before"] = json!(3);
    read["response"]["server_status"] = json!(3);
    let rollback = control(3, "ROLLBACK", 3, 2);
    let inactive_end = control(4, "ROLLBACK", 2, 2);
    let records = [(0, &begin), (1, &read), (2, &rollback), (3, &inactive_end)];
    let legacy = Native
        .prepare_replay_scope(DependencyScope::Startup, &records)
        .unwrap();
    assert_eq!(legacy[&0], ReplaySessionStep::Optional);
    assert_eq!(legacy[&2], ReplaySessionStep::Optional);
    assert_eq!(legacy[&3], ReplaySessionStep::Optional);

    let strict = Native.prepare_event_session(&records).unwrap().steps;
    assert_eq!(strict[&0], ReplaySessionStep::Start);
    assert_eq!(
        strict[&1],
        ReplaySessionStep::Continue {
            after: ProtocolRef::connection("mysql", uuid::Uuid::nil(), 1),
            end: false,
        }
    );
    assert_eq!(
        strict[&2],
        ReplaySessionStep::ReadOnlyEnd {
            after: ProtocolRef::connection("mysql", uuid::Uuid::nil(), 2),
        }
    );
    assert!(!strict.contains_key(&3));
}

#[test]
fn event_session_proves_implicit_starts_and_keeps_write_ends_exact() {
    use traffic_protocol::connection::ReplaySessionStep;

    let read = |sequence, before| {
        let mut record = event();
        record["query_sequence"] = json!(sequence);
        record["server_status_before"] = json!(before);
        record["response"]["server_status"] = json!(1);
        record
    };
    let control = |sequence, sql, after, affected_rows| {
        let mut record = read(sequence, 1);
        record["sql"] = json!(sql);
        record["response"] = json!({
            "status":"ok", "server_status":after, "affected_rows":affected_rows, "last_insert_id":0
        });
        record
    };
    let mut records = [
        read(1, 0),
        control(2, "UPDATE items SET id=8 WHERE id=7", 1, 0),
        control(3, "COMMIT", 0, 0),
        read(4, 0),
        control(5, "ROLLBACK", 0, 0),
    ];
    let prepare = |records: &[Value]| {
        Native
            .prepare_event_session(&records.iter().enumerate().collect::<Vec<_>>())
            .unwrap()
            .steps
    };
    let steps = prepare(&records);
    assert_eq!(steps[&0], ReplaySessionStep::ImplicitStart);
    assert_eq!(
        steps[&2],
        ReplaySessionStep::Continue {
            after: ProtocolRef::connection("mysql", uuid::Uuid::nil(), 2),
            end: true,
        }
    );
    assert_eq!(steps[&3], ReplaySessionStep::ImplicitStart);
    assert_eq!(
        steps[&4],
        ReplaySessionStep::ReadOnlyEnd {
            after: ProtocolRef::connection("mysql", uuid::Uuid::nil(), 4),
        }
    );
    records[4]["query_sequence"] = json!(6);
    let steps = prepare(&records);
    assert_ne!(steps.get(&3), Some(&ReplaySessionStep::ImplicitStart));
    assert_eq!(steps[&4], ReplaySessionStep::Unverified);

    let mut snapshot = control(
        1,
        "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        0,
        0,
    );
    snapshot["server_status_before"] = json!(0);
    let steps = prepare(&[snapshot, read(2, 0), control(3, "ROLLBACK", 0, 0)]);
    assert_eq!(steps[&1], ReplaySessionStep::Start);
    assert!(matches!(
        steps[&2],
        ReplaySessionStep::Continue { end: true, .. }
    ));
}

pub(super) fn locked_rollback_source() -> [Value; 2] {
    let mut locked = event();
    locked["query_sequence"] = json!(28);
    locked["sql"] = json!(
        "SELECT system_configs.id AS system_configs_id FROM system_configs WHERE system_configs.config_key='mode' LIMIT 1 FOR UPDATE"
    );
    locked["server_status_before"] = json!(0);
    locked["response"]["server_status"] = json!(1);
    let mut rollback = locked.clone();
    rollback["query_sequence"] = json!(29);
    rollback["sql"] = json!("ROLLBACK");
    rollback["server_status_before"] = json!(1);
    rollback["response"] =
        json!({"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0});
    [locked, rollback]
}

#[test]
fn implicit_locked_read_can_open_only_a_complete_exact_rollback_span() {
    use traffic_protocol::connection::ReplaySessionStep;

    let [locked, rollback] = locked_rollback_source();
    let prepare = |records: &[Value]| {
        Native
            .prepare_event_session(&records.iter().enumerate().collect::<Vec<_>>())
            .unwrap()
            .steps
    };

    let steps = prepare(&[locked.clone(), rollback.clone()]);
    assert_eq!(steps[&0], ReplaySessionStep::ImplicitStart);
    assert_eq!(
        steps[&1],
        ReplaySessionStep::Continue {
            after: ProtocolRef::connection("mysql", uuid::Uuid::nil(), 28),
            end: true,
        }
    );
    assert_eq!(
        prepare(std::slice::from_ref(&locked))[&0],
        ReplaySessionStep::Unverified
    );

    let mut commit = rollback.clone();
    commit["sql"] = json!("COMMIT");
    assert_eq!(
        prepare(&[locked.clone(), commit])[&0],
        ReplaySessionStep::Start
    );
    let mut other_lane = rollback.clone();
    other_lane["connection_id"] = json!(uuid::Uuid::from_u128(1));
    assert_eq!(
        prepare(&[locked.clone(), other_lane])[&0],
        ReplaySessionStep::Unverified
    );
    let mut gap = rollback.clone();
    gap["query_sequence"] = json!(30);
    assert_eq!(
        prepare(&[locked.clone(), gap])[&0],
        ReplaySessionStep::Unverified
    );

    let mut udf = locked.clone();
    udf["sql"] = json!(
        "SELECT custom_function(id) FROM system_configs WHERE config_key='mode' LIMIT 1 FOR UPDATE"
    );
    assert_eq!(
        prepare(&[udf, rollback.clone()])[&0],
        ReplaySessionStep::Start
    );
    let mut setup = rollback.clone();
    setup["query_sequence"] = json!(27);
    setup["sql"] = json!("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    setup["server_status_before"] = json!(0);
    assert_eq!(
        prepare(&[setup, locked, rollback])[&1],
        ReplaySessionStep::Start
    );
}
