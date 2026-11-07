use super::*;
use crate::interaction::model::{
    InputAction, InputActionKind, InputTranscript, Protocol, WireMessage,
};
use crate::replay::{ReplayStreamTiming, control::handle_control_request};

const FIRST: &str = "SELECT id FROM prefix_users WHERE id=1";
const ORDINARY: &str = "SELECT id FROM prefix_tasks WHERE id=1";
const LOCK: &str = "SELECT id FROM prefix_users WHERE id=1 FOR UPDATE";

async fn replay() -> (tempfile::TempDir, ReplayRuntime, [Uuid; 2]) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".traffic-e2e/local/recording");
    std::fs::create_dir_all(&root).unwrap();
    crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
    let lanes = [Uuid::new_v4(), Uuid::new_v4()];
    let mut records = Vec::new();
    for (index, (lane, second)) in lanes.into_iter().zip([LOCK, ORDINARY]).enumerate() {
        let mut rows = [
            read(lane, 1, FIRST, 0, 1),
            read(lane, 2, second, 1, 1),
            control(lane, 3, "COMMIT", 1, 0),
        ];
        for (order, row) in rows.iter_mut().enumerate() {
            let ms = 100 + index * 10 + order;
            row["request_started_at"] = json!(format!("2020-01-01T00:00:00.{ms:03}Z"));
            row["timestamp"] = json!(format!("2020-01-01T00:00:00.{ms:03}Z"));
        }
        records.extend(rows);
    }
    let jsonl = records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect::<String>();
    let runtime = fixture_with_case(&root, &jsonl).await;
    let mut transcript = InputTranscript::new(Protocol::SocketIo, Default::default());
    transcript.actions.push(InputAction {
        sequence: 1,
        offset_ms: 5,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("40"),
        },
    });
    std::fs::write(root.join("case/request.json"),
        json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket","timestamp":"2020-01-01T00:00:00Z",
            "interaction": transcript}).to_string()).unwrap();
    {
        let mut state = runtime.state.lock().await;
        state.stream_timing = Some(ReplayStreamTiming::Fast);
        state.stream_interval_cap_ms = 5;
    }
    for command in ["begin", "input_timing_begin"] {
        let request = serde_json::from_value(json!({"command":command,"case_id":"case"})).unwrap();
        let (result, _) = handle_control_request(request, runtime.state.clone(), None, None).await;
        assert_eq!(result["ok"], true, "{result}");
        if command == "input_timing_begin" {
            assert_eq!(result["ordered_fast"], true, "{result}");
        }
    }
    (temp, runtime, lanes)
}

async fn target_session() -> (ReplaySession, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let identity = identity();
    (
        ReplaySession {
            control: crate::dependency::termination::ConnectionControl::new(&socket).unwrap(),
            request_started: tokio::time::Instant::now(),
            target: identity.target,
            database: identity.database,
            username: identity.username,
            next_statement_id: 1,
            status_flags: 2,
            statements: HashMap::new(),
            transaction_scope: Default::default(),
            savepoints: Default::default(),
            transaction_witness: Default::default(),
            deferred_prefix: None,
        },
        peer,
    )
}

async fn query(runtime: &ReplayRuntime, session: &mut ReplaySession, sql: &str) -> Result<()> {
    let (mut wire, _reader) = tokio::io::duplex(4096);
    crate::replay::mysql::session::handle_query(&mut wire, runtime.state.clone(), session, sql)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn both_sockets_get_the_same_first_reply_before_their_source_occurrences_are_bound() {
    for order in [[LOCK, ORDINARY], [ORDINARY, LOCK]] {
        let (_temp, runtime, [locking, ordinary]) = replay().await;
        let (mut first, _first_peer) = target_session().await;
        let (mut second, _second_peer) = target_session().await;
        for session in [&mut first, &mut second] {
            query(&runtime, session, "BEGIN").await.unwrap();
            query(&runtime, session, FIRST).await.unwrap();
            assert!(session.deferred_prefix.is_some());
        }
        {
            let state = runtime.state.lock().await;
            assert!(
                !state
                    .mysql
                    .events
                    .matched_queries
                    .iter()
                    .any(|row| row.sql.as_deref() == Some(FIRST))
            );
        }
        for (session, sql) in [&mut first, &mut second].into_iter().zip(order) {
            query(&runtime, session, sql).await.unwrap();
            assert!(session.deferred_prefix.is_none());
            {
                let state = runtime.state.lock().await;
                let matches = &state.mysql.events.matched_queries;
                let initial = matches
                    .iter()
                    .rev()
                    .find(|row| row.sql.as_deref() == Some(FIRST))
                    .unwrap();
                assert_eq!(
                    initial.source_connection_id,
                    Some(if sql == LOCK { locking } else { ordinary })
                );
                assert_eq!(initial.source_query_sequence, Some(1));
            }
            query(&runtime, session, "COMMIT").await.unwrap();
        }
        let state = runtime.state.lock().await;
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert_eq!(
            state
                .mysql
                .events
                .matched_queries
                .iter()
                .filter(|row| row.sql.as_deref() == Some(FIRST))
                .count(),
            2
        );
    }
}

#[tokio::test]
async fn a_reserved_read_cannot_replace_a_lock_or_commit() {
    let (_temp, runtime, _) = replay().await;
    let (mut session, _peer) = target_session().await;
    query(&runtime, &mut session, "BEGIN").await.unwrap();
    query(&runtime, &mut session, FIRST).await.unwrap();
    assert!(query(&runtime, &mut session, "COMMIT").await.is_err());
    let (_temp, runtime, [locking, _]) = replay().await;
    let (mut session, _peer) = target_session().await;
    query(&runtime, &mut session, "BEGIN").await.unwrap();
    query(&runtime, &mut session, FIRST).await.unwrap();
    query(&runtime, &mut session, LOCK).await.unwrap();
    let state = runtime.state.lock().await;
    let end = state
        .mysql
        .exchanges
        .iter()
        .position(|exchange| {
            exchange.record.connection_id == Some(locking)
                && exchange.record.query_sequence == Some(3)
        })
        .unwrap();
    assert!(state.mysql.transaction_equivalence.requires_witness(end));
}
