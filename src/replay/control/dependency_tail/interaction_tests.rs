//! Wire close is independent of a delayed application's final dependency call.
use super::tests::{Fixture, GET, client, command, fixture, fixture_with_response};
use super::*;
use crate::interaction::model::{
    EndObservation, EndReason, InputAction, InputActionKind, InputTranscript, OutputObservation,
    Protocol, TRANSCRIPT_VERSION,
};
use crate::interaction::policy::InteractionPolicy;
use crate::replay::control::{begin_case, end_case};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

async fn original_interaction(fixture: &Fixture, protocol: Protocol, elapsed: u64) {
    let directory = fixture.root.join("case-a");
    let mut input = InputTranscript::new(protocol, InteractionPolicy::default());
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: elapsed.saturating_sub(200),
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Close {
            code: None,
            reason: String::new(),
        },
    });
    let output = OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol,
        events: vec![],
        end: EndObservation {
            reason: EndReason::ClientClose,
            offset_ms: elapsed,
            pending: vec![],
            clean: true,
            partial_message: None,
            close: None,
        },
    };
    tokio::fs::write(
        directory.join("request.json"),
        json!({"interaction":input}).to_string(),
    )
    .await
    .unwrap();
    tokio::fs::write(
        directory.join("expected-response.json"),
        json!({"duration_ms":elapsed,"interaction":output}).to_string(),
    )
    .await
    .unwrap();
}

async fn waiting(state: &Arc<Mutex<ReplayState>>) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while state
            .lock()
            .await
            .dependency_tails
            .waiting("case-a")
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the old Case must retain its original pending read");
}

#[tokio::test]
async fn wire_close_retains_late_cleanup_read_before_admitting_the_next_case() {
    for protocol in [Protocol::SocketIo, Protocol::WebSocket] {
        let document = r#"{"socket_id":"another-live-session"}"#;
        let response = format!("${}\r\n{document}\r\n", document.len());
        // The prefix was delivered before wire close. This remaining Source
        // exchange is the disconnect hook's read after its grace interval.
        let fixture = fixture_with_response(None, 0, Some(("bulk_string", &response))).await;
        original_interaction(&fixture, protocol, 600).await;
        let state = fixture.runtime.state.clone();
        {
            let mut state = state.lock().await;
            state.case_dependency_post_response_window = Duration::ZERO;
            state.dependency_tails = CaseTails::default()
                .with_async_rules(BTreeMap::new(), Duration::from_secs(5))
                .with_no_progress_timeout(Duration::from_millis(50));
        }
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["ok"],
            true
        );
        let (mut redis, redis_task) = client(state.clone()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (cleanup_ready, cleanup_allowed) = tokio::sync::oneshot::channel();
        let target = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            websocket
                .send(Message::Text("0{\"sid\":\"unit\"}".into()))
                .await
                .unwrap();
            assert!(matches!(
                websocket.next().await.unwrap().unwrap(),
                Message::Text(_)
            ));
            websocket
                .send(Message::Text(
                    "40/test,{\"sid\":\"registered-session\"}".into(),
                ))
                .await
                .unwrap();
            assert!(matches!(
                websocket.next().await.unwrap().unwrap(),
                Message::Close(_)
            ));
            websocket.flush().await.unwrap(); // peer sees close before the hook finishes
            drop(websocket);
            // Wait until the test observes the pending tail. A wall-clock
            // delay can finish before that observation under suite load.
            cleanup_allowed.await.unwrap();
            redis.write_all(GET).await.unwrap();
            let mut actual = vec![0; response.len()];
            redis.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, response.as_bytes());
            let online: Value = serde_json::from_str(document).unwrap();
            // The actual finite Source response preserves the foreign SID;
            // the old connection must not delete the successor's online key.
            assert_ne!(online["socket_id"], "registered-session");
            redis.shutdown().await.unwrap();
        });
        let (mut websocket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}/socket.io/"))
                .await
                .unwrap();
        websocket.next().await.unwrap().unwrap();
        websocket
            .send(Message::Text("40/test,{}".into()))
            .await
            .unwrap();
        websocket.next().await.unwrap().unwrap();
        websocket.close(None).await.unwrap();
        assert!(matches!(
            websocket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        let ending_state = state.clone();
        let ending = tokio::spawn(async move { end_case(&command("end"), ending_state).await });
        waiting(&state).await;
        assert!(!ending.is_finished());
        {
            let state = state.lock().await;
            let waiting = state.dependency_tails.waiting("case-a").unwrap();
            assert_eq!(waiting["source_post_input_allowance_ms"], 200);
            assert_eq!(waiting["no_progress_timeout_ms"], 250);
        }
        let deadline = deadline(&state, "case-a").await.unwrap();
        assert!(deadline > Instant::now() + Duration::from_millis(80));
        let mut next = command("begin");
        next.case_id = Some("case-b".into());
        assert_eq!(begin_case(&next, state.clone()).await["ok"], false);
        assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
        cleanup_ready.send(()).unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(2), ending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended["ok"], true, "{ended}");
        target.await.unwrap();
        redis_task.await.unwrap().unwrap();
        {
            let state = state.lock().await;
            assert!(state.redis.snapshot().unused_case.is_empty());
            assert!(!state.redis.case_has_runtime_failure("case-a"));
            assert!(!state.redis.case_has_runtime_failure("case-b"));
        }
        assert_eq!(begin_case(&next, state.clone()).await["ok"], true);
        next.command = "end".into();
        assert_eq!(end_case(&next, state).await["ok"], true);
    }
}

#[tokio::test]
async fn rejected_native_dependency_preserves_failure_then_releases_after_actual_io_drains() {
    for consumed in [false, true] {
        let fixture = fixture(None, 0).await;
        original_interaction(&fixture, Protocol::SocketIo, 600).await;
        let state = fixture.runtime.state.clone();
        state.lock().await.case_dependency_post_response_window = Duration::ZERO;
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["ok"],
            true
        );
        let (mut peer, task) = client(state.clone()).await;
        if consumed {
            peer.write_all(GET).await.unwrap();
            let mut response = [0; 5];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"+OK\r\n");
        }
        // A rejected real Target request closes its dependency connection. The
        // failed Case remains dirty without consuming its unused Source calls.
        peer.write_all(b"*2\r\n$3\r\nGET\r\n$5\r\nother\r\n")
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut end = command("end");
        end.fail_on_dirty = true;
        let ended = end_case(&end, state.clone()).await;
        assert_eq!(ended["ok"], false, "{ended}");
        assert_eq!(ended["dirty"], true);
        {
            let state = state.lock().await;
            assert!(state.active_case_id.is_none());
            assert!(state.redis.case_has_runtime_failure("case-a"));
            assert_eq!(
                state.redis.snapshot().unused_case.len(),
                usize::from(!consumed)
            );
        }
        let mut next = command("begin");
        next.case_id = Some("case-b".into());
        assert_eq!(begin_case(&next, state.clone()).await["ok"], true);
        next.command = "end".into();
        assert_eq!(end_case(&next, state.clone()).await["ok"], true);
        peer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn recorded_native_dependency_error_is_consumed_without_a_replay_rejection() {
    let fixture = fixture_with_response(None, 0, Some(("error", "-ERR recorded\r\n"))).await;
    original_interaction(&fixture, Protocol::SocketIo, 600).await;
    let state = fixture.runtime.state.clone();
    state.lock().await.case_dependency_post_response_window = Duration::ZERO;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut peer, task) = client(state.clone()).await;
    peer.write_all(GET).await.unwrap();
    let mut response = [0; 15];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"-ERR recorded\r\n");
    let mut end = command("end");
    end.fail_on_dirty = true;
    let ended = end_case(&end, state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(state.lock().await.redis.snapshot().unused_case.is_empty());
    assert!(!state.lock().await.redis.case_has_runtime_failure("case-a"));
    peer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn missing_interaction_call_after_source_idle_allowance_fails_case_and_allows_next() {
    let fixture = fixture(None, 0).await;
    original_interaction(&fixture, Protocol::SocketIo, 600).await;
    let state = fixture.runtime.state.clone();
    {
        let mut state = state.lock().await;
        state.case_dependency_post_response_window = Duration::ZERO;
        state.dependency_tails = CaseTails::default()
            .with_async_rules(BTreeMap::new(), Duration::from_secs(1))
            .with_no_progress_timeout(Duration::from_millis(50));
    }
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let ending_state = state.clone();
    let ending = tokio::spawn(async move { end_case(&command("end"), ending_state).await });
    waiting(&state).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(225)).await;
    assert!(!ending.is_finished());
    tokio::time::advance(Duration::from_millis(50)).await;
    let ended = ending.await.unwrap();
    // fail_on_dirty is false: ending succeeds while preserving failure evidence.
    assert_eq!(ended["ok"], true, "{ended}");
    assert_eq!(ended["dirty"], true);
    let state_guard = state.lock().await;
    let failure = state_guard.dependency_tails.failure("case-a").unwrap();
    assert_eq!(failure["kind"], "case_no_progress");
    assert_eq!(failure["waiting"]["no_progress_timeout_ms"], 250);
    assert_eq!(state_guard.redis.snapshot().unused_case.len(), 1);
    assert!(state_guard.active_case_id.is_none());
    drop(state_guard);
    let mut next = command("begin");
    next.case_id = Some("case-b".into());
    assert_eq!(begin_case(&next, state.clone()).await["ok"], true);
    next.command = "end".into();
    assert_eq!(end_case(&next, state).await["ok"], true);
}

#[tokio::test]
async fn cancelling_interaction_tail_wait_cannot_release_or_renew_the_case() {
    let fixture = fixture(None, 0).await;
    original_interaction(&fixture, Protocol::SocketIo, 500).await;
    let state = fixture.runtime.state.clone();
    state.lock().await.case_dependency_post_response_window = Duration::ZERO;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let original_deadline = deadline(&state, "case-a").await;
    let ending_state = state.clone();
    let ending = tokio::spawn(async move { end_case(&command("end"), ending_state).await });
    waiting(&state).await;
    ending.abort();
    assert!(ending.await.unwrap_err().is_cancelled());
    let mut next = command("begin");
    next.case_id = Some("case-b".into());
    assert_eq!(begin_case(&next, state.clone()).await["ok"], false);
    assert_eq!(deadline(&state, "case-a").await, original_deadline);
    let (mut peer, task) = client(state.clone()).await;
    peer.write_all(GET).await.unwrap();
    let mut response = [0; 5];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"+OK\r\n");
    assert_eq!(end_case(&command("end"), state).await["ok"], true);
    peer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn missing_interaction_tail_preserves_original_budget_failure_and_allows_next() {
    let fixture = fixture(None, 0).await;
    original_interaction(&fixture, Protocol::SocketIo, 0).await;
    let state = fixture.runtime.state.clone();
    {
        let mut state = state.lock().await;
        state.case_dependency_post_response_window = Duration::ZERO;
        state.dependency_tails =
            CaseTails::default().with_async_rules(BTreeMap::new(), Duration::from_millis(50));
    }
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], false, "{ended}");
    assert_eq!(ended["dirty"], true);
    assert!(ended["error"].as_str().unwrap().contains("budget"));
    assert!(state.lock().await.active_case_id.is_none());
    assert_eq!(state.lock().await.redis.snapshot().unused_case.len(), 1);
    assert!(
        state
            .lock()
            .await
            .dependency_tails
            .failure("case-a")
            .is_some()
    );
    let mut next = command("begin");
    next.case_id = Some("case-b".into());
    assert_eq!(begin_case(&next, state.clone()).await["ok"], true);
    next.command = "end".into();
    assert_eq!(end_case(&next, state).await["ok"], true);
}
