use super::*;
use crate::dependency::{
    DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
};
use crate::replay::ReplayExchangeStatus;

fn cancelled_dependency(duration: u64) -> Value {
    let mut record = dependency();
    record["outcome"] = serde_json::to_value(crate::DependencyExchangeOutcome::Terminated(
        DependencyTermination {
            side: TerminationSide::Client,
            kind: TerminationKind::Reset,
            scope: TerminationScope::Connection,
        },
    ))
    .unwrap();
    record["duration_ms"] = Value::from(duration);
    record["response_stream"] = serde_json::json!({
        "version":2,"headers_ms":5,
        "chunks":[{"at_ms":10,"start":0,"end":3},{"at_ms":20,"start":3,"end":6}],
        "end_ms":duration,"complete":true
    });
    record
}

#[tokio::test]
async fn cancelled_dependency_delivers_prefix_then_waits_for_target_cancellation() {
    exercise_cancelled_stream(180, Some(180), true, true).await;
}

#[tokio::test]
async fn cancelled_dependency_early_target_cancellation_is_dirty() {
    exercise_cancelled_stream(300, Some(80), false, true).await;
}

#[tokio::test]
async fn cancelled_dependency_without_target_cancellation_is_dirty() {
    exercise_cancelled_stream(80, None, false, true).await;
}

#[tokio::test]
async fn cancellation_in_timing_window_without_the_recorded_prefix_is_dirty() {
    exercise_cancelled_stream(400, Some(360), false, false).await;
}

async fn exercise_cancelled_stream(
    recorded: u64,
    close_at: Option<u64>,
    passes: bool,
    full_prefix: bool,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("cancelled-stream");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let mut record = cancelled_dependency(recorded);
    if !full_prefix {
        record["response_stream"]["chunks"][1]["at_ms"] = Value::from(390);
    }
    tokio::fs::write(case.join("dependencies.jsonl"), record.to_string())
        .await
        .unwrap();
    let (address, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay(&case, Vec::new()).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    let started = tokio::time::Instant::now();
    client
        .write_all(b"POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(client.read_u8().await.unwrap());
    }
    assert_eq!(chunk(&mut client).await, b"one");
    if full_prefix {
        assert_eq!(chunk(&mut client).await, b"two");
    }
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .http_events
            .matched_count,
        0
    );
    if let Some(at) = close_at {
        let mut byte = [0];
        let deadline = started + Duration::from_millis(at);
        assert!(
            tokio::time::timeout_at(deadline, client.read(&mut byte))
                .await
                .is_err(),
            "replay must not fabricate EOF after the response prefix"
        );
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = runtime.state.lock().await;
            if matches!(
                state.protocols.http_exchanges[0].status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            ) {
                break;
            }
            drop(state);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert_eq!(
        state.protocols.http_exchanges[0].status.is_consumed(),
        passes
    );
    assert_eq!(
        state.protocols.http_events.matched_count,
        usize::from(passes)
    );
    assert_eq!(state.protocols.http_events.unsupported.is_empty(), passes);
    if close_at.is_none() {
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.read(&mut byte))
                .await
                .is_err(),
            "validation timeout must not close Target's dependency socket"
        );
    }
    if !full_prefix {
        assert!(
            state.protocols.http_events.unsupported[0]
                .reason
                .contains("prefix")
        );
    }
    task.abort();
}

#[test]
fn historical_incomplete_streams_are_not_reinterpreted_as_cancellation() {
    let mut record = cancelled_dependency(100);
    record["response_stream"]["version"] = Value::from(1);
    assert!(
        super::super::super::termination::validate_record(&serde_json::from_value(record).unwrap())
            .is_err()
    );
}
