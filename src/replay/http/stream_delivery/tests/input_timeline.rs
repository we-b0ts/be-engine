//! Real flushed dependency prefixes gate a separately delivered primary close.
use super::*;
use crate::replay::control::{ReplayControlRequest, handle_control_request};

async fn control(runtime: &Arc<crate::replay::ReplayRuntime>, value: Value) -> Value {
    let request: ReplayControlRequest = serde_json::from_value(value).unwrap();
    handle_control_request(request, runtime.state.clone(), None, None)
        .await
        .0
}

async fn exercise_shared_close(cap: u64, abandon: bool) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("shared-close");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let epoch = "2026-11-03T13:28:26Z";
    let mut dep = dependency();
    dep["id"] = json!("stream-1");
    dep["request_started_at"] = json!(epoch);
    dep["response_body"]["data"] = json!("onetwolate");
    dep["response_stream"] = json!({"version":2,"headers_ms":10,"chunks":[
        {"at_ms":90000,"start":0,"end":3},{"at_ms":99000,"start":3,"end":6},
        {"at_ms":101000,"start":6,"end":10}],"end_ms":142000,"complete":true});
    tokio::fs::write(case.join("dependencies.jsonl"), dep.to_string())
        .await
        .unwrap();
    let input = crate::interaction::model::InputTranscript::new(
        crate::interaction::model::Protocol::Sse,
        crate::interaction::policy::InteractionPolicy {
            request_timeout_ms: 900000,
            max_duration_ms: 900000,
            ..Default::default()
        },
    );
    let mut input = serde_json::to_value(input).unwrap();
    input["actions"] = json!([{"sequence":1,"offset_ms":100000,"after":[],"compressible_gap":false,
        "action":{"kind":"close","code":null,"reason":""}}]);
    tokio::fs::write(
        case.join("request.json"),
        json!({"timestamp":epoch,"interaction":input}).to_string(),
    )
    .await
    .unwrap();
    let (address, runtime, task) =
        crate::replay::http::tests::spawn_http_replay(&case, vec![]).await;
    let id = {
        let mut state = runtime.state.lock().await;
        state.stream_timing = Some(crate::replay::ReplayStreamTiming::Fast);
        state.stream_interval_cap_ms = cap;
        state.cases.keys().next().unwrap().clone()
    };
    if runtime.state.lock().await.active_case_id.is_none() {
        let b = control(&runtime, json!({"command":"begin","case_id":id})).await;
        assert_eq!(b["ok"], true, "{b}");
    }
    let begin = control(
        &runtime,
        json!({"command":"http_input_timing_begin","case_id":id}),
    )
    .await;
    assert_eq!(begin["enabled"], true, "{begin}");
    let query = json!({"epoch":begin["epoch"],"sequence":1,"completed":[]});
    let close = |command: &str| json!({"command":command,"case_id":id,"input_timing":query});
    assert_eq!(
        control(&runtime, close("http_input_timing_closed")).await["ok"],
        false,
        "close cannot precede an unstarted Source input prefix"
    );
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert_eq!(chunk(&mut client).await, b"one");
    assert_eq!(chunk(&mut client).await, b"two");
    assert!(
        tokio::time::timeout(Duration::from_millis(30), chunk(&mut client))
            .await
            .is_err(),
        "future Source bytes must wait for the actual primary close acknowledgement"
    );
    let ready = control(&runtime, close("http_input_timing_wait")).await;
    assert_eq!(ready["ready"], true, "{ready}");
    if abandon {
        runtime.state.lock().await.advance_admission_epoch();
        assert_eq!(
            control(&runtime, close("http_input_timing_closed")).await["ok"],
            false
        );
        runtime
            .state
            .lock()
            .await
            .http_input_timing
            .as_ref()
            .unwrap()
            .abort();
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest).await;
        assert!(!rest.windows(4).any(|v| v == b"late"));
    } else {
        assert_eq!(
            control(&runtime, close("http_input_timing_closed")).await["ok"],
            true
        );
        assert_eq!(chunk(&mut client).await, b"late");
        assert!(chunk(&mut client).await.is_empty());
    }
    task.abort();
}

#[tokio::test]
async fn fast_http_timeline_preserves_wire_prefix_close_and_future_data_order() {
    tokio::time::timeout(Duration::from_secs(4), async {
        exercise_shared_close(5, false).await;
        exercise_shared_close(0, false).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abandoned_http_timeline_cannot_release_future_source_bytes() {
    tokio::time::timeout(Duration::from_secs(4), exercise_shared_close(5, true))
        .await
        .unwrap();
}
