use super::*;
use crate::replay::ReplayExchangeStatus;
use tokio::time::{Duration, timeout};

async fn selected(
    payload: &str,
) -> (
    tempfile::TempDir,
    Arc<Mutex<ReplayState>>,
    RecordedHttpExchange,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    crate::replay::http::tests::write_http_case(&case, "http", "full.test", "/full", "", payload)
        .await;
    let (_, runtime, serving) = crate::replay::http::tests::spawn_http_replay(&case, vec![]).await;
    let state = runtime.state.clone();
    let record = state.lock().await.match_http_request(
        HttpReplayScheme::Http,
        &TargetKey {
            host: "full.test".into(),
            port: 80,
        },
        &Method::POST,
        &"/full".parse().unwrap(),
        Some("full.test"),
        b"",
        &HeaderSnapshot::new(),
        Utc::now(),
    );
    let Ok(record) = record else {
        panic!("native full response must match")
    };
    assert_eq!(
        state.lock().await.http_exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    (temp, state, record, serving)
}
async fn status(state: &Arc<Mutex<ReplayState>>, expected: ReplayExchangeStatus) {
    timeout(Duration::from_secs(1), async {
        loop {
            if state.lock().await.http_exchanges[0].status == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn body(
    state: Arc<Mutex<ReplayState>>,
    record: RecordedHttpExchange,
    progress: DeliveryProgress,
    finished: tokio::sync::watch::Receiver<bool>,
) -> Response<DeliveryBody> {
    super::super::response(
        record,
        tokio::time::Instant::now(),
        state,
        None,
        None,
        Transport {
            progress,
            finished,
            observation: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn final_body_frame_is_not_consumption_until_actual_http_writer_flushes() {
    let (_temp, state, record, serving) = selected("abcdef").await;
    let progress = DeliveryProgress::default();
    let (_finished, receiver) = tokio::sync::watch::channel(false);
    let mut response = body(state.clone(), record, progress.clone(), receiver).await;
    let frame = response.body_mut().frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap(), b"abcdef".as_slice());
    assert_eq!(
        state.lock().await.http_exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    progress.flushed();
    status(&state, ReplayExchangeStatus::Consumed).await;
    assert_eq!(state.lock().await.http_events.matched_count, 1);
    serving.abort();
}

#[tokio::test]
async fn ordinary_body_cancellation_before_and_after_queue_never_consumes() {
    for queue in [false, true] {
        let (_temp, state, record, serving) = selected("abcdef").await;
        let progress = DeliveryProgress::default();
        let (finished, receiver) = tokio::sync::watch::channel(false);
        let mut response = body(state.clone(), record, progress, receiver).await;
        if queue {
            response.body_mut().frame().await.unwrap().unwrap();
        }
        drop(response);
        finished.send_replace(true);
        status(&state, ReplayExchangeStatus::Failed).await;
        let locked = state.lock().await;
        assert_eq!(locked.http_events.matched_count, 0);
        assert!(locked.http_case_is_dirty("case"));
        serving.abort();
    }
}

#[tokio::test]
async fn empty_body_keeps_its_header_delivery_obligation_when_hyper_skips_body_polling() {
    let (_temp, state, mut record, serving) = selected("").await;
    record.response_status = Some(204);
    let progress = DeliveryProgress::default();
    let (_finished, receiver) = tokio::sync::watch::channel(false);
    let response = body(state.clone(), record, progress.clone(), receiver).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    drop(response);
    assert_eq!(
        state.lock().await.http_exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    progress.flushed();
    status(&state, ReplayExchangeStatus::Consumed).await;
    serving.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn real_tcp_cancellation_of_an_unflushed_ordinary_body_keeps_source_unused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    let payload = "x".repeat(8 * 1024 * 1024);
    crate::replay::http::tests::write_http_case(&case, "http", "full.test", "/full", "", &payload)
        .await;
    let (addr, runtime, serving) =
        crate::replay::http::tests::spawn_http_replay(&case, vec![]).await;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(1024).unwrap();
    let mut client = socket.connect(addr).await.unwrap();
    client
        .write_all(b"POST /full HTTP/1.1\r\nHost: full.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    timeout(Duration::from_secs(2), async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        runtime.state.lock().await.http_exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    crate::dependency::termination::ConnectionControl::new(&client)
        .unwrap()
        .reset()
        .unwrap();
    status(&runtime.state, ReplayExchangeStatus::Failed).await;
    let locked = runtime.state.lock().await;
    assert_eq!(locked.http_events.matched_count, 0);
    assert_eq!(
        locked
            .unused_http_exchanges(ReplaySource::Case, false)
            .len(),
        1
    );
    serving.abort();
}
