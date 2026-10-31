use super::*;
use crate::replay::control::{ReplayControlRequest, begin_case, end_case};
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn command(name: &str, case: &str) -> ReplayControlRequest {
    serde_json::from_value(json!({"command":name,"case_id":case,"fail_on_dirty":true})).unwrap()
}
async fn wait_pending(state: &Arc<Mutex<ReplayState>>, pending: bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.lock().await.http_ingress.has_pending() == pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn partial(addr: SocketAddr, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("POST {path} HTTP/1.1\r\nHost: ingress.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\na").as_bytes()).await.unwrap();
    stream
}
async fn finish(stream: &mut TcpStream) -> Vec<u8> {
    stream.write_all(b"bcd").await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}
async fn ordinary(
    root: &Path,
) -> (
    SocketAddr,
    Arc<crate::replay::ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    for case in ["case-a", "case-b"] {
        super::super::tests::write_http_case(
            &root.join(case),
            "http",
            "ingress.test",
            &format!("/{case}"),
            "abcd",
            "ok",
        )
        .await;
    }
    super::super::tests::spawn_http_replay(root, vec![]).await
}

#[tokio::test]
async fn streamed_request_body_is_actual_case_io_before_any_source_claim() {
    let temp = tempfile::tempdir().unwrap();
    let (addr, runtime, serving) = ordinary(temp.path()).await;
    let state = runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin", "case-a"), state.clone()).await["ok"],
        true
    );
    let mut stream = partial(addr, "/case-a").await;
    wait_pending(&state, true).await;
    {
        let locked = state.lock().await;
        assert!(
            locked
                .http_exchanges
                .iter()
                .all(|e| e.status.is_available())
        );
        assert_eq!(
            locked.http_ingress.report().observations[0].status,
            "reading_body"
        );
    }
    let ending_state = state.clone();
    let ending =
        tokio::spawn(async move { end_case(&command("end", "case-a"), ending_state).await });
    tokio::task::yield_now().await;
    let next = begin_case(&command("begin", "case-b"), state.clone()).await;
    assert_eq!(next["ok"], false, "{next}");
    assert!(!ending.is_finished());
    assert!(finish(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    let ended = tokio::time::timeout(Duration::from_secs(2), ending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert_eq!(
        begin_case(&command("begin", "case-b"), state.clone()).await["ok"],
        true
    );
    let mut second = partial(addr, "/case-b").await;
    assert!(finish(&mut second).await.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        end_case(&command("end", "case-b"), state.clone()).await["ok"],
        true
    );
    let locked = state.lock().await;
    assert_eq!(locked.http_ingress.report().pending, 0);
    assert!(locked.http_exchanges.iter().all(|e| e.status.is_consumed()));
    let observations = locked.http_ingress.report().observations;
    assert_eq!(observations[0].observed_case_id.as_deref(), Some("case-a"));
    assert_eq!(observations[1].observed_case_id.as_deref(), Some("case-b"));
    serving.abort();
}

#[tokio::test]
async fn cancelled_stream_body_releases_actual_io_and_remains_dirty_without_consumption() {
    let temp = tempfile::tempdir().unwrap();
    let (addr, runtime, serving) = ordinary(temp.path()).await;
    let state = runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin", "case-a"), state.clone()).await["ok"],
        true
    );
    let stream = partial(addr, "/case-a").await;
    wait_pending(&state, true).await;
    drop(stream);
    wait_pending(&state, false).await;
    let ended = end_case(&command("end", "case-a"), state.clone()).await;
    assert_eq!(ended["dirty"], true, "{ended}");
    let locked = state.lock().await;
    assert!(locked.http_ingress.case_failed("case-a"));
    assert!(
        locked
            .http_exchanges
            .iter()
            .all(|e| e.status.is_available())
    );
    assert!(matches!(
        locked.http_ingress.report().observations[0].status,
        "body_error" | "cancelled"
    ));
    serving.abort();
}

async fn run_owned(root: &Path, process: bool) -> std::path::PathBuf {
    let raw = root.join("raw");
    super::super::tests::write_http_case(&raw, "http", "ingress.test", "/run", "abcd", "ok").await;
    std::fs::rename(
        raw.join("dependencies.jsonl"),
        raw.join("global-dependencies.jsonl"),
    )
    .unwrap();
    std::fs::write(raw.join("dependencies.jsonl"), "").unwrap();
    crate::replay::test_support::recording::centralize(&raw, if process { &[0] } else { &[] }).await
}

#[tokio::test]
async fn uniquely_proven_process_head_does_not_hold_case_ownership_for_its_body() {
    let temp = tempfile::tempdir().unwrap();
    let case = run_owned(temp.path(), true).await;
    let case_id = case.file_name().unwrap().to_str().unwrap();
    let (addr, runtime, serving) = super::super::tests::spawn_http_replay(&case, vec![]).await;
    let state = runtime.state.clone();
    let mut stream = partial(addr, "/run").await;
    wait_pending(&state, true).await;
    {
        let locked = state.lock().await;
        assert!(locked.http_ingress.report().observations[0].process_head_unique);
        assert!(!locked.http_has_case_in_flight());
    }
    let ended = tokio::time::timeout(
        Duration::from_secs(1),
        end_case(&command("end", case_id), state.clone()),
    )
    .await
    .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(state.lock().await.active_case_id.is_none());
    assert!(finish(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    let locked = state.lock().await;
    assert!(
        locked
            .http_exchanges
            .iter()
            .all(|e| e.source == ReplaySource::Process && e.status.is_consumed())
    );
    assert!(!locked.http_ingress.case_failed(case_id));
    serving.abort();
}

#[tokio::test]
async fn startup_uses_real_header_admission_across_primary_boundary_only() {
    for admitted_before in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let case = run_owned(temp.path(), false).await;
        let case_id = case.file_name().unwrap().to_str().unwrap();
        let (addr, runtime, serving) = super::super::tests::spawn_http_replay(&case, vec![]).await;
        let state = runtime.state.clone();
        let mut stream = if admitted_before {
            let stream = partial(addr, "/run").await;
            wait_pending(&state, true).await;
            Some(stream)
        } else {
            None
        };
        let boundary = crate::replay::control::handle_control_request(
            command("request_begin", case_id),
            state.clone(),
            None,
            None,
        )
        .await
        .0;
        assert_eq!(boundary["ok"], true, "{boundary}");
        assert_eq!(
            state
                .lock()
                .await
                .startup_phase
                .report()
                .unstarted_business_dependencies["http"],
            1
        );
        let mut stream = match stream.take() {
            Some(stream) => stream,
            None => partial(addr, "/run").await,
        };
        let response = finish(&mut stream).await;
        assert_eq!(
            response.starts_with(b"HTTP/1.1 200"),
            admitted_before,
            "{}",
            String::from_utf8_lossy(&response)
        );
        let locked = state.lock().await;
        assert_eq!(
            locked
                .startup_phase
                .report()
                .unstarted_business_dependencies["http"],
            usize::from(!admitted_before)
        );
        assert_eq!(
            locked.http_exchanges[0].status.is_consumed(),
            admitted_before
        );
        serving.abort();
    }
}

#[test]
fn dropping_a_service_future_releases_the_atomic_barrier_without_claiming_source() {
    let mut ingress = HttpIngress::default();
    ingress.activate_case(Some("case"));
    let mut admission = ingress.handle().admit();
    ingress.configure_head(
        &mut admission,
        HttpReplayScheme::Http,
        &TargetKey {
            host: "ingress.test".into(),
            port: 80,
        },
        &Method::POST,
        &"/path".parse().unwrap(),
        Some("ingress.test"),
    );
    assert!(ingress.has_case_pending(Some("case")));
    drop(admission);
    assert!(!ingress.has_pending());
    assert!(ingress.case_failed("case"));
    assert_eq!(ingress.report().observations[0].status, "cancelled");
}

async fn prime(client: &mut TcpStream) {
    client
        .write_all(b"POST /prime HTTP/1.1\r\nHost: ingress.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let length = String::from_utf8(head)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut bytes = vec![0; length];
    client.read_exact(&mut bytes).await.unwrap();
}

#[tokio::test]
async fn headers_queued_for_replay_mutex_already_hold_the_observed_case() {
    let temp = tempfile::tempdir().unwrap();
    for case in ["case-a", "case-b"] {
        super::super::tests::write_http_case(
            &temp.path().join(case),
            "http",
            "ingress.test",
            &format!("/{case}"),
            "abcd",
            "ok",
        )
        .await;
    }
    let extra = temp.path().join("prime.jsonl");
    super::super::tests::write_http_dependency(&extra, "http", "ingress.test", "/prime", "", "ok")
        .await;
    let path = temp.path().join("case-a/dependencies.jsonl");
    let mut raw = std::fs::read(&path).unwrap();
    raw.extend(std::fs::read(extra).unwrap());
    std::fs::write(path, raw).unwrap();
    let (addr, runtime, serving) =
        super::super::tests::spawn_http_replay(temp.path(), vec![]).await;
    let state = runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin", "case-a"), state.clone()).await["ok"],
        true
    );
    let mut client = TcpStream::connect(addr).await.unwrap();
    prime(&mut client).await;
    let locked = state.lock().await;
    client.write_all(b"POST /case-a HTTP/1.1\r\nHost: ingress.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\na").await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !locked.http_ingress.has_case_pending(Some("case-a")) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !locked.http_ingress.try_close_case("case-a"),
        "the final empty check cannot outrun a parsed header waiting for Replay state"
    );
    assert_eq!(
        locked
            .http_ingress
            .report()
            .observations
            .last()
            .unwrap()
            .observed_case_id
            .as_deref(),
        Some("case-a")
    );
    drop(locked);
    let ending_state = state.clone();
    let ending =
        tokio::spawn(async move { end_case(&command("end", "case-a"), ending_state).await });
    assert!(finish(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let ended = ending.await.unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    serving.abort();
}

#[tokio::test]
async fn headers_waiting_for_replay_mutex_keep_their_real_startup_phase_token() {
    let temp = tempfile::tempdir().unwrap();
    let raw = temp.path().join("raw");
    super::super::tests::write_http_case(&raw, "http", "ingress.test", "/run", "abcd", "ok").await;
    let main = std::fs::read_to_string(raw.join("dependencies.jsonl")).unwrap();
    super::super::tests::write_http_dependency(
        &raw.join("prime.jsonl"),
        "http",
        "ingress.test",
        "/prime",
        "",
        "ok",
    )
    .await;
    let prime = std::fs::read_to_string(raw.join("prime.jsonl")).unwrap();
    std::fs::write(raw.join("global-dependencies.jsonl"), main + &prime).unwrap();
    std::fs::write(raw.join("dependencies.jsonl"), "").unwrap();
    let case = crate::replay::test_support::recording::centralize(&raw, &[1]).await;
    let case_id = case.file_name().unwrap().to_str().unwrap();
    let (addr, runtime, serving) = super::super::tests::spawn_http_replay(&case, vec![]).await;
    let state = runtime.state.clone();
    let mut client = TcpStream::connect(addr).await.unwrap();
    self::prime(&mut client).await;
    let mut locked = state.lock().await;
    client.write_all(b"POST /run HTTP/1.1\r\nHost: ingress.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\na").await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !locked.http_ingress.has_case_pending(Some(case_id)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    locked.close_startup_phase(case_id);
    assert_eq!(
        locked
            .startup_phase
            .report()
            .unstarted_business_dependencies["http"],
        1
    );
    assert!(
        locked
            .http_ingress
            .report()
            .observations
            .last()
            .unwrap()
            .startup_admitted
    );
    drop(locked);
    assert!(finish(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let locked = state.lock().await;
    assert_eq!(
        locked
            .startup_phase
            .report()
            .unstarted_business_dependencies["http"],
        0
    );
    serving.abort();
}

#[test]
fn admission_after_the_close_fence_cannot_be_rebound_by_a_later_case() {
    let mut ingress = HttpIngress::default();
    ingress.activate_case(Some("old"));
    assert!(ingress.try_close_case("old"));
    let admission = ingress.handle().admit();
    assert_eq!(admission.case_id(), None);
    ingress.activate_case(Some("next"));
    assert_eq!(
        admission.case_id(),
        None,
        "waiting for the Replay lock cannot change the independent header observation"
    );
    assert!(!ingress.has_case_pending(Some("next")));
    assert!(ingress.has_pending());
    drop(admission);
    assert!(!ingress.has_pending());
}
