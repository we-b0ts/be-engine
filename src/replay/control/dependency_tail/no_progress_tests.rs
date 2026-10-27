//! Idle failure retains evidence and the session; delivery remains resource-timed.
use super::tests::{GET, client, command, fixture};
use super::*;
use crate::replay::control::{begin_case, end_case, handle_control_request, run_control_socket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn default_five_second_idle_budget_ends_only_the_current_case() {
    let fixture = fixture(Some(900_000), 1).await;
    let state = fixture.runtime.state.clone();
    state.lock().await.case_dependency_post_response_window = Duration::ZERO;
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    tokio::time::pause();
    let ending_state = state.clone();
    let ending = tokio::spawn(async move {
        let mut request = command("end");
        request.fail_on_dirty = true;
        end_case(&request, ending_state).await
    });
    while state
        .lock()
        .await
        .dependency_tails
        .waiting("case-a")
        .is_none()
    {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert!(!ending.is_finished());
    tokio::time::advance(Duration::from_millis(26)).await;
    let ended = ending.await.unwrap();
    assert_eq!(ended["ok"], false, "{ended}");
    assert_eq!(ended["dirty"], true);
    let (failure, _) =
        handle_control_request(command("case_execution_status"), state.clone(), None, None).await;
    assert_eq!(failure["kind"], "case_no_progress");
    let waiting = &failure["failures"][0]["waiting"];
    assert_eq!(waiting["no_progress_timeout_ms"], 5000);
    assert_eq!(waiting["pending_source_dependencies"], 1);
    assert_eq!(waiting["actual_io_in_flight"], false);
    assert_eq!(waiting["references"][0]["reference"]["protocol"], "redis");
    assert_eq!(state.lock().await.redis.snapshot().unused_case.len(), 1);
    let mut next = command("begin");
    next.case_id = Some("case-b".into());
    assert_eq!(begin_case(&next, state.clone()).await["ok"], true);
    next.command = "end".into();
    assert_eq!(end_case(&next, state.clone()).await["ok"], true);
    let mut finalizing = command("finalize");
    finalizing.fail_on_incomplete = true;
    let report = fixture.root.join("final.json");
    let (finalized, stop) =
        handle_control_request(finalizing, state.clone(), Some(report.clone()), None).await;
    assert!(stop);
    assert_eq!(finalized["complete"], true);
    assert_eq!(finalized["dirty"], true);
    let report: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(report).await.unwrap()).unwrap();
    assert_eq!(
        report["case_execution_failures"][0]["kind"],
        "case_no_progress"
    );
    assert!(crate::replay::report_has_case_dirty_events(&report));
}

#[tokio::test]
async fn actual_redis_delivery_longer_than_the_idle_budget_remains_successful() {
    let fixture = fixture(Some(2000), 250).await;
    let state = fixture.runtime.state.clone();
    state.lock().await.dependency_tails =
        CaseTails::default().with_no_progress_timeout(Duration::from_millis(50));
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let (mut peer, task) = client(state.clone()).await;
    peer.write_all(GET).await.unwrap();
    while !crate::replay::control::case_cleanup::has_started(&*state.lock().await) {
        tokio::task::yield_now().await;
    }
    let started = Instant::now();
    let ended = end_case(&command("end"), state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(started.elapsed() >= Duration::from_millis(150));
    let mut response = [0; 5];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"+OK\r\n");
    assert!(state.lock().await.dependency_tails.failures().is_empty());
    peer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn readonly_control_remains_available_during_end_and_mutations_stay_serial() {
    let fixture = fixture(Some(900_000), 1).await;
    let state = fixture.runtime.state.clone();
    {
        let mut state = state.lock().await;
        state.case_dependency_post_response_window = Duration::ZERO;
        state.dependency_tails =
            CaseTails::default().with_no_progress_timeout(Duration::from_millis(250));
    }
    let socket = crate::replay::allocate_control_socket();
    let session = fixture.root.join("session.json");
    let server = tokio::spawn(run_control_socket(
        state.clone(),
        None,
        Some(session.clone()),
        Some(socket),
    ));
    let request = |command: &str, case: &str| crate::MysqlReplayControlConfig {
        session_path: session.clone(),
        command: command.into(),
        case_id: Some(case.into()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        wait_timeout: Some(Duration::from_secs(2)),
    };
    use crate::replay::control::send_control_request as send;
    send(request("wait_ready", "case-a")).await.unwrap();
    send(request("begin", "case-a")).await.unwrap();
    let ending = tokio::spawn(send(request("end", "case-a")));
    while state
        .lock()
        .await
        .dependency_tails
        .waiting("case-a")
        .is_none()
    {
        tokio::task::yield_now().await;
    }
    let next = tokio::spawn(send(request("begin", "case-b")));
    let status = tokio::time::timeout(
        Duration::from_millis(100),
        send(request("status", "case-a")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        status["session"]["waiting"]["pending_source_dependencies"],
        1
    );
    assert_eq!(status["session"]["active_case_id"], "case-a");
    assert!(!next.is_finished());
    ending.await.unwrap().unwrap();
    assert_eq!(next.await.unwrap().unwrap()["active_case_id"], "case-b");
    send(request("end", "case-b")).await.unwrap();
    send(request("stop", "case-b")).await.unwrap();
    server.await.unwrap().unwrap();
}
