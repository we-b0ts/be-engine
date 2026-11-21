use super::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn phase_fence_keeps_real_inflight_and_never_counts_protocol_control_or_process() {
    let mut counts = Counts::default();
    let mut unclaimed = ReplayExchangeStatus::Available;
    counts.observe(ReplaySource::Startup, &mut unclaimed, true, true);
    assert_eq!(unclaimed, ReplayExchangeStatus::StartupBlocked);
    assert!(!unclaimed.is_consumed());
    let mut responding = ReplayExchangeStatus::Responding;
    counts.observe(ReplaySource::Startup, &mut responding, true, true);
    assert_eq!(responding, ReplayExchangeStatus::Responding);
    let mut process = ReplayExchangeStatus::Available;
    counts.observe(ReplaySource::Process, &mut process, true, true);
    let mut control = ReplayExchangeStatus::Available;
    counts.observe(ReplaySource::Startup, &mut control, false, true);
    assert_eq!(process, ReplayExchangeStatus::Available);
    assert_eq!(control, ReplayExchangeStatus::Available);
    assert_eq!((counts.required, counts.unstarted), (2, 1));
    assert!(!StartupPhase::default().report().is_dirty());
}

fn exchange(connection: uuid::Uuid, command: &str, args: &[&str]) -> Value {
    let capture = |value: &str| json!({"encoding":"utf8","data":value,"truncated":false});
    let args = args.iter().map(|arg| capture(arg)).collect::<Vec<_>>();
    json!({"event_type":"redis_exchange","connection_id":connection,"sequence":1,"target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,"command":command,"args":args,"response_kind":"bulk_string","response":capture("$1\r\nx\r\n"),"duration_ms":0,"replay_safe":true})
}

#[tokio::test]
async fn primary_boundary_prevents_a_case_call_from_paying_missing_startup_even_if_process_matches()
{
    assert_finite_process_exchange("GET", &["same"], b"*2\r\n$3\r\nGET\r\n$4\r\nsame\r\n").await;
}

#[tokio::test]
async fn process_eval_returns_the_recorded_reply_once() {
    assert_finite_process_exchange(
        "EVAL",
        &["return ARGV[1]", "1", "same", "x"],
        b"*5\r\n$4\r\nEVAL\r\n$14\r\nreturn ARGV[1]\r\n$1\r\n1\r\n$4\r\nsame\r\n$1\r\nx\r\n",
    )
    .await;
}

async fn assert_finite_process_exchange(command: &str, args: &[&str], request: &[u8]) {
    let temp = tempfile::tempdir().unwrap();
    let raw_case = temp.path().join("raw-case");
    std::fs::create_dir_all(&raw_case).unwrap();
    std::fs::write(raw_case.join("dependencies.jsonl"), "").unwrap();
    std::fs::write(
        raw_case.join("global-dependencies.jsonl"),
        format!(
            "{}\n{}\n",
            exchange(uuid::Uuid::new_v4(), command, args),
            exchange(uuid::Uuid::new_v4(), command, args)
        ),
    )
    .unwrap();
    let case = crate::replay::test_support::recording::centralize(&raw_case, &[1]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: case.clone(),
            selected_case_ids: vec![],
            dns_listen: endpoint,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        endpoint,
        addr,
    )
    .await
    .unwrap();
    let state = runtime.state.clone();
    let initial = state.lock().await.startup_phase.report();
    assert_eq!(initial.status, "phase_unverified");
    assert_eq!(initial.business_inventory["redis"], 1);
    assert!(
        initial.is_dirty(),
        "implicit replay cannot invent an observed startup boundary"
    );
    let case_id = case.file_name().unwrap().to_str().unwrap();
    let command =
        serde_json::from_value(json!({"command":"request_begin","case_id":case_id})).unwrap();
    let result = crate::replay::control::handle_control_request(command, state.clone(), None, None)
        .await
        .0;
    assert_eq!(result["ok"], true, "{result}");
    let frozen = state.lock().await.startup_phase.report();
    assert_eq!(frozen.status, "verified");
    assert_eq!(frozen.unstarted_business_dependencies["redis"], 1);
    let task = tokio::spawn(async move {
        let _ = runtime.run_tcp(listener).await;
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut response = [0; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"$1\r\nx\r\n", "Process remains eligible");
    client.write_all(request).await.unwrap();
    let mut rejected = [0; 128];
    let count = client.read(&mut rejected).await.unwrap();
    assert_eq!(count, 0, "late Case cannot borrow the startup reply");
    let report = state.lock().await.snapshot_report();
    assert_eq!(
        report.startup_phase.unstarted_business_dependencies["redis"],
        1
    );
    assert!(report.is_dirty());
    task.abort();
}
