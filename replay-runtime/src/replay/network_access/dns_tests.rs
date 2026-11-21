use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime, handle_dns_query};
use std::sync::Arc;
use tokio::net::UdpSocket;

async fn runtime(temp: &Path) -> ReplayRuntime {
    let case_dir = temp.join("case-a");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    tokio::fs::write(
        temp.join(RECORDING_NETWORK_FILENAME),
        r#"{"version":1,"resolved_domains":["dns-only.test","reachable.test"],"accessed_endpoints":[{"host":"reachable.test","port":8080}]}"#,
    ).await.unwrap();
    ReplayRuntime::load(
        ReplayConfig {
            case_dir,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.join("ca.pem")),
            ca_key_path: Some(temp.join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap()
}

async fn answer(runtime: &ReplayRuntime, host: &str, qtype: u16) -> Vec<u8> {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    client
        .send_to(&query, server.local_addr().unwrap())
        .await
        .unwrap();
    let mut buf = [0; 512];
    let (len, peer) = server.recv_from(&mut buf).await.unwrap();
    handle_dns_query(server, runtime.state.clone(), buf[..len].to_vec(), peer)
        .await
        .unwrap();
    let len = tokio::time::timeout(std::time::Duration::from_secs(1), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..2], &[0x12, 0x34]);
    assert_eq!(buf[3] & 0x0f, 0);
    buf[..len].to_vec()
}

#[tokio::test]
async fn recorded_dns_only_domain_has_no_invented_address_or_transport() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path()).await;
    for qtype in [1, 28] {
        let reply = answer(&runtime, "DNS-ONLY.TEST", qtype).await;
        assert_eq!(&reply[6..8], &[0, 0]);
    }
    let state = runtime.state.lock().await;
    assert!(state.unrecorded_domain_ips.is_empty());
    assert!(!state.snapshot_report().is_dirty());
}

#[tokio::test]
async fn recorded_endpoint_keeps_address_and_strict_unrecorded_port_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path()).await;
    let reply = answer(&runtime, "reachable.test", 1).await;
    assert_eq!(&reply[6..8], &[0, 1]);
    let fake_ip = Ipv4Addr::new(
        reply[reply.len() - 4],
        reply[reply.len() - 3],
        reply[reply.len() - 2],
        reply[reply.len() - 1],
    );
    let mut state = runtime.state.lock().await;
    assert!(
        state
            .targets
            .iter()
            .any(|t| t.fake_ip == fake_ip && t.port == 8080)
    );
    let target = state.unrecorded_target_for(fake_ip, 8081).unwrap();
    state.record_unrecorded_target(target);
    assert_eq!(state.snapshot_report().unrecorded_targets.len(), 1);
    assert!(state.snapshot_report().is_dirty());
}

#[tokio::test]
async fn entirely_new_domain_still_quarantines_and_rejects_transport() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path()).await;
    let reply = answer(&runtime, "new.test", 1).await;
    assert_eq!(&reply[6..8], &[0, 1]);
    let mut state = runtime.state.lock().await;
    let fake_ip = *state.unrecorded_domain_ips.get("new.test").unwrap();
    assert!(!state.snapshot_report().is_dirty());
    let target = state.unrecorded_target_for(fake_ip, 8080).unwrap();
    state.record_unrecorded_target(target);
    assert!(state.snapshot_report().is_dirty());
}
