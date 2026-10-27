use super::*;

pub(super) fn forwarding_calls(fixture: &Fixture) -> Vec<serde_json::Value> {
    fixture
        .calls()
        .into_iter()
        .filter(|call| {
            call["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "port-forward")
        })
        .collect()
}

#[tokio::test]
async fn unexpected_exit_is_fatal_without_starting_a_replacement() {
    for code in [0, 7] {
        let fixture = Fixture::new(&[8100]);
        fixture.settings(serde_json::json!({
            "ports": [8100], "exit_code": code,
            "runtime_stderr": ["lost connection to pod: private-token"]
        }));
        let mut forwards = PortForwards::default();
        forwards
            .prepare(&fixture.config, Duration::from_secs(5))
            .await
            .unwrap();
        std::fs::write(fixture.temp.path().join("exit"), "").unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), forwards.failure())
            .await
            .unwrap();
        let error = format!("{error:#}");
        assert!(error.contains(&format!("exit status: {code}")), "{error}");
        assert!(error.contains("connection_lost"), "{error}");
        assert!(!error.contains("private-token"));
        assert_eq!(forwarding_calls(&fixture).len(), 1);
        forwards.shutdown().await.unwrap();
        assert_eq!(forwarding_calls(&fixture).len(), 1);
    }
}

#[tokio::test]
async fn one_failed_port_stops_other_forwarding_children_on_shutdown() {
    let fixture = Fixture::new(&[8100, 9000]);
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    let calls = forwarding_calls(&fixture);
    let pid = calls[0]["pid"].as_u64().unwrap() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    let error = tokio::time::timeout(Duration::from_secs(2), forwards.failure())
        .await
        .unwrap();
    assert!(error.to_string().contains("exited"), "{error:#}");
    forwards.shutdown().await.unwrap();
    assert_eq!(forwarding_calls(&fixture).len(), 2);
    for port in [8100, 9000] {
        let address: SocketAddr = serde_json::from_slice(
            &std::fs::read(fixture.temp.path().join(format!("listen-{port}.json"))).unwrap(),
        )
        .unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
}
