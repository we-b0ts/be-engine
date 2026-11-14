//! A cancelled native claim must publish a final failed report, rather than hang.
use super::*;
use serde_json::json;

fn command(name: &str, case: Option<&str>) -> ReplayControlRequest {
    ReplayControlRequest {
        command: name.into(),
        case_id: case.map(str::to_owned),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        identity_pairs: vec![],
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    }
}

#[tokio::test]
async fn finalize_after_cancelled_mysql_delivery_seals_dirty_evidence() {
    let root = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    let sql = "UPDATE jobs SET active=1 WHERE id=7";
    std::fs::write(
        source.join("dependencies.jsonl"),
        json!({
            "event_type":"mysql_exchange", "connection_id":Uuid::from_u128(91),
            "query_sequence":1,"target_host":"db.test","target_port":3306,
            "command":"COM_QUERY","sql":sql,"replay_safe":true
        })
        .to_string(),
    )
    .unwrap();
    let case = crate::replay::test_support::recording::centralize_partitioned(&source, &[]).await;
    let report_path = root.path().join("report.json");
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case,
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(report_path.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.path().join("ca.pem")),
            ca_key_path: Some(root.path().join("key.pem")),
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap();
    let state = runtime.state.clone();
    let case = state.lock().await.cases.keys().next().unwrap().clone();
    assert_eq!(
        begin_case(&command("begin", Some(&case)), state.clone()).await["ok"],
        true
    );
    let matched = {
        let mut state = state.lock().await;
        state
            .match_exchange(
                &ReplaySessionIdentity {
                    target: Some(TargetKey {
                        host: "db.test".into(),
                        port: 3306,
                    }),
                    database: Some("app".into()),
                    username: Some("reader".into()),
                },
                "COM_QUERY",
                Some(sql),
                None,
            )
            .unwrap()
    };
    let index = matched.index;
    // Dropping the real delivery guard is what cancellation does while the
    // native I/O future is suspended. Its receipt changes without ReplayState.
    drop(matched.claim.guard());
    drop(matched);
    {
        let state = state.lock().await;
        assert_eq!(
            state.protocols.mysql.exchanges[index].status,
            ReplayExchangeStatus::Responding
        );
        assert_eq!(
            state.protocols.mysql.exchange_status(index),
            Some(ReplayExchangeStatus::Failed)
        );
        assert!(!state.protocols.mysql.has_in_flight());
    }
    let ended = tokio::time::timeout(
        Duration::from_secs(2),
        end_case(&command("end", Some(&case)), state.clone()),
    )
    .await
    .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert_eq!(ended["dirty"], true, "{ended}");

    let (finalized, stop) = handle_control_request(
        command("finalize", None),
        state.clone(),
        Some(report_path.clone()),
        None,
    )
    .await;
    assert_eq!(finalized["ok"], true, "{finalized}");
    assert_eq!(finalized["dirty"], true, "{finalized}");
    assert!(stop);
    let report: Value = serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["finalized"], true);
    assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 1);
    assert!(report["matched_queries"].as_array().unwrap().is_empty());
    assert!(state.lock().await.finalized_at.is_some());
}
