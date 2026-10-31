//! A genuine finalized session uses the same ownership identity as cold receipt validation.
use super::*;

#[tokio::test]
async fn actual_replay_receipt_uses_the_streamed_frozen_ownership_identity() {
    let target = tempfile::tempdir().unwrap();
    let recorder = crate::Recorder::new(
        target
            .path()
            .join(".traffic-e2e/local/artifacts/recordings"),
    )
    .await
    .unwrap();
    crate::replay::test_support::recording::publish_case(&recorder).await;
    recorder.finish_run().await.unwrap();
    let root = recorder.run_dir.as_ref();
    let (_, manifest) = recording::manifest(root).unwrap();
    let expected = crate::rewrite::dependency_attribution_identity_for_source(
        target.path(),
        root,
        &manifest.run_id,
    )
    .unwrap();
    let addr = "127.0.0.1:0".parse().unwrap();
    let report = target.path().join("replay/report.json");
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: root.clone(),
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(report.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: None,
            ca_key_path: None,
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
    let case = manifest.inputs[0].case_id;
    for command in ["begin", "request_begin", "end", "finalize"] {
        let input=serde_json::from_value(serde_json::json!({"command":command,"case_id":case,"fail_on_dirty":true,"fail_on_incomplete":true})).unwrap();
        let (response, _) = crate::replay::control::handle_control_request(
            input,
            runtime.state.clone(),
            Some(report.clone()),
            None,
        )
        .await;
        assert_eq!(response["ok"], true, "{command}: {response}");
    }
    let actual: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let receipt = crate::replay::validate_completed_receipt(&actual).unwrap();
    assert_eq!(actual["dependency_attribution_snapshot"], expected);
    assert_eq!(
        receipt.dependency_attribution_snapshot.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        crate::rewrite::dependency_attribution_snapshot(target.path(), &manifest.run_id).unwrap(),
        expected
    );
    let old = crate::policy_evidence::digest(b"[]");
    assert_ne!(
        expected, old,
        "old expanded-DTO receipts must become stale rather than being relabeled"
    );
}
