use super::*;
use chrono::{Duration, Utc};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::fs;

async fn request(addr: std::net::SocketAddr) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("/business")
                .header("host", "api.example.test")
                .header(
                    "x-amz-date",
                    Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
                )
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "recorded"
    );
}

#[tokio::test]
async fn header_apply_and_reused_rule_schedule_the_owner_api_without_reclassifying_old_evidence() {
    let target = configured_target();
    fs::write(
        target.path().join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
    let source = target
        .path()
        .join(".traffic-e2e/local/artifacts/recordings/recording");
    let case = source.join("case-headers");
    let clock = Utc::now() - Duration::days(1);
    crate::replay::write_http_case(
        &case,
        "fake_ip_http",
        "api.example.test",
        "/business",
        "{}",
        "recorded",
    )
    .await;
    let dependency = case.join("dependencies.jsonl");
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&dependency).unwrap()).unwrap();
    record["request_started_at"] = json!(clock);
    record["request_headers"] = json!({"x-amz-date":[clock.format("%Y%m%dT%H%M%SZ").to_string()]});
    fs::write(&dependency, format!("{record}\n")).unwrap();
    fs::write(
        case.join("request.json"),
        json!({"method":"GET","uri":"/api","timestamp":clock}).to_string(),
    )
    .unwrap();
    fs::write(
        source.join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let evidence_paths = crate::e2e_run::jwt_evidence::test_support::install_attempt(
        target.path(),
        &source,
        &[(case.clone(), 200, 200)],
        Utc::now(),
    );
    let (addr, runtime, task) = crate::replay::spawn_coordinator_http_replay(&case, None).await;
    request(addr).await;
    let mut report = crate::replay::snapshot_http_replay(&runtime).await;
    report["finalized"] = json!(true);
    let replay = evidence_paths.replay;
    let aggregate = evidence_paths.aggregate;
    let assertions = evidence_paths.assertions;
    crate::replay::write_http_replay_evidence(&replay, &report).await;
    fs::write(aggregate, r#"{"complete":true,"dirty":true}"#).unwrap();
    fs::write(assertions, "{}").unwrap();
    let original_report = fs::read(&replay).unwrap();
    let original_recording = fs::read(&dependency).unwrap();
    let mut state = implementation_state_with_inventory(false);
    state.case_source = Some(source.clone());
    state.group_id = Some(state.api.clone());
    state.source_revision = Some("source".into());
    worker::confirm_current_for_test(&mut state);
    let store = RewriteStore::new(target.path()).unwrap();
    let context = || crate::RewriteContext {
        target_root: target.path().into(),
    };
    for reused in [false, true] {
        let evidence = rewrite::evidence::commands(target.path(), &state)
            .into_iter()
            .find(|c| c.query_id.ends_with("dirty-clusters"))
            .unwrap();
        let evidence_id = rewrite::evidence::query(target.path(), &state, &evidence.query_id)
            .unwrap()
            .evidence_id;
        store.save(&state).unwrap();
        let planned = rewrite::plan_rewrite_dependency_rule(
            context(),
            crate::RewriteDependencyRulePlanOptions {
                evidence_id,
                ownership: crate::RewriteDependencyOwnership::RequestOwned,
                name: Some("signing-time".into()),
                source_evidence: Some("sdk.py:build_headers uses current UTC time".into()),
                selector: crate::RewriteDependencyRuleSelector::HttpHeaderTimestamp {
                    selector: crate::HttpHeaderTimestampSelector {
                        host: "api.example.test".into(),
                        port: 80,
                        method: "POST".into(),
                        path: "/business".into(),
                        header: "x-amz-date".into(),
                        format: crate::ResponseTimestampFormat::AmzDate,
                    },
                },
            },
        )
        .unwrap();
        let plan_id = planned.plan_id.unwrap();
        let applied = rewrite::apply_rewrite_dependency_rule(context(), &plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["reused_existing"], reused);
        assert!(applied.evidence_reclassification.is_none());
        state = store.load().unwrap().unwrap();
        assert!(state.rule_replay_pending);
        assert!(!state.e2e_current);
        assert!(state.active_issue.is_some());
        assert!(worker::runtime::scopes(&state).is_empty());
        assert_eq!(fs::read(&replay).unwrap(), original_report);
        assert_eq!(fs::read(&dependency).unwrap(), original_recording);
    }
    let (next_addr, next_runtime, next_task) = crate::replay::spawn_coordinator_http_replay(
        &case,
        Some(target.path().join(".traffic-e2e/verification.yaml")),
    )
    .await;
    request(next_addr).await;
    let next_report = crate::replay::snapshot_http_replay(&next_runtime).await;
    assert!(
        next_report["http_request_header_mismatches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
    next_task.abort();
}
