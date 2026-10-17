use super::*;
use crate::replay::policy::test_fixture::{ManagedFixtureDirectory, managed_tempdir};
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const HOST: &str = "sharing.example.test";

fn record(uri: &str, body: &str, second: u32) -> Value {
    json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),
        "scheme":"fake_ip_http","authority":HOST,"method":"POST","uri":uri,
        "timestamp":format!("2026-10-17T00:00:{second:02}Z"),
        "request_headers":{},"request_body":{"encoding":"utf8","data":"","truncated":false},
        "response_status":200,"response_headers":{},
        "response_body":{"encoding":"utf8","data":body,"truncated":false}})
}

async fn fixture(global_shared: bool) -> (ManagedFixtureDirectory, PathBuf) {
    let temp = managed_tempdir().unwrap();
    let root = temp.path();
    fs::write(
        root.join("recording-run.json"),
        r#"{"status":"completed","run_id":"shared-global-http"}"#,
    )
    .unwrap();
    for (name, ordinary) in [("a", 1), ("b", 2)] {
        let case = root.join(name);
        fs::create_dir(&case).unwrap();
        fs::write(
            case.join("request.json"),
            json!({"method":"GET","uri":format!("/api/{name}")}).to_string(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
        let mut records = (0..ordinary)
            .map(|index| record(&format!("/ordinary-{name}-{index}"), "ordinary", 1))
            .collect::<Vec<_>>();
        records.push(record(
            &format!("/token?origin={name}"),
            name,
            if name == "a" { 10 } else { 30 },
        ));
        fs::write(
            case.join("dependencies.jsonl"),
            records
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
    }
    let mut globals = vec![record("/global", "global-ordinary", 1)];
    if global_shared {
        globals.push(record("/token?origin=global", "global-shared", 20));
    }
    fs::write(
        root.join("global-dependencies.jsonl"),
        globals
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let policy = root.join("policy.yaml");
    crate::replay::write_policy_fixture(&policy, format!(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: shared-token\n  protocol: http\n  target: {{host: {HOST}, port: 80}}\n  http: {{method: POST, path: /token}}\n  replay_scope: recording_run\n  source_evidence: 'Source token is reused across API requests'\n"
    )).unwrap();
    crate::replay::write_test_recording_network_manifest(root);
    let document = crate::policy::parse_policy(&fs::read_to_string(&policy).unwrap()).unwrap();
    let fingerprint = crate::policy::compile_policy(&document)
        .unwrap()
        .fingerprints
        .full;
    crate::replay::report::prewarm_global_report(root, &[], Some(&fingerprint))
        .await
        .unwrap();
    (temp, policy)
}

async fn load(root: &Path, case: &str, policy: &Path) -> (ReplayRuntime, PathBuf) {
    let report = root.join(format!("results/{case}/report.json"));
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: root.join(case),
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(report.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.join(format!("results/{case}/ca.pem"))),
            ca_key_path: Some(root.join(format!("results/{case}/ca-key.pem"))),
            policy_path: Some(policy.into()),
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap();
    (runtime, report)
}

fn consume(state: &mut ReplayState, uri: &str, expected: &str) -> usize {
    let response = state.match_http_request(
        HttpReplayScheme::Http,
        &TargetKey {
            host: HOST.into(),
            port: 80,
        },
        &Method::POST,
        &uri.parse().unwrap(),
        Some(HOST),
        b"",
        &HeaderSnapshot::new(),
        Utc::now(),
    );
    let Ok(response) = response else {
        panic!("native HTTP request must match {uri}");
    };
    assert_eq!(
        decode_body(response.response_body.as_ref().unwrap()).unwrap(),
        expected.as_bytes()
    );
    state.http_events.matched.last().unwrap().index
}

async fn publish_and_compare(runtime: &ReplayRuntime, report: &Path) -> Value {
    let (mut value, expected) = {
        let mut state = runtime.state.lock().await;
        let mut expected = vec![];
        state
            .visit_global_http_unused(&mut |row| {
                expected.push(row);
                Ok(())
            })
            .unwrap();
        assert_eq!(state.global_http_unused_count(), expected.len());
        state.finalized_at = Some(Utc::now());
        (
            serde_json::to_value(state.snapshot_report()).unwrap(),
            expected,
        )
    };
    let details = crate::replay::report::global_evidence::prepare(runtime.state.clone(), report)
        .await
        .unwrap();
    let manifest = details.manifests["http"].clone();
    value["global_evidence"] = details.manifests.clone();
    fs::write(report, serde_json::to_vec(&value).unwrap()).unwrap();
    details.commit();
    let actual = crate::replay::read_global_dependency_page(report, "http", 0, 100).unwrap();
    assert_eq!(actual.total, expected.len());
    assert_eq!(actual.items, expected);
    manifest
}

#[tokio::test]
async fn transformed_native_global_http_uses_complete_session_projection_for_each_api() {
    let (temp, policy) = fixture(true).await;
    let mut indexes = vec![];
    for case in ["a", "b"] {
        let (runtime, report) = load(temp.path(), case, &policy).await;
        {
            let mut state = runtime.state.lock().await;
            assert!(!state.regular_global.contains_key("http"));
            assert!(state.regular_global.contains_key("redis"));
            assert!(state.http_global_report_usage().count().is_none());
            indexes.push(consume(&mut state, "/token?origin=global", "global-shared"));
            consume(&mut state, &format!("/token?origin={case}"), case);
        }
        let manifest = publish_and_compare(&runtime, &report).await;
        assert!(
            manifest.get("kind").is_none(),
            "HTTP falls back to complete native pages"
        );
    }
    assert_ne!(
        indexes[0], indexes[1],
        "each API retains its native sorted indexes"
    );
}

#[tokio::test]
async fn case_only_http_cross_case_shares_the_same_global_core_across_api_scopes() {
    let (temp, policy) = fixture(false).await;
    let mut keys = vec![];
    for case in ["a", "b"] {
        let (runtime, report) = load(temp.path(), case, &policy).await;
        {
            let mut state = runtime.state.lock().await;
            assert!(state.regular_global.contains_key("http"));
            assert_eq!(consume(&mut state, "/global", "global-ordinary"), 0);
            consume(&mut state, &format!("/token?origin={case}"), case);
        }
        let manifest = publish_and_compare(&runtime, &report).await;
        assert_eq!(manifest["kind"], "global_compact_v1");
        keys.push(manifest["regular"]["inventory"]["key"].clone());
    }
    assert_eq!(keys[0], keys[1], "Case scope changes only session extras");
}
