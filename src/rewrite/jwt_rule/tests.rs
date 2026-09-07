use super::*;
use crate::request_rules::tests::request;
use crate::rewrite::{
    model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase},
    store::RewriteStore,
};
use chrono::DateTime;
use std::fs;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct Fixture {
    target: tempfile::TempDir,
    state: RewriteState,
    request: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let target = tempfile::tempdir().unwrap();
    let root = target.path();
    crate::rewrite::test_support::install_project_config(
        root,
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        root.join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(root.join(".traffic-e2e/Dockerfile.e2e"), "FROM scratch\n").unwrap();
    fs::write(root.join(".gitignore"), ".traffic-e2e/local/\n").unwrap();
    for args in [
        vec!["init", "-q", "-b", "master"],
        vec!["config", "user.name", "Test"],
        vec!["config", "user.email", "test@example.com"],
        vec!["add", "."],
        vec!["commit", "-qm", "baseline"],
    ] {
        assert!(
            std::process::Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    fs::write(
        root.join(".traffic-e2e/local/target.env"),
        "SECRET_KEY=test-signing-key\n",
    )
    .unwrap();
    let source = root.join(".traffic-e2e/local/artifacts/recordings/recording");
    let case = source.join("case-1");
    fs::create_dir_all(&case).unwrap();
    let recorded = 1_700_000_000;
    let request_path = case.join("request.json");
    fs::write(
        &request_path,
        serde_json::to_vec(&request(
            json!({"sub":"test-user","exp":recorded+3600}),
            "test-signing-key",
            recorded,
        ))
        .unwrap(),
    )
    .unwrap();
    crate::e2e_run::jwt_evidence::test_support::install_attempt(
        root,
        &source,
        &[(case, 200, 401)],
        DateTime::from_timestamp(recorded + 7200, 0).unwrap(),
    );
    // Keep the replay input encrypted exactly as managed recording does.
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let encryption_key = [42_u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&encryption_key).unwrap();
    let mut recorded_value: Value =
        serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
    let plaintext = recorded_value["headers"]["authorization"][0]
        .as_str()
        .unwrap();
    let nonce = [7_u8; 12];
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"authorization",
            },
        )
        .unwrap();
    recorded_value["headers"]["authorization"][0] = json!(format!(
        "traffic-e2e:enc:v1:aes-256-gcm:{}:{}",
        STANDARD.encode(nonce),
        STANDARD.encode(ciphertext)
    ));
    fs::write(&request_path, serde_json::to_vec(&recorded_value).unwrap()).unwrap();
    fs::create_dir_all(root.join(".traffic-e2e/local/secrets")).unwrap();
    fs::write(
        root.join(".traffic-e2e/local/secrets/traffic-e2e-enc.sec"),
        STANDARD.encode(encryption_key),
    )
    .unwrap();
    let mut state = crate::rewrite::test_state();
    super::super::inventory::install(&mut state, vec!["GET /api".into(), "GET /other".into()])
        .unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.case_source = Some(source);
    state.group_id = Some("GET /api".into());
    state.e2e_current = false;
    state.require_comparison = false;
    state.recording_require_comparison = false;
    state.active_issue = Some(RewriteIssue {
        id: "issue-jwt".into(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "200 became 401".into(),
        pointer_pattern: Some("$status".into()),
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".into(),
        attempt: 1,
        comparison_observation: None,
    });
    Fixture {
        target,
        state,
        request: request_path,
    }
}

fn options() -> JwtRulePlanOptions {
    JwtRulePlanOptions {
        id: "session-jwt".into(),
        header: "authorization".into(),
        algorithm: JwtAlgorithm::HS256,
        signing_key_ref: "session-jwt".into(),
        key_source: Some(SigningKeySource::TargetEnv {
            name: "SECRET_KEY".into(),
        }),
        leeway_seconds: 60,
    }
}

fn plan_fixture(f: &mut Fixture) -> RewriteRuleReport {
    let root = f.target.path();
    let query = evidence::commands(root, &f.state)
        .into_iter()
        .find(|q| q.query_id.ends_with("jwt-time-validity"))
        .unwrap();
    let ev = evidence::query(root, &f.state, &query.query_id).unwrap();
    assert_eq!(ev.applicable_rule_planners.len(), 1);
    assert!(!ev.facts["signature_verified"].as_bool().unwrap());
    plan(
        root,
        &mut f.state,
        ev.evidence_id,
        Some("auth.rs verifies SECRET_KEY HS256 session JWT with 60s expiration leeway".into()),
        options(),
    )
    .unwrap()
}

#[tokio::test]
async fn discovery_plan_apply_and_real_http_replay_use_the_original_recording() {
    let mut f = fixture();
    let original = fs::read(&f.request).unwrap();
    let preview = plan_fixture(&mut f);
    assert_eq!(preview.traffic_e2e_report["signature_verified"], true);
    assert!(!keys::binding_path(f.target.path()).exists());
    assert!(
        !fs::read_to_string(f.target.path().join(".traffic-e2e/verification.yaml"))
            .unwrap()
            .contains("request_rules")
    );
    let record = f.state.rule_plan.clone().unwrap();
    let result = apply(f.target.path(), &mut f.state, record).unwrap();
    assert_eq!(result.traffic_e2e_report["requires_rerecording"], false);
    assert!(result.next_command.argv.iter().any(|s| s == "next"));
    assert!(f.state.recording_refresh.is_none());
    assert!(!f.state.e2e_current);
    assert_eq!(fs::read(&f.request).unwrap(), original);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for expected in [401, 200] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if bytes.windows(4).any(|b| b == b"\r\n\r\n") {
                    break;
                }
            }
            let raw = String::from_utf8(bytes).unwrap();
            let token = raw
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                        .map(|(_, v)| v.trim().strip_prefix("Bearer ").unwrap())
                })
                .unwrap();
            let valid = jsonwebtoken::decode::<Value>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(b"test-signing-key"),
                &jsonwebtoken::Validation::default(),
            )
            .is_ok();
            let status = if valid { 200 } else { 401 };
            assert_eq!(status, expected);
            stream.write_all(format!("HTTP/1.1 {status} Result\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
        }
    });
    let make_client = || {
        crate::recorded_request::RecordedHttpClient::new(
            origin.clone(),
            std::time::Duration::from_secs(5),
            1024,
        )
    };
    assert_eq!(make_client().send(&f.request).await.unwrap().status, 401);
    let response = make_client()
        .with_request_rules(
            f.target.path(),
            &f.target.path().join(".traffic-e2e/verification.yaml"),
        )
        .unwrap()
        .send(&f.request)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.request_rules.len(), 1);
    let actual_path = f.target.path().join("actual-response.json");
    fs::write(&actual_path, serde_json::to_vec(&json!({
        "version":1,"status":200,"request_sent_at":response.request_sent_at,
        "request_rules":response.request_rules,"body":{"encoding":"utf8","data":"{}","truncated":false}
    })).unwrap()).unwrap();
    let assertion = crate::assert_recorded_response(crate::ResponseAssertionOptions {
        case_id: "case-1".into(),
        request: f.request.clone(),
        expected_response: f.request.parent().unwrap().join("expected-response.json"),
        actual_response: actual_path,
        policy: f.target.path().join(".traffic-e2e/verification.yaml"),
    })
    .unwrap();
    assert!(assertion.passed);
    assert_eq!(fs::read(&f.request).unwrap(), original);
    server.await.unwrap();
}

#[test]
fn source_401_does_not_offer_a_refresh_rule_and_rotated_runtime_key_is_rejected() {
    let mut f = fixture();
    plan_fixture(&mut f);
    let record = f.state.rule_plan.clone().unwrap();
    let report = apply(f.target.path(), &mut f.state, record).unwrap();
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("test-signing-key"));
    assert!(!serialized.contains("test-user"));
    let expected = f.request.parent().unwrap().join("expected-response.json");
    fs::write(expected, r#"{"status":401}"#).unwrap();
    assert!(
        facts(f.target.path(), &f.state)
            .unwrap()
            .candidates
            .is_empty()
    );
    fs::write(
        f.target.path().join(".traffic-e2e/local/target.env"),
        "SECRET_KEY=rotated\n",
    )
    .unwrap();
    let error = keys::resolve_binding(f.target.path(), "session-jwt").unwrap_err();
    assert!(error.to_string().contains("changed since rule apply"));
}

#[test]
fn apply_rejects_key_policy_and_evidence_changes_without_writing_rules() {
    for change in ["key", "policy", "request"] {
        let mut f = fixture();
        plan_fixture(&mut f);
        let record = f.state.rule_plan.clone().unwrap();
        match change {
            "key" => fs::write(
                f.target.path().join(".traffic-e2e/local/target.env"),
                "SECRET_KEY=rotated\n",
            )
            .unwrap(),
            "policy" => fs::write(
                f.target.path().join(".traffic-e2e/verification.yaml"),
                "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n# changed\n",
            )
            .unwrap(),
            _ => {
                let mut value: Value =
                    serde_json::from_slice(&fs::read(&f.request).unwrap()).unwrap();
                value["uri"] = json!("/changed");
                fs::write(&f.request, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        assert!(apply(f.target.path(), &mut f.state, record).is_err());
        assert!(!keys::binding_path(f.target.path()).exists());
    }
}

#[test]
fn plan_rejects_wrong_key_and_insufficient_expiration_evidence() {
    let mut f = fixture();
    fs::write(
        f.target.path().join(".traffic-e2e/local/target.env"),
        "SECRET_KEY=wrong-key\n",
    )
    .unwrap();
    let query = evidence::commands(f.target.path(), &f.state)
        .into_iter()
        .find(|q| q.query_id.ends_with("jwt-time-validity"))
        .unwrap();
    let ev = evidence::query(f.target.path(), &f.state, &query.query_id).unwrap();
    let error = plan(
        f.target.path(),
        &mut f.state,
        ev.evidence_id,
        Some("source uses JWT exp validation".into()),
        options(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not verify"));
    assert!(!error.to_string().contains("wrong-key"));
    let mut candidate = facts(f.target.path(), &f.state)
        .unwrap()
        .candidates
        .remove(0);
    candidate.replayed_at = DateTime::from_timestamp(candidate.exp + 30, 0).unwrap();
    let request =
        serde_json::from_slice(&crate::request_headers::load_request_file(&f.request).unwrap())
            .unwrap();
    assert!(jwt_evidence::verify_candidate(&candidate, &request, b"test-signing-key", 60).is_err());
}

#[test]
fn global_apply_invalidates_other_completed_api_without_new_recording() {
    let mut f = fixture();
    f.state.api_inventory[1].status = super::super::model::RewriteApiStatus::Complete;
    f.state.api_inventory[1].e2e_current = true;
    plan_fixture(&mut f);
    let id = f.state.rule_plan.as_ref().unwrap().id.clone();
    RewriteStore::new(f.target.path())
        .unwrap()
        .save(&f.state)
        .unwrap();
    let report = super::super::apply_rewrite_rule(
        crate::RewriteContext {
            target_root: f.target.path().into(),
        },
        &id,
    )
    .unwrap();
    let state = RewriteStore::new(f.target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        state.api_inventory[1].status,
        super::super::model::RewriteApiStatus::RevalidationPending
    );
    assert!(!state.api_inventory[1].e2e_current);
    assert!(state.recording_refresh.is_none());
    assert_eq!(report.traffic_e2e_report["requires_rerecording"], false);
}

#[test]
fn jwt_evidence_discovers_mounts_and_file_binding_without_exposing_values() {
    let mut f = fixture();
    let root = f.target.path();
    let config_path = root.join(".traffic-e2e/project.yaml");
    let mut config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    config["project"]["target"]["startup"]["mounts"] =
        serde_yaml::to_value(vec!["/app/.env", "/var/app"]).unwrap();
    fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let mounts_root = root.join(crate::repository::LOCAL_STARTUP_MOUNTS_ROOT);
    fs::create_dir_all(mounts_root.join("app")).unwrap();
    fs::create_dir_all(mounts_root.join("var/app")).unwrap();
    fs::write(
        mounts_root.join("app/.env"),
        "SECRET_KEY=test-signing-key\nUNRELATED_TOKEN=do-not-expose\n",
    )
    .unwrap();
    crate::startup::install_startup_snapshot(
        root,
        vec![
            crate::startup::StartupSnapshotMount {
                path: "/app/.env".into(),
                writable: false,
            },
            crate::startup::StartupSnapshotMount {
                path: "/var/app".into(),
                writable: true,
            },
        ],
    );
    // The application imports dotenv itself; this field is not a Docker env.
    fs::write(root.join(".traffic-e2e/local/target.env"), "PORT=8080\n").unwrap();
    let query = evidence::commands(root, &f.state)
        .into_iter()
        .find(|q| q.query_id.ends_with("jwt-time-validity"))
        .unwrap();
    let ev = evidence::query(root, &f.state, &query.query_id).unwrap();
    let discovery = &ev.facts["signing_key_discovery"];
    assert_eq!(discovery["environment"]["variables"], json!(["PORT"]));
    assert_eq!(
        discovery["startup_mounts"]["mounts"],
        json!([
            {"path":"/app/.env","writable":false},
            {"path":"/var/app","writable":true}
        ])
    );
    let serialized = serde_json::to_string(&ev).unwrap();
    for secret in [
        "test-signing-key",
        "do-not-expose",
        "test-user",
        "UNRELATED_TOKEN",
    ] {
        assert!(!serialized.contains(secret));
    }
    let mut opts = options();
    opts.key_source = Some(SigningKeySource::TargetFile {
        path: discovery["startup_mounts"]["mounts"][0]["path"]
            .as_str()
            .unwrap()
            .into(),
        field: "SECRET_KEY".into(),
    });
    plan(
        root,
        &mut f.state,
        ev.evidence_id,
        Some("auth.rs loads SECRET_KEY from /app/.env with 60s leeway".into()),
        opts,
    )
    .unwrap();
    let record = f.state.rule_plan.clone().unwrap();
    apply(root, &mut f.state, record).unwrap();
    assert_eq!(
        keys::resolve_binding(root, "session-jwt").unwrap(),
        b"test-signing-key"
    );
    let discovery = discovery::query(root);
    assert_eq!(
        discovery["existing_bindings"]["references"][0],
        json!({"signing_key_ref":"session-jwt", "source":{
            "kind":"target_file", "path":"/app/.env", "field":"SECRET_KEY"
        }})
    );
    assert!(
        keys::resolve_source(
            root,
            &SigningKeySource::TargetFile {
                path: "/var/app/.env".into(),
                field: "SECRET_KEY".into()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("read-only")
    );
}

#[test]
fn jwt_discovery_keeps_evidence_and_environment_when_mount_snapshot_is_unavailable() {
    let f = fixture();
    let report = evidence_facts(f.target.path(), &f.state).unwrap();
    assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
    let discovery = &report["signing_key_discovery"];
    assert_eq!(discovery["environment"]["variables"], json!(["SECRET_KEY"]));
    assert_eq!(discovery["startup_mounts"]["status"], "unavailable");
    for (field, kind) in [("environment", "env"), ("startup_mounts", "mount")] {
        assert_eq!(
            discovery[field]["inspect_command"],
            serde_json::to_value(action::command(
                f.target.path(),
                vec!["startup".into(), kind.into(), "list".into()],
                Vec::new()
            ))
            .unwrap()
        );
    }
    assert!(!report.to_string().contains("test-signing-key"));
}
