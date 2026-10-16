use super::*;
use crate::request_rules::tests::request;
use crate::rewrite::model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase};
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
        root.join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v1\nrules: []\n",
    )
    .unwrap();
    fs::write(
        root.join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
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
        location: JwtTokenLocation::BearerHeader {
            header: "authorization".into(),
        },
        algorithm: JwtAlgorithm::HS256,
        signing_key_ref: "session-jwt".into(),
        key_source: Some(SigningKeySource::TargetEnv {
            name: "SECRET_KEY".into(),
        }),
        leeway_seconds: 60,
    }
}

fn install_input_fixture(root: &std::path::Path, location: Value, signing_key: Value) {
    let policy = json!({"format":"traffic-policy/v1","rules":[{
        "id":"session-jwt","match":{},"effect":{"kind":"input_jwt","location":location,
        "algorithm":"HS256","signing_key":signing_key,"time":"preserve_relative"},
        "proof":{"source":"fixture/auth.rs:1","fact":"Source verifies this signed JWT and its relative expiry"}}]});
    let document = crate::policy::parse_policy(&policy.to_string()).unwrap();
    crate::policy::compile_policy(&document).unwrap();
    fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn discovery_plan_apply_and_real_http_replay_use_the_original_recording() {
    let mut f = fixture();
    let original = fs::read(&f.request).unwrap();
    let root = f.target.path();
    let before = serde_json::to_value(&f.state).unwrap();
    let policy_before = fs::read(root.join(".traffic-e2e/policy.yaml")).unwrap();
    let error = plan(
        root,
        &mut f.state,
        "old-evidence".into(),
        Some("Source verifies JWT".into()),
        options(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("retired"));
    assert_eq!(serde_json::to_value(&f.state).unwrap(), before);
    assert_eq!(
        fs::read(root.join(".traffic-e2e/policy.yaml")).unwrap(),
        policy_before
    );
    install_input_fixture(
        root,
        json!({"kind":"bearer_header","name":"authorization"}),
        json!({"kind":"target_env","name":"SECRET_KEY"}),
    );
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
            &f.target.path().join(".traffic-e2e/policy.yaml"),
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
        policy: f.target.path().join(".traffic-e2e/policy.yaml"),
    })
    .unwrap();
    assert!(assertion.passed);
    assert_eq!(fs::read(&f.request).unwrap(), original);
    server.await.unwrap();
}

#[test]
fn retired_jwt_planning_preserves_all_recorded_inputs_and_workflow() {
    for location in [
        JwtTokenLocation::BearerHeader {
            header: "authorization".into(),
        },
        JwtTokenLocation::RawHeader {
            raw_header: "x-token".into(),
        },
        JwtTokenLocation::QueryParameter {
            query_param: "token".into(),
        },
    ] {
        let mut f = fixture();
        let policy = f.target.path().join(".traffic-e2e/policy.yaml");
        let before_policy = fs::read(&policy).unwrap();
        let before_request = fs::read(&f.request).unwrap();
        let before = serde_json::to_value(&f.state).unwrap();
        let mut opts = options();
        opts.location = location;
        let error = plan(
            f.target.path(),
            &mut f.state,
            "old-evidence".into(),
            Some("Source JWT validation".into()),
            opts,
        )
        .unwrap_err();
        assert!(error.to_string().contains("retired"));
        assert_eq!(serde_json::to_value(&f.state).unwrap(), before);
        assert_eq!(fs::read(&policy).unwrap(), before_policy);
        assert_eq!(fs::read(&f.request).unwrap(), before_request);
        assert!(
            !f.target
                .path()
                .join(".traffic-e2e/local/secrets/jwt-signing-keys.json")
                .exists()
        );
    }
}

#[test]
fn source_authentication_failures_do_not_offer_input_time_adaptation() {
    let f = fixture();
    fs::write(
        f.request.parent().unwrap().join("expected-response.json"),
        r#"{"status":401}"#,
    )
    .unwrap();
    assert!(
        facts(f.target.path(), &f.state)
            .unwrap()
            .candidates
            .is_empty()
    );
}

#[test]
fn query_parameter_evidence_guides_and_plans_the_matching_location() {
    let f = fixture();
    let recorded = 1_700_000_000;
    let raw = crate::request_rules::tests::token(
        json!({"sub":"test-user","exp":recorded+3600}),
        "test-signing-key",
    );
    let mut request = crate::request_rules::tests::request(
        json!({"sub":"unused","exp":recorded+3600}),
        "test-signing-key",
        recorded,
    );
    request["headers"] = json!({});
    request["uri"] = json!(format!("/api?message_ids=1%2C2&download_token={raw}"));
    fs::write(&f.request, serde_json::to_vec(&request).unwrap()).unwrap();

    let query = evidence::commands(f.target.path(), &f.state)
        .into_iter()
        .find(|query| query.query_id.ends_with("jwt-time-validity"))
        .unwrap();
    let report = evidence::query(f.target.path(), &f.state, &query.query_id).unwrap();
    assert_eq!(
        report.facts["candidates"][0]["query_param"],
        "download_token"
    );
    let planner = &report.applicable_rule_planners[0];
    assert!(
        planner
            .command
            .argv
            .windows(2)
            .any(|pair| pair == ["rule", "plan"])
    );
    assert!(planner.command.argv.iter().any(|arg| arg == "--file"));
    assert!(
        !planner
            .command
            .argv
            .iter()
            .any(|arg| arg == "--query-param")
    );
}

#[test]
fn raw_header_expiry_is_plannable_for_html_and_earlier_dependency_failures() {
    for actual_status in [200, 503] {
        let f = fixture();
        let recorded = 1_700_000_000;
        let mut request = crate::request_rules::tests::request(
            json!({"sub":"test-user","exp":recorded+300}),
            "test-signing-key",
            recorded,
        );
        let raw = crate::request_rules::tests::token(
            json!({"sub":"test-user","exp":recorded+300}),
            "test-signing-key",
        );
        request["headers"] = json!({"x-download-token":[raw],"x-unrelated":["one","two"]});
        fs::write(&f.request, serde_json::to_vec(&request).unwrap()).unwrap();
        let case = f.request.parent().unwrap();
        crate::e2e_run::jwt_evidence::test_support::install_attempt(
            f.target.path(),
            case.parent().unwrap(),
            &[(case.to_path_buf(), 200, actual_status)],
            DateTime::from_timestamp(recorded + 7200, 0).unwrap(),
        );
        let query = evidence::commands(f.target.path(), &f.state)
            .into_iter()
            .find(|query| query.query_id.ends_with("jwt-time-validity"))
            .unwrap();
        let report = evidence::query(f.target.path(), &f.state, &query.query_id).unwrap();
        assert_eq!(
            report.facts["candidates"][0]["raw_header"],
            "x-download-token"
        );
        let planner = &report.applicable_rule_planners[0];
        assert!(
            planner
                .command
                .argv
                .windows(2)
                .any(|args| args == ["rule", "plan"])
        );
        assert!(planner.command.argv.iter().any(|arg| arg == "--file"));
        assert!(
            !planner
                .command
                .argv
                .iter()
                .any(|arg| arg == "--header-scheme")
        );
    }
}

#[test]
fn jwt_evidence_discovers_mounts_and_configured_file_source_without_exposing_values() {
    let f = fixture();
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
    install_input_fixture(
        root,
        json!({"kind":"bearer_header","name":"authorization"}),
        json!({"kind":"target_file","path":"/app/.env","field":"SECRET_KEY"}),
    );
    assert!(
        !root
            .join(".traffic-e2e/local/secrets/jwt-signing-keys.json")
            .exists()
    );
    let discovery = discovery::query(root);
    let profile = &discovery["configured_profiles"]["profiles"][0];
    assert_eq!(profile["profile"], profile["signing_key_ref"]);
    assert_eq!(
        profile["signing_key_source"],
        json!({"kind":"target_file","path":"/app/.env","field":"SECRET_KEY"})
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

#[test]
fn jwt_candidate_discovery_accepts_failed_responses_and_rejects_missing_recorded_status() {
    for (actual, expected, count) in [
        (401, Some(json!(200)), 1),
        (403, Some(json!(200)), 1),
        (401, Some(json!(403)), 0),
        (403, Some(json!(401)), 0),
        (403, Some(json!(403)), 0),
        (403, None, 0),
        (403, Some(json!("200")), 0),
        (200, Some(json!(200)), 1),
        (503, Some(json!(200)), 1),
    ] {
        let f = fixture();
        let case = f.request.parent().unwrap().to_path_buf();
        crate::e2e_run::jwt_evidence::test_support::install_attempt(
            f.target.path(),
            f.state.case_source.as_deref().unwrap(),
            &[(case.clone(), 200, actual)],
            DateTime::from_timestamp(1_700_007_200, 0).unwrap(),
        );
        let expected = expected.map_or_else(|| json!({}), |status| json!({"status":status}));
        fs::write(case.join("expected-response.json"), expected.to_string()).unwrap();
        let evidence = facts(f.target.path(), &f.state).unwrap();
        assert_eq!(evidence.candidates.len(), count);
        assert!(!evidence.signature_verified);
        if let Some(candidate) = evidence.candidates.first() {
            assert_eq!(candidate.source_status, 200);
            assert_eq!(candidate.target_status, u64::from(actual));
        }
    }
}

#[test]
fn both_auth_statuses_require_expiration_and_a_verified_signature_before_planning() {
    for status in [401, 403] {
        for scenario in ["expired", "unexpired", "invalid_signature"] {
            let mut f = fixture();
            let recorded = 1_700_000_000;
            let expiry = recorded
                + if scenario == "unexpired" {
                    10_000
                } else {
                    3_600
                };
            let key = if scenario == "invalid_signature" {
                "untrusted-key"
            } else {
                "test-signing-key"
            };
            fs::write(
                &f.request,
                serde_json::to_vec(&request(
                    json!({"sub":"test-user","exp":expiry}),
                    key,
                    recorded,
                ))
                .unwrap(),
            )
            .unwrap();
            crate::e2e_run::jwt_evidence::test_support::install_attempt(
                f.target.path(),
                f.state.case_source.as_deref().unwrap(),
                &[(f.request.parent().unwrap().into(), 200, status)],
                DateTime::from_timestamp(recorded + 7_200, 0).unwrap(),
            );
            let query = evidence::commands(f.target.path(), &f.state)
                .into_iter()
                .find(|query| query.query_id.ends_with("jwt-time-validity"))
                .unwrap();
            let evidence = evidence::query(f.target.path(), &f.state, &query.query_id).unwrap();
            assert_eq!(evidence.facts["signature_verified"], false);
            assert_eq!(
                evidence.facts["candidates"].as_array().unwrap().len(),
                usize::from(scenario != "unexpired")
            );
            let policy_path = f.target.path().join(".traffic-e2e/policy.yaml");
            let policy = fs::read(&policy_path).unwrap();
            let result = plan(
                f.target.path(),
                &mut f.state,
                evidence.evidence_id,
                Some("auth.rs verifies SECRET_KEY HS256 JWTs with 60s expiration leeway".into()),
                options(),
            );
            assert!(result.unwrap_err().to_string().contains("retired"));
            assert!(f.state.rule_plan.is_none());
            assert_eq!(fs::read(policy_path).unwrap(), policy);
        }
    }
}
