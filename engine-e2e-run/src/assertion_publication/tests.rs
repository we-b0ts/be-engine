//! Published JWT differences remain readable after the active directory is gone.
use super::*;
use crate::case_group::CaseGroupInventory;
use crate::model::{AssertionCase, CaseExecution, CaseStatus, RunStatus};
use crate::{E2eRunContext, E2eRunInitOptions, resolve_e2e_response_rule_evidence, run_config};
use serde_json::json;
use traffic_engine_verification::policy::runtime::{
    ResponseBodyRuleEvidence, ResponseJwtRuleFeedback, plan_response_jwt_rule,
};
use traffic_engine_verification::primary_protocol::assertion::{
    ResponseAssertionOptions, assert_recorded_response,
};

#[test]
fn published_jwt_evidence_survives_first_publish_replacement_and_retired_authoring() {
    for replacement in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        install_project(root);
        let context = E2eRunContext {
            target_root: root.into(),
            case_source: root.into(),
            run_key: None,
        };
        let (_, layout) = run_config::resolve_layout(root, root, None).unwrap();
        let active = layout.active_dir;
        let latest = layout.latest_dir;
        fs::create_dir_all(active.join("reports")).unwrap();
        fs::create_dir_all(active.join("tmp")).unwrap();
        fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
        fs::write(
            root.join(".traffic-e2e/local/target.env"),
            "SECRET_KEY=publication-test-key\n",
        )
        .unwrap();
        if replacement {
            fs::create_dir_all(latest.join("reports")).unwrap();
            fs::write(
                latest.join("reports/assertion-detail-old.json"),
                "old evidence",
            )
            .unwrap();
        }
        let policy = root.join(".traffic-e2e/policy.yaml");
        fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
        let token = |now| {
            jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &json!({"sub":"user","iat":now,"exp":now+1800}),
                &jsonwebtoken::EncodingKey::from_secret(b"publication-test-key"),
            )
            .unwrap()
        };
        let source_time = 1_700_000_000_i64;
        let target_time = source_time + 86400;
        let request = root.join("request.json");
        let expected = root.join("expected.json");
        let actual = active.join("tmp/actual.json");
        store::write_json(&request,&json!({"method":"POST","uri":"/token","timestamp":chrono::DateTime::from_timestamp(source_time,0).unwrap()})).unwrap();
        let response = |now| json!({"version":1,"status":200,"headers":{},"request_sent_at":chrono::DateTime::from_timestamp(now,0).unwrap(),"body":{"encoding":"utf8","data":json!({"access_token":token(now)}).to_string(),"truncated":false}});
        store::write_json(&expected, &response(source_time)).unwrap();
        store::write_json(&actual, &response(target_time)).unwrap();
        let detail = assert_recorded_response(ResponseAssertionOptions {
            case_id: "case".into(),
            request: request.clone(),
            expected_response: expected.clone(),
            actual_response: actual.clone(),
            policy: policy.clone(),
        })
        .unwrap();
        let detail_path = active.join("reports/assertion-detail-1.json");
        store::write_json(&detail_path, &detail).unwrap();
        let summary = ResponseAssertionSummary {
            passed: detail.passed,
            method: detail.method.clone(),
            path: detail.path.clone(),
            gateway_protocol: detail.gateway_protocol,
            body_codec: detail.body_codec,
            body_diagnosis: detail.body_diagnosis.clone(),
            difference_count: detail.differences.len(),
            difference_index: detail.differences.clone(),
            representative_difference: detail.differences.first().cloned(),
            detail_report: detail_path.clone(),
            detail_fingerprint: crate::verification_progress::fingerprint(
                &fs::read(&detail_path).unwrap(),
            ),
            request,
            expected_response: expected,
            actual_response: actual,
            policy_path: detail.policy_path.clone(),
            policy_fingerprint: detail.policy_fingerprint.clone(),
        };
        let mut state = ActiveRunState::new(
            "run".into(),
            1,
            &CaseGroupInventory {
                case_source: root.into(),
                source_revision: "source".into(),
                case_inventory_id: "inventory".into(),
                groups: vec![],
            },
            &active,
        );
        state.status = RunStatus::Failed;
        state.apis.push(crate::model::ApiExecution {
            api_key: "POST /token".into(),
            group_id: "POST /token".into(),
            method: "POST".into(),
            api_pattern: "/token".into(),
            case_ids: vec!["case".into()],
            total: 1,
            passed: 0,
            failed: 1,
            incomplete: 0,
            complete_pass: false,
            report_dir: active.join("reports"),
        });
        state.cases.push(CaseExecution {
            case_id: "case".into(),
            case_dir: root.into(),
            group_id: "POST /token".into(),
            status: CaseStatus::Failed,
            assertion_passed: Some(false),
            replay_clean: Some(true),
            response_assertion: Some(summary.clone()),
            response_unavailable_reason: None,
            execution_failure: None,
        });
        let mut assertions = AssertionReport::new(&state, true);
        assertions.cases.push(AssertionCase {
            case_id: "case".into(),
            passed: false,
            response: Some(summary),
        });
        store::write_json(&state.assertions_report, &assertions).unwrap();
        store::write_json(
            &state.aggregate_report,
            &json!({"case_source":root,"complete":true,"dirty":false,"selected_case_ids":["case"]}),
        )
        .unwrap();
        store::publish_snapshot(&active, &latest, &state).unwrap();
        assert!(!active.exists());
        let published: ActiveRunState = store::read_yaml(&latest.join("state.yaml")).unwrap();
        assert!(!published.replay_report.exists());
        let evidence = resolve_e2e_response_rule_evidence(context.clone(), "POST /token").unwrap();
        assert_eq!(evidence.replay, published.replay_report);
        assert!(
            crate::query_rule_policy_freshness(
                context.clone(),
                "POST /token",
                &detail.policy_fingerprint,
            )
            .ensure_current("dependency request evidence")
            .is_err()
        );
        for (path, message) in [
            (
                &evidence.assertions,
                "runner-owned assertion evidence is missing",
            ),
            (
                &evidence.aggregate,
                "runner-owned aggregate evidence is missing",
            ),
        ] {
            let moved = path.with_extension("missing");
            fs::rename(path, &moved).unwrap();
            let error =
                resolve_e2e_response_rule_evidence(context.clone(), "POST /token").unwrap_err();
            assert!(error.to_string().contains(message));
            fs::rename(moved, path).unwrap();
        }
        let unchanged = [
            fs::read(&policy).unwrap(),
            fs::read(&evidence.assertions).unwrap(),
            fs::read(&evidence.aggregate).unwrap(),
        ];
        let error = plan_response_jwt_rule(ResponseJwtRuleFeedback {
            policy_path:policy.clone(),api:"POST /token".into(),
            rules:vec![serde_json::from_value(json!({"pointer":"/access_token","algorithm":"HS256","signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"source_evidence":"Issuer:issue signs current identity claims and a 30-minute expiry"})).unwrap()],
            evidence:ResponseBodyRuleEvidence::FocusedE2e { assertion_report:evidence.assertions.clone(),aggregate_report:evidence.aggregate.clone() },
        }).err().expect("retired authoring must not mutate a published run");
        assert!(
            error
                .to_string()
                .contains("legacy rule authoring is retired")
        );
        assert_eq!(fs::read(&policy).unwrap(), unchanged[0]);
        assert_eq!(fs::read(&evidence.assertions).unwrap(), unchanged[1]);
        assert_eq!(fs::read(&evidence.aggregate).unwrap(), unchanged[2]);
    }
}

fn install_project(root: &std::path::Path) {
    let commands: &[&[&str]] = &[
        &["init", "-q", "-b", "master"],
        &[
            "-c",
            "user.name=E2E Test",
            "-c",
            "user.email=e2e-test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    ];
    for args in commands {
        assert!(
            std::process::Command::new("git")
                .current_dir(root)
                .args(*args)
                .status()
                .unwrap()
                .success()
        );
    }
    let directory = root.join(".traffic-e2e");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("Dockerfile.target"), "FROM scratch\n").unwrap();
    fs::write(
        directory.join("policy.yaml"),
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    let options = E2eRunInitOptions {
        target_root: root.into(),
        target_dockerfile: ".traffic-e2e/Dockerfile.target".into(),
        target_startup: Default::default(),
        replay_policy: ".traffic-e2e/policy.yaml".into(),
        pr_base: "master".into(),
        recorder_config: ".traffic-e2e/project.yaml".into(),
        force: false,
    };
    let mut recorder = crate::config::AppConfig::default();
    recorder.http_gateway.ready.enabled = true;
    fs::write(
        directory.join("project.yaml"),
        run_config::render_project_config(&options, recorder).unwrap(),
    )
    .unwrap();
}
