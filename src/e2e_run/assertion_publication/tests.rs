//! Exercise a published response-JWT planner after the active directory is gone.
use super::*;
use crate::case_group::CaseGroupInventory;
use crate::e2e_run::model::{AssertionCase, CaseExecution, CaseStatus, RunStatus};
use crate::{
    ResponseAssertionOptions, ResponseBodyRuleEvidence, ResponseJwtRuleFeedback,
    assert_recorded_response, plan_response_jwt_rule,
};
use serde_json::json;

#[test]
fn published_jwt_evidence_is_consumable_on_first_publish_and_replacement() {
    for replacement in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let active = root.join(".active");
        let latest = root.join("latest");
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
        let policy = root.join(".traffic-e2e/verification.yaml");
        fs::write(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
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
        state.cases.push(CaseExecution {
            case_id: "case".into(),
            case_dir: root.into(),
            group_id: "POST /token".into(),
            status: CaseStatus::Failed,
            assertion_passed: Some(false),
            replay_clean: Some(true),
            response_assertion: Some(summary.clone()),
            response_unavailable_reason: None,
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
        let plan = plan_response_jwt_rule(ResponseJwtRuleFeedback {
            policy_path:policy,api:"POST /token".into(),
            rules:vec![serde_json::from_value(json!({"pointer":"/access_token","algorithm":"HS256","signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"source_evidence":"Issuer:issue signs current identity claims and a 30-minute expiry"})).unwrap()],
            evidence:ResponseBodyRuleEvidence::FocusedE2e { assertion_report:published.assertions_report,aggregate_report:published.aggregate_report },
        }).unwrap();
        assert_eq!(plan.report().matching_cases, 1);
        plan.apply().unwrap();
    }
}
