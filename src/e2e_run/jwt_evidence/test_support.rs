use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
use crate::e2e_run::{config, model, store, support};
use std::path::{Path, PathBuf};

pub(crate) fn install_attempt(
    root: &Path,
    source: &Path,
    cases: &[(PathBuf, u16, u16)],
    replayed_at: DateTime<Utc>,
) -> crate::E2eResponseRuleEvidence {
    let (_, layout) = config::resolve_layout(root, source, None).unwrap();
    let latest = layout
        .run_root
        .join("focused")
        .join(support::api_directory("GET /api"))
        .join("latest");
    std::fs::create_dir_all(latest.join("reports")).unwrap();
    let inventory = CaseGroupInventory {
        case_source: source.to_path_buf(),
        source_revision: "source".into(),
        case_inventory_id: "inventory".into(),
        groups: vec![CanonicalCaseGroup {
            group_id: "GET /api".into(),
            method: "GET".into(),
            source_route: "/api".into(),
            pattern: Some("/api".into()),
            case_inventory_id: "inventory".into(),
            cases: cases
                .iter()
                .map(|(dir, _, _)| CanonicalCase {
                    case_id: dir.file_name().unwrap().to_str().unwrap().into(),
                    case_dir: dir.clone(),
                    recorded_at: None,
                })
                .collect(),
        }],
    };
    let mut state = model::ActiveRunState::new("recording".into(), 1, &inventory, &latest);
    state.apis.push(model::ApiExecution {
        api_key: "GET /api".into(),
        group_id: "GET /api".into(),
        method: "GET".into(),
        api_pattern: "/api".into(),
        case_ids: cases
            .iter()
            .map(|(p, _, _)| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect(),
        total: cases.len() as u32,
        passed: 0,
        failed: cases.len() as u32,
        incomplete: 0,
        complete_pass: false,
        report_dir: latest.join("reports"),
    });
    state.status = model::RunStatus::Failed;
    state.started_at = replayed_at;
    state.finished_at = Some(replayed_at);
    for (case, (dir, expected, actual)) in state.cases.iter_mut().zip(cases) {
        let actual_path = latest
            .join("reports")
            .join(format!("{}.json", case.case_id));
        let body = serde_json::json!({"encoding":"utf8","data":"{}","truncated":false});
        store::write_json(
            &actual_path,
            &serde_json::json!({"status":actual,"body":body,"request_sent_at":replayed_at}),
        )
        .unwrap();
        store::write_json(
            &dir.join("expected-response.json"),
            &serde_json::json!({"status":expected,"body":body}),
        )
        .unwrap();
        case.status = model::CaseStatus::Failed;
        case.response_assertion = Some(model::ResponseAssertionSummary {
            passed: false,
            method: "GET".into(),
            path: "/api".into(),
            gateway_protocol: crate::ResponseGatewayProtocol::Http,
            body_codec: crate::ResponseBodyCodec::Json,
            body_diagnosis: None,
            difference_count: 1,
            difference_index: Vec::new(),
            representative_difference: None,
            detail_report: latest.join("unused-detail.json"),
            detail_fingerprint: "detail".into(),
            request: dir.join("request.json"),
            expected_response: dir.join("expected-response.json"),
            actual_response: actual_path,
            policy_path: root
                .join(".traffic-e2e/verification.yaml")
                .display()
                .to_string(),
            policy_fingerprint: "policy".into(),
        });
    }
    store::write_yaml(&latest.join("state.yaml"), &state).unwrap();
    crate::E2eResponseRuleEvidence {
        replay: state.replay_report,
        assertions: state.assertions_report,
        aggregate: state.aggregate_report,
    }
}
