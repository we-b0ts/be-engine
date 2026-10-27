use crate::{
    E2eApiRunResult, E2eDependencyGate, E2eReplayGate, E2eResponseGate, ResponseDifferenceKind,
};

use super::fingerprint;
use super::model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner};

pub(super) fn from_e2e(
    api: &str,
    result: &E2eApiRunResult,
    target_fingerprint: String,
) -> RewriteIssue {
    let (kind, owner, summary, pointer, possible_causes) = match result.gates.responses {
        _ if result.gates.replay == E2eReplayGate::Incomplete
            && result.diagnosis.counts.executed > 0
            && result.diagnosis.replay_finalized != Some(true) => (
            RewriteIssueKind::Replay,
            RewriteIssueOwner::TrafficE2eSystem,
            format!(
                "Replay evidence is incomplete after {} of {} cases executed; inspect lifecycle and coverage diagnostics before planning from this incomplete attempt",
                result.diagnosis.counts.executed, result.diagnosis.counts.selected
            ),
            None,
            vec!["replay_lifecycle_or_control_failure".into(),"incomplete_replay_publication".into()],
        ),
        _ if !result.diagnosis.execution_failures.is_empty() => (
            RewriteIssueKind::Dependency,
            RewriteIssueOwner::SourceInvestigation,
            "Replay interrupted requests because dependencies did not match; inspect execution_failures before downstream response differences".to_string(),
            None,
            vec![
                "dependency_unmatched".to_string(),
                "request_owned_target_call_mismatch".to_string(),
                "source_proven_value_contract_missing".to_string(),
                "replay_capability_gap".to_string(),
            ],
        ),
        E2eResponseGate::Nonpassing => {
            let representative = result.diagnosis.representative.as_ref();
            let response_rule_candidate = representative.is_some_and(|value| {
                value.body_diagnosis.as_ref().is_some_and(|body| {
                    !body.codec_candidates.is_empty()
                        && (!body.unordered_path_candidates.is_empty()
                            || !body.unordered_joined_string_candidates.is_empty())
                })
            });
            let pointer = representative.map(|value| value.pointer.as_str());
            let differences = &result.diagnosis.response_differences;
            let observed_clusters = differences
                .failure_clusters
                .len()
                .saturating_add(differences.omitted_failure_clusters);
            let cluster_scope = if differences.omitted_differences == 0 {
                "clusters"
            } else {
                "observed clusters"
            };
            (
                RewriteIssueKind::Response,
                if response_rule_candidate {
                    RewriteIssueOwner::SourceInvestigation
                } else {
                    RewriteIssueOwner::TargetCode
                },
                format!(
                    "{} nonpassing cases among {} executed cases have {} response differences across {} {}",
                    result.diagnosis.counts.response_nonpassing,
                    result.diagnosis.counts.executed,
                    differences.total_differences,
                    observed_clusters,
                    cluster_scope,
                ),
                pointer,
                if response_rule_candidate {
                    vec![
                        "structured_response_body_order_candidate".to_string(),
                        "source_contract_must_prove_order_is_irrelevant".to_string(),
                    ]
                } else {
                    response_possible_causes(representative.map(|value| value.difference_kind))
                },
            )
        }
        _ if result
            .diagnosis
            .lifecycle_errors
            .iter()
            .any(|error| is_replay_startup_failure(error)) =>
        {
            (
                RewriteIssueKind::Replay,
                RewriteIssueOwner::TrafficE2eSystem,
                result
                    .diagnosis
                    .lifecycle_errors
                    .iter()
                    .find(|error| is_replay_startup_failure(error))
                    .unwrap()
                    .clone(),
                None,
                vec!["replay_startup_or_evidence_loading".into()],
            )
        }
        _ if result.diagnosis.counts.executed == 0 => {
            let lifecycle_error = result
                .diagnosis
                .lifecycle_errors
                .first()
                .map(String::as_str);
            (
                RewriteIssueKind::TargetRuntime,
                RewriteIssueOwner::TargetRuntime,
                lifecycle_error.map_or_else(
                    || {
                        "target lifecycle failed before any response assertion completed"
                            .to_string()
                    },
                    |error| format!("target lifecycle failed before assertions: {error}"),
                ),
                None,
                target_runtime_possible_causes(lifecycle_error),
            )
        }
        _ if result.gates.replay == E2eReplayGate::Incomplete => (
            RewriteIssueKind::Replay,
            RewriteIssueOwner::TrafficE2eSystem,
            if result.diagnosis.replay_finalized == Some(true) {
                format!(
                    "Replay finalized, but evidence is incomplete after {} of {} selected cases executed",
                    result.diagnosis.counts.executed, result.diagnosis.counts.selected
                )
            } else {
                "Replay evidence is incomplete".to_string()
            },
            None,
            vec!["replay_lifecycle_or_capability_gap".to_string()],
        ),
        _ if result.gates.dependencies == E2eDependencyGate::Dirty => (
            RewriteIssueKind::Dependency,
            RewriteIssueOwner::SourceInvestigation,
            "responses pass but dependency evidence is dirty".to_string(),
            None,
            vec![
                "request_owned_target_call_mismatch".to_string(),
                "process_owned_dependency".to_string(),
                "replay_capability_gap".to_string(),
            ],
        ),
        _ => (
            RewriteIssueKind::TargetRuntime,
            RewriteIssueOwner::TargetRuntime,
            format!("E2E attempt ended with status {}", result.status),
            None,
            vec!["target_or_runner_lifecycle".to_string()],
        ),
    };
    RewriteIssue {
        id: id(api, kind_name(kind), pointer.unwrap_or("<none>")),
        kind,
        owner,
        summary,
        pointer_pattern: pointer.map(crate::e2e_run::response_pointer_pattern),
        representative: result.diagnosis.representative.clone(),
        egress_rejections: result.diagnosis.egress_rejections.clone(),
        recorder_capture_diagnosis: None,
        response_diagnosis: (kind == RewriteIssueKind::Response)
            .then(|| result.diagnosis.response_differences.clone()),
        possible_causes,
        observed_target_fingerprint: target_fingerprint,
        attempt: result.attempt,
    }
}

fn is_replay_startup_failure(error: &str) -> bool {
    error.starts_with("Replay startup failed")
        || error.starts_with("Replay dependency index preparation failed")
        || error.starts_with("replay process exited before becoming ready")
        || error.starts_with("replay server did not become ready")
}

pub(super) fn response_possible_causes(kind: Option<ResponseDifferenceKind>) -> Vec<String> {
    let causes: &[&str] = match kind {
        Some(ResponseDifferenceKind::ResponseUnavailable) => &[
            "target_request_handler_failure",
            "target_response_stream_failure",
            "dependency_failure_before_response",
            "target_request_timeout_or_connection_close",
            "response_assertion_evaluation_or_evidence_failure",
        ],
        Some(ResponseDifferenceKind::StatusMismatch) => &[
            "request_authentication_or_precondition",
            "target_status_or_error_mapping",
            "source_compatible_boot_or_request_context",
            "dependency_or_runtime_branch_result",
        ],
        Some(
            ResponseDifferenceKind::HeaderMissingActual
            | ResponseDifferenceKind::HeaderUnexpectedActual
            | ResponseDifferenceKind::HeaderValueMismatch,
        ) => &[
            "target_response_header_behavior",
            "target_framework_or_middleware_configuration",
            "source_compatible_cors_or_cache_policy",
            "gateway_or_application_header_ownership",
        ],
        Some(ResponseDifferenceKind::ArrayOrderMismatch) => &[
            "target_collection_ordering",
            "map_or_set_iteration_order",
            "intentional_source_nondeterminism",
            "unordered_policy_candidate_only_if_contents_are_equal",
        ],
        Some(ResponseDifferenceKind::TimeReferenceMissing) => &[
            "missing_recorded_request_start_time",
            "missing_target_request_start_time",
            "recording_or_replay_time_capture",
        ],
        Some(
            ResponseDifferenceKind::TimeFieldInvalid
            | ResponseDifferenceKind::TimestampOutsideRequestWindow
            | ResponseDifferenceKind::DurationDeltaMismatch,
        ) => &[
            "time_rule_unit_or_format",
            "request_relative_time_generation",
            "source_or_target_clock",
        ],
        Some(
            ResponseDifferenceKind::GeneratedFieldNotScalar
            | ResponseDifferenceKind::UnorderedFieldNotArray
            | ResponseDifferenceKind::UnorderedArrayContentMismatch
            | ResponseDifferenceKind::UnorderedJoinedStringFieldNotString
            | ResponseDifferenceKind::UnorderedJoinedStringContentMismatch
            | ResponseDifferenceKind::CounterFieldUnsupportedType,
        ) => &[
            "verification_rule_shape_or_scope",
            "target_response_structure",
            "source_value_mechanism",
        ],
        _ => &[
            "target_implementation_or_rendering",
            "response_affecting_local_cache_or_runtime_state",
            "dependency_call_topology_or_result",
            "intentional_source_nondeterminism",
        ],
    };
    causes.iter().map(|cause| (*cause).to_string()).collect()
}

fn target_runtime_possible_causes(error: Option<&str>) -> Vec<String> {
    let causes: &[&str] = if error.is_some_and(|error| {
        let error = error.to_ascii_lowercase();
        error.contains("target image build")
            || error.contains("target-build ssh")
            || error.contains("target dockerfile")
    }) {
        &[
            "target_build_ssh_identity",
            "target_dockerfile_build_contract",
            "target_cargo_or_image_build",
        ]
    } else {
        &[
            "target_startup_or_readiness",
            "source_compatible_configuration",
            "replay_interception_environment",
        ]
    };
    causes.iter().map(|cause| (*cause).to_string()).collect()
}

pub(super) fn id(api: &str, kind: &str, pointer: &str) -> String {
    format!(
        "issue-{}",
        fingerprint::id(&[
            api,
            kind,
            &crate::e2e_run::response_pointer_pattern(pointer)
        ])
        .trim_start_matches("fnv1a64:")
    )
}

fn kind_name(kind: RewriteIssueKind) -> &'static str {
    match kind {
        RewriteIssueKind::TargetQuality => "target_quality",
        RewriteIssueKind::Response => "response",
        RewriteIssueKind::TargetRuntime => "target_runtime",
        RewriteIssueKind::Replay => "replay",
        RewriteIssueKind::Dependency => "dependency",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_interruption_takes_priority_over_ordinary_and_stream_response_failures() {
        for pointer in ["$response", "$interaction/end/clean"] {
            let mut result: E2eApiRunResult = serde_json::from_value(serde_json::json!({
                "run_key":"run","api":"GET /api","attempt":1,"status":"failed","passed":false,"progress":"progress.yaml",
                "gates":{"responses":"nonpassing","replay":"complete","dependencies":"dirty"},
                "diagnosis":{"counts":{"selected":2,"executed":2,"response_passed":0,"response_nonpassing":2,"response_incomplete":0},
                    "execution_failures":[{"case_id":"interrupted","kind":"dependency_unmatched","request_completed":false,"failures":[{"protocol":"redis","target_event_index":1}]}],
                    "response_differences":{"total_differences":2,"indexed_differences":2,"omitted_differences":0,"failure_clusters":[],"omitted_failure_clusters":0},
                    "representative":{"case_id":"interrupted","pointer":pointer,"difference_kind":"value_mismatch","expected":{"presence":"present","value":true},"actual":{"presence":"present","value":false}}}
            })).unwrap();
            let issue = from_e2e("GET /api", &result, "target".into());
            assert_eq!(issue.kind, RewriteIssueKind::Dependency);
            assert_eq!(issue.owner, RewriteIssueOwner::SourceInvestigation);
            assert!(issue.pointer_pattern.is_none());
            assert!(issue.summary.contains("execution_failures"));
            assert_eq!(issue.representative, result.diagnosis.representative);
            result.gates.replay = E2eReplayGate::Incomplete;
            let interrupted = from_e2e("GET /api", &result, "target".into());
            assert_eq!(interrupted.kind, RewriteIssueKind::Replay);
            assert_eq!(interrupted.owner, RewriteIssueOwner::TrafficE2eSystem);
            assert_eq!(interrupted.representative, result.diagnosis.representative);
            result.gates.replay = E2eReplayGate::Complete;
            result.diagnosis.execution_failures.clear();
            assert_eq!(
                from_e2e("GET /api", &result, "target".into()).kind,
                RewriteIssueKind::Response,
                "dirty inventory alone must not override independent response failures"
            );
        }
    }

    #[test]
    fn failures_before_any_request_keep_the_actual_engine_or_target_owner() {
        for (error, expected) in [
            (
                "Replay startup failed: Redis subscription evidence missing",
                RewriteIssueOwner::TrafficE2eSystem,
            ),
            (
                "Replay dependency index preparation failed: changed evidence",
                RewriteIssueOwner::TrafficE2eSystem,
            ),
            (
                "target image build failed: compiler error",
                RewriteIssueOwner::TargetRuntime,
            ),
        ] {
            let result: E2eApiRunResult = serde_json::from_value(serde_json::json!({
                "run_key":"run","api":"GET /api","attempt":1,"status":"failed","passed":false,"progress":"progress.yaml",
                "gates":{"responses":"incomplete","replay":"incomplete","dependencies":"unknown"},
                "diagnosis":{"counts":{"selected":1,"executed":0,"response_passed":0,"response_nonpassing":0,"response_incomplete":1},
                    "response_differences":{"total_differences":0,"indexed_differences":0,"omitted_differences":0,"failure_clusters":[],"omitted_failure_clusters":0},
                    "lifecycle_errors":[error]}
            })).unwrap();
            let issue = from_e2e("GET /api", &result, "target".into());
            assert_eq!(issue.owner, expected);
        }
    }

    fn partial_run_result() -> E2eApiRunResult {
        serde_json::from_value(serde_json::json!({
            "run_key":"run","api":"POST /api/callback","attempt":1,"status":"failed","passed":false,"progress":"progress.yaml",
            "gates":{"responses":"nonpassing","replay":"incomplete","dependencies":"unknown"},
            "diagnosis":{
                "replay_finalized":true,
                "counts":{"selected":200,"executed":40,"response_passed":0,"response_nonpassing":40,"response_incomplete":160},
                "execution_failures":[{"case_id":"interrupted","kind":"dependency_unmatched","request_completed":false}],
                "response_differences":{"total_differences":0,"indexed_differences":0,"omitted_differences":0,"failure_clusters":[],"omitted_failure_clusters":0},
                "lifecycle_errors":["API \"POST /api/callback\" stopped after reaching the configured failure limit of 40 case(s)"]
            }
        })).unwrap()
    }

    #[test]
    fn finalized_failure_limited_replay_keeps_the_dependency_cause() {
        let result = partial_run_result();
        let issue = from_e2e("POST /api/callback", &result, "target".into());
        assert_eq!(issue.kind, RewriteIssueKind::Dependency);
        assert_eq!(issue.owner, RewriteIssueOwner::SourceInvestigation);
        assert!(issue.summary.contains("dependencies did not match"));
        assert!(
            !issue
                .possible_causes
                .iter()
                .any(|cause| cause.contains("lifecycle"))
        );
        assert_eq!(result.gates.replay, E2eReplayGate::Incomplete);
        assert!(!result.passed);
    }

    #[test]
    fn unfinalized_and_legacy_partial_replay_keep_the_system_owner() {
        for finalized in [Some(false), None] {
            let mut result = partial_run_result();
            result.diagnosis.replay_finalized = finalized;
            let issue = from_e2e("POST /api/callback", &result, "target".into());
            assert_eq!(issue.kind, RewriteIssueKind::Replay);
            assert_eq!(issue.owner, RewriteIssueOwner::TrafficE2eSystem);
            assert!(issue.summary.contains("40 of 200"));
        }
    }

    #[test]
    fn finalized_partial_coverage_does_not_claim_finalization_failed() {
        let mut result = partial_run_result();
        result.diagnosis.execution_failures.clear();
        result.gates.responses = E2eResponseGate::Incomplete;
        let issue = from_e2e("POST /api/callback", &result, "target".into());
        assert_eq!(issue.kind, RewriteIssueKind::Replay);
        assert!(issue.summary.contains("Replay finalized"));
        assert!(issue.summary.contains("40 of 200"));
        assert!(!issue.summary.contains("did not finalize"));

        result.gates.responses = E2eResponseGate::Nonpassing;
        assert_eq!(
            from_e2e("POST /api/callback", &result, "target".into()).kind,
            RewriteIssueKind::Response
        );
    }

    #[test]
    fn unavailable_response_causes_point_to_request_completion_failures() {
        let causes = response_possible_causes(Some(ResponseDifferenceKind::ResponseUnavailable));

        assert!(causes.iter().any(|cause| cause.contains("request_handler")));
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains("connection_close"))
        );
        assert!(!causes.iter().any(|cause| cause.contains("nondeterminism")));
    }

    #[test]
    fn target_build_failure_causes_point_to_ssh_contract_and_cargo() {
        let causes = target_runtime_possible_causes(Some(
            "target image build failed: managed target-build SSH agent has no identity",
        ));

        assert!(
            causes
                .iter()
                .any(|cause| cause == "target_build_ssh_identity")
        );
        assert!(
            causes
                .iter()
                .any(|cause| cause == "target_dockerfile_build_contract")
        );
        assert!(!causes.iter().any(|cause| cause.contains("readiness")));
    }
}
