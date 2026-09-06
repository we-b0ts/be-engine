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
            "Replay evidence is incomplete".to_string(),
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
        comparison_observation: None,
    }
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
        Some(ResponseDifferenceKind::ArrayOrderMismatch) => &[
            "target_collection_ordering",
            "map_or_set_iteration_order",
            "intentional_source_nondeterminism",
            "unordered_policy_candidate_only_if_contents_are_equal",
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
        RewriteIssueKind::Response => "response",
        RewriteIssueKind::TargetRuntime => "target_runtime",
        RewriteIssueKind::Replay => "replay",
        RewriteIssueKind::Dependency => "dependency",
        RewriteIssueKind::Comparison => "comparison",
        RewriteIssueKind::ProcessOutput => "process_output",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
