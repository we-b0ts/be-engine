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
            let pointer = representative.map(|value| value.pointer.as_str());
            (
                RewriteIssueKind::Response,
                RewriteIssueOwner::TargetCode,
                format!(
                    "{} of {} executed cases have response mismatches",
                    result.diagnosis.counts.response_nonpassing, result.diagnosis.counts.executed
                ),
                pointer,
                response_possible_causes(representative.map(|value| value.difference_kind)),
            )
        }
        _ if result.diagnosis.counts.executed == 0 => (
            RewriteIssueKind::TargetRuntime,
            RewriteIssueOwner::TargetRuntime,
            result.diagnosis.lifecycle_errors.first().map_or_else(
                || "target lifecycle failed before any response assertion completed".to_string(),
                |error| format!("target lifecycle failed before assertions: {error}"),
            ),
            None,
            vec![
                "target_startup_or_readiness".to_string(),
                "source_compatible_configuration".to_string(),
                "replay_interception_environment".to_string(),
            ],
        ),
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
                "process_scoped_background_dependency".to_string(),
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
        pointer_pattern: pointer.map(normalize_pointer),
        representative: result.diagnosis.representative.clone(),
        possible_causes,
        observed_target_fingerprint: target_fingerprint,
        attempt: result.attempt,
        comparison_observation: None,
    }
}

pub(super) fn response_possible_causes(kind: Option<ResponseDifferenceKind>) -> Vec<String> {
    let causes: &[&str] = match kind {
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
            ResponseDifferenceKind::DynamicFieldNotScalar
            | ResponseDifferenceKind::UnorderedFieldNotArray
            | ResponseDifferenceKind::UnorderedArrayContentMismatch
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

pub(super) fn normalize_pointer(pointer: &str) -> String {
    if !pointer.starts_with('/') {
        return pointer.to_string();
    }
    pointer
        .split('/')
        .map(|token| {
            if !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit()) {
                "*"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn id(api: &str, kind: &str, pointer: &str) -> String {
    format!(
        "issue-{}",
        fingerprint::id(&[api, kind, &normalize_pointer(pointer)]).trim_start_matches("fnv1a64:")
    )
}

fn kind_name(kind: RewriteIssueKind) -> &'static str {
    match kind {
        RewriteIssueKind::Response => "response",
        RewriteIssueKind::TargetRuntime => "target_runtime",
        RewriteIssueKind::Replay => "replay",
        RewriteIssueKind::Dependency => "dependency",
        RewriteIssueKind::Comparison => "comparison",
    }
}
