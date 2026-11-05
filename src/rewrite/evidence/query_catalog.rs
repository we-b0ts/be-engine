//! Issue-scoped diagnostic query availability and purpose.
use super::*;

pub(super) fn query_kinds(
    state: &RewriteState,
    issue: &RewriteIssue,
) -> Vec<(&'static str, &'static str)> {
    let mut queries = Vec::new();
    let typed_body_candidate = issue
        .representative
        .as_ref()
        .is_some_and(|representative| representative.body_diagnosis.is_some());
    if matches!(
        issue.kind,
        RewriteIssueKind::TargetRuntime | RewriteIssueKind::Replay
    ) {
        queries.push((
            QUERY_TARGET_RUNTIME_DIAGNOSTICS,
            "Inspect bounded target stdout, stderr, and container state from the failed attempt",
        ));
    }
    let response_unavailable = issue.representative.as_ref().is_some_and(|representative| {
        representative.difference_kind == ResponseDifferenceKind::ResponseUnavailable
    });
    let standard_header_difference = issue
        .representative
        .as_ref()
        .is_some_and(|representative| representative.pointer.starts_with("$headers/"));
    let dependency_evidence_first = matches!(
        issue.kind,
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    );
    if dependency_evidence_first {
        queries.push((
            QUERY_DIRTY_CLUSTERS,
            "Cluster case-scoped dirty dependencies by protocol, endpoint, and reason",
        ));
        queries.push((
            QUERY_SOURCE_PROCESS_TRAFFIC,
            source_process_evidence_purpose(issue.kind),
        ));
    }
    if matches!(
        issue.kind,
        RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) && issue.representative.is_some()
    {
        queries.push((
            QUERY_CASE_RESPONSE_DIFFERENCES,
            "Inspect all response differences in the representative case before implementation",
        ));
    }
    queries.push((
        QUERY_REPRESENTATIVES,
        "Show the bounded representative with explicit value presence",
    ));
    if !dependency_evidence_first && source_process_evidence_relevant(issue) {
        queries.push((
            QUERY_SOURCE_PROCESS_TRAFFIC,
            source_process_evidence_purpose(issue.kind),
        ));
    }
    if issue.representative.is_some() {
        if !response_unavailable && !typed_body_candidate && !standard_header_difference {
            queries.extend([
                (
                    QUERY_SOURCE_VARIATION,
                    "Measure the representative source value across recorded cases",
                ),
                (
                    QUERY_COLLECTION_EQUIVALENCE,
                    "Check whether representative arrays are equal as multisets",
                ),
            ]);
        }
        queries.push((
            QUERY_DEPENDENCY_CORRELATION,
            "Correlate response outcomes with dependency cleanliness",
        ));
        if !response_unavailable && !typed_body_candidate && !standard_header_difference {
            queries.push((
                QUERY_POLICY_APPLICABILITY,
                "Check structural rule applicability without authorizing a rule",
            ));
        }
    }
    if issue.kind == RewriteIssueKind::Response {
        queries.push((QUERY_JWT_TIME_VALIDITY, "Check failed 401 requests for JWT expiration between recording and replay; plan verifies signatures"));
        queries.push((
            QUERY_DIRTY_CLUSTERS,
            "Cluster case-scoped dirty dependencies by protocol, endpoint, and reason",
        ));
    }
    if issue.recorder_capture_diagnosis.is_some() {
        queries.push((QUERY_IP_CAPTURE, "Inspect reported IP origin and recorder response rewrite eligibility before system repair"));
    }
    if state.attempt_delta.is_some() {
        queries.push((
            QUERY_ATTEMPT_DELTA,
            "Compare response convergence with the previous attempt",
        ));
    }
    if matches!(
        issue.kind,
        RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) {
        queries.push((QUERY_API_INFORMATION, "Inspect full dependency ownership, unused occurrences, hypothesis attempts and verification obligations on demand"));
        queries.push((execution::KIND,"Page through every case interrupted by an unmatched dependency, including cases omitted from the overview"));
        if issue.kind != RewriteIssueKind::Replay {
            queries.push((QUERY_TARGET_RUNTIME_DIAGNOSTICS, "Inspect bounded target stdout, stderr, and container state alongside failed response or dependency evidence"));
        }
        queries.push((QUERY_HTTP_REQUESTS, "Inspect failed HTTP dependency requests, exact Source/Target body differences, and complete protected body pages"));
        queries.push((QUERY_UNIFIED_RULE_CANDIDATES,"Inspect physical field bindings and bounded strategy drafts; inventory Source-owned time, duration, unordered and identity locations together"));
    }
    queries
}

fn source_process_evidence_relevant(issue: &RewriteIssue) -> bool {
    match issue.kind {
        RewriteIssueKind::TargetQuality => false,
        RewriteIssueKind::TargetRuntime => issue
            .possible_causes
            .iter()
            .any(|cause| cause == "source_compatible_configuration"),
        _ => true,
    }
}

fn source_process_evidence_purpose(kind: RewriteIssueKind) -> &'static str {
    match kind {
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay => {
            "Inspect source bootstrap and configured process-owned traffic before classifying dirty dependencies as request-owned or process-owned"
        }
        RewriteIssueKind::Response => {
            "Use this evidence when startup, background refresh, or local-cache state may explain the response mismatch"
        }
        RewriteIssueKind::TargetRuntime => {
            "Use this evidence when target startup or readiness may depend on source bootstrap traffic"
        }
        RewriteIssueKind::TargetQuality => {
            "Read context.delivery.required_repairs and address the assigned code finding; no traffic diagnosis is required."
        }
    }
}
