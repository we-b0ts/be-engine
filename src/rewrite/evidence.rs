use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::evidence_model::RewriteEvidenceReport;
use super::model::{RewriteEvidenceCommand, RewriteIssue, RewriteIssueKind, RewriteState};
use super::process_output_model::RewriteWorkScope;
use super::{artifacts, fingerprint, source_process_traffic};
use crate::case_group::resolve_published_case_dir;
use crate::comparison_recording::resolve_comparison_case_dir;
use crate::e2e_run::response_pointer_scope;
use crate::{
    E2eDirtyCluster, E2eDirtyCounts, E2eRunContext, E2eValueObservation, E2eValuePresence,
    ResponseBodyCodec, ResponseDifferenceKind, query_e2e_case_response_differences,
    query_e2e_dependency_correlation, query_e2e_dirty_counts, query_e2e_source_variation,
    query_e2e_target_runtime_diagnostics,
};

mod access;
pub use access::{query_rewrite_evidence, query_rewrite_evidence_for_scope};
mod overview;
mod response_body;
mod rule_guidance;
pub(super) use rule_guidance::supports_response_body_codec;
use rule_guidance::{applicable_rule_planners, rule_hints};

const QUERY_JWT_TIME_VALIDITY: &str = "jwt_time_validity";
const QUERY_CASE_RESPONSE_DIFFERENCES: &str = "case_response_differences";
const QUERY_REPRESENTATIVES: &str = "representatives";
const QUERY_SOURCE_VARIATION: &str = "source_variation";
const QUERY_COLLECTION_EQUIVALENCE: &str = "collection_equivalence";
const QUERY_DEPENDENCY_CORRELATION: &str = "dependency_correlation";
const QUERY_SOURCE_PROCESS_TRAFFIC: &str = "source_process_traffic";
const QUERY_IP_CAPTURE: &str = "ip_capture";
const QUERY_DIRTY_CLUSTERS: &str = "dirty_clusters";
const QUERY_POLICY_APPLICABILITY: &str = "policy_applicability";
const QUERY_ATTEMPT_DELTA: &str = "attempt_delta";
const QUERY_TARGET_RUNTIME_DIAGNOSTICS: &str = "target_runtime_diagnostics";

pub(super) fn commands(target_root: &Path, state: &RewriteState) -> Vec<RewriteEvidenceCommand> {
    let Some(issue) = &state.active_issue else {
        return Vec::new();
    };
    query_kinds(state, issue)
        .into_iter()
        .map(|(kind, purpose)| {
            let query_id = query_identifier(state, issue, kind, 0);
            RewriteEvidenceCommand {
                purpose: purpose.to_string(),
                command: super::action::command(
                    target_root,
                    vec!["evidence".to_string(), query_id.clone()],
                    Vec::new(),
                ),
                query_id,
            }
        })
        .collect()
}

pub(super) fn accepts_query(state: &RewriteState, requested_id: &str) -> bool {
    state.active_issue.as_ref().is_some_and(|issue| {
        requested_id == overview::api_query_id(state, issue)
            || requested_query(state, issue, requested_id).is_some()
    })
}

fn requested_query(
    state: &RewriteState,
    issue: &RewriteIssue,
    requested_id: &str,
) -> Option<(&'static str, usize)> {
    query_kinds(state, issue)
        .into_iter()
        .find_map(|(kind, _)| {
            (query_identifier(state, issue, kind, 0) == requested_id).then_some((kind, 0))
        })
        .or_else(|| {
            case_response_difference_offset(state, issue, requested_id)
                .map(|offset| (QUERY_CASE_RESPONSE_DIFFERENCES, offset))
        })
}

pub(super) fn query(
    target_root: &Path,
    state: &RewriteState,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    let issue = state
        .active_issue
        .as_ref()
        .context("rewrite workflow has no active issue")?;
    if requested_id == overview::api_query_id(state, issue) {
        return overview::report(
            target_root,
            state,
            RewriteWorkScope::Api {
                api: state.api.clone(),
            },
            issue,
            requested_id,
        );
    }
    let requested = requested_query(state, issue, requested_id).with_context(|| {
        format!(
            "evidence query is stale or is not valid for active issue {}",
            issue.id
        )
    })?;
    let (kind, offset) = requested;
    let (facts, does_not_prove, next_step) = facts(target_root, state, issue, kind, offset)?;
    let evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[requested_id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    Ok(RewriteEvidenceReport {
        schema_version: 4,
        context: None,
        evidence_id: evidence_id.clone(),
        issue_id: issue.id.clone(),
        query: kind.to_string(),
        applicable_rule_planners: applicable_rule_planners(
            target_root,
            issue.kind,
            kind,
            &facts,
            &evidence_id,
        ),
        rule_hints: rule_hints(target_root, kind, &facts),
        facts,
        queries: Vec::new(),
        does_not_prove,
        next_step,
    })
}

fn has_redis_bootstrap_traffic(facts: &Value) -> bool {
    facts
        .pointer("/bootstrap/protocols")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|protocol| protocol.as_str() == Some("redis"))
}

fn source_process_next_step(kind: RewriteIssueKind) -> &'static str {
    match kind {
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay => {
            "Compare the dirty-cluster endpoints and operations with this evidence, then use source code to prove request or process ownership."
        }
        RewriteIssueKind::Response | RewriteIssueKind::Comparison => {
            "Use matching endpoints to prioritize source startup, refresh, and local-cache paths, then prove the response-driving path in source code."
        }
        RewriteIssueKind::TargetRuntime => {
            "Inspect source startup and readiness paths only for matching bootstrap dependencies."
        }
        RewriteIssueKind::ProcessOutput => {
            "Use the recorded process output manifests and inspect the target startup path."
        }
    }
}

fn facts(
    target_root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    kind: &str,
    offset: usize,
) -> Result<(Value, Vec<String>, String)> {
    match kind {
        QUERY_JWT_TIME_VALIDITY => Ok((super::jwt_rule::evidence_facts(target_root, state)?,
            vec!["Unverified JWT time claims and HTTP 401 do not alone prove authentication causality or rule applicability.".into()],
            "For time-drift candidates, inspect signing_key_discovery for target variable names, startup mount paths/access modes, existing bindings and discovery commands. Trace the source/target JWT path, configuration precedence and expiration leeway, then use the returned rule planner with the proven signing-key source. Plan/apply verifies original signatures.".into())),
        QUERY_IP_CAPTURE => Ok((super::response_url_evidence::facts(target_root, state)?,
            vec!["The IP omission is reported by target analysis; source consumption and absence of equivalent recorded calls require source/dependency evidence.".to_string()],
            "Prove the IP origin. For a supported JSON URL, execute the returned recorder-capture plan and apply, then verify a fresh recording before submitting a remaining system defect.".to_string())),
        QUERY_CASE_RESPONSE_DIFFERENCES => {
            case_response_difference_facts(target_root, state, issue, offset)
        }
        QUERY_REPRESENTATIVES => {
            let (pointer_scope, representative) =
                representative_facts(target_root, state, issue)?;
            let (does_not_prove, next_step) = representative_guidance(issue.kind);
            Ok((
                json!({
                    "pointer_scope": pointer_scope,
                    "representative": representative,
                    "comparison_observation": issue.comparison_observation,
                }),
                does_not_prove,
                next_step,
            ))
        }
        QUERY_SOURCE_VARIATION => {
            let representative = issue
                .representative
                .as_ref()
                .context("active issue has no replay representative")?;
            let variation = query_e2e_source_variation(
                e2e_context(target_root, state)?,
                group_id(state)?,
                &representative.pointer,
            )?;
            Ok((
                serde_json::to_value(variation)?,
                vec![
                    "source variation alone does not prove intentional nondeterminism".to_string(),
                    "it does not establish cache ownership or lifecycle".to_string(),
                ],
                "Use source code to prove the value mechanism before planning a rule."
                    .to_string(),
            ))
        }
        QUERY_COLLECTION_EQUIVALENCE => {
            let representative = issue
                .representative
                .as_ref()
                .context("active issue has no replay representative")?;
            let equivalent = collection_equivalence(
                &representative.expected,
                &representative.actual,
            );
            Ok((
                serde_json::to_value(equivalent)?,
                vec!["multiset equality does not prove that source order is semantically irrelevant".to_string()],
                "Inspect the source collection type and API ordering contract before planning an unordered rule."
                    .to_string(),
            ))
        }
        QUERY_DEPENDENCY_CORRELATION => {
            let correlation = query_e2e_dependency_correlation(
                e2e_context(target_root, state)?,
                group_id(state)?,
            )?;
            Ok((
                serde_json::to_value(correlation)?,
                vec!["correlation does not prove that a dependency difference drives the response".to_string()],
                "Trace the representative response field through source local state and dependency calls."
                    .to_string(),
            ))
        }
        QUERY_SOURCE_PROCESS_TRAFFIC => {
            let facts = serde_json::to_value(source_process_traffic::evidence_view(
                target_root,
                state,
            ))?;
            let available = facts.get("available").and_then(Value::as_bool) == Some(true);
            let next_step = if available {
                source_process_next_step(issue.kind)
            } else {
                "Continue with the other issue evidence. Missing source-process traffic evidence does not authorize a new recording or prove that the source has no startup, background, or local-cache behavior."
            };
            Ok((
                facts,
                vec![
                    "bootstrap timing and frequency do not prove process ownership or local-cache causality"
                        .to_string(),
                    "configured process-owned rule matches prove only declared process scope; they do not prove response causality or replace request-owned target behavior"
                        .to_string(),
                ],
                next_step.to_string(),
            ))
        }
        QUERY_DIRTY_CLUSTERS => {
            let counts = query_e2e_dirty_counts(e2e_context(target_root, state)?, group_id(state)?)?;
            let mut facts = dirty_cluster_facts(target_root, counts);
            if facts["clusters"].as_array().is_some_and(|clusters| clusters.iter().any(|c| c["protocol"] == "http" && c["reason"] == "unmatched_target")) {
                facts["http_unordered_candidates"] = crate::e2e_run::query_http_unordered_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
                facts["cross_case_candidates"] = crate::e2e_run::query_http_cross_case_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
            }
            if let Some(rejections) = &issue.egress_rejections { facts["egress_rejections"] = rejections.clone(); }
            let limitations = dirty_cluster_limitations(&facts);
            Ok((
                facts,
                limitations,
                "Start with the largest endpoint cluster. Execute representative_dependencies_command when present to summarize that case's dependency targets, then select a returned detail_command before proving request or process ownership and response causality in source code."
                    .to_string(),
            ))
        }
        QUERY_POLICY_APPLICABILITY => Ok((
            policy_applicability(issue),
            vec!["structural applicability does not authorize a response rule".to_string()],
            "A rule still requires source-code proof and the evidence-validating rewrite rule plan."
                .to_string(),
        )),
        QUERY_ATTEMPT_DELTA => Ok((
            serde_json::to_value(&state.attempt_delta)?,
            vec!["improvement or regression does not identify a root cause".to_string()],
            "If two repairs do not improve the active cluster, produce a bounded structural replan instead of adding another field patch."
                .to_string(),
        )),
        QUERY_TARGET_RUNTIME_DIAGNOSTICS => {
            let diagnostics = query_e2e_target_runtime_diagnostics(
                e2e_context(target_root, state)?,
                group_id(state)?,
            )?;
            anyhow::ensure!(
                diagnostics.attempt == issue.attempt,
                "target runtime diagnostics belong to attempt {}, not active issue attempt {}",
                diagnostics.attempt,
                issue.attempt
            );
            Ok((
                serde_json::to_value(diagnostics)?,
                vec![
                    "container output proves only what the target process emitted".to_string(),
                    "an empty log does not prove that startup succeeded or failed".to_string(),
                ],
                "Use target stdout, stderr, and runtime state to identify the first concrete startup or readiness failure."
                    .to_string(),
            ))
        }
        _ => anyhow::bail!("unsupported rewrite evidence query {kind:?}"),
    }
}

fn dirty_cluster_facts(target_root: &Path, counts: E2eDirtyCounts) -> Value {
    let representative_dependencies_command = counts
        .clusters
        .iter()
        .find_map(|cluster| cluster.representative.as_ref())
        .map(|representative| {
            super::case_dependencies::summary_command(target_root, &representative.case_dir)
        });
    json!({
        "clusters": counts.clusters,
        "complete": counts.complete,
        "dirty": counts.dirty,
        "case_event_counts": counts.case_event_counts,
        "omitted_clusters": counts.omitted_clusters,
        "representative_dependencies_command": representative_dependencies_command,
    })
}

fn dirty_cluster_limitations(facts: &Value) -> Vec<String> {
    let mut limitations = vec![
        "dirty event counts do not prove process ownership".to_string(),
        "they do not prove response causality".to_string(),
    ];
    if facts
        .get("clusters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|cluster| cluster.get("protocol").and_then(Value::as_str) == Some("motan"))
    {
        limitations.push(
            "Motan dirty evidence does not indicate a business-argument mismatch".to_string(),
        );
    }
    limitations
}

fn representative_facts(
    target_root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
) -> Result<(&'static str, Value)> {
    if let Some(representative) = issue.representative.as_ref() {
        let case_dir =
            resolve_published_case_dir(&case_source(target_root, state)?, &representative.case_id)?;
        let mut response_difference = json!({
            "pointer": representative.pointer,
            "kind": representative.difference_kind,
            "expected": representative.expected,
            "actual": representative.actual,
        });
        if let Some(gateway_protocol) = representative.gateway_protocol {
            response_difference["gateway_protocol"] = json!(gateway_protocol);
        }
        if let Some(body_codec) = representative.body_codec {
            response_difference["body_codec"] = json!(body_codec);
        }
        if let Some(body_diagnosis) = &representative.body_diagnosis {
            response_difference["body_diagnosis"] = json!(body_diagnosis);
        }
        return Ok((
            response_pointer_scope(&representative.pointer),
            json!({
                "case_id": representative.case_id,
                "case_dir": case_dir,
                "response_difference": response_difference,
            }),
        ));
    }
    if matches!(
        issue.kind,
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) {
        let evidence = query_e2e_dirty_counts(e2e_context(target_root, state)?, group_id(state)?)?;
        let Some(cluster) = evidence.clusters.first() else {
            return Ok(("not_applicable", Value::Null));
        };
        return Ok((
            "not_applicable",
            dependency_representative(target_root, cluster),
        ));
    }
    let Some(observation) = issue.comparison_observation.as_ref() else {
        return Ok(("not_applicable", Value::Null));
    };
    let case_id = observation
        .get("case_id")
        .and_then(Value::as_str)
        .context("comparison representative has no case id")?;
    let pointer = observation
        .get("pointer")
        .and_then(Value::as_str)
        .context("comparison representative has no response pointer")?;
    let difference_kind = observation
        .get("difference_kind")
        .context("comparison representative has no difference kind")?;
    let source_before = observation
        .get("source_before")
        .context("comparison representative has no source-before value")?;
    let candidate = observation
        .get("candidate")
        .context("comparison representative has no candidate value")?;
    let source_after = observation
        .get("source_after")
        .context("comparison representative has no source-after value")?;
    let run_id = state
        .comparison_run_id
        .as_deref()
        .context("comparison representative has no recording run")?;
    let case_dir =
        resolve_comparison_case_dir(&artifacts::comparison_run(target_root, run_id), case_id)?;
    let mut response_difference = json!({
        "pointer": pointer,
        "kind": difference_kind,
        "source_before": source_before,
        "candidate": candidate,
        "source_after": source_after,
    });
    if let Some(body_diagnosis) = observation
        .get("body_diagnosis")
        .filter(|value| !value.is_null())
    {
        response_difference["body_diagnosis"] = body_diagnosis.clone();
    }
    if let Some(gateway_protocol) = observation.get("gateway_protocol") {
        response_difference["gateway_protocol"] = gateway_protocol.clone();
    }
    if let Some(body_codec) = observation.get("body_codec") {
        response_difference["body_codec"] = body_codec.clone();
    }
    Ok((
        response_pointer_scope(pointer),
        json!({
            "case_id": case_id,
            "case_dir": case_dir,
            "response_difference": response_difference,
        }),
    ))
}

fn dependency_representative(target_root: &Path, cluster: &E2eDirtyCluster) -> Value {
    let representative = cluster.representative.as_ref();
    json!({
        "cluster_id": cluster.cluster_id,
        "protocol": cluster.protocol,
        "endpoint": cluster.endpoint,
        "scope": cluster.scope,
        "reason": cluster.reason,
        "count": cluster.count,
        "case_count": cluster.case_count,
        "operations": cluster.operations,
        "source_pre_readiness_interactions": cluster.source_pre_readiness_interactions,
        "source_pre_readiness_role": "reference_only",
        "case_id": representative.map(|value| &value.case_id),
        "case_dir": representative.map(|value| &value.case_dir),
        "dependencies_command": representative.map(|value| {
            super::case_dependencies::summary_command(target_root, &value.case_dir)
        }),
        "dependency_difference": representative.map(|value| &value.difference),
    })
}

fn case_response_difference_facts(
    target_root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    offset: usize,
) -> Result<(Value, Vec<String>, String)> {
    let representative = issue
        .representative
        .as_ref()
        .context("active response issue has no replay representative")?;
    let page = query_e2e_case_response_differences(
        e2e_context(target_root, state)?,
        group_id(state)?,
        &representative.case_id,
        offset,
    )?;
    let case_dir =
        resolve_published_case_dir(&case_source(target_root, state)?, &representative.case_id)?;
    let next_page = page.next_offset.map(|next_offset| {
        let query_id = case_response_difference_query_id(state, issue, next_offset);
        json!({
            "query_id": query_id,
            "command": super::action::command(
                target_root,
                vec!["evidence".to_string(), query_id],
                Vec::new(),
            ),
        })
    });
    let has_next_page = next_page.is_some();
    let next_step = if has_next_page {
        "Use the returned differences to identify a coherent cause. Execute facts.next_page.command only when the remaining differences are needed to distinguish that cause before implementation."
    } else {
        "Trace one coherent response-difference cluster through source and target code before implementing the smallest compatible repair."
    };
    let mut facts = json!({
        "case_id": page.case_id,
        "case_dir": case_dir,
        "gateway_protocol": page.gateway_protocol,
        "body_codec": page.body_codec,
        "body_diagnosis": page.body_diagnosis,
        "total_differences": page.total_differences,
        "offset": page.offset,
        "returned_differences": page.returned_differences,
        "omitted_differences": page.omitted_differences,
        "differences": page.differences,
    });
    if let Some(next_page) = next_page {
        facts["next_page"] = next_page;
    }
    Ok((
        facts,
        vec![
            "response differences establish observable incompatibilities, not their shared business cause"
                .to_string(),
            "matching pointer patterns do not by themselves prove one implementation root cause"
                .to_string(),
        ],
        next_step.to_string(),
    ))
}

fn representative_guidance(kind: RewriteIssueKind) -> (Vec<String>, String) {
    match kind {
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay => (
            vec![
                "endpoint and pre-readiness correlation does not prove process ownership"
                    .to_string(),
                "an unused recorded exchange does not prove that the target should reproduce it"
                    .to_string(),
            ],
            "Execute the returned dependencies_command for the representative case, select a target detail_command when needed, then use source code to prove request ownership, process ownership, and response causality."
                .to_string(),
        ),
        _ => (
            vec![
                "the recorded case and response difference do not prove the business cause"
                    .to_string(),
            ],
            "Inspect the coordinator-selected immutable case directory, then trace the response difference through source and target code."
                .to_string(),
        ),
    }
}

fn query_kinds(state: &RewriteState, issue: &RewriteIssue) -> Vec<(&'static str, &'static str)> {
    let mut queries = Vec::new();
    let typed_body_candidate = issue
        .representative
        .as_ref()
        .is_some_and(|representative| representative.body_diagnosis.is_some())
        || issue
            .comparison_observation
            .as_ref()
            .is_some_and(|observation| {
                observation
                    .get("body_diagnosis")
                    .is_some_and(|body| !body.is_null())
            });
    if issue.kind == RewriteIssueKind::TargetRuntime {
        queries.push((
            QUERY_TARGET_RUNTIME_DIAGNOSTICS,
            "Inspect bounded target stdout, stderr, and container state from the failed attempt",
        ));
    }
    let response_unavailable = issue.representative.as_ref().is_some_and(|representative| {
        representative.difference_kind == ResponseDifferenceKind::ResponseUnavailable
    });
    if issue.kind == RewriteIssueKind::Response && issue.representative.is_some() {
        queries.push((
            QUERY_CASE_RESPONSE_DIFFERENCES,
            "Inspect all response differences in the representative case before implementation",
        ));
    }
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
        if !response_unavailable && !typed_body_candidate {
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
        if !response_unavailable && !typed_body_candidate {
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
    queries
}

fn source_process_evidence_relevant(issue: &RewriteIssue) -> bool {
    match issue.kind {
        RewriteIssueKind::ProcessOutput => false,
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
        RewriteIssueKind::Response | RewriteIssueKind::Comparison => {
            "Use this evidence when startup, background refresh, or local-cache state may explain the response mismatch"
        }
        RewriteIssueKind::TargetRuntime => {
            "Use this evidence when target startup or readiness may depend on source bootstrap traffic"
        }
        RewriteIssueKind::ProcessOutput => {
            "Inspect the recorded process output manifests and target startup path"
        }
    }
}

fn query_id(state: &RewriteState, issue: &RewriteIssue, kind: &str) -> String {
    // Global workflow revisions change while other API workers are active. Bind
    // the command only to evidence inputs owned by this API slice.
    let attempt = issue.attempt.to_string();
    let case_source = state
        .case_source
        .as_ref()
        .map(|path| path.to_string_lossy())
        .unwrap_or_default();
    let scope = fingerprint::id(&[
        "rewrite-evidence-query-v2",
        &state.workflow_id,
        &state.api,
        &issue.id,
        &attempt,
        &issue.observed_target_fingerprint,
        state.case_inventory_id.as_deref().unwrap_or_default(),
        state.source_revision.as_deref().unwrap_or_default(),
        state.group_id.as_deref().unwrap_or_default(),
        state.comparison_run_id.as_deref().unwrap_or_default(),
        case_source.as_ref(),
        kind,
    ]);
    format!(
        "evq-{}-{}",
        scope.trim_start_matches("fnv1a64:"),
        kind.replace('_', "-")
    )
}

fn query_identifier(
    state: &RewriteState,
    issue: &RewriteIssue,
    kind: &str,
    offset: usize,
) -> String {
    if kind == QUERY_CASE_RESPONSE_DIFFERENCES {
        case_response_difference_query_id(state, issue, offset)
    } else {
        query_id(state, issue, kind)
    }
}

fn case_response_difference_query_id(
    state: &RewriteState,
    issue: &RewriteIssue,
    offset: usize,
) -> String {
    let case_id = issue
        .representative
        .as_ref()
        .map(|representative| representative.case_id.as_str())
        .unwrap_or("<missing-representative>");
    let case_scope = fingerprint::id(&["response-difference-case", case_id]);
    query_id(
        state,
        issue,
        &format!(
            "{QUERY_CASE_RESPONSE_DIFFERENCES}_case_{}_page_{offset}",
            case_scope.trim_start_matches("fnv1a64:")
        ),
    )
}

fn case_response_difference_offset(
    state: &RewriteState,
    issue: &RewriteIssue,
    requested_id: &str,
) -> Option<usize> {
    let (_, offset) = requested_id.rsplit_once("-page-")?;
    let offset = offset.parse::<usize>().ok()?;
    (case_response_difference_query_id(state, issue, offset) == requested_id).then_some(offset)
}

pub(super) fn e2e_context(target_root: &Path, state: &RewriteState) -> Result<E2eRunContext> {
    Ok(E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source: state
            .case_source
            .clone()
            .context("rewrite workflow has no finalized case source")?,
        run_key: None,
    })
}

pub(super) fn case_source(target_root: &Path, state: &RewriteState) -> Result<std::path::PathBuf> {
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no finalized case source")?;
    Ok(if case_source.is_absolute() {
        case_source
    } else {
        target_root.join(case_source)
    })
}

pub(super) fn group_id(state: &RewriteState) -> Result<&str> {
    state
        .group_id
        .as_deref()
        .context("rewrite workflow has no prepared API group")
}

fn collection_equivalence(expected: &E2eValueObservation, actual: &E2eValueObservation) -> Value {
    if expected.presence != E2eValuePresence::Present
        || actual.presence != E2eValuePresence::Present
    {
        return json!({
            "applicable": false,
            "reason": "both representative values must be present arrays",
        });
    }
    let (Some(Value::Array(expected_values)), Some(Value::Array(actual_values))) =
        (&expected.value, &actual.value)
    else {
        return json!({
            "applicable": false,
            "reason": "both representative values must be present arrays",
        });
    };
    let expected = multiset(expected_values);
    let actual = multiset(actual_values);
    json!({
        "applicable": true,
        "expected_items": expected.values().sum::<usize>(),
        "actual_items": actual.values().sum::<usize>(),
        "multiset_equal": expected == actual,
    })
}

fn multiset(values: &[Value]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        let key = serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string());
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn policy_applicability(issue: &RewriteIssue) -> Value {
    let Some(representative) = &issue.representative else {
        return json!({"eligible_kinds": [], "reason": "no response representative"});
    };
    let mut eligible = Vec::new();
    if representative.expected.presence == E2eValuePresence::Present
        && representative.actual.presence == E2eValuePresence::Present
    {
        eligible.extend([
            "timestamp_with_source_proof",
            "duration_with_source_proof",
            "uuid_with_source_proof",
            "random_with_source_proof",
        ]);
        eligible.push("counter_in_comparison_with_source_proof");
        if matches!(representative.expected.value, Some(Value::Array(_)))
            && matches!(representative.actual.value, Some(Value::Array(_)))
        {
            eligible.push("unordered_if_multiset_equal_and_source_order_is_irrelevant");
        }
    }
    json!({
        "pointer": representative.pointer,
        "difference_kind": representative.difference_kind,
        "eligible_kinds": eligible,
        "forbidden_without_more_proof": ["missing_field", "type_mismatch", "local_cache", "stable_target_logic"],
    })
}

#[cfg(test)]
#[path = "evidence/response_body_tests.rs"]
mod response_body_tests;

#[cfg(test)]
#[path = "evidence/tests.rs"]
mod tests;
