use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::evidence_model::RewriteEvidenceReport;
use super::model::{
    RewriteEvidenceCommand, RewriteIssue, RewriteIssueKind, RewritePhase, RewriteState,
};
use super::work_scope::RewriteWorkScope;
use super::{fingerprint, source_process_traffic};
use crate::case_group::resolve_published_case_dir;
use crate::e2e_run::response_pointer_scope;
use crate::{
    E2eDirtyCluster, E2eDirtyCounts, E2eRunContext, E2eValueObservation, E2eValuePresence,
    ResponseBodyCodec, ResponseDifferenceKind, query_e2e_case_response_differences,
    query_e2e_dependency_correlation, query_e2e_dirty_counts, query_e2e_source_variation,
    query_e2e_target_runtime_diagnostics,
};

mod access;
pub(super) mod execution;
mod redis_argument;
pub use redis_argument::query_rewrite_redis_argument_for_scope;
mod http_requests;
mod query_catalog;
mod redis_stream_progress;
mod report;
pub use access::{query_rewrite_evidence, query_rewrite_evidence_for_scope};
use query_catalog::query_kinds;
mod diagnosis;
mod mysql_diagnosis;
mod overview;
pub(super) mod policy_freshness;
mod response_body;
mod rule_guidance;
mod unified_discovery;
mod witness;
pub(super) use rule_guidance::supports_response_body_codec;
use rule_guidance::{applicable_rule_planners, rule_hints};
pub use witness::query_rewrite_witness_for_scope;

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
const QUERY_UNIFIED_RULE_CANDIDATES: &str = "unified_rule_candidates";
const QUERY_HTTP_REQUESTS: &str = "http_request_differences";
const QUERY_API_INFORMATION: &str = "api_information";

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
            || http_requests::parse(state, issue, requested_id).is_some()
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
            unified_discovery::parse(state, issue, requested_id)
                .map(|_| (QUERY_UNIFIED_RULE_CANDIDATES, 0))
        })
        .or_else(|| {
            case_response_difference_offset(state, issue, requested_id)
                .map(|offset| (QUERY_CASE_RESPONSE_DIFFERENCES, offset))
        })
        .or_else(|| {
            execution::parse(state, issue, requested_id).map(|offset| (execution::KIND, offset))
        })
}

pub(super) fn is_rule_discovery_query(
    state: &RewriteState,
    issue: &RewriteIssue,
    query_id: &str,
) -> bool {
    requested_query(state, issue, query_id)
        .is_some_and(|(kind, _)| kind == QUERY_UNIFIED_RULE_CANDIDATES)
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
    let requested = requested_query(state, issue, requested_id)
        .or_else(|| {
            http_requests::parse(state, issue, requested_id).map(|_| (QUERY_HTTP_REQUESTS, 0))
        })
        .with_context(|| {
            format!(
                "evidence query is stale or is not valid for active issue {}",
                issue.id
            )
        })?;
    let (kind, offset) = requested;
    let (mut facts, does_not_prove, mut next_step) = if kind == QUERY_HTTP_REQUESTS {
        (http_requests::facts(target_root, state, issue, requested_id)?,
            vec!["Retained candidates and raw body differences do not prove a successful match, response causality, or authorization for a rule.".into()],
            "Follow candidates_query, differences_query, and source_body_query/target_body_query. Body pages return exact captured bytes; concatenate them by offset and verify sha256. Runtime rule traces retain their original policy fingerprint; unavailable historical traces require fresh Replay.".into())
    } else if kind == QUERY_UNIFIED_RULE_CANDIDATES {
        (unified_discovery::facts(target_root, state, issue, requested_id)?,
            vec!["A mechanical draft requires Source code proof and full selected evidence validation. Derived delivery never proves independent Target response behavior.".into()],
            "Inspect candidates[].draft_policy and source_entry.locations. Follow pagination.next_page for omitted summaries and pagination.next_scan for remaining observations. Draft fields and formats add to current declarations; inspect the planned changes, add Source proof and use the returned planner. Bounded discovery never proves complete coverage.".into())
    } else {
        facts(target_root, state, issue, kind, offset)?
    };
    if let Some(refresh) = policy_freshness::attach(target_root, state, issue, kind, &mut facts)? {
        next_step = refresh;
    }
    let evidence_id = unified_discovery::evidence_id(requested_id, &facts)?;
    let mut planners =
        applicable_rule_planners(target_root, issue.kind, kind, &facts, &evidence_id);
    if kind == QUERY_UNIFIED_RULE_CANDIDATES
        && facts["policy_freshness"]["requires_fresh_replay"] != true
    {
        planners.push(super::evidence_model::RewriteApplicableRulePlanner {
            kind: "unified".into(),
            capability: "Source-proven typed value contract across comparison surfaces".into(),
            evidence_id: evidence_id.clone(),
            command: super::action::command(
                target_root,
                vec![
                    "rule".into(),
                    "plan".into(),
                    "--file".into(),
                    "<rule.yaml>".into(),
                    "--evidence".into(),
                    evidence_id.clone(),
                ],
                vec![],
            ),
        });
    }
    let mut hints = rule_hints(target_root, kind, &facts);
    if let Some(hint) = unified_rule_hint(target_root, state) {
        hints.push(hint);
    }
    Ok(RewriteEvidenceReport {
        schema_version: 4,
        context: None,
        evidence_id: evidence_id.clone(),
        issue_id: issue.id.clone(),
        query: kind.to_string(),
        applicable_rule_planners: planners,
        rule_hints: hints,
        facts,
        queries: Vec::new(),
        does_not_prove,
        next_step,
    })
}

pub(super) fn report_for_id(
    root: &Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Option<RewriteEvidenceReport> {
    if evidence_id.starts_with("evidence-discovery:") {
        return unified_discovery::report_for_id(root, state, evidence_id);
    }
    commands(root, state).into_iter().find_map(|command| {
        let report = query(root, state, &command.query_id).ok()?;
        (report.evidence_id == evidence_id).then_some(report)
    })
}

/// Recognize a current overview without promoting it to planning authority.
pub(super) fn current_overview_matches(root: &Path, state: &RewriteState, id: &str) -> bool {
    // Excluded/externally repaired slices retain their issue for later recovery,
    // but have no current implementation dispatch to put in an overview.
    if state.phase != RewritePhase::ImplementationRequired
        || super::regression_scope::is_skipped(state, &state.api)
    {
        return false;
    }
    state.active_issue.as_ref().is_some_and(|issue| {
        query(root, state, &overview::api_query_id(state, issue))
            .is_ok_and(|report| report.evidence_id == id)
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
        RewriteIssueKind::Response => {
            "Use matching endpoints to prioritize source startup, refresh, and local-cache paths, then prove the response-driving path in source code."
        }
        RewriteIssueKind::TargetRuntime => {
            "Inspect source startup and readiness paths only for matching bootstrap dependencies."
        }
        RewriteIssueKind::TargetQuality => {
            "Read context.delivery.required_repairs and address the assigned code finding; no traffic diagnosis is required."
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
        QUERY_API_INFORMATION => Ok((
            super::dependency_review::api_information(target_root, state, &state.api, 0)?,
            vec!["Unused Source occurrences and unmatched Target observations do not establish ownership or authorize a rule.".into()],
            "Inspect the relevant hypothesis or occurrence, follow its returned detail/pagination command, and prove its Source behavior before proposing a repair or rule.".into(),
        )),
        QUERY_JWT_TIME_VALIDITY => Ok((super::jwt_rule::evidence_facts(target_root, state)?,
            vec!["Unverified JWT time claims and HTTP 401 do not alone prove authentication causality or rule applicability.".into()],
            "For time-drift candidates, inspect signing_key_discovery for target variable names, startup mount paths/access modes, existing bindings and discovery commands. Trace the source/target JWT path, configuration precedence and expiration leeway, then use the returned rule planner with the proven signing-key source. Plan/apply verifies original signatures.".into())),
        QUERY_IP_CAPTURE => Ok((super::response_url_evidence::facts(target_root, state)?,
            vec!["The IP omission is reported by target analysis; source consumption and absence of equivalent recorded calls require source/dependency evidence.".to_string()],
            "Prove the IP origin. For a supported JSON URL, write a self-contained capture_http_response rule, use rule plan --file with this evidence, inspect and apply the plan, then verify a fresh recording before submitting a remaining system defect.".to_string())),
        QUERY_CASE_RESPONSE_DIFFERENCES => {
            case_response_difference_facts(target_root, state, issue, offset)
        }
        execution::KIND => Ok((execution::facts(target_root,state,issue,offset)?,
            vec!["A bounded page or omitted case does not prove absence of an execution failure. Follow pagination.next_page through every page.".into()],
            "Follow pagination.next_page for the remaining failed cases. Inspect each case's own failures and target_event_index; do not attribute another case's failure to it. Unused Source dependencies alone remain dirty inventory, not an execution interruption.".into())),
        QUERY_REPRESENTATIVES => {
            let (pointer_scope, representative) =
                representative_facts(target_root, state, issue)?;
            let (does_not_prove, next_step) = representative_guidance(issue.kind);
            let mut facts = json!({
                    "pointer_scope": pointer_scope,
                    "representative": representative,
                });
            if rule_guidance::has_response_jwt(&facts) {
                facts["signing_key_discovery"] = super::jwt_rule::signing_key_discovery(target_root);
            }
            Ok((facts, does_not_prove, next_step))
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
            let execution = crate::e2e_run::query_execution_context(e2e_context(target_root,state)?,group_id(state)?,issue.attempt)?;
            execution::attach(target_root,state,issue,&execution,&mut facts);
            facts["dependency_request_candidates"] = crate::e2e_run::query_dependency_request_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
            if facts["dependency_request_candidates"].as_array().is_some_and(|items| items.iter().any(|item| item["capability"] == "redis_json_request")) {
                facts["signing_key_discovery"] = super::jwt_rule::signing_key_discovery(target_root);
            }
            facts["dynamic_capture_candidates"] = crate::e2e_run::query_dynamic_capture_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
            if facts["clusters"].as_array().is_some_and(|clusters| clusters.iter().any(|c| c["protocol"] == "http" && c["reason"] == "unmatched_target")) {
                facts["http_request_differences_command"] = serde_json::to_value(super::action::command(target_root,
                    vec!["evidence".into(), query_id(state, issue, QUERY_HTTP_REQUESTS)], Vec::new()))?;
                facts["http_unordered_candidates"] = crate::e2e_run::query_http_unordered_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
                facts["redis_unordered_candidates"] = crate::e2e_run::query_redis_unordered_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
                facts["cross_case_candidates"] = crate::e2e_run::query_http_cross_case_candidates(e2e_context(target_root, state)?, group_id(state)?)?;
            }
            if let Some(rejections) = &issue.egress_rejections { facts["egress_rejections"] = rejections.clone(); }
            mysql_diagnosis::attach(&mut facts);
            let limitations = dirty_cluster_limitations(&facts);
            let next_step = if let Some(failures) = facts["execution_failures"].as_array().filter(|failures| !failures.is_empty()) {
                format!("{} {}",execution::guidance(failures),mysql_diagnosis::next_step(&facts))
            } else {mysql_diagnosis::next_step(&facts)};
            Ok((
                facts,
                limitations,
                next_step,
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
    limitations.extend(mysql_diagnosis::limitations(facts));
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
    Ok(("not_applicable", Value::Null))
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
        "target_matches": representative.map(|value| &value.target_matches),
        "target_matches_may_be_truncated": representative
            .map(|value| value.target_matches_may_be_truncated),
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

pub(super) fn unified_rule_hint(
    root: &Path,
    state: &RewriteState,
) -> Option<super::evidence_model::RewriteRuleHint> {
    let command = commands(root, state).into_iter().find(|q| {
        state
            .active_issue
            .as_ref()
            .is_some_and(|issue| is_rule_discovery_query(state, issue, &q.query_id))
    })?;
    Some(super::evidence_model::RewriteRuleHint {
        capability:"unified_value_contract".into(),rule:"traffic-policy/v3".into(),
        hint:"Use the differences and Source locations to diagnose this issue. This query exposes supported content formats and carrier bindings, even when no draft exists. Rules require Source proof, complete plan validation and genuine Replay; equal/null observations do not authorize a rule.".into(),
        help:command.command,
    })
}

fn query_id(state: &RewriteState, issue: &RewriteIssue, kind: &str) -> String {
    // Global workflow revisions change while other API implementers are active. Bind
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
    if kind == execution::KIND {
        execution::id(state, issue, offset)
    } else if kind == QUERY_CASE_RESPONSE_DIFFERENCES {
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
    if representative.pointer.starts_with("$headers/") {
        return json!({
            "pointer": representative.pointer,
            "difference_kind": representative.difference_kind,
            "eligible_kinds": [],
            "reason": "standard response headers are built-in exact assertions, not response rules",
        });
    }
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
