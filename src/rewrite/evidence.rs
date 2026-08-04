use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::model::{
    RewriteApplicableRulePlanner, RewriteEvidenceCommand, RewriteEvidenceReport, RewriteIssue,
    RewriteIssueKind, RewriteState,
};
use super::{artifacts, fingerprint};
use crate::case_group::resolve_published_case_dir;
use crate::comparison_recording::resolve_comparison_case_dir;
use crate::e2e_run::response_pointer_scope;
use crate::recorder::load_pre_readiness_traffic_summary;
use crate::{
    E2eDirtyCluster, E2eDirtyCounts, E2eRunContext, E2eValueObservation, E2eValuePresence,
    query_e2e_dependency_correlation, query_e2e_dirty_counts, query_e2e_source_variation,
};

const QUERY_REPRESENTATIVES: &str = "representatives";
const QUERY_SOURCE_VARIATION: &str = "source_variation";
const QUERY_COLLECTION_EQUIVALENCE: &str = "collection_equivalence";
const QUERY_DEPENDENCY_CORRELATION: &str = "dependency_correlation";
const QUERY_PRE_READINESS_TRAFFIC: &str = "pre_readiness_traffic";
const QUERY_DIRTY_CLUSTERS: &str = "dirty_clusters";
const QUERY_POLICY_APPLICABILITY: &str = "policy_applicability";
const QUERY_ATTEMPT_DELTA: &str = "attempt_delta";

pub(super) fn commands(target_root: &Path, state: &RewriteState) -> Vec<RewriteEvidenceCommand> {
    let Some(issue) = &state.active_issue else {
        return Vec::new();
    };
    query_kinds(state, issue)
        .into_iter()
        .map(|(kind, purpose)| {
            let query_id = query_id(state, issue, kind);
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

pub(super) fn query(
    target_root: &Path,
    state: &RewriteState,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    let issue = state
        .active_issue
        .as_ref()
        .context("rewrite workflow has no active issue")?;
    let kind = query_kinds(state, issue)
        .into_iter()
        .find_map(|(kind, _)| (query_id(state, issue, kind) == requested_id).then_some(kind))
        .with_context(|| {
            format!(
                "evidence query is stale or is not valid for active issue {}",
                issue.id
            )
        })?;
    let (facts, does_not_prove, next_step) = facts(target_root, state, issue, kind)?;
    let evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[requested_id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    Ok(RewriteEvidenceReport {
        schema_version: 1,
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
        facts,
        does_not_prove,
        next_step,
    })
}

fn applicable_rule_planners(
    target_root: &Path,
    issue_kind: RewriteIssueKind,
    query_kind: &str,
    facts: &Value,
    evidence_id: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    if issue_kind != RewriteIssueKind::Dependency || query_kind != QUERY_DIRTY_CLUSTERS {
        return Vec::new();
    }
    let protocols = facts
        .get("clusters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|cluster| cluster.get("protocol").and_then(Value::as_str))
        .filter(|protocol| matches!(*protocol, "http" | "memcached" | "motan" | "redis"))
        .collect::<std::collections::BTreeSet<_>>();
    protocols
        .into_iter()
        .map(|protocol| RewriteApplicableRulePlanner {
            kind: "background_dependencies".to_string(),
            protocol: protocol.to_string(),
            evidence_id: evidence_id.to_string(),
            command: super::action::command(
                target_root,
                vec![
                    "dependency-rule".to_string(),
                    "plan".to_string(),
                    protocol.to_string(),
                    "--help".to_string(),
                ],
                Vec::new(),
            ),
        })
        .collect()
}

fn facts(
    target_root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
    kind: &str,
) -> Result<(Value, Vec<String>, String)> {
    match kind {
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
        QUERY_PRE_READINESS_TRAFFIC => {
            let summary = load_pre_readiness_traffic_summary(&case_source(target_root, state)?)?;
            let facts = match summary {
                Some(summary) => {
                    let endpoint_counts = summary
                        .endpoints
                        .iter()
                        .map(|endpoint| {
                            (
                                endpoint.endpoint.clone(),
                                Value::from(endpoint.interaction_count),
                            )
                        })
                        .collect::<serde_json::Map<_, _>>();
                    json!({
                        "available": true,
                        "scope": "recorded_source_before_readiness",
                        "interaction_count": summary.data_interactions,
                        "endpoint_counts": endpoint_counts,
                        "excluded_non_data_events": summary.excluded_events,
                        "unresolved_interactions": summary.unresolved_interactions,
                        "omitted_interactions": summary.omitted_interactions,
                        "truncated": summary.truncated,
                    })
                }
                None => json!({
                    "available": false,
                    "scope": "recorded_source_before_readiness",
                    "reason": "the finalized recording has no global dependency evidence",
                    "endpoint_counts": {},
                }),
            };
            Ok((
                facts,
                vec![
                    "endpoint frequency does not prove asynchronous or process ownership"
                        .to_string(),
                    "it does not establish local-cache lifecycle or response causality"
                        .to_string(),
                ],
                "Inspect source startup scheduling and cache loader paths only for endpoints with relevant data interactions."
                    .to_string(),
            ))
        }
        QUERY_DIRTY_CLUSTERS => {
            let counts = query_e2e_dirty_counts(e2e_context(target_root, state)?, group_id(state)?)?;
            Ok((
                dirty_cluster_facts(target_root, counts),
                vec![
                    "dirty event counts do not prove process ownership".to_string(),
                    "they do not prove response causality".to_string(),
                ],
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

fn representative_facts(
    target_root: &Path,
    state: &RewriteState,
    issue: &RewriteIssue,
) -> Result<(&'static str, Value)> {
    if let Some(representative) = issue.representative.as_ref() {
        let case_dir =
            resolve_published_case_dir(&case_source(target_root, state)?, &representative.case_id)?;
        return Ok((
            response_pointer_scope(&representative.pointer),
            json!({
                "case_id": representative.case_id,
                "case_dir": case_dir,
                "response_difference": {
                    "pointer": representative.pointer,
                    "kind": representative.difference_kind,
                    "expected": representative.expected,
                    "actual": representative.actual,
                },
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
    Ok((
        response_pointer_scope(pointer),
        json!({
            "case_id": case_id,
            "case_dir": case_dir,
            "response_difference": {
                "pointer": pointer,
                "kind": difference_kind,
                "source_before": source_before,
                "candidate": candidate,
                "source_after": source_after,
            },
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

fn representative_guidance(kind: RewriteIssueKind) -> (Vec<String>, String) {
    match kind {
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay => (
            vec![
                "endpoint and pre-readiness correlation does not prove process ownership"
                    .to_string(),
                "an unused recorded exchange does not prove that the target should reproduce it"
                    .to_string(),
            ],
            "Execute the returned dependencies_command for the representative case, select a target detail_command when needed, then use source code to prove request ownership, startup/background ownership, and response causality."
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
    let mut queries = vec![(
        QUERY_REPRESENTATIVES,
        "Show the bounded representative with explicit value presence",
    )];
    queries.push((
        QUERY_PRE_READINESS_TRAFFIC,
        "Summarize source data interactions observed before readiness by endpoint",
    ));
    if issue.representative.is_some() {
        queries.extend([
            (
                QUERY_SOURCE_VARIATION,
                "Measure the representative source value across recorded cases",
            ),
            (
                QUERY_COLLECTION_EQUIVALENCE,
                "Check whether representative arrays are equal as multisets",
            ),
            (
                QUERY_DEPENDENCY_CORRELATION,
                "Correlate response outcomes with dependency cleanliness",
            ),
            (
                QUERY_POLICY_APPLICABILITY,
                "Check structural rule applicability without authorizing a rule",
            ),
        ]);
    }
    if matches!(
        issue.kind,
        RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) {
        queries.push((
            QUERY_DIRTY_CLUSTERS,
            "Cluster case-scoped dirty dependencies by protocol, endpoint, and reason",
        ));
    }
    if state.attempt_delta.is_some() {
        queries.push((
            QUERY_ATTEMPT_DELTA,
            "Compare response convergence with the previous attempt",
        ));
    }
    queries
}

fn query_id(state: &RewriteState, issue: &RewriteIssue, kind: &str) -> String {
    format!(
        "evq-r{}-{}-{}",
        state.revision,
        issue.id.trim_start_matches("issue-"),
        kind.replace('_', "-")
    )
}

fn e2e_context(target_root: &Path, state: &RewriteState) -> Result<E2eRunContext> {
    Ok(E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source: state
            .case_source
            .clone()
            .context("rewrite workflow has no finalized case source")?,
        run_key: None,
    })
}

fn case_source(target_root: &Path, state: &RewriteState) -> Result<std::path::PathBuf> {
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

fn group_id(state: &RewriteState) -> Result<&str> {
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
        eligible.push("dynamic_with_source_proof");
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
#[path = "evidence/tests.rs"]
mod tests;
