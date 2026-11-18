use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use serde_json::json;

use super::super::fingerprint;
use super::super::model::{RewriteIssue, RewriteState};
use super::super::work_scope::RewriteWorkScope;
#[cfg(test)]
use super::super::worker;
use super::RewriteEvidenceReport;

const QUERY_OVERVIEW: &str = "overview";

pub(super) fn query_id(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    issue: &RewriteIssue,
) -> String {
    match scope {
        RewriteWorkScope::Api { .. } => super::query_id(state, issue, QUERY_OVERVIEW),
    }
}

pub(super) fn api_query_id(state: &RewriteState, issue: &RewriteIssue) -> String {
    super::query_id(state, issue, QUERY_OVERVIEW)
}

pub(super) fn report(
    target_root: &Path,
    state: &RewriteState,
    scope: RewriteWorkScope,
    issue: &RewriteIssue,
    requested_id: &str,
) -> Result<RewriteEvidenceReport> {
    let scope = super::super::api_selector::canonical_scope(state, &scope);
    let mut queries = match &scope {
        RewriteWorkScope::Api { .. } if issue.kind != crate::RewriteIssueKind::TargetQuality => {
            super::commands(target_root, state)
        }
        RewriteWorkScope::Api { .. } => Vec::new(),
    };
    let methods = match &scope {
        RewriteWorkScope::Api { api } => super::super::api_selector::members(state, &api.parse()?),
    };
    let mut discovery_ids = queries
        .iter()
        .filter(|query| super::is_rule_discovery_query(state, issue, &query.query_id))
        .map(|query| query.query_id.clone())
        .collect::<BTreeSet<_>>();
    let mut method_issues = Vec::new();
    for api in &methods {
        let Ok(selected) = super::super::inventory::scoped(state, Some(&api.parse()?)) else {
            // Awaiting refresh/system-repair inventory may lack a retained AI
            // slice. Its method contract is still present in method_apis.
            continue;
        };
        if let Some(method_issue) = selected.active_issue.as_ref() {
            let method_queries = if method_issue.kind != crate::RewriteIssueKind::TargetQuality {
                super::commands(target_root, &selected)
            } else {
                Vec::new()
            };
            if api != &state.api {
                discovery_ids.extend(
                    method_queries
                        .iter()
                        .filter(|query| {
                            super::is_rule_discovery_query(&selected, method_issue, &query.query_id)
                        })
                        .map(|query| query.query_id.clone()),
                );
                queries.extend(method_queries.clone());
            }
            method_issues
                .push(json!({"api": api, "issue": method_issue,
                    "query_ids": method_queries.iter().map(|query| &query.query_id).collect::<Vec<_>>() }));
        }
    }
    let rule_discovery = queries
        .iter()
        .filter(|query| discovery_ids.contains(&query.query_id))
        .collect::<Vec<_>>();
    let mut facts = json!({ "work_scope": scope, "issue": issue, "method_apis": methods,
        "method_issues": method_issues,"rule_discovery":rule_discovery });
    // A diagnosis entrypoint must not reconstruct whole-run ownership merely to
    // show one issue. Keep that authenticated projection behind its own query.
    facts["api_information"] = json!({"deferred": true,
        "query_id": queries.iter().find(|query| query.query_id
            == super::query_id(state, issue, super::QUERY_API_INFORMATION)).map(|query| &query.query_id),
        "retained_attempt": state.attempts.last().filter(|attempt| attempt.attempt == issue.attempt),
        "freshness": "retained attempt; current acceptance is checked by the detail query" });
    if matches!(
        issue.kind,
        crate::RewriteIssueKind::Response
            | crate::RewriteIssueKind::Dependency
            | crate::RewriteIssueKind::Replay
    ) {
        facts["dependency_witness_query"] = json!(super::super::action::command(
            target_root,
            vec![
                "evidence".into(),
                "--api".into(),
                super::super::api_selector::public_api(&state.api).to_owned(),
                "--witness".into(),
                "<witness-id>".into(),
                "--pointer".into(),
                "<json-pointer>".into()
            ],
            vec![]
        ));
        facts["mysql_sql_value_pointers"] = json!({
            "request":"/sql_values/<sql-token-index>/value",
            "decoded_json":"/sql_values/<sql-token-index>/json/<field-path>",
            "response_request":"/request/sql_values/<sql-token-index>/value",
            "token_indexes":"physical_fields.fields[].observed_positions in unified-rule-candidates; a candidate is not proof of a successful match"
        });
        facts["redis_target_argument_query"] = json!(super::super::action::command(
            target_root,
            vec![
                "evidence".into(),
                "--api".into(),
                super::super::api_selector::public_api(&state.api).to_owned(),
                "--redis-target-event".into(),
                "<case-id>:<target-event-index>".into(),
                "--argument-index".into(),
                "<zero-based-index>".into()
            ],
            vec![]
        ));
    }
    // Retained issues may predate dependency-first attribution. Expose the
    // original execution cause without changing their persisted identity.
    let execution_context = if matches!(
        issue.kind,
        crate::RewriteIssueKind::Response
            | crate::RewriteIssueKind::Dependency
            | crate::RewriteIssueKind::Replay
    ) {
        match super::e2e_context(target_root, state).and_then(|context| {
            crate::e2e_run::query_execution_context(context, super::group_id(state)?, issue.attempt)
        }) {
            Ok(execution) => Some(execution),
            Err(error) => {
                facts["execution_evidence"] = json!({"available": false,
                    "reason": error.to_string().chars().take(1024).collect::<String>()});
                None
            }
        }
    } else {
        None
    };
    if let Some(execution) = &execution_context {
        super::execution::attach(target_root, state, issue, execution, &mut facts);
    }
    let runtime_interrupted = execution_context.as_ref().is_some_and(|context| {
        context["status"] == "interrupted"
            && context["replay_finalized"] == false
            && context["executed_cases"].as_u64().unwrap_or(0) > 0
    });
    let execution_failures = execution_context
        .as_ref()
        .map(|context| &context["execution_failures"])
        .filter(|failures| failures.as_array().is_some_and(|items| !items.is_empty()));
    if let Some(failures) = execution_failures.as_ref() {
        facts["execution_failures"] = (*failures).clone();
        facts["primary_failure"] = json!({
            "kind": if failures.as_array().is_some_and(|rows| super::execution::has_unconsumed_dependencies(rows)) {
                "case_execution_incomplete"
            } else { "dependency_unmatched" },
            "request_completed": false,
            "response_differences_in_interrupted_cases_are_downstream": true,
        });
        queries.sort_by_key(|query| !query.query_id.ends_with("-dirty-clusters"));
        facts["dependency_diagnosis"] = json!(queries.iter().find(|query| {
            query.query_id == super::query_id(state, issue, super::QUERY_DIRTY_CLUSTERS)
        }));
    }
    if runtime_interrupted {
        facts["execution_context"] = json!(execution_context);
        facts["primary_failure"] = json!({"kind":"replay_interrupted","scope":"api_attempt"});
        queries.sort_by_key(|query| !query.query_id.ends_with("-target-runtime-diagnostics"));
        facts["runtime_diagnosis"] = json!(queries.iter().find(|query| query.query_id
            == super::query_id(state, issue, super::QUERY_TARGET_RUNTIME_DIAGNOSTICS)));
    }
    facts["diagnosis"] = super::diagnosis::overview(state, issue, &facts, &queries);
    let evidence_id = format!(
        "evidence-{}",
        fingerprint::id(&[requested_id, &serde_json::to_string(&facts)?])
            .trim_start_matches("fnv1a64:")
    );
    Ok(RewriteEvidenceReport {
        schema_version: 5,
        context: Some(super::report::context(target_root, state, &scope)),
        evidence_id,
        issue_id: issue.id.clone(),
        query: QUERY_OVERVIEW.to_string(),
        facts,
        queries,
        applicable_rule_planners: Vec::new(),
        rule_hints: super::unified_rule_hint(target_root,state).into_iter().collect(),
        does_not_prove: vec![
            "Issue ownership and possible causes are investigation guidance, not a proven root cause."
                .to_string(),
        ],
        next_step: if runtime_interrupted {
            "Replay was interrupted before final publication. Execute runtime_diagnosis.command, then use that diagnostic report's evidence_id for a proven replay-capability-gap route. The overview ID is not a route diagnostic. Earlier case dependency/response failures remain observations; rule planning needs a complete finalized attempt.".into()
        } else if let Some(failures) = execution_failures {
            super::execution::guidance(failures.as_array().expect("nonempty execution failures"))
        } else if issue.kind == crate::RewriteIssueKind::TargetQuality {
            "Read context.delivery.required_repairs, fix the assigned finding, then commit and return the exact delivery_commit with its original dispatch and lease identities.".to_string()
        } else { match scope {
            RewriteWorkScope::Api { .. } =>
                "Start with facts.diagnosis: inspect its mismatch locations and next_queries, resolving query_ids through queries[].command. Check each method_issues entry. Strategies are conditional; use detail evidence and Source proof before choosing a repair or rule.",
        }.to_string() },
    })
}

#[cfg(test)]
mod tests;
