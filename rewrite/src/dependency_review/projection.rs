//! One factual API projection for successful, failed and diagnostic attempts.
use crate::{RewriteContext, model::RewriteState};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

const PAGE: usize = 20;

pub fn dependency_attribution_api_information(
    context: RewriteContext,
    api: &str,
    offset: usize,
) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let selected = crate::api_selector::scoped(&state, api)?;
    let route = crate::api_selector::public_api(&selected.api).to_owned();
    let methods = crate::api_selector::members(&state, &route.parse()?);
    let mut results = Vec::new();
    for method in methods {
        let selected = crate::inventory::scoped(&state, Some(&method.parse()?))?;
        results.push(information(&root, &selected, &method, offset)?);
    }
    if results.is_empty() {
        results.push(information(&root, &selected, &selected.api, offset)?);
    }
    let accepted = results.iter().all(|result| {
        matches!(
            result["acceptance"]["verdict"].as_str(),
            Some("passed" | "ai-verified")
        )
    });
    Ok(
        json!({"schema":"target-api-information/v3","api":route,"work_scope":{"kind":"api","api":route},
        "accepted":accepted,"batch_verified":super::batch_current(&root,&state)?,
        "completion_scope":"workflow_contracts","workflow_verified":super::workflow_verification::current(&root,&state)? && !super::workflow_verification::pending(&state),
        "workflow_method_apis":super::workflow_verification::methods(&state),"method_results":results}),
    )
}

pub(crate) fn information(
    root: &Path,
    state: &RewriteState,
    api: &str,
    offset: usize,
) -> Result<Value> {
    let last = state.attempts.last();
    let report = state
        .case_source
        .as_ref()
        .zip(state.group_id.as_deref())
        .map(|(source, group)| {
            let context = crate::E2eRunContext {
                target_root: root.into(),
                case_source: source.clone(),
                run_key: None,
            };
            crate::e2e_run::resolve_e2e_response_rule_evidence(context.clone(), group).and_then(
                |evidence| {
                    let mut report = serde_json::from_slice::<Value>(&fs::read(evidence.replay)?)?;
                    let summary =
                        crate::e2e_run::finalized_focused_attempt_summary(context, group)?;
                    ensure!(last.is_some_and(|attempt|attempt.attempt==summary.attempt),"published method evidence and workflow attempt differ; reconcile the actual session before projecting one conclusion");
                    super::verification::filter_cases(&mut report, &summary.selected_case_ids);
                    Ok(report)
                },
            )
        })
        .transpose();
    let (report, unavailable_reason) = match report {
        Ok(Some(report)) => (report, None),
        Ok(None) => (Value::Null, Some("no actual Replay exists".to_string())),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    let batch_current = super::batch_verification::current(root, state)?;
    let receipt_current = super::verification::receipt_current(root, state, api)?;
    let target_current = state.target_fingerprint.as_ref().is_some_and(|stored| {
        crate::fingerprint::repository_fingerprint(root).is_ok_and(|current| stored == &current)
    });
    let verdict = if batch_current {
        "passed"
    } else if receipt_current {
        "ai-verified"
    } else if state.dependency_review.receipts.contains_key(api) {
        "pending"
    } else if state.e2e_current
        && target_current
        && !crate::verification_obligations::blocks_api(&state.dependency_review.obligations, api)
    {
        "passed"
    } else if last.is_some_and(|attempt| !attempt.passed) {
        "failed"
    } else {
        "pending"
    };
    let mut groups = hypothesis_groups(&report);
    for (id, group) in &mut groups {
        group["all_attempts_command"] = json!(hypothesis_command(
            root,
            api,
            id,
            last.map_or(0, |attempt| attempt.attempt),
            0
        ));
    }
    let occurrence_information = occurrence_information(root, state, api, &report, offset)
        .unwrap_or_else(|error| json!({"available":false,"reason":error.to_string()}));
    let obligations = state
        .dependency_review
        .obligations
        .values()
        .filter(|o| o.pending())
        .map(|o| {
            let blocks_current_api =
                crate::verification_obligations::scope_matches_api(&o.scope, api);
            json!({"obligation":o,"blocks_current_api":blocks_current_api,
                "verify_command":crate::action::command(root,vec!["dependency-attribution".into(),"verify".into(),o.id.clone()],vec![])})
        })
        .collect::<Vec<_>>();
    let claims = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| claim.method_api == api && claim.recording_run_id == state.recording_run_id)
        .collect::<Vec<_>>();
    let investigations = super::investigations::for_api(root, state, api)?;
    let mut actions = Vec::new();
    if groups
        .values()
        .any(|group| group["source_proof_required"] == true)
    {
        actions.push(json!({"owner":"api_implementer","action":"prove_value_mechanisms",
            "required":"Inspect Source generators and references for the grouped value hypotheses. Correct Target behavior or submit one batch of independently proved value rules; a candidate is diagnostic evidence."}));
    }
    if claims.iter().any(|claim| {
        matches!(
            claim.status,
            super::model::ClaimStatus::Pending | super::model::ClaimStatus::Unresolved
        )
    }) {
        actions.push(json!({"owner":"repository_analyst","action":"prove_source_attribution",
            "command":crate::action::command(root,vec!["dependency-attribution".into(),"context".into()],vec![])}));
    }
    if investigations.iter().any(|entry| {
        matches!(
            entry["investigation"]["status"].as_str(),
            Some("pending" | "unresolved")
        )
    }) {
        actions.push(json!({"owner":"api_implementer","action":"diagnose_owned_missing_traffic",
            "required":"Return Source proof for this API's async lifecycle rule or the exact recording omission and capture/response-rewrite repair."}));
    }
    let next = (offset.saturating_add(PAGE) < groups.len()).then(|| {
        crate::action::command(
            root,
            vec![
                "dependency-attribution".into(),
                "show".into(),
                "--api".into(),
                crate::api_selector::public_api(api).into(),
                "--offset".into(),
                offset.saturating_add(PAGE).to_string(),
            ],
            vec![],
        )
    });
    Ok(
        json!({"schema":"target-api-information/v3","api":crate::api_selector::public_api(api),"method_api":api,
        "work_scope":{"kind":"api","api":crate::api_selector::public_api(api)},
        "recording_run_id":state.recording_run_id,"source_revision":state.source_revision,
        "actual_attempt":last,"actual_session_id":report["session_id"],"actual_evidence_available":!report.is_null(),
        "unavailable_reason":unavailable_reason,"acceptance":{"verdict":verdict,"scope":"method_contract",
            "completion_scope":"workflow_contracts","workflow_verified":super::workflow_verification::current(root,state)? && !super::workflow_verification::pending(state),
            "actual_attempt":last.map(|attempt|attempt.attempt),"receipt":receipt_current.then(||state.dependency_review.receipts.get(api)),
            "batch_verified":batch_current,"complete_batch_receipt":batch_current.then_some(&state.dependency_review.batch_receipt)},
        "gates":last.map(|attempt|&attempt.gates),"response_counts":last.map(|attempt|&attempt.counts),
        "dependency_counts":(!report.is_null()).then(||crate::protocols::replay::report::evidence::build_dependency_evidence(&report).case_event_counts),
        "dependency_occurrences":occurrence_information,
        "hypotheses":{"total_groups":groups.len(),"total_attempts":report["dependency_hypothesis_attempts"].as_array().map_or(0,Vec::len),
            "coverage_error":report["dependency_hypothesis_coverage_error"],"groups":groups.into_values().skip(offset).take(PAGE).collect::<Vec<_>>(),
            "offset":offset,"next":next},"ownership_claims":claims,"owned_request_investigations":investigations,"obligations":obligations,"next_actions":actions,
        "coordinate_contract":{"sql_params":"zero-based; inline SQL uses original token positions",
            "redis_args":"zero-based after command; SET args[0] is the key","json":"original JSON pointer"}}),
    )
}

use traffic_rewrite_evidence::attribution_projection::{
    hypothesis_command, hypothesis_groups, occurrence_information,
};

pub fn dependency_attribution_hypotheses(
    context: RewriteContext,
    api: &str,
    method: &str,
    candidate: &str,
    attempt: u64,
    offset: usize,
) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    let method_api = format!("{method} {api}");
    let selected = crate::inventory::scoped(&state, Some(&method_api.parse()?))?;
    ensure!(
        selected
            .attempts
            .last()
            .is_some_and(|last| last.attempt == attempt),
        "hypothesis attempt changed; obtain current API information"
    );
    traffic_rewrite_evidence::attribution_projection::hypotheses(
        &root, &selected, api, method, candidate, attempt, offset,
    )
}
