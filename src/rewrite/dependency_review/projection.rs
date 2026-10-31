//! One factual API projection for successful, failed and diagnostic attempts.
use crate::rewrite::{RewriteContext, model::RewriteState};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

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
    let selected = crate::rewrite::api_selector::scoped(&state, api)?;
    let route = crate::rewrite::api_selector::public_api(&selected.api).to_owned();
    let methods = crate::rewrite::api_selector::members(&state, &route.parse()?);
    let mut results = Vec::new();
    for method in methods {
        let selected = crate::rewrite::inventory::scoped(&state, Some(&method.parse()?))?;
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
        "accepted":accepted,"batch_verified":super::batch_verification::current(&root,&state)?,"method_results":results}),
    )
}

pub(in crate::rewrite) fn information(
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
        crate::rewrite::fingerprint::repository_fingerprint(root)
            .is_ok_and(|current| stored == &current)
    });
    let verdict = if batch_current {
        "passed"
    } else if receipt_current {
        "ai-verified"
    } else if state.dependency_review.receipts.contains_key(api) {
        "pending"
    } else if state.e2e_current
        && target_current
        && !crate::rewrite::verification_obligations::blocks_api(
            &state.dependency_review.obligations,
            api,
        )
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
                crate::rewrite::verification_obligations::scope_matches_api(&o.scope, api);
            json!({"obligation":o,"blocks_current_api":blocks_current_api,
                "verify_command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"verify".into(),o.id.clone()],vec![])})
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
            "command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"context".into()],vec![])}));
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
        crate::rewrite::action::command(
            root,
            vec![
                "dependency-attribution".into(),
                "show".into(),
                "--api".into(),
                crate::rewrite::api_selector::public_api(api).into(),
                "--offset".into(),
                offset.saturating_add(PAGE).to_string(),
            ],
            vec![],
        )
    });
    Ok(
        json!({"schema":"target-api-information/v3","api":crate::rewrite::api_selector::public_api(api),"method_api":api,
        "work_scope":{"kind":"api","api":crate::rewrite::api_selector::public_api(api)},
        "recording_run_id":state.recording_run_id,"source_revision":state.source_revision,
        "actual_attempt":last,"actual_session_id":report["session_id"],"actual_evidence_available":!report.is_null(),
        "unavailable_reason":unavailable_reason,"acceptance":{"verdict":verdict,"scope":"method_contract",
            "actual_attempt":last.map(|attempt|attempt.attempt),"receipt":receipt_current.then(||state.dependency_review.receipts.get(api)),
            "batch_verified":batch_current,"complete_batch_receipt":batch_current.then_some(&state.dependency_review.batch_receipt)},
        "gates":last.map(|attempt|&attempt.gates),"response_counts":last.map(|attempt|&attempt.counts),
        "dependency_counts":(!report.is_null()).then(||crate::replay::report::build_dependency_evidence(&report).case_event_counts),
        "dependency_occurrences":occurrence_information,
        "hypotheses":{"total_groups":groups.len(),"total_attempts":report["dependency_hypothesis_attempts"].as_array().map_or(0,Vec::len),
            "coverage_error":report["dependency_hypothesis_coverage_error"],"groups":groups.into_values().skip(offset).take(PAGE).collect::<Vec<_>>(),
            "offset":offset,"next":next},"ownership_claims":claims,"owned_request_investigations":investigations,"obligations":obligations,"next_actions":actions,
        "coordinate_contract":{"sql_params":"zero-based; inline SQL uses original token positions",
            "redis_args":"zero-based after command; SET args[0] is the key","json":"original JSON pointer"}}),
    )
}

fn occurrence_information(
    root: &Path,
    state: &RewriteState,
    api: &str,
    report: &Value,
    offset: usize,
) -> Result<Value> {
    let source = super::source::load(state)?;
    let selected = source
        .apis
        .iter()
        .filter(|(_, method)| method.as_str() == api)
        .map(|(id, _)| id.to_string())
        .collect();
    let unused = super::source::unused(&source, report, &selected)?;
    let targets = super::investigations::unmatched_observations(report, &selected);
    let entries = unused.iter().skip(offset).take(PAGE).map(|id| {
        let event = &source.exchanges[id];
        json!({"source_exchange_id":id,"captured_owner":event.capture.attribution,
            "effective_attribution":state.dependency_review.decisions.get(id).map(|decision|decision.decision(*id)),"capture_complete":event.complete,
            "source_query":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"source".into(),"--exchange-id".into(),id.to_string()],vec![])})
    }).collect::<Vec<_>>();
    Ok(
        json!({"available":true,"source_inventory_id":source.identity,"unused_total":unused.len(),"unused":entries,
        "unmatched_target_observation_ids":targets.iter().skip(offset).take(PAGE).collect::<Vec<_>>(),"unmatched_total":targets.len(),"offset":offset,
        "next_command":(offset.saturating_add(PAGE)<unused.len().max(targets.len())).then(||crate::rewrite::action::command(root,
            vec!["dependency-attribution".into(),"show".into(),"--api".into(),crate::rewrite::api_selector::public_api(api).into(),"--offset".into(),offset.saturating_add(PAGE).to_string()],vec![])),
        "claim_command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"claim".into(),"--file".into(),"<foreign-unused.json>".into()],vec![]),
        "investigate_command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"investigate".into(),"--file".into(),"<target-investigation.json>".into()],vec![]),
        "proof_boundary":"Unused Source identities and unmatched protected Target identities are independent observations; neither determines the other side or its owner."}),
    )
}

fn hypothesis_groups(report: &Value) -> BTreeMap<String, Value> {
    let mut groups = BTreeMap::<String, Value>::new();
    for attempt in report["dependency_hypothesis_attempts"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(id) = attempt["candidate_id"].as_str() else {
            continue;
        };
        let group = groups.entry(id.into()).or_insert_with(||json!({
            "candidate_id":id,"carriers":{},"pointer":attempt["pointer"],
            "draft_policy":attempt["draft_policy"],"attempt_count":0,"selected_count":0,"rejected_count":0,
            "source_proof_required":false,"proof_status":"unreviewed","validation_statuses":{},
            "representative_attempts":[],
            "required_source_fact":"Locate the Source generator and prove type, clock or identity-reference semantics for this exact slot and scope."}));
        group["attempt_count"] = json!(group["attempt_count"].as_u64().unwrap_or(0) + 1);
        let carrier = attempt["carrier"].as_str().unwrap_or("unavailable");
        group["carriers"][carrier] = json!(group["carriers"][carrier].as_u64().unwrap_or(0) + 1);
        if group["representative_attempts"]
            .as_array()
            .is_some_and(|items| items.len() < 5)
        {
            group["representative_attempts"]
                .as_array_mut()
                .expect("attempt array")
                .push(attempt.clone());
        }
        let status = attempt["status"].as_str().unwrap_or("unknown");
        let count_key = if status == "selected" {
            "selected_count"
        } else {
            "rejected_count"
        };
        if status == "selected" || status == "rejected" {
            group[count_key] = json!(group[count_key].as_u64().unwrap_or(0) + 1);
        }
        if status != "rejected" {
            group["source_proof_required"] = json!(true);
        }
        let validation = attempt["validation"].as_str().unwrap_or("unavailable");
        group["validation_statuses"][validation] = json!(
            group["validation_statuses"][validation]
                .as_u64()
                .unwrap_or(0)
                + 1
        );
    }
    groups
}

fn hypothesis_command(
    root: &Path,
    method_api: &str,
    candidate: &str,
    attempt: u64,
    offset: usize,
) -> crate::rewrite::RewriteCommandSpec {
    let (method, api) = method_api.split_once(' ').unwrap_or(("", method_api));
    crate::rewrite::action::command(
        root,
        vec![
            "dependency-attribution".into(),
            "hypotheses".into(),
            "--api".into(),
            api.into(),
            "--method".into(),
            method.into(),
            "--candidate".into(),
            candidate.into(),
            "--attempt".into(),
            attempt.to_string(),
            "--offset".into(),
            offset.to_string(),
        ],
        vec![],
    )
}

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
    let selected = crate::rewrite::inventory::scoped(&state, Some(&method_api.parse()?))?;
    ensure!(
        selected
            .attempts
            .last()
            .is_some_and(|last| last.attempt == attempt),
        "hypothesis attempt changed; obtain current API information"
    );
    let context = crate::E2eRunContext {
        target_root: root.clone(),
        case_source: selected.case_source.clone().context("Source absent")?,
        run_key: None,
    };
    let group = selected.group_id.clone().context("method group absent")?;
    let summary = crate::e2e_run::finalized_focused_attempt_summary(context.clone(), &group)?;
    ensure!(
        summary.attempt == attempt,
        "hypothesis evidence belongs to another finalized attempt"
    );
    let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(context, &group)?;
    let bytes = fs::read(evidence.replay)?;
    let mut report: Value = serde_json::from_slice(&bytes)?;
    super::verification::filter_cases(&mut report, &summary.selected_case_ids);
    let attempts = report["dependency_hypothesis_attempts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|value| value["candidate_id"].as_str() == Some(candidate))
        .collect::<Vec<_>>();
    ensure!(
        !attempts.is_empty(),
        "candidate has no persisted attempts in this method's actual execution"
    );
    Ok(
        json!({"schema":"target-hypothesis-evidence/v3","api":api,"method":method,"actual_attempt":attempt,
        "actual_session_id":report["session_id"],"report_sha256":super::source::digest(&bytes),"candidate_id":candidate,
        "total":attempts.len(),"offset":offset,"items":attempts.iter().skip(offset).take(PAGE).collect::<Vec<_>>(),
        "next_command":(offset.saturating_add(PAGE)<attempts.len()).then(||hypothesis_command(&root,&method_api,candidate,attempt,offset.saturating_add(PAGE))),
        "proof_status":"Every item is a diagnostic hypothesis, including passed probes; it does not establish Source business permission or waive any request."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_searches_remain_visible_without_becoming_proven_rules() {
        let report = json!({"dependency_hypothesis_attempts":[
            {"candidate_id":"id","status":"rejected","validation":"failed"},
            {"candidate_id":"id","status":"selected","validation":"passed"}
        ]});
        let groups = hypothesis_groups(&report);
        assert_eq!(groups["id"]["attempt_count"], 2);
        assert_eq!(groups["id"]["rejected_count"], 1);
        assert_eq!(groups["id"]["selected_count"], 1);
        assert_eq!(groups["id"]["proof_status"], "unreviewed");
    }
}
