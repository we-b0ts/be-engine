//! Bounded Source occurrence and actual Target hypothesis projections.
use crate::model::RewriteState;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
const PAGE: usize = 20;

pub fn occurrence_information(
    root: &Path,
    state: &RewriteState,
    api: &str,
    report: &Value,
    offset: usize,
) -> Result<Value> {
    let source =
        traffic_rewrite_rules::rewrite::dependency_review::source::occurrences::for_diagnosis(
            state, api, report,
        )?;
    let unused = &source.unused;
    let targets = unmatched_observations(report, &source.selected);
    let entries = unused.iter().skip(offset).take(PAGE).map(|(id,event)| {
        json!({"source_exchange_id":id,"captured_owner":event.captured_owner,
            "default_case_attribution":source.case_defaults.get(id),
            "effective_attribution":state.dependency_review.decisions.get(id).map(|decision|decision.decision(*id)),"capture_complete":event.capture_complete,
            "source_query":crate::action::command(root,vec!["dependency-attribution".into(),"source".into(),"--exchange-id".into(),id.to_string()],vec![])})
    }).collect::<Vec<_>>();
    Ok(
        json!({"available":true,"source_inventory_id":source.identity,"unused_total":unused.len(),"unused":entries,
        "unmatched_target_observation_ids":targets.iter().skip(offset).take(PAGE).collect::<Vec<_>>(),"unmatched_total":targets.len(),"offset":offset,
        "next_command":(offset.saturating_add(PAGE)<unused.len().max(targets.len())).then(||crate::action::command(root,
            vec!["dependency-attribution".into(),"show".into(),"--api".into(),crate::api_selector::public_api(api).into(),"--offset".into(),offset.saturating_add(PAGE).to_string()],vec![])),
        "claim_command":crate::action::command(root,vec!["dependency-attribution".into(),"claim".into(),"--file".into(),"<foreign-unused.json>".into()],vec![]),
        "investigate_command":crate::action::command(root,vec!["dependency-attribution".into(),"investigate".into(),"--file".into(),"<target-investigation.json>".into()],vec![]),
        "proof_boundary":"Unused Source identities and unmatched protected Target identities are independent observations; neither determines the other side or its owner."}),
    )
}

pub fn hypothesis_groups(report: &Value) -> BTreeMap<String, Value> {
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

pub fn hypothesis_command(
    root: &Path,
    method_api: &str,
    candidate: &str,
    attempt: u64,
    offset: usize,
) -> traffic_rewrite_model::rewrite::RewriteCommandSpec {
    let (method, api) = method_api.split_once(' ').unwrap_or(("", method_api));
    crate::action::command(
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

pub fn unmatched_observations(report: &Value, cases: &BTreeSet<String>) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for events in [
        report["unmatched_queries"].as_array(),
        report["unmatched_http_requests"].as_array(),
        report["redis"]["unmatched"].as_array(),
        report["memcached"]["unmatched"].as_array(),
        report["motan"]["unmatched"].as_array(),
        report["kafka"]["unmatched"].as_array(),
    ]
    .into_iter()
    .flatten()
    {
        for event in events.iter().filter(|event| {
            event["case_id"]
                .as_str()
                .is_some_and(|case| cases.contains(case))
        }) {
            if let Some(id) = event["target_observation_id"].as_str() {
                ids.insert(id.into());
            }
        }
    }
    ids
}

pub fn filter_cases(value: &mut Value, selected: &BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for value in fields.values_mut() {
                filter_cases(value, selected);
            }
        }
        Value::Array(values) => {
            values.retain(|event| {
                event["case_id"]
                    .as_str()
                    .is_none_or(|case| selected.contains(case))
            });
            for value in values {
                filter_cases(value, selected);
            }
        }
        _ => {}
    }
}

pub fn hypotheses(
    root: &Path,
    selected: &RewriteState,
    api: &str,
    method: &str,
    candidate: &str,
    attempt: u64,
    offset: usize,
) -> Result<Value> {
    let method_api = format!("{method} {api}");
    let context = crate::E2eRunContext {
        target_root: root.into(),
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
    filter_cases(&mut report, &summary.selected_case_ids);
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
        "actual_session_id":report["session_id"],"report_sha256":crate::policy_evidence::digest(&bytes),"candidate_id":candidate,
        "total":attempts.len(),"offset":offset,"items":attempts.iter().skip(offset).take(PAGE).collect::<Vec<_>>(),
        "next_command":(offset.saturating_add(PAGE)<attempts.len()).then(||hypothesis_command(root,&method_api,candidate,attempt,offset.saturating_add(PAGE))),
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
