//! Public continuation commands preserve bounds and independent evidence roles.
use super::*;

fn frames(count: usize, target: bool, times: bool) -> Value {
    let mut output = stream(target);
    output["interaction"]["events"] = json!(
        (0..count)
            .map(|index| {
                let kind = if count > 256 && index + 1 == count {
                    "response.completed".into()
                } else {
                    format!("response.part.{index}")
                };
                let mut data =
                    json!({"type":kind,"id":if times {"stable"} else if target {"new"} else {"old"},"private":PRIVATE});
                if times {
                    data["created_at"] = json!(START + if target { 60 } else { 0 });
                }
                event(&kind, data, index)
            })
            .collect::<Vec<_>>()
    );
    output
}

fn response_issue(fixture: &Fixture) {
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    fixture.store().save(&state).unwrap();
}

fn continuation(fixture: &Fixture, facts: &Value, name: &str) -> crate::RewriteEvidenceReport {
    let next = &facts["pagination"][name];
    assert_eq!(
        next["command"]["argv"].as_array().unwrap().last().unwrap(),
        &next["query_id"]
    );
    query_rewrite_evidence(fixture.context(), next["query_id"].as_str().unwrap()).unwrap()
}

#[test]
fn identity_only_source_bindings_have_totals_omissions_and_a_public_summary_page() {
    let fixture = fixture();
    response_issue(&fixture);
    install(&fixture, frames(25, false, false), frames(25, true, false));
    let first = fixture.evidence();
    assert_eq!(first.facts["candidate_count"], 0);
    assert_eq!(first.facts["source_entry"]["location_count"], 25);
    assert_eq!(
        first.facts["source_entry"]["locations"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert_eq!(first.facts["source_entry"]["summary_omitted"], 5);
    assert_eq!(first.facts["bounded_analysis"]["summary_limited"], true);
    assert_eq!(first.facts["pagination"]["scan_remaining"], false);
    let next = continuation(&fixture, &first.facts, "next_page");
    assert_eq!(next.facts["pagination"]["summary_offset"], 20);
    assert_eq!(next.facts["source_entry"]["location_count"], 25);
    assert_eq!(
        next.facts["source_entry"]["locations"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(next.facts["candidate_count"], 0);
    assert!(next.facts["pagination"].get("next_page").is_none());
    assert_eq!(
        next.facts["source_entry"]["locations"][4]["location"]["slot"]["sse_data"]["json_type"],
        "response.part.24"
    );
    assert!(!serde_json::to_string(&next).unwrap().contains(PRIVATE));
}

#[test]
fn candidate_summary_pages_and_scan_windows_both_reach_late_sse_frames() {
    let fixture = fixture();
    response_issue(&fixture);
    install(&fixture, frames(300, false, true), frames(300, true, true));
    let first = fixture.evidence();
    assert_eq!(first.facts["observations_examined"], 256);
    assert_eq!(first.facts["candidate_count"], 1);
    assert_eq!(first.facts["source_entry"]["summary_omitted"], 235);
    let page = continuation(&fixture, &first.facts, "next_page");
    assert_eq!(
        page.facts["source_entry"]["locations"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert_eq!(
        page.facts["source_entry"]["locations"][0]["location"]["slot"]["sse_data"]["json_type"],
        "response.part.20"
    );
    let scan = continuation(&fixture, &first.facts, "next_scan");
    assert!(scan.facts["observations_examined"].as_u64().unwrap() <= 256);
    assert_eq!(scan.facts["candidate_count"], 1);
    assert_eq!(scan.facts["source_entry"]["location_count"], 45);
    assert_eq!(scan.facts["pagination"]["scan_remaining"], false);
    let second_page = continuation(&fixture, &scan.facts, "next_page");
    let final_page = continuation(&fixture, &second_page.facts, "next_page");
    assert_eq!(
        final_page.facts["source_entry"]["locations"][4]["location"]["slot"]["sse_data"]["json_type"],
        "response.completed"
    );
    assert_eq!(
        final_page.facts["bounded_analysis"]["complete_coverage"],
        false
    );
    assert!(
        !serde_json::to_string(&final_page)
            .unwrap()
            .contains(PRIVATE)
    );
}

#[test]
fn scan_continuations_rotate_surfaces_and_reject_stale_issue_ids() {
    let fixture = fixture();
    response_issue(&fixture);
    install_dependencies(&fixture);
    install(
        &fixture,
        frames(300, false, false),
        frames(300, true, false),
    );
    let first = fixture.evidence();
    let next = continuation(&fixture, &first.facts, "next_scan");
    assert_eq!(
        next.facts["bounded_analysis"]["scan_order"][0],
        "dependency"
    );
    assert_eq!(
        next.facts["source_entry"]["locations"][0]["location"]["surface"],
        "dependency.request"
    );
    assert_eq!(next.facts["observations_examined"], 256);
    let query = first.facts["pagination"]["next_scan"]["query_id"]
        .as_str()
        .unwrap();
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().attempt += 1;
    fixture.store().save(&state).unwrap();
    assert!(query_rewrite_evidence(fixture.context(), query).is_err());
}

#[test]
fn a_failed_case_late_in_inventory_is_examined_before_passing_cases() {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
        (2..=300).map(|index| {
            let case = source.join(format!("apis/api/00000000-0000-4000-8000-{index:012x}"));
            fs::create_dir_all(&case).unwrap();
            write(&case.join("request.json"), json!({"timestamp":"2026-10-16T00:00:00Z","method":"GET","uri":"/api","body":body(json!({}))}));
            fs::write(case.join("dependencies.jsonl"), "").unwrap();
            case
        }).collect()
    });
    fixture.confirm();
    fixture.replace_case_responses("00000000-0000-4000-8000-00000000012c", json!({"status":200,"body":body(json!({"late":START})),"timestamp":"2026-10-16T00:00:00Z"}), json!({"version":1,"status":200,"body":body(json!({"late":START+60})),"request_sent_at":"2026-10-16T00:01:00Z","response_completed_at":"2026-10-16T00:01:00Z"}));
    let mut assertions: Value =
        serde_json::from_slice(&fs::read(&fixture.paths.assertions).unwrap()).unwrap();
    for case in assertions["cases"].as_array_mut().unwrap() {
        case["response"]["passed"] =
            json!(case["case_id"] != "00000000-0000-4000-8000-00000000012c");
    }
    write(&fixture.paths.assertions, assertions);
    let mut state = fixture.state();
    let issue = state.active_issue.as_mut().unwrap();
    issue.kind = RewriteIssueKind::Response;
    issue.representative = None;
    fixture.store().save(&state).unwrap();
    let facts = fixture.evidence().facts;
    assert!(facts["observations_examined"].as_u64().unwrap() <= 256);
    assert!(
        facts["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |candidate| candidate["witness_id"] == "00000000-0000-4000-8000-00000000012c"
                    && candidate["draft_policy"]["json"]["fields"]
                        .get("/late")
                        .is_some()
            )
    );
    assert_eq!(facts["pagination"]["scan_remaining"], true);
}

#[test]
fn continuation_evidence_plans_reject_tampering_and_preserve_policy_freshness() {
    let fixture = fixture();
    response_issue(&fixture);
    install(&fixture, frames(25, false, true), frames(25, true, true));
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/created_at":{"kind":"time","formats":["unix_seconds"]}
        }}}),
    );
    let first = fixture.evidence();
    let page = continuation(&fixture, &first.facts, "next_page");
    assert!(page.evidence_id.starts_with("evidence-discovery:"));
    let mut tampered = page.evidence_id.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == '0' { '1' } else { '0' });
    assert!(
        plan_rewrite_unified_rule(
            fixture.context(),
            RewriteUnifiedRulePlanOptions {
                file: fixture.proposal.clone(),
                evidence_id: tampered,
            }
        )
        .is_err()
    );
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().attempt += 1;
    fixture.store().save(&state).unwrap();
    assert!(
        plan_rewrite_unified_rule(
            fixture.context(),
            RewriteUnifiedRulePlanOptions {
                file: fixture.proposal.clone(),
                evidence_id: page.evidence_id,
            }
        )
        .is_err()
    );
    fixture.confirm();
    let first = fixture.evidence();
    let page = continuation(&fixture, &first.facts, "next_page");
    let plan = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id: page.evidence_id.clone(),
        },
    )
    .unwrap();
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(
        plan_rewrite_unified_rule(
            fixture.context(),
            RewriteUnifiedRulePlanOptions {
                file: fixture.proposal.clone(),
                evidence_id: page.evidence_id,
            }
        )
        .is_err()
    );
    let fresh_first = fixture.evidence();
    let stale_policy_page = continuation(&fixture, &fresh_first.facts, "next_page");
    assert_eq!(
        stale_policy_page.facts["policy_freshness"]["requires_fresh_replay"],
        true
    );
    assert!(stale_policy_page.applicable_rule_planners.is_empty());
    assert!(
        plan_rewrite_unified_rule(
            fixture.context(),
            RewriteUnifiedRulePlanOptions {
                file: fixture.proposal.clone(),
                evidence_id: stale_policy_page.evidence_id,
            }
        )
        .is_err()
    );
}
