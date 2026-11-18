//! Mechanism-specific explanations share one typed rule authoring transaction.
use super::super::evidence_model::{RewriteApplicableRulePlanner, RewriteRuleHint};
use super::*;
mod generated_values;
#[cfg(test)]
mod registered_tests;
mod resource_fields;
pub use generated_values::has_response_jwt;

pub fn help(root: &Path) -> super::super::model::RewriteCommandSpec {
    super::super::action::command(
        root,
        vec!["rule".into(), "plan".into(), "--help".into()],
        vec![],
    )
}

pub fn plan_command(root: &Path, evidence: &str) -> super::super::model::RewriteCommandSpec {
    super::super::action::command(
        root,
        vec![
            "rule".into(),
            "plan".into(),
            "--file".into(),
            "<rule.yaml>".into(),
            "--evidence".into(),
            evidence.into(),
        ],
        vec![],
    )
}

pub fn nonempty(value: &Value) -> bool {
    value.as_array().is_some_and(|items| !items.is_empty())
}

pub fn cluster(facts: &Value, protocol: &str, reason: &str) -> bool {
    facts["clusters"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["protocol"] == protocol && item["reason"] == reason)
    })
}

pub fn complete_candidates(facts: &Value, name: &str) -> bool {
    nonempty(&facts[name]["candidates"]) && facts[name]["omitted_candidates"] == 0
}

pub fn try_rule_hints(root: &Path, query: &str, facts: &Value) -> Result<Vec<RewriteRuleHint>> {
    if let Some(hint) = super::policy_freshness::refresh_hint(root, facts) {
        return Ok(vec![hint]);
    }
    let mut hints = registered_hints(root, facts);
    let mut context = facts.clone();
    context["query"] = json!(query);
    for finding in
        crate::value_extensions::analyze_context(crate::value_extensions::policies(), &context)?
    {
        hints.push(RewriteRuleHint {
            capability: finding.policy.clone(),
            rule: finding.policy,
            hint: finding.hint,
            help: help(root),
        });
    }
    hints.extend(generated_values::hints(root, query, facts));
    hints.extend(resource_fields::hints(root, query, facts));
    let mut add = |capability: &str, rule: &str, instruction: &str| {
        hints.push(RewriteRuleHint {
        capability: capability.into(), rule: rule.into(),
        hint: format!("{instruction} Return a traffic-policy/v3 proposal with fresh Source file:line proof and the current evidence ID. Use rule plan --file <rule.yaml> --evidence <evidence-id>, review the plan, apply, then complete its genuine Replay or recording obligations."),
        help: help(root),
    })
    };
    if query == QUERY_UNIFIED_RULE_CANDIDATES
        && facts["source_entry"]["locations"]
            .as_array()
            .is_some_and(|bindings| {
                bindings
                    .iter()
                    .any(|b| b["location"]["slot"].get("sse_data").is_some())
            })
    {
        add(
            "sse_data_contract",
            "sse_data",
            "Review source_entry.locations and declare JSON field formats once in root json.fields, including terminal output. The same map applies to ordinary bodies, SSE data, SQL JSON and cache JSON. Declare time formats, duration units, unordered collections or generated identity formats from Source behavior. The engine derives complete typed Source equality and distinctness internally across carriers. Immutable and dependency-delivered inputs remain anchored. Missing events, event order and unselected values stay strict. Drafts never infer identity permission. See docs/sse-value-contracts.md.",
        );
    }
    if query == QUERY_REPRESENTATIVES {
        for codec in response_body::codec_candidates(facts) {
            add(
                codec,
                "response_body",
                match codec {
                    "protobuf" => {
                        "The focused-E2E response has a protobuf codec candidate. Declare typed numeric field paths and types before selecting source-proven unordered fields. Encoded bytes alone do not prove a schema or ordering intent."
                    }
                    "hessian2" => {
                        "The focused-E2E response has a Hessian2 candidate. Select source-proven sets or joined strings through a typed response_body effect; joined strings require the proven separator."
                    }
                    "docx" => {
                        "The response has DOCX OPC package differences. Trace the differing part and element to Source before proposing a shared DOCX format and the API codec position. Consult docs/content-policy-layout.md; package members and unselected XML remain strict."
                    }
                    _ => {
                        "Review the complete focused-E2E response and trace Source encoding before declaring a codec or a field contract."
                    }
                },
            );
        }
        return Ok(hints);
    }
    if query == QUERY_IP_CAPTURE {
        return Ok(hints);
    }
    if query == QUERY_JWT_TIME_VALIDITY && nonempty(&facts["candidates"]) {
        add(
            "jwt_time_shift",
            "input_token_rebase",
            "Trace the inbound token location and signing key in the frozen startup inputs. A named signature profile and API request position authorize re-signing with preserved relative time. Source signature and lifetime evidence are required; consult docs/signature-profiles.md for the supported declaration.",
        );
        return Ok(hints);
    }
    if query == QUERY_SOURCE_PROCESS_TRAFFIC && has_redis_bootstrap_traffic(facts) {
        add(
            "redis_bootstrap",
            "process_ownership",
            "Trace the named Source startup task and complete initialization inventory before proposing process_dependencies. Inspect existing lifetime declarations; unused calls alone do not prove process ownership.",
        );
        return Ok(hints);
    }
    if query != QUERY_DIRTY_CLUSTERS {
        return Ok(hints);
    }
    if cluster(facts, "redis", "unused_recorded") || cluster(facts, "mysql", "unused_recorded") {
        add(
            "api_triggered_process_traffic",
            "process_ownership",
            "Unused dependency calls are not evidence of process ownership and can be detached API work. Prove the unique API origin, typed request-body predicates and captured SQL identity; linked scripts, transaction members and resource calls retain their own proof. process_owned is an ownership effect and cannot be inferred from a value codec or a shared task ID. Target failures and finite consumption stay required.",
        );
    }
    for protocol in ["http", "redis"] {
        if cluster(facts, protocol, "unmatched_target") {
            add(
                if protocol == "http" {
                    "http_cross_case"
                } else {
                    "redis_cross_case"
                },
                "cross-case",
                "A matching exchange in another case is only a sharing candidate. Trace Source initialization, refresh and side effects before proposing localcache.requests. A value format cannot authorize reuse or manufacture a response.",
            );
        }
    }
    if facts["clusters"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["protocol"] == "memcached"))
    {
        add(
            "memcached",
            "value-contract",
            "Investigate Memcached SET value differences through the same JSON or typed PB value contract used by Redis. Choose an explicit operation/key and logical field; protocol presence alone proves neither a time strategy nor an ordering exemption.",
        );
    }
    Ok(hints)
}

#[cfg(any(test, feature = "test-support"))]
pub fn rule_hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    try_rule_hints(root, query, facts).expect("registered evidence analysis succeeds")
}

pub fn registered_hints(root: &Path, facts: &Value) -> Vec<RewriteRuleHint> {
    let mut seen = std::collections::BTreeSet::new();
    facts["policy_findings"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(facts["candidates"].as_array().into_iter().flatten())
        .filter_map(|candidate| {
            let policy = candidate["policy"]
                .as_str()
                .or_else(|| candidate["mechanism"].as_str())?;
            let hint = candidate["hint"].as_str()?;
            if !seen.insert((policy, hint)) {
                return None;
            }
            Some(RewriteRuleHint {
                capability: policy.into(),
                rule: policy.into(),
                hint: hint.into(),
                help: help(root),
            })
        })
        .collect()
}

pub fn applicable_rule_planners(
    root: &Path,
    issue: RewriteIssueKind,
    query: &str,
    facts: &Value,
    evidence: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    if facts["policy_freshness"]["requires_fresh_replay"] == true {
        return vec![];
    }
    let mut planners = generated_values::planners(root, issue, query, facts, evidence);
    planners.extend(resource_fields::planners(
        root, issue, query, facts, evidence,
    ));

    let mut add = |kind: &str, capability: &str| {
        planners.push(RewriteApplicableRulePlanner {
            kind: kind.into(),
            capability: capability.into(),
            evidence_id: evidence.into(),
            command: plan_command(root, evidence),
        })
    };
    if query == QUERY_REPRESENTATIVES && issue == RewriteIssueKind::Response {
        for codec in response_body::codec_candidates(facts) {
            add("response_body", codec);
        }
    }
    if query == QUERY_JWT_TIME_VALIDITY && nonempty(&facts["candidates"]) {
        add("request_rule", "jwt_time_shift");
    }
    if query == QUERY_IP_CAPTURE
        && facts["reported"]["origin"] == "http-response"
        && nonempty(&facts["http_response_url_candidates"])
    {
        add("recorder_capture", "http_response_url");
    }
    if query == QUERY_SOURCE_PROCESS_TRAFFIC
        && issue == RewriteIssueKind::Response
        && has_redis_bootstrap_traffic(facts)
    {
        add("dependency_ownership", "redis_bootstrap");
    }
    if query != QUERY_DIRTY_CLUSTERS
        || !matches!(
            issue,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
    {
        return planners;
    }
    for (name, capability) in [
        ("http_unordered_candidates", "resource_field_contract"),
        ("redis_unordered_candidates", "resource_field_contract"),
    ] {
        if complete_candidates(facts, name) {
            add("dependency_value", capability);
        }
    }
    if facts["cross_case_candidates"]["candidates"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["request_match"] == "verified"))
    {
        add("dependency_scope", "http_cross_case");
    }
    if super::protocol_diagnosis::has_value_difference(facts) {
        add("dependency_value", "resource_field_contract");
    }
    if issue == RewriteIssueKind::Dependency {
        let protocols = facts["clusters"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|cluster| cluster["protocol"].as_str())
            .filter(|p| matches!(*p, "http" | "memcached" | "motan" | "redis" | "mysql"))
            .collect::<std::collections::BTreeSet<_>>();
        for protocol in protocols {
            add("dependency_ownership", protocol);
        }
    }
    planners
}

pub fn supports_response_body_codec(facts: &Value, codec: ResponseBodyCodec) -> bool {
    let expected = match codec {
        ResponseBodyCodec::Protobuf => "protobuf",
        ResponseBodyCodec::Hessian2 => "hessian2",
        ResponseBodyCodec::Docx => "docx",
        _ => return false,
    };
    response_body::codec_candidates(facts).contains(&expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_time_planner_is_discoverable_for_response_failures_with_dependency_evidence() {
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Replay,
            RewriteIssueKind::Dependency,
        ] {
            let planners = applicable_rule_planners(
                Path::new("/target"),
                kind,
                QUERY_DIRTY_CLUSTERS,
                &serde_json::json!({"clusters":[{"protocol":"mysql", "reason":"unmatched_target"}]}),
                "current",
            );
            let time = planners
                .iter()
                .find(|p| p.capability == "resource_field_contract")
                .unwrap();
            assert_eq!(time.evidence_id, "current");
            assert!(time.command.argv.contains(&"--file".into()));
        }
        assert!(
            applicable_rule_planners(
                Path::new("/target"),
                RewriteIssueKind::Response,
                QUERY_DIRTY_CLUSTERS,
                &serde_json::json!({"clusters":[{"protocol":"redis"}]}),
                "current"
            )
            .iter()
            .all(|p| p.capability != "resource_field_contract")
        );
    }

    #[test]
    fn counter_evidence_offers_discovery_but_requires_source_evidence_for_a_plan() {
        let root = Path::new("/target");
        let facts = serde_json::json!({"egress_rejections":{"rejected_packets_in_samples":2},"clusters":[]});
        let hints = rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].capability, "documents");
        assert!(hints[0].help.argv.contains(&"rule".into()));
        assert!(hints[0].hint.contains("route --cause unrecorded-ip"));
        assert!(
            applicable_rule_planners(
                root,
                RewriteIssueKind::Response,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "current"
            )
            .is_empty()
        );
        for facts in [
            serde_json::json!({}),
            serde_json::json!({"egress_rejections":{"rejected_packets_in_samples":0,"unavailable_cases":1}}),
        ] {
            assert!(rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts).is_empty());
        }
    }
}

#[cfg(test)]
mod cross_case_tests {
    use super::*;
    #[test]
    fn cross_case_discovery_requires_verified_candidates_even_during_response_failure() {
        let root = Path::new("/target");
        let mut facts = serde_json::json!({"clusters": [{"protocol":"http", "reason":"unmatched_target"}],
            "cross_case_candidates": {"candidates": [{"request_match":"unavailable"}]}});
        assert!(
            rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|hint| hint.rule == "cross-case")
        );
        assert!(
            applicable_rule_planners(
                root,
                RewriteIssueKind::Response,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "ev"
            )
            .is_empty()
        );
        facts["cross_case_candidates"]["candidates"][0]["request_match"] =
            serde_json::json!("verified");
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            let planners = applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "ev");
            let planner = planners
                .iter()
                .find(|p| p.capability == "http_cross_case")
                .unwrap();
            assert_eq!(planner.kind, "dependency_scope");
            assert!(planner.command.argv.contains(&"--file".into()));
        }
    }
}

#[cfg(test)]
mod http_unordered_tests {
    use super::*;
    #[test]
    fn unordered_is_discoverable_before_responses_pass_but_planning_requires_candidates() {
        let root = Path::new("/target");
        let mut facts =
            serde_json::json!({"clusters":[{"protocol":"http","reason":"unmatched_target"}]});
        assert!(
            rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|h| h.rule == "unordered")
        );
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            assert!(
                !applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "ev")
                    .iter()
                    .any(|p| p.capability == "resource_field_contract")
            );
        }
        facts["http_unordered_candidates"] = serde_json::json!({"candidates":[{"selector":{"pointer":"/department_ids"}}],"omitted_candidates":0});
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            let planners = applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "ev");
            let planner = planners
                .iter()
                .find(|p| p.capability == "resource_field_contract")
                .unwrap();
            assert_eq!(planner.kind, "dependency_value");
            assert!(planner.command.argv.contains(&"--file".into()));
            assert!(planner.command.argv.contains(&"ev".into()));
        }
        facts["http_unordered_candidates"]["omitted_candidates"] = serde_json::json!(1);
        assert!(
            !applicable_rule_planners(
                root,
                RewriteIssueKind::Dependency,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "ev"
            )
            .iter()
            .any(|p| p.capability == "resource_field_contract")
        );
    }
}

#[cfg(test)]
mod redis_unordered_tests {
    use super::*;
    #[test]
    fn unordered_is_discoverable_before_responses_pass_but_planning_requires_candidates() {
        let root = Path::new("/target");
        let mut facts =
            serde_json::json!({"clusters":[{"protocol":"redis","reason":"unmatched_target"}]});
        assert!(
            rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|h| h.rule == "unordered")
        );
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            assert!(
                !applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "ev")
                    .iter()
                    .any(|p| p.capability == "resource_field_contract")
            );
        }
        facts["redis_unordered_candidates"] = serde_json::json!({"candidates":[{"selector":{"field":{"codec":"json","pointer":"/ids"}}}],"omitted_candidates":0});
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            let planners = applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "ev");
            let planner = planners
                .iter()
                .find(|p| p.capability == "resource_field_contract")
                .unwrap();
            assert_eq!(planner.kind, "dependency_value");
            assert!(planner.command.argv.contains(&"--file".into()));
            assert!(planner.command.argv.contains(&"ev".into()));
        }
        facts["redis_unordered_candidates"]["omitted_candidates"] = serde_json::json!(1);
        assert!(
            !applicable_rule_planners(
                root,
                RewriteIssueKind::Dependency,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "ev"
            )
            .iter()
            .any(|p| p.capability == "resource_field_contract")
        );
    }
}
