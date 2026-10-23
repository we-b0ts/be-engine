//! Mechanism-specific explanations share one typed rule authoring transaction.
use super::super::evidence_model::{RewriteApplicableRulePlanner, RewriteRuleHint};
use super::*;
mod generated_values;
mod http_client_metadata;
mod http_header_timestamp;
mod stateful_dependencies;
pub(super) use generated_values::has_response_jwt;

pub(super) fn http_header_timestamp_candidates(facts: &Value) -> Vec<Value> {
    http_header_timestamp::candidates(facts)
}

fn help(root: &Path) -> super::super::model::RewriteCommandSpec {
    super::super::action::command(
        root,
        vec!["rule".into(), "plan".into(), "--help".into()],
        vec![],
    )
}

fn plan_command(root: &Path, evidence: &str) -> super::super::model::RewriteCommandSpec {
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

fn nonempty(value: &Value) -> bool {
    value.as_array().is_some_and(|items| !items.is_empty())
}

fn cluster(facts: &Value, protocol: &str, reason: &str) -> bool {
    facts["clusters"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["protocol"] == protocol && item["reason"] == reason)
    })
}

fn complete_candidates(facts: &Value, name: &str) -> bool {
    nonempty(&facts[name]["candidates"]) && facts[name]["omitted_candidates"] == 0
}

pub(super) fn rule_hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    if let Some(hint) = super::policy_freshness::refresh_hint(root, facts) {
        return vec![hint];
    }
    let mut hints = generated_values::hints(root, query, facts);
    hints.extend(stateful_dependencies::hints(root, query, facts));
    let mut add = |capability: &str, rule: &str, instruction: &str| {
        hints.push(RewriteRuleHint {
        capability: capability.into(), rule: rule.into(),
        hint: format!("{instruction} Write a self-contained traffic-policy/v1 rule with fresh Source file:line proof: at most three file references and a causal fact of at most 200 UTF-8 bytes. Use one document source_revision. Use rule plan --file <rule.yaml> --evidence <evidence-id>, inspect the immutable plan, apply, then complete its genuine Replay or recording obligations."),
        help: help(root),
    })
    };
    if query == QUERY_UNIFIED_RULE_CANDIDATES
        && facts["source_entry"]["bindings"]
            .as_array()
            .is_some_and(|bindings| {
                bindings
                    .iter()
                    .any(|b| b["binding"]["slot"].get("sse_data").is_some())
            })
    {
        add(
            "sse_data_contract",
            "sse_data",
            "Review source_entry.bindings for exact slot.sse_data event/json_type selectors. Contract pointers address data JSON. Time drafts require Source clock proof; generated identities require Source generator/lifetime proof, explicit prefix/format and the same binding across all referring events/pointers, including terminal output. Identity permissions are never inferred as candidates. Missing events and event order remain strict and require Target investigation. See docs/sse-value-contracts.md.",
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
                        "DOCX OPC package differences can use source-proven XML timestamp fields. Each decompressed part and its native package association remain evidence; declare the exact part and element."
                    }
                    _ => {
                        "Review the complete focused-E2E response and trace Source encoding before declaring a codec or a field contract."
                    }
                },
            );
        }
        return hints;
    }
    if query == QUERY_IP_CAPTURE {
        add(
            "http_response_url",
            "recorder_capture",
            "Trace the reported IP to Source generation. A capture_http_response effect must declare exact authority, method, path and proven URL pointers. Review path construction and existing scope, then verify a fresh recording. Static addresses require Source configuration or a Source mock.",
        );
        return hints;
    }
    if query == QUERY_JWT_TIME_VALIDITY && nonempty(&facts["candidates"]) {
        add(
            "jwt_time_shift",
            "input_token_rebase",
            "Trace the inbound token location and signing key in the frozen startup inputs. Declare input_jwt with an explicit algorithm and relative-time contract; Source signature and lifetime evidence are required.",
        );
        return hints;
    }
    if query == QUERY_SOURCE_PROCESS_TRAFFIC && has_redis_bootstrap_traffic(facts) {
        add(
            "redis_bootstrap",
            "process_ownership",
            "Trace process startup and initialization ownership in Source. A process_owned effect requires its Source revision and complete acquisition inventory; unused calls alone do not prove ownership.",
        );
        return hints;
    }
    if query != QUERY_DIRTY_CLUSTERS {
        return hints;
    }
    if cluster(facts, "redis", "unused_recorded") || cluster(facts, "mysql", "unused_recorded") {
        add(
            "api_triggered_process_traffic",
            "process_ownership",
            "Unused dependency calls are not evidence of process ownership and can be detached API work. Prove the unique API origin, typed request-body predicates and captured SQL identity; linked scripts, transaction members and resource calls retain their own proof. process_owned is an ownership effect and cannot be inferred from a value codec or a shared task ID. Target failures and finite consumption stay required.",
        );
    }
    if nonempty(&facts["http_header_timestamp_candidates"]) {
        add(
            "http_header_timestamp",
            "header-timestamp",
            "Trace source SDK header generation and declare a typed http_request header time contract with its own dependency request anchor, exact endpoint, method and path. Header presence, multiplicity and authentication remain checked.",
        );
    }
    if http_client_metadata::has_difference(facts) {
        add(
            "http_client_metadata",
            "http_client_metadata",
            "SDK metadata header differences remain strict until explicitly authorized. protected=false concerns confidentiality, not acceptance. Trace both the SDK generator and the downstream consumer/middleware. If these exact names have no application, authentication, routing or idempotency role, declare http_client_metadata with API, endpoint, method, path and exact supported header names. The audit retains differences as observations with a rule ID; do not emulate another language's SDK identity. Source proof, complete per-name witnesses and fresh Replay are required. See docs/http-client-metadata.md.",
        );
    }
    for (protocol, capability) in [
        ("http", "http_json_unordered"),
        ("redis", "redis_value_unordered"),
    ] {
        if cluster(facts, protocol, "unmatched_target") {
            add(
                capability,
                "unordered",
                "Inspect protected Source/Target value differences. Declare the dependency.request surface, exact resource and value slot, explicit JSON or PB codec, and only Source-proven unordered logical fields. A response rule does not authorize outbound request changes.",
            );
            add(
                if protocol == "http" {
                    "http_cross_case"
                } else {
                    "redis_cross_case"
                },
                "cross-case",
                "A matching exchange in another case is a sharing candidate. A finite_sharing effect needs complete Source inventory plus proof of shared initialization, refresh and side effects. Value contracts do not change ownership, snapshot admission or available responses.",
            );
        }
    }
    if nonempty(&facts["redis_lock_candidates"]["candidates"]) {
        add(
            "redis_lock",
            "lock",
            "Trace Source token generation and conditional release before declaring redis_lock. Matching SET NX or script shape is a candidate. Exact key/options, script identity, database/authentication, linked token equality and finite consumption remain checked.",
        );
    }
    if nonempty(&facts["redis_publish_candidates"]["candidates"]) {
        add(
            "redis_publish",
            "publish",
            "Trace the PUBLISH identity generator and lifetime before declaring redis_publish_identity with its bounded exact channel and explicit identity position. All other bytes and case-local identity consistency remain checked.",
        );
    }
    if facts["egress_rejections"]["rejected_packets_in_samples"]
        .as_u64()
        .is_some_and(|n| n > 0)
    {
        add(
            "http_response_url",
            "recorder_capture",
            "Packet rejection counts identify neither an IP nor its origin. Inspect Source calls and use route --cause unrecorded-ip with current evidence when the endpoint is known. A capture_http_response effect requires Source URL provenance and a fresh recording.",
        );
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
    hints
}

pub(super) fn applicable_rule_planners(
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
    planners.extend(stateful_dependencies::planners(
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
        ("redis_publish_candidates", "redis_publish"),
        ("redis_lock_candidates", "redis_lock"),
        ("http_unordered_candidates", "http_json_unordered"),
        ("redis_unordered_candidates", "redis_value_unordered"),
    ] {
        if complete_candidates(facts, name) {
            add("dependency_value", capability);
        }
    }
    if nonempty(&facts["http_header_timestamp_candidates"]) {
        add("dependency_value", "http_header_timestamp");
    }
    if http_client_metadata::has_difference(facts) {
        add("dependency_value", "http_client_metadata");
    }
    if facts["cross_case_candidates"]["candidates"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["request_match"] == "verified"))
    {
        add("dependency_scope", "http_cross_case");
    }
    if super::mysql_diagnosis::has_sql_mismatch(facts) {
        add("dependency_value", "mysql_sql_time");
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

pub(in crate::rewrite) fn supports_response_body_codec(
    facts: &Value,
    codec: ResponseBodyCodec,
) -> bool {
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
                .find(|p| p.capability == "mysql_sql_time")
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
            .all(|p| p.capability != "mysql_sql_time")
        );
    }

    #[test]
    fn counter_evidence_offers_discovery_but_requires_source_evidence_for_a_plan() {
        let root = Path::new("/target");
        let facts = serde_json::json!({"egress_rejections":{"rejected_packets_in_samples":2},"clusters":[]});
        let hints = rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].capability, "http_response_url");
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
                    .any(|p| p.capability == "http_json_unordered")
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
                .find(|p| p.capability == "http_json_unordered")
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
            .any(|p| p.capability == "http_json_unordered")
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
                    .any(|p| p.capability == "redis_value_unordered")
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
                .find(|p| p.capability == "redis_value_unordered")
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
            .any(|p| p.capability == "redis_value_unordered")
        );
    }
}

#[cfg(test)]
mod redis_lock_tests {
    use super::*;
    #[test]
    fn lock_hint_requires_witness_and_planner_requires_complete_candidates_for_each_issue_kind() {
        let root = Path::new("/target");
        let mut facts =
            serde_json::json!({"clusters":[{"protocol":"redis","reason":"unmatched_target"}]});
        assert!(
            !rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|h| h.rule == "lock")
        );
        facts["redis_lock_candidates"] = serde_json::json!({"candidates":[{"selector":{"host":"redis.test","port":6379,"key":"lock:1"}}],"omitted_candidates":0});
        assert!(
            rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|h| h.rule == "lock")
        );
        for kind in [
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Response,
            RewriteIssueKind::Replay,
        ] {
            let planners =
                applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "current");
            let planner = planners
                .iter()
                .find(|p| p.capability == "redis_lock")
                .unwrap();
            assert!(
                planner.command.argv.contains(&"--file".into())
                    && planner.command.argv.contains(&"current".into())
            );
            assert!(
                !applicable_rule_planners(root, kind, QUERY_REPRESENTATIVES, &facts, "current")
                    .iter()
                    .any(|p| p.capability == "redis_lock")
            );
        }
        facts["redis_lock_candidates"]["omitted_candidates"] = 1.into();
        assert!(
            !applicable_rule_planners(
                root,
                RewriteIssueKind::Dependency,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "current"
            )
            .iter()
            .any(|p| p.capability == "redis_lock")
        );
    }
}

#[cfg(test)]
mod redis_publish_tests {
    use super::*;
    #[test]
    fn publish_planner_requires_complete_uuid_witnesses_and_current_evidence() {
        let root = Path::new("/target");
        let mut facts =
            serde_json::json!({"clusters":[{"protocol":"redis","reason":"unmatched_target"}]});
        assert!(
            !rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|hint| hint.rule == "publish")
        );
        facts["redis_publish_candidates"] = serde_json::json!({"candidates":[{"selector":{"host":"redis.test","port":6379,"channel":"events","uuid_index":0}}],"omitted_candidates":0});
        assert!(
            rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts)
                .iter()
                .any(|hint| hint.rule == "publish")
        );
        for kind in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            let planners =
                applicable_rule_planners(root, kind, QUERY_DIRTY_CLUSTERS, &facts, "current");
            let planner = planners
                .iter()
                .find(|planner| planner.capability == "redis_publish")
                .unwrap();
            assert!(
                planner.command.argv.contains(&"--file".into())
                    && planner.command.argv.contains(&"current".into())
            );
            assert!(
                !applicable_rule_planners(root, kind, QUERY_REPRESENTATIVES, &facts, "current")
                    .iter()
                    .any(|planner| planner.capability == "redis_publish")
            );
        }
        facts["redis_publish_candidates"]["omitted_candidates"] = 1.into();
        assert!(
            !applicable_rule_planners(
                root,
                RewriteIssueKind::Dependency,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "current"
            )
            .iter()
            .any(|planner| planner.capability == "redis_publish")
        );
    }
}
