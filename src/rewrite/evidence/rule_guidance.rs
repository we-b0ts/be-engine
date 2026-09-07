use super::super::evidence_model::{RewriteApplicableRulePlanner, RewriteRuleHint};
use super::*;

pub(super) fn rule_hints(
    target_root: &Path,
    query_kind: &str,
    facts: &Value,
) -> Vec<RewriteRuleHint> {
    if query_kind == QUERY_REPRESENTATIVES {
        let codecs = response_body::codec_candidates(facts);
        if codecs.is_empty() {
            return Vec::new();
        }
        let configured = response_body::configured(facts);
        return codecs
            .into_iter()
            .map(|codec| {
                let hint = match (configured, codec) {
                    (true, "protobuf") => "The response body codec is protobuf. Review unordered_path_candidates as mechanical candidates; they do not authorize order-insensitive comparison. Apply only fields whose order is irrelevant in the source contract, with field_path, semantic display_path, explicit element_type, and source_evidence.",
                    (true, "hessian2") => "The response body codec is Hessian2. Candidates identify lists or joined strings but do not authorize order-insensitive comparison. Apply only source-proven sets; joined strings also require the reviewed separator.",
                    (false, "protobuf") => "The exact response body is a protobuf candidate. The response rule planner can configure the codec and verify the existing focused-E2E or comparison artifacts offline without recording new traffic.",
                    (false, "hessian2") => "The exact response body is a Hessian2 candidate. The response rule planner can configure the codec and verify the existing focused-E2E or comparison artifacts offline without recording new traffic.",
                    _ => "The exact response body has a supported codec candidate. Review the body evidence before applying a response rule.",
                };
                RewriteRuleHint {
                    capability: codec.to_string(),
                    rule: "response_body".to_string(),
                    hint: hint.to_string(),
                    help: super::super::action::command(
                        target_root,
                        vec![
                            "rule".to_string(),
                            "plan".to_string(),
                            "--body-codec".to_string(),
                            codec.to_string(),
                            "--help".to_string(),
                        ],
                        Vec::new(),
                    ),
                }
            })
            .collect();
    }
    if query_kind == QUERY_IP_CAPTURE {
        return vec![RewriteRuleHint {
            capability: "http_response_url".to_string(), rule: "recorder_capture".to_string(),
            hint: "Trace the reported IP to source code. HTTP JSON URL fields can use response rewrite pointers. plan-http-response first returns a path review, including existing rules with the same authority, method and pointers. Check source path construction even for the first rule; choose an exact path or pattern, then explicitly submit --pattern-checked and a brief --source-evidence note. Inspect the merge diff, apply and verify fresh recording before submitting a remaining capture defect. Static or hardcoded addresses require source configuration or a source mock.".to_string(),
            help: super::super::action::command(target_root, vec!["recorder-capture".into(), "plan-http-response".into(), "--help".into()], Vec::new()),
        }];
    }
    if query_kind != QUERY_DIRTY_CLUSTERS {
        return Vec::new();
    }
    let has_memcached = facts
        .get("clusters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|cluster| cluster.get("protocol").and_then(Value::as_str) == Some("memcached"));
    let mut hints = Vec::new();
    if facts["egress_rejections"]["rejected_packets_in_samples"]
        .as_u64()
        .is_some_and(|count| count > 0)
    {
        hints.push(RewriteRuleHint {
            capability:"http_response_url".into(), rule:"recorder_capture".into(),
            hint:"Rejected outbound packet counts accompany this response/dependency failure. They identify no IP or origin. Inspect source dependency calls; a source-proven upstream JSON IP URL can use response rewrite pointers. Run route --cause unrecorded-ip with current evidence once the endpoint and source are known, then follow plan/apply and recording refresh before submitting a remaining system defect.".into(),
            help: super::super::action::command(target_root, vec!["recorder-capture".into(),"plan-http-response".into(),"--help".into()],Vec::new()),
        });
    }
    if has_memcached {
        hints.push(RewriteRuleHint {
        capability: "memcached".to_string(),
        rule: "protobuf-timestamp".to_string(),
        hint: "Investigate this rule when a Memcached SET value contains a protobuf varint field generated from the current Unix time."
            .to_string(),
        help: super::super::action::command(
            target_root,
            vec![
                "dependency-rule".to_string(),
                "plan".to_string(),
                "memcached".to_string(),
                "protobuf-timestamp".to_string(),
                "--help".to_string(),
            ],
            Vec::new(),
        ),
    });
    }
    hints
}

pub(super) fn applicable_rule_planners(
    target_root: &Path,
    issue_kind: RewriteIssueKind,
    query_kind: &str,
    facts: &Value,
    evidence_id: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    let mut planners = Vec::new();
    if query_kind == QUERY_JWT_TIME_VALIDITY {
        let mut seen = std::collections::BTreeSet::new();
        for candidate in facts["candidates"].as_array().into_iter().flatten() {
            let header = candidate["header"].as_str().unwrap_or_default();
            let algorithm = candidate["algorithm"].as_str().unwrap_or_default();
            if !seen.insert((header, algorithm)) {
                continue;
            }
            planners.push(RewriteApplicableRulePlanner {
                kind: "request_rule".into(),
                capability: "jwt_time_shift".into(),
                evidence_id: evidence_id.into(),
                command: super::super::action::command(
                    target_root,
                    vec![
                        "rule".into(),
                        "plan".into(),
                        "--request-kind".into(),
                        "jwt".into(),
                        "--evidence-id".into(),
                        evidence_id.into(),
                        "--header".into(),
                        header.into(),
                        "--algorithm".into(),
                        algorithm.into(),
                        "--help".into(),
                    ],
                    Vec::new(),
                ),
            });
        }
        return planners;
    }

    if query_kind == QUERY_IP_CAPTURE && facts["reported"]["origin"] == "http-response" {
        for candidate in facts["http_response_url_candidates"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let mut arguments = vec![
                "recorder-capture".to_string(),
                "plan-http-response".to_string(),
                "--evidence-id".to_string(),
                evidence_id.to_string(),
            ];
            for (flag, field) in [
                ("--case-id", "case_id"),
                ("--response-id", "response_id"),
                ("--name", "authority"),
                ("--pointer", "pointer"),
            ] {
                arguments.extend([
                    flag.to_string(),
                    candidate[field].as_str().unwrap_or_default().to_string(),
                ]);
            }
            arguments.extend([
                "--path-pattern".to_string(),
                format!(
                    "{} {}",
                    candidate["method"].as_str().unwrap_or_default(),
                    candidate["path"].as_str().unwrap_or_default()
                ),
            ]);
            planners.push(RewriteApplicableRulePlanner {
                kind: "recorder_capture".to_string(),
                capability: "http_response_url".to_string(),
                evidence_id: evidence_id.to_string(),
                command: super::super::action::command(target_root, arguments, Vec::new()),
            });
        }
    }
    if query_kind == QUERY_REPRESENTATIVES
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Comparison
        )
    {
        let configured = response_body::configured(facts);
        planners.extend(
            response_body::codec_candidates(facts)
                .into_iter()
                .map(|codec| {
                    let mut arguments = vec![
                        "rule".to_string(),
                        "plan".to_string(),
                        "--evidence-id".to_string(),
                        evidence_id.to_string(),
                        "--body-codec".to_string(),
                        codec.to_string(),
                    ];
                    if configured {
                        arguments.push("--help".to_string());
                    }
                    RewriteApplicableRulePlanner {
                        kind: "response_body".to_string(),
                        capability: codec.to_string(),
                        evidence_id: evidence_id.to_string(),
                        command: super::super::action::command(target_root, arguments, Vec::new()),
                    }
                }),
        );
    }
    if issue_kind == RewriteIssueKind::Response
        && query_kind == QUERY_SOURCE_PROCESS_TRAFFIC
        && has_redis_bootstrap_traffic(facts)
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_ownership".to_string(),
            capability: "redis_bootstrap".to_string(),
            evidence_id: evidence_id.to_string(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".to_string(),
                    "plan".to_string(),
                    "redis".to_string(),
                    "--help".to_string(),
                ],
                Vec::new(),
            ),
        });
    }
    if issue_kind != RewriteIssueKind::Dependency || query_kind != QUERY_DIRTY_CLUSTERS {
        return planners;
    }
    let protocols = facts
        .get("clusters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|cluster| cluster.get("protocol").and_then(Value::as_str))
        .filter(|protocol| {
            matches!(
                *protocol,
                "http" | "memcached" | "motan" | "redis" | "mysql"
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    planners.extend(
        protocols
            .into_iter()
            .map(|protocol| RewriteApplicableRulePlanner {
                kind: "dependency_ownership".to_string(),
                capability: protocol.to_string(),
                evidence_id: evidence_id.to_string(),
                command: super::super::action::command(
                    target_root,
                    vec![
                        "dependency-rule".to_string(),
                        "plan".to_string(),
                        protocol.to_string(),
                        "--help".to_string(),
                    ],
                    Vec::new(),
                ),
            }),
    );
    planners
}

pub(in crate::rewrite) fn supports_response_body_codec(
    facts: &Value,
    codec: ResponseBodyCodec,
) -> bool {
    let expected = match codec {
        ResponseBodyCodec::Protobuf => "protobuf",
        ResponseBodyCodec::Hessian2 => "hessian2",
        _ => return false,
    };
    response_body::codec_candidates(facts).contains(&expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_evidence_offers_discovery_but_requires_source_evidence_for_a_plan() {
        let root = Path::new("/target");
        let facts = serde_json::json!({"egress_rejections":{"rejected_packets_in_samples":2},"clusters":[]});
        let hints = rule_hints(root, QUERY_DIRTY_CLUSTERS, &facts);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].capability, "http_response_url");
        assert!(hints[0].help.argv.contains(&"plan-http-response".into()));
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
