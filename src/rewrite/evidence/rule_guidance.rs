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
                    (_, "docx") => "Both response bodies are DOCX OPC packages. Review package-part differences and add only source-proven dynamic XML timestamps; ZIP entry timestamps and compression metadata are container metadata, while every decompressed part remains exact.",
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
    if facts["clusters"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|c| c["protocol"] == "http" && c["reason"] == "unmatched_target")
    }) {
        hints.push(RewriteRuleHint {
            capability: "http_json_unordered".into(), rule: "unordered".into(),
            hint: "Inspect http_unordered_candidates for same-request JSON array reorderings. A candidate is not proof that order is non-contractual: trace source collection construction and downstream use. Return the exact endpoint, JSON Pointer and source evidence to the coordinator for dependency-rule plan http unordered / apply and fresh Replay. Old reports require fresh Replay; response unordered rules do not change outbound dependency matching.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(), "plan".into(), "http".into(), "unordered".into(), "--help".into()], Vec::new()),
        });
        hints.push(RewriteRuleHint {
            capability: "http_cross_case".into(), rule: "cross-case".into(),
            hint: "Inspect cross_case_candidates. A matching exchange in another case is a candidate, not proof of sharing. Trace source shared initialization/cache/refresh and side effects. Unavailable request identity requires fresh Replay; do not change target behavior or treat the call as background work.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(), "plan".into(), "http".into(), "cross-case".into(), "--help".into()], Vec::new()),
        });
    }
    if facts["clusters"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|c| c["protocol"] == "redis" && c["reason"] == "unmatched_target")
    }) {
        hints.push(RewriteRuleHint {
            capability: "redis_value_unordered".into(), rule: "unordered".into(),
            hint: "Inspect redis_unordered_candidates. Redis string-write values automatically compare JSON objects by content; JSON arrays and Protobuf repeated fields require source-proven unordered semantics. Confirm host, port, exact key or key affixes, field path and Protobuf element type. Use dependency-rule plan redis unordered, apply and fresh Replay; this never changes dependency ownership. Old reports require fresh Replay.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(), "plan".into(), "redis".into(), "unordered".into(), "--help".into()], Vec::new()),
        });
    }
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
    if query_kind == QUERY_DIRTY_CLUSTERS
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
        && facts["http_unordered_candidates"]["candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        && facts["http_unordered_candidates"]["omitted_candidates"] == 0
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "http_json_unordered".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "http".into(),
                    "unordered".into(),
                    "--evidence-id".into(),
                    evidence_id.into(),
                    "--help".into(),
                ],
                Vec::new(),
            ),
        });
    }
    if query_kind == QUERY_DIRTY_CLUSTERS
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
        && facts["redis_unordered_candidates"]["candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        && facts["redis_unordered_candidates"]["omitted_candidates"] == 0
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "redis_value_unordered".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "redis".into(),
                    "unordered".into(),
                    "--evidence-id".into(),
                    evidence_id.into(),
                    "--help".into(),
                ],
                Vec::new(),
            ),
        });
    }

    if query_kind == QUERY_DIRTY_CLUSTERS
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
        && facts["cross_case_candidates"]["candidates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|c| c["request_match"] == "verified"))
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_scope".into(),
            capability: "http_cross_case".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "http".into(),
                    "cross-case".into(),
                    "--evidence-id".into(),
                    evidence_id.into(),
                    "--help".into(),
                ],
                Vec::new(),
            ),
        });
    }
    if query_kind == QUERY_JWT_TIME_VALIDITY {
        let mut seen = std::collections::BTreeSet::new();
        for candidate in facts["candidates"].as_array().into_iter().flatten() {
            let (selector_flag, selector) =
                if let Some(query_param) = candidate["query_param"].as_str() {
                    ("--query-param", query_param)
                } else {
                    ("--header", candidate["header"].as_str().unwrap_or_default())
                };
            let algorithm = candidate["algorithm"].as_str().unwrap_or_default();
            if !seen.insert((selector_flag, selector, algorithm)) {
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
                        selector_flag.into(),
                        selector.into(),
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
                    if configured || codec == "docx" {
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
    if query_kind == QUERY_DIRTY_CLUSTERS
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
        && facts["clusters"].as_array().is_some_and(|clusters| {
            clusters
                .iter()
                .any(|cluster| cluster["protocol"] == "mysql")
        })
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "mysql_sql_time".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "mysql-time".into(),
                    "--help".into(),
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
                &serde_json::json!({"clusters":[{"protocol":"mysql"}]}),
                "current",
            );
            let time = planners
                .iter()
                .find(|p| p.capability == "mysql_sql_time")
                .unwrap();
            assert_eq!(time.evidence_id, "current");
            assert!(time.command.argv.contains(&"mysql-time".into()));
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
            assert!(planner.command.argv.contains(&"cross-case".into()));
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
            assert!(planner.command.argv.contains(&"unordered".into()));
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
            assert!(planner.command.argv.contains(&"unordered".into()));
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
