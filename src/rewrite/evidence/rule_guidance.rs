use super::super::evidence_model::{RewriteApplicableRulePlanner, RewriteRuleHint};
use super::*;
mod generated_values;
mod http_header_timestamp;
pub(super) use generated_values::has_response_jwt;

pub(super) fn http_header_timestamp_candidates(facts: &Value) -> Vec<Value> {
    http_header_timestamp::candidates(facts)
}

pub(super) fn rule_hints(
    target_root: &Path,
    query_kind: &str,
    facts: &Value,
) -> Vec<RewriteRuleHint> {
    if let Some(hint) = super::policy_freshness::refresh_hint(target_root, facts) {
        return vec![hint];
    }
    if query_kind == QUERY_REPRESENTATIVES {
        let mut hints = generated_values::hints(target_root, query_kind, facts);
        let codecs = response_body::codec_candidates(facts);
        if codecs.is_empty() {
            return hints;
        }
        let configured = response_body::configured(facts);
        hints.extend(codecs
            .into_iter()
            .map(|codec| {
                let hint = match (configured, codec) {
                    (true, "protobuf") => "The response body codec is protobuf. Review unordered_path_candidates as mechanical candidates; they do not authorize order-insensitive comparison. Apply only fields whose order is irrelevant in the source contract, with field_path, semantic display_path, explicit element_type, and source_evidence.",
                    (true, "hessian2") => "The response body codec is Hessian2. Candidates identify lists or joined strings but do not authorize order-insensitive comparison. Apply only source-proven sets; joined strings also require the reviewed separator.",
                    (false, "protobuf") => "The exact response body is a protobuf candidate. The response rule planner can configure the codec and verify the existing focused-E2E artifacts offline without recording new traffic.",
                    (false, "hessian2") => "The exact response body is a Hessian2 candidate. The response rule planner can configure the codec and verify the existing focused-E2E artifacts offline without recording new traffic.",
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
            );
        return hints;
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
    let mut hints = generated_values::hints(target_root, query_kind, facts);
    if facts["clusters"].as_array().is_some_and(|clusters| {
        clusters.iter().any(|cluster| {
            cluster["protocol"] == "redis"
                && cluster["reason"] == "unused_recorded"
                && cluster["operations"].as_object().is_some_and(|ops| {
                    ops.keys().any(|command| {
                        matches!(
                            command.as_str(),
                            "GET" | "DEL" | "LRANGE" | "EVALSHA" | "SCRIPT"
                        )
                    })
                })
        })
    }) {
        hints.push(RewriteRuleHint {
            capability: "api_triggered_process_traffic".into(), rule: "api-triggered".into(),
            hint: "Unused Redis GET/DEL/LRANGE/EVALSHA and linked SCRIPT EXISTS can be another API's asynchronous work. DEL key_sequence binds every key to one identity; script binds an exact digest/KEYS envelope to identity_argv_index. Trace source spawning and cleanup; identify an explicit single-row MySQL INSERT and its integer identity before proposing trigger_source. request_body_json selects typed fields in the trigger REQUEST BODY (JSON Pointer), never query or response. A shared task ID is a candidate, not ownership proof. Plan verifies unique recorded origins, foreign-case references and conflicts; it preserves trigger/resource API calls, target failures and finite responses. Existing complete recordings are reusable. See docs/api-triggered-process-traffic.md.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(),"plan".into(),"redis".into(),"api-triggered".into(),"--help".into()], Vec::new()),
        });
    }

    if facts["clusters"].as_array().is_some_and(|clusters| {
        clusters
            .iter()
            .any(|c| c["protocol"] == "mysql" && c["reason"] == "unused_recorded")
    }) {
        hints.push(RewriteRuleHint {
            capability: "api_triggered_process_traffic".into(), rule: "mysql-api-triggered".into(),
            hint: "Discovery only: unused MySQL calls are not evidence of process ownership. First trace request-owned calls, including ORM expiration/refresh after commit or rollback and later attribute access; see mysql_unused_diagnosis. A source-proven detached API task can produce unused MySQL SELECTs/UPDATEs inside another API case. Trace direct and indirect terminal-result collectors, not only polling/cancel endpoints. Use mysql --trigger-source JSON --identity-value-index N to bind a SELECT template '?' slot to one uniquely captured INSERT identity. request_body_json selects the trigger request BODY. Plan verifies identity and foreign-case evidence; source_evidence must prove caller ownership. Complete transaction boundaries require --include-transaction-boundaries and wire/status evidence; explicit read-only --transaction-member selectors cover only helpers inside that anchored transaction. Same-name ordinary SELECT rules with the exact selector may be narrowed; target failures and direct trigger/resource calls remain required. See docs/api-triggered-process-traffic.md.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(),"plan".into(),"mysql".into(),"--help".into()], Vec::new()),
        });
    }

    if facts["http_header_timestamp_candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        hints.push(RewriteRuleHint {
            capability: "http_header_timestamp".into(), rule: "header-timestamp".into(),
            hint: "HTTP request header differences contain timestamp-format candidates near each dependency request's own start. Trace SDK/source generation and confirm host, port, method, path and header. Use dependency-rule plan http header-timestamp with --timestamp-format and source evidence, apply, then fresh Replay. The tolerance is fixed at five seconds; primary API request clocks are not used. Presence, multiplicity, invalid times and ordinary identity headers remain checked.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(), "plan".into(), "http".into(), "header-timestamp".into(), "--help".into()], Vec::new()),
        });
    }
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
        hints.push(RewriteRuleHint {
            capability: "redis_cross_case".into(), rule: "cross-case".into(),
            hint: "If an existing case-scoped GET/HGET time-shift rule describes a shared source cache, inspect the completed recording for one exact read in a sibling case. Confirm the same host, port, database, key and field, then trace cache initialization, refresh and side effects in source. A finalized unmatched Replay report and source evidence are required for dependency-rule plan redis cross-case; apply requires fresh Replay.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(), "plan".into(), "redis".into(), "cross-case".into(), "--help".into()], Vec::new()),
        });
    }
    if facts["redis_lock_candidates"]["candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        hints.push(RewriteRuleHint {
            capability: "redis_lock".into(), rule: "lock".into(),
            hint: "Inspect redis_lock_candidates for token-only SET NX or same-key script/DELEX argument differences. Trace source random ownership tokens and conditional release; the command shape does not prove lock semantics. Configure host, port and a bounded key selector through dependency-rule plan redis lock, apply and fresh Replay. One rule preserves token equality across references without configuring a UUID format or script SHA. Keys, expiry/options, scripts, database/authentication and finite exchange consumption remain strict.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(),"plan".into(),"redis".into(),"lock".into(),"--help".into()], Vec::new()),
        });
    }
    if facts["redis_publish_candidates"]["candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        hints.push(RewriteRuleHint {
            capability: "redis_publish".into(), rule: "publish".into(),
            hint: "Inspect redis_publish_candidates for an exact-channel PUBLISH payload differing only at one ASCII UUID v4 position. Trace that identity's random generation and lifetime in source. Use dependency-rule plan redis publish with --uuid-field (an exact marker such as host_id) or --uuid-index, apply and fresh Replay. Channel, all other payload bytes, database/authentication, identity consistency and finite consumption stay strict; no message codec is assumed.".into(),
            help: super::super::action::command(target_root, vec!["dependency-rule".into(),"plan".into(),"redis".into(),"publish".into(),"--help".into()], Vec::new()),
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
    if facts["policy_freshness"]["requires_fresh_replay"] == true {
        return Vec::new();
    }
    let mut planners =
        generated_values::planners(target_root, issue_kind, query_kind, facts, evidence_id);
    if query_kind == QUERY_DIRTY_CLUSTERS
        && matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
        )
        && facts["redis_publish_candidates"]["candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        && facts["redis_publish_candidates"]["omitted_candidates"] == 0
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "redis_publish".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "redis".into(),
                    "publish".into(),
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
        && facts["redis_lock_candidates"]["candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        && facts["redis_lock_candidates"]["omitted_candidates"] == 0
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "redis_lock".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "redis".into(),
                    "lock".into(),
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
        && facts["http_header_timestamp_candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    {
        planners.push(RewriteApplicableRulePlanner {
            kind: "dependency_value".into(),
            capability: "http_header_timestamp".into(),
            evidence_id: evidence_id.into(),
            command: super::super::action::command(
                target_root,
                vec![
                    "dependency-rule".into(),
                    "plan".into(),
                    "http".into(),
                    "header-timestamp".into(),
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
                } else if let Some(raw_header) = candidate["raw_header"].as_str() {
                    ("--header", raw_header)
                } else {
                    ("--header", candidate["header"].as_str().unwrap_or_default())
                };
            let algorithm = candidate["algorithm"].as_str().unwrap_or_default();
            let raw_header = candidate["raw_header"].is_string();
            if !seen.insert((selector_flag, selector, algorithm, raw_header)) {
                continue;
            }
            let mut arguments = vec![
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
            ];
            if raw_header {
                arguments.extend(["--header-scheme".into(), "raw".into()]);
            }
            planners.push(RewriteApplicableRulePlanner {
                kind: "request_rule".into(),
                capability: "jwt_time_shift".into(),
                evidence_id: evidence_id.into(),
                command: super::super::action::command(target_root, arguments, Vec::new()),
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
    if query_kind == QUERY_REPRESENTATIVES && matches!(issue_kind, RewriteIssueKind::Response) {
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
            clusters.iter().any(|cluster| {
                cluster["protocol"] == "mysql" && cluster["reason"] == "unmatched_target"
            })
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
                &serde_json::json!({"clusters":[{"protocol":"mysql", "reason":"unmatched_target"}]}),
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
                planner.command.argv.contains(&"lock".into())
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
                planner.command.argv.contains(&"publish".into())
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
