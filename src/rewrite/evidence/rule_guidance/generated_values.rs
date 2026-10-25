//! Difference-triggered authoring hints; source proof and plan validation remain mandatory.
use super::*;

fn has_header_difference(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::Object(fields) => {
            fields
                .get("pointer")
                .and_then(Value::as_str)
                .is_some_and(|pointer| pointer.starts_with("$headers/"))
                || fields
                    .get("header_date_candidates")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())
                || fields
                    .values()
                    .any(|value| has_header_difference(value, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .any(|value| has_header_difference(value, depth + 1)),
        _ => false,
    }
}

pub(in crate::rewrite::evidence) fn has_response_jwt(value: &Value) -> bool {
    fn contains(value: &Value, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        match value {
            Value::String(raw) => crate::ResponseJwtRule::is_candidate(raw),
            Value::Object(fields) => {
                fields.get("jwt_candidate") == Some(&Value::Bool(true))
                    || fields.values().any(|value| contains(value, depth + 1))
            }
            Value::Array(items) => items.iter().any(|value| contains(value, depth + 1)),
            _ => false,
        }
    }
    contains(value, 0)
}

pub(super) fn hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    let mut hints = Vec::new();
    if query == QUERY_DIRTY_CLUSTERS
        && facts["dependency_request_candidates"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["capability"] == "redis_key_request")
            })
    {
        hints.push(RewriteRuleHint {
            capability: "redis_key_request".into(), rule: "dependency-request".into(),
            hint: "A Redis key mismatch is a candidate, not proof of generation. Declare bounded key patterns under redis.keys without resource or database selectors. Use key_format with an ordered commands list only when Source proves a generated key segment or command sequence; scalar values use kind/formats and complete JSON values automatically use json.fields. Command argument time declarations contain one format; equal Source instants imply equal Target instants internally, without authored bindings or clock groups. Script commands retain their exact script identity. Stable key segments, increments, TTL/options, authentication, actual endpoint/database pairing, lane order and finite consumption remain checked. Native derivation contracts remain necessary for transformations not covered by these formats. Failed candidates publish no identity relations. See docs/redis-key-contracts.md; recordings remain unchanged.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_response_jwt(facts) {
        hints.push(RewriteRuleHint {
            capability: "response_jwt".into(), rule: "response-jwt".into(),
            hint: "A recorded response contains a JWT candidate; decoding does not prove generation or a valid signature. Trace Source signing and key configuration using signing_key_discovery without exposing key bytes. Named signatures profiles and global JWT formats cover ordinary tokens; API response positions retain additional signed relationships. Consult docs/signature-profiles.md only after confirming the Source behavior, then return a Source-backed proposal for plan/apply and genuine Replay.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_header_difference(facts, 0) {
        hints.push(RewriteRuleHint {
            capability: "response_header_date".into(), rule: "header-date".into(),
            hint: "Inspect the header difference and header_date_candidates, then trace Source construction. If Source proves a generated filename date, preserve its API scope and propose the response header position described in docs/content-policy-layout.md. Stable filename text, other parameters and header presence/count/order remain required. A differing header alone authorizes no exception. Submit Source proof for plan/apply and complete fresh Replay.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    if query == QUERY_DIRTY_CLUSTERS
        && (facts["dynamic_capture_candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
            || super::super::mysql_diagnosis::has_sql_mismatch(facts))
    {
        hints.push(RewriteRuleHint {
            capability: "dynamic_value".into(), rule: "dynamic-value".into(),
            hint: "Inspect the reported identity candidates and trace Source generation and reuse before choosing a format. Reuse the existing global declarations; Source-proven composite strings can use a global template while retaining literal text and complete identity values. Source-known outbound path positions belong under http.requests. Consult docs/content-policy-layout.md for those authoring choices. Equal values, nulls and absent fields do not prove generation. Return independent Source proof for plan/apply and fresh Replay.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    if query == QUERY_DIRTY_CLUSTERS
        && facts["dependency_request_candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    {
        hints.push(RewriteRuleHint {
            capability: "dependency_request".into(), rule: "dependency-request".into(),
            hint: "Inspect the protected dependency_request_candidates and compare them with Source behavior. Reuse existing formats and preserve protocol, resource, content and finite-call checks. Complete supported multipart requests already compare their ordered parts; outer-boundary differences need no policy exception. For a Source-proven format or carrier gap, consult docs/content-policy-layout.md and return the smallest declaration with Source proof for plan/apply. Missing drafts, equal responses and null values grant no permission; complete genuine Replay after application.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    hints
}

pub(super) fn planners(
    root: &Path,
    kind: RewriteIssueKind,
    query: &str,
    facts: &Value,
    evidence_id: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    if !matches!(
        kind,
        RewriteIssueKind::Response | RewriteIssueKind::Replay | RewriteIssueKind::Dependency
    ) {
        return Vec::new();
    }
    hints(root, query, facts)
        .into_iter()
        .map(|hint| RewriteApplicableRulePlanner {
            kind: hint.capability.clone(),
            capability: hint.capability,
            evidence_id: evidence_id.into(),
            command: super::plan_command(root, evidence_id),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn response_jwt_guidance_is_candidate_only_and_does_not_echo_tokens() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let raw = format!(
            "{}.{}.AA",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"example","exp":2000}"#)
        );
        let facts = json!({"representative":{"response_difference":{"expected":{"value":raw}}}});
        let hints = hints(Path::new("/target"), QUERY_REPRESENTATIVES, &facts);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].capability, "response_jwt");
        assert!(!serde_json::to_string(&hints).unwrap().contains(&raw));
        assert!(hints[0].hint.contains("does not prove"));
        assert!(!has_response_jwt(&json!({"value":"opaque-access-token"})));
        let url = format!("/api/download?other=a%2Fb&token={raw}#content");
        let facts = json!({"representative":{"response_difference":{"actual":{"value":url}}}});
        let hints = super::hints(Path::new("/target"), QUERY_REPRESENTATIVES, &facts);
        assert_eq!(hints[0].capability, "response_jwt");
        assert!(hints[0].hint.contains("signatures profiles"));
        assert!(hints[0].hint.contains("API response positions"));
        let rendered = serde_json::to_string(&hints).unwrap();
        assert!(!rendered.contains(&raw));
        assert!(!rendered.contains(&url));
        let facts = json!({"representative":{"pointer":"/access_token","expected":{"presence":"present","value":"<redacted string bytes=500>","jwt_candidate":true}}});
        let planners = planners(
            Path::new("/target"),
            RewriteIssueKind::Response,
            QUERY_REPRESENTATIVES,
            &facts,
            "evidence",
        );
        assert!(planners.iter().any(|p| p.capability == "response_jwt"));
    }

    #[test]
    fn header_rules_are_offered_without_body_codecs_and_identity_rules_require_capture_evidence() {
        let root = Path::new("/target");
        let facts = json!({"representative":{"pointer":"$headers/content-disposition"}});
        assert!(
            super::super::rule_hints(root, QUERY_REPRESENTATIVES, &facts)
                .iter()
                .any(|hint| hint.capability == "response_header_date")
        );
        let facts = json!({"clusters":[{"protocol":"mysql","reason":"unmatched_target"}]});
        assert_eq!(hints(root, QUERY_DIRTY_CLUSTERS, &facts).len(), 1);
        assert!(hints(root, QUERY_REPRESENTATIVES, &json!({})).is_empty());
        assert_eq!(
            hints(
                root,
                QUERY_DIRTY_CLUSTERS,
                &json!({"dynamic_capture_candidates":[{"capture":{"protocol":"redis"}}]})
            )
            .len(),
            1
        );
        assert_eq!(
            hints(
                root,
                QUERY_DIRTY_CLUSTERS,
                &json!({"dynamic_capture_candidates":[{"capture":{"protocol":"http"}}]})
            )
            .len(),
            1
        );
        let request =
            json!({"dependency_request_candidates":[{"capability":"redis_json_request"}]});
        assert_eq!(
            hints(root, QUERY_DIRTY_CLUSTERS, &request)[0].capability,
            "dependency_request"
        );
        let request = json!({"dependency_request_candidates":[{"capability":"redis_key_request"}]});
        let hints = hints(root, QUERY_DIRTY_CLUSTERS, &request);
        assert!(
            hints
                .iter()
                .any(|hint| hint.capability == "redis_key_request"
                    && hint.hint.contains("not proof")
                    && hint.hint.contains("key_format"))
        );
    }

    #[test]
    fn current_carrier_guidance_keeps_existing_planners_without_recommending_retired_authoring() {
        let root = Path::new("/target");
        let header = json!({"representative":{"pointer":"$headers/content-disposition",
            "header_date_candidates":[{"parameter":"filename","format":"%Y-%m-%d"}]}});
        let hinted = hints(root, QUERY_REPRESENTATIVES, &header);
        assert_eq!(hinted[0].capability, "response_header_date");
        assert!(hinted[0].hint.contains("API scope"));
        assert!(hinted[0].hint.contains("docs/content-policy-layout.md"));
        assert!(hinted[0].hint.contains("Source proof"));
        assert!(!hinted[0].hint.contains("Declare response_header_date"));
        assert!(!hinted[0].hint.contains("timezone"));
        assert_eq!(
            planners(
                root,
                RewriteIssueKind::Response,
                QUERY_REPRESENTATIVES,
                &header,
                "current"
            )[0]
            .evidence_id,
            "current"
        );

        let multipart = json!({"dependency_request_candidates":[{"capability":"http_multipart"}]});
        let hinted = hints(root, QUERY_DIRTY_CLUSTERS, &multipart);
        assert_eq!(hinted.len(), 1);
        assert_eq!(hinted[0].capability, "dependency_request");
        assert!(
            hinted[0]
                .hint
                .contains("outer-boundary differences need no policy exception")
        );
        assert!(!hinted[0].hint.contains("multipart_boundary"));
        assert!(!hinted[0].hint.contains("native typed contracts"));
        assert!(hinted[0].help.argv.contains(&"--help".into()));
        let available = planners(
            root,
            RewriteIssueKind::Dependency,
            QUERY_DIRTY_CLUSTERS,
            &multipart,
            "current",
        );
        assert_eq!(available[0].capability, "dependency_request");
        assert!(
            available[0]
                .command
                .argv
                .ends_with(&["--evidence".into(), "current".into()])
        );
    }

    #[test]
    fn compound_format_guidance_requires_existing_candidate_evidence_not_value_appearance() {
        let root = Path::new("/target");
        for value in [
            Value::Null,
            json!("wss://example/sessions/random?ticket=random"),
            json!("c29tZS1iYXNlNjQ"),
        ] {
            let facts = json!({"representative":{"pointer":"/url",
                "expected":{"presence":"present","value":value},
                "actual":{"presence":"present","value":value}}});
            assert!(hints(root, QUERY_REPRESENTATIVES, &facts).is_empty());
            assert!(hints(root, QUERY_DIRTY_CLUSTERS, &facts).is_empty());
        }
        let candidate = json!({"dynamic_capture_candidates":[{"capture":{"protocol":"http"}}]});
        let hinted = hints(root, QUERY_DIRTY_CLUSTERS, &candidate);
        assert_eq!(hinted.len(), 1);
        assert_eq!(hinted[0].capability, "dynamic_value");
        assert!(hinted[0].hint.contains("global template"));
        assert!(hinted[0].hint.contains("http.requests"));
        assert!(hinted[0].hint.contains("Source proof"));
        assert!(
            !hinted[0].hint.contains("template:"),
            "routine hints should not embed a configuration example"
        );
    }
}
