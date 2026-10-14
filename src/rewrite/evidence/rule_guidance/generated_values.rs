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
            Value::String(raw) => {
                crate::request_rules::jwt::Token::parse(raw)
                    .ok()
                    .flatten()
                    .is_some()
                    || crate::request_rules::jwt::url_query::has_candidate(raw)
            }
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
    if query == QUERY_REPRESENTATIVES && has_response_jwt(facts) {
        hints.push(RewriteRuleHint {
            capability: "response_jwt".into(), rule: "response-jwt".into(),
            hint: "Response observations contain a compact HMAC JWT candidate, directly or inside an HTTP(S) URL query; decoding alone does not prove generation or a valid signature. Trace source issuance, key precedence, nonce generation and expiry derivation. Use rule plan --response-jwt with pointer, algorithm, signing_key_source and source_evidence. An explicit url_query_param extracts one unique query value and keeps all other URL bytes exact. dynamic_claims supports legacy UUID v4 [/jti] or typed /jti and /nonce formats (uuid_v4, or base64url with decoded_bytes). Optional expires_at selects an RFC3339 response field whose floored Unix seconds must equal the same token's exp. Inspect signing_key_discovery; plan verifies both signatures, stable claims, nonce consistency and request-relative times within five seconds. Do not exempt whole URLs or tokens with random. Apply and fresh Replay; recordings and authentication remain unchanged.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_header_difference(facts, 0) {
        hints.push(RewriteRuleHint {
            capability: "response_header_date".into(), rule: "header-date".into(),
            hint: "A response header difference can contain a current-date filename. Review header_date_candidates, then prove the source date format and timezone. Use rule plan --header-date with the header and optional parameter (filename also checks filename*), apply, and fresh Replay. Each side must use its own request's calendar date; disposition, filename prefix/extension, other parameters, multiplicity and body remain checked. Existing recordings are reusable.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    if query == QUERY_DIRTY_CLUSTERS
        && (facts["dynamic_capture_candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
            || facts["clusters"].as_array().is_some_and(|items| {
                items.iter().any(|cluster| {
                    cluster["protocol"] == "mysql" && cluster["reason"] == "unmatched_target"
                })
            }))
    {
        hints.push(RewriteRuleHint {
            capability: "dynamic_value".into(), rule: "dynamic-value".into(),
            hint: "If a source-generated identity differs in decoded dependency requests, trace its generator and lifetime. Inspect dynamic_capture_candidates for Redis/HTTP witnesses. Use rule plan --dynamic-value with one MySQL SQL value, Redis SET/HSET value or RPUSH element, or HTTP JSON pointer/path_segment capture, exact allowed host/port endpoints, and source evidence. The applied dependency_rules entry uses kind: dynamic_value. HTTP path_segment captures declare exact, random hex and UTC timestamp fields; timestamps use each dependency request start with the shared inclusive five-second window. Add SQL reference endpoints to targets. Path witnesses do not prove generation, and uploaded bytes and headers remain checked. HTTP and Redis JSON captures support value_type: integer for one explicit JSON pointer; numeric values retain JSON integer type and are never inferred as automatic references. String remains the default. Format is optional. Apply and fresh Replay bind one consistent case-local identity across decoded requests without listing each reference. Fixed values, authentication/database, finite consumption and case ownership remain strict; hashes and opaque binary payloads are not inferred.".into(),
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
            hint: "Review dependency_request_candidates and trace source generation before using rule plan --dependency-request RULE_JSON. Reuse dependency_rules protocol/target/case selectors: Redis commands.argument_values select SET/RPUSH JSON time fields, ZADD/ZREMRANGEBYSCORE time parameters, or explicit EVAL/EVALSHA ARGV time locations with script identity; HTTP multipart.boundary: normalize selects only transport delimiters. HTTP json.time maps exact JSON pointers to time: preserve_relative and format: unix_seconds, unix_milliseconds or rfc3339; these use independently captured dependency request starts, with completion-minus-duration fallback for older source captures. Redis time fields use recorded/replay inbound request anchors. No configured clock or offset is needed; the fixed inclusive 5s window and common shift preserve related parameter differences. HTTP JSON time rules keep other fields, query and identity headers exact and reject overlapping normalizations. Inspect signing_key_discovery for available startup variable names and mount paths without secret values. SET JWT fields require a declared target startup signing_key_source, algorithm and relative_to JSON time field; optional dynamic_claims: [/jti] requires a case-local UUID v4 binding. Stable JSON, keys, other arguments, signatures, JWT lifetimes, multipart part bytes/order, headers/auth, case ownership and finite consumption remain strict. Planning verifies protected current target witnesses against immutable recordings; apply then fresh Replay. No raw JWT/key/file bytes are exposed in discovery.".into(),
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
            command: super::super::super::action::command(
                root,
                vec![
                    "rule".into(),
                    "plan".into(),
                    "--evidence-id".into(),
                    evidence_id.into(),
                    "--help".into(),
                ],
                Vec::new(),
            ),
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
        assert!(hints[0].hint.contains("url_query_param"));
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
    }
}
