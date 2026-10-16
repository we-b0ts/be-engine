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
            hint: "A Redis key mismatch is a candidate, not proof of generation. Trace Source and declare a redis_sequence effect with an exact endpoint/database/API and explicit key_contract in a self-contained rule. time_window validates one canonical numeric segment against each inbound request clock (fixed five-second window); INCRBY/EXPIRE order, increment, TTL and stable segments remain exact. SET capture requires one fixed-affix template, binding and bounded hex/base64url/uuid_v4 format; JSON identity references and request-relative time fields are checked atomically with the key. Failed comparisons commit no bindings. Later key/JSON references require a committed case-local binding; transform: sha256 verifies derivation only from that binding. Digest-shaped captures alone are opaque identities. Apply the first capture and fresh Replay before planning a later reference; fingerprint-only key_bindings carry the proof. Each field has one explicit owner; key contracts and identity captures cannot overlap on the same command/key. Authentication, lanes, stable fields and finite consumption remain strict. See docs/redis-key-contracts.md; recordings remain unchanged.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_response_jwt(facts) {
        hints.push(RewriteRuleHint {
            capability: "response_jwt".into(), rule: "response-jwt".into(),
            hint: "Response observations contain a compact signed JWT candidate (HS256/HS384/HS512/RS256), directly or inside an HTTP(S) URL query; decoding alone does not prove generation or a valid signature. Trace source issuance, key precedence, nonce generation and expiry derivation. Declare a response_jwt effect with pointer, algorithm, signing_key and fresh Source proof in a self-contained rule. An explicit url_query_param extracts one unique query value and keeps all other URL bytes exact. nonces declare typed /jti and /nonce formats (uuid_v4, or base64url with decoded_bytes). Optional expires_at selects an RFC3339 or explicit unix_seconds field equal to the signed exp; issued_at and ttl can enforce signed iat and expiry derivation. RS256 recorded_mysql selects one exact case-local public-key dependency and binds kid/algorithm; it never decrypts a private key. Inspect signing_key_discovery; plan verifies both signatures, stable claims, nonce consistency and request-relative times within five seconds. Do not exempt whole URLs or tokens with random. Apply and fresh Replay; recordings and authentication remain unchanged.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_header_difference(facts, 0) {
        hints.push(RewriteRuleHint {
            capability: "response_header_date".into(), rule: "header-date".into(),
            hint: "A response header difference can contain a current-date filename. Review header_date_candidates, then prove the source date format and timezone. Declare response_header_date with the header, format, timezone and optional parameter (filename also checks filename*) in a self-contained rule, then plan, apply and complete fresh Replay. Each side must use its own request's calendar date; disposition, filename prefix/extension, other parameters, multiplicity and body remain checked. Existing recordings are reusable.".into(),
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
            hint: "If a source-generated identity differs in dependency requests, trace its generator, capture location, lifetime and every reference. Declare an identity effect with exact resource/operation, typed capture slot and separately proven references; format and SHA256 derivation are explicit contracts. MySQL time locations require distinct proven bindings, including clock groups. Failed speculative matches commit no identity. Stable fields, authentication/database, finite consumption and case ownership remain checked. Use the same self-contained rule file and plan/apply transaction; apply requires genuine Replay, and hashes or opaque bytes never imply generation.".into(),
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
            hint: "Review protected dependency_request_candidates and trace Source generation. Declare value rules through surface/resource/operation/slot/codec/contract; JSON and typed PB use the same time and unordered core. Use native redis_sequence, http_request or mysql_values only for protocol-owned arguments, signatures, multipart or stateful relationships. Explicit script identity, key/options, stable arguments, auth/database, multipart parts, query and finite consumption remain native evidence. Time fields declare format, dependency/case anchor and proven clock_group; naive timestamps require utc_offset. Startup keys resolve from immutable startup inputs without exposing bytes. Write the rule file, plan against the current evidence, inspect the complete Source coverage and retained failed Target witnesses, apply and finish genuine Replay.".into(),
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
        let request = json!({"dependency_request_candidates":[{"capability":"redis_key_request"}]});
        let hints = hints(root, QUERY_DIRTY_CLUSTERS, &request);
        assert!(
            hints
                .iter()
                .any(|hint| hint.capability == "redis_key_request"
                    && hint.hint.contains("not proof")
                    && hint.hint.contains("key_contract"))
        );
    }
}
