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
            hint: "Response observations contain a compact signed JWT candidate (HS256/HS384/HS512/RS256), directly or inside an HTTP(S) URL query; decoding alone does not prove generation or a valid signature. Define named signatures profiles once, with kind, algorithm and private startup key provenance. Global json.fields kind: jwt uses the explicit default profile, or signature: <name>; it authenticates HMAC signatures, NumericDates, stable/declared claims and complete-token correspondence across carriers. Global RS256 fails closed; existing exact native recorded-public-key assertions remain available. The retired identity formats: [jwt] authoring syntax is rejected; use kind: jwt with a named profile, not a keyless bypass. Generic URL query fields reuse the same global formats. API request headers/query/body explicitly authorize re-signing through existing strict input owners. API response positions retain necessary query token selection, nonce echo and signed expiry companion checks. Inspect signing_key_discovery and immutable Source facts, publish no key bytes, and finish genuine Replay.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(), "plan".into(), "--help".into()], Vec::new()),
        });
    }
    if query == QUERY_REPRESENTATIVES && has_header_difference(facts, 0) {
        hints.push(RewriteRuleHint {
            capability: "response_header_date".into(), rule: "header-date".into(),
            hint: "A response header difference can contain a current-date filename. Review header_date_candidates, then prove the source date format and timezone. Declare response_header_date with the header, format, timezone and optional parameter (filename also checks filename*) in a self-contained rule, then plan, apply and complete fresh Replay. Each side must use its own request calendar date; disposition, filename prefix/extension, other parameters, multiplicity and body remain checked. Ordinary scalar header formats instead belong under http.headers. Header presence, count and order cannot be waived, including SDK metadata headers. Existing recordings are reusable.".into(),
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
            hint: "If an identity differs, inspect complete Source locations and declare its format once per global json.fields pointer, mysql.tables scalar column, redis.keys scalar value or http.headers name. JSON is detected across supported carriers without API, table-column or cache-key codec copies. Equal complete typed Source values require equal Target values internally; distinct identities cannot merge. No authored binding, field_ref or generator-first capture is needed. Reads reuse established Target values and anchor unknown historical inputs. Equal values, paired nulls and paired absence are implicit; one-sided presence and unselected content remain strict. Failed candidates commit no identities. Additional native contracts remain for unsupported compound formats and cryptographic transformations. Plan with independent Source proof and finish genuine Replay.".into(),
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
            hint: "Review protected dependency_request_candidates and trace Source behavior. Use the single json.fields map for decoded JSON, mysql.tables patterns/fields for scalar columns not inferred from SQL temporal metadata, redis.keys for scalar values, key formats and ordered commands, and http.headers for scalar headers. Ordinary formats need no API, resource alias, binding, clock_group or relation declaration. Unknown encodings remain exact. Protocol TTLs retain their native units and expiry checks. localcache.requests marks finite shared initialization reads; HTTP entries require an explicit host. process_dependencies.tasks.<Source-task-name>.requests groups actual process dependencies across protocols. Neither lifetime declaration relaxes request content or creates response data. Multipart, DOCX, WSS path derivation and encrypted AES envelopes still require their existing native typed contracts; no automatic global support is implied. Named signatures centralize algorithm/key definitions; global kind: jwt authenticates through its named profile, while API positions retain explicit input rewriting and extra nonce/expiry checks. Review complete Source coverage and independent Target witnesses, plan/apply, then finish genuine Replay. See docs/resource-field-contracts.md and docs/redis-generated-requests.md.".into(),
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
}
