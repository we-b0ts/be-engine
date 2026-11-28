//! Authentication comparison for unresolved HTTP header and query slots.
use serde_json::Value;
use traffic_contract::compare::{self, AnchorClocks, Comparison, LeafContext, VerifiedField};
use traffic_policy_value::{
    auth::{Carrier, Matcher, RULE_ID},
    formats::url::Document as UrlDocument,
    host::NativeRequestFallback,
};
use traffic_protocol::message::ProjectedMessage;

const AUTHORIZATION: &str = "/headers/authorization/0";
const QUERY: &str = "/uri/query/";

pub(super) struct Fallback(pub Matcher);

impl NativeRequestFallback for Fallback {
    fn compare(
        &self,
        source: &ProjectedMessage,
        target: &ProjectedMessage,
        unmatched: &mut Vec<&str>,
        clocks: AnchorClocks,
    ) -> Comparison {
        let mut result = Comparison::default();
        if source.structure["headers"]["authorization"].as_u64() == Some(1) {
            unmatched.retain(|location| {
                if *location != AUTHORIZATION {
                    return true;
                }
                let Some(compared) =
                    self.compare_slot(source, target, location, Carrier::Authorization, clocks)
                else {
                    return true;
                };
                result.merge_and_validate(compared);
                false
            });
        }

        if !unmatched.iter().any(|location| location.starts_with(QUERY)) {
            return result;
        }
        let (Some(source_uri), Some(target_uri)) = (query_uri(source), query_uri(target)) else {
            return result;
        };
        let Some(presigned) = presigned_query(&source_uri) else {
            return result;
        };
        if presigned {
            // A presigned request covers the complete URI, including its other
            // query values. Interpret its signature fields as a single group.
            if let Some(compared) =
                self.compare_values(&source_uri, &target_uri, Carrier::Value, clocks)
            {
                result.merge_and_validate(compared);
                unmatched.retain(|location| !location.starts_with(QUERY));
            }
            return result;
        }
        unmatched.retain(|location| {
            if !location.starts_with(QUERY) {
                return true;
            }
            let Some(compared) =
                self.compare_slot(source, target, location, Carrier::QueryParameter, clocks)
            else {
                return true;
            };
            result.merge_and_validate(compared);
            false
        });
        result
    }
}

impl Fallback {
    fn compare_slot(
        &self,
        source: &ProjectedMessage,
        target: &ProjectedMessage,
        location: &str,
        carrier: Carrier,
        clocks: AnchorClocks,
    ) -> Option<Comparison> {
        let source = std::str::from_utf8(&source.values.get(location)?.bytes).ok()?;
        let target = std::str::from_utf8(&target.values.get(location)?.bytes).ok()?;
        let mut result = self.compare_values(source, target, carrier, clocks)?;
        result.scope_observations(location);
        Some(result)
    }

    fn compare_values(
        &self,
        source: &str,
        target: &str,
        carrier: Carrier,
        clocks: AnchorClocks,
    ) -> Option<Comparison> {
        // Use the same staged identity and observation handling as decoded values.
        let verify = |context: LeafContext<'_>| {
            self.0
                .compare(source, target, carrier, context.clocks)
                .ok_or_else(|| "authentication values differ".to_owned())
        };
        let field = VerifiedField {
            rule_id: RULE_ID,
            pointer: "",
            verifier: &verify,
        };
        let result = compare::compare_with_verified(
            &Value::String(source.to_owned()),
            &Value::String(target.to_owned()),
            &[],
            &[],
            &[field],
            clocks,
        );
        result.passed().then_some(result)
    }
}

fn presigned_query(uri: &str) -> Option<bool> {
    let absolute = if uri.starts_with('/') {
        format!("https://replay.invalid{uri}")
    } else {
        uri.to_owned()
    };
    // The existing URL codec rejects duplicate names after percent decoding.
    let query = UrlDocument::parse(&Value::String(absolute)).ok()?;
    Some(query.logical.get("X-Amz-Algorithm").is_some())
}

fn query_uri(message: &ProjectedMessage) -> Option<String> {
    let shape = message.structure.get("uri")?;
    let query = shape.get("query")?.as_array()?;
    if shape.get("absolute_path")?.as_bool() != Some(true) || query.len() > 64 {
        return None;
    }
    let mut uri = match (
        shape.get("scheme")?.as_str(),
        shape.get("authority")?.as_str(),
    ) {
        (None, None) => String::new(),
        (Some(scheme), Some(authority)) => format!("{scheme}://{authority}"),
        _ => return None,
    };
    for index in 0..shape.get("segments")?.as_u64()? {
        uri.push('/');
        uri.push_str(
            std::str::from_utf8(&message.values.get(&format!("/uri/path/{index}"))?.bytes).ok()?,
        );
    }
    uri.push('?');
    for (index, part) in query.iter().enumerate() {
        if index != 0 {
            uri.push('&');
        }
        uri.push_str(part.get("name")?.as_str()?);
        if part.get("has_equals")?.as_bool()? {
            uri.push('=');
            uri.push_str(
                std::str::from_utf8(&message.values.get(&format!("{QUERY}{index}"))?.bytes).ok()?,
            );
        }
    }
    Some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_contract::time::ClockPair;
    use traffic_protocol_http::message::RequestMessage;

    fn clocks() -> AnchorClocks {
        AnchorClocks {
            dependency: ClockPair {
                source: Some("2026-11-26T01:00:00Z".parse().unwrap()),
                target: Some("2026-11-27T01:00:00Z".parse().unwrap()),
            },
            ..Default::default()
        }
    }

    #[test]
    fn presigned_request_compares_the_query_as_a_group() {
        let uri = |date: &str, signature: &str| {
            format!(
                "/bucket/object?partNumber=1&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date={date}T010000Z&X-Amz-Credential=access%2F{date}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature={signature}"
            )
        };
        let request = |uri| RequestMessage {
            method: "GET".into(),
            uri,
            headers: Default::default(),
            body: Default::default(),
        };
        let source = request(uri("20261126", &"a".repeat(64)));
        let prepared = crate::value_extensions::prepare_message(&source, &[])
            .unwrap()
            .with_request_fallback(Fallback(Matcher::default()));
        let contracts = crate::value_extensions::strict_values();
        let compare = |target: RequestMessage| {
            prepared
                .compare(&target, clocks(), contracts.metadata())
                .unwrap()
        };

        let target_uri = uri("20261127", &"b".repeat(64));
        let accepted = compare(request(target_uri.clone()));
        assert!(accepted.passed());
        assert_eq!(accepted.time_validations[RULE_ID], 1);

        let changed_query = compare(request(target_uri.replace("partNumber=1", "partNumber=2")));
        assert!(!changed_query.passed());

        let mut changed_body = request(target_uri);
        changed_body.body = bytes::Bytes::from_static(b"unexpected");
        let rejected = compare(changed_body);
        assert!(!rejected.passed());
        assert!(rejected.time_validations.is_empty());
        assert!(rejected.identity_pairs().is_empty());
    }

    #[test]
    fn jwt_fallback_pairs_header_and_query_without_accepting_ambiguous_carriers()
    -> anyhow::Result<()> {
        let policy = traffic_engine_policy::policy::parse_and_compile_policy(
            "format: traffic-policy/v3\nsignatures:\n  example: {kind: jwt, algorithm: HS256, infer: true, key: {kind: target_env, name: KEY}}\n",
        )?;
        let json = policy
            .global_json
            .expect("inferred signatures compile without JSON rules");
        json.signatures.prepare(std::path::Path::new("."), |_, _| {
            Ok((
                b"dummy test authentication key 32 bytes".to_vec(),
                Vec::new(),
            ))
        })?;
        let matcher = json.auth_matcher().unwrap();
        // Both fixtures have the same subject and scope. Their timestamps match the separate request clocks.
        const SOURCE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2ZXJpZmljYXRpb24tZml4dHVyZSIsInNjb3BlIjoicmVhZCIsImlhdCI6MTc5NTY1NDgwMCwiZXhwIjoxNzk1NjU0OTIwfQ.SPEEUZlJ87WXE9VP-JAkouZt4XaOT-8RFCsQFfA4DjI";
        const TARGET: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2ZXJpZmljYXRpb24tZml4dHVyZSIsInNjb3BlIjoicmVhZCIsImlhdCI6MTc5NTc0MTIwMCwiZXhwIjoxNzk1NzQxMzIwfQ.t184B-rbGL3RlgB2xlOeiOW7xemNDtt8SqZ8g6FFCa8";
        let request = |token: &str, duplicate: bool| RequestMessage {
            method: "GET".into(),
            uri: format!(
                "/download?credential={token}{}",
                if duplicate {
                    "&cred%65ntial=duplicate"
                } else {
                    ""
                }
            ),
            headers: [("authorization".into(), vec![format!("Bearer {token}")])].into(),
            body: Default::default(),
        };
        let contracts = crate::value_extensions::strict_values();
        for duplicate in [false, true] {
            let prepared =
                crate::value_extensions::prepare_message(&request(SOURCE, duplicate), &[])?
                    .with_request_fallback(Fallback(matcher.clone()));
            let result =
                prepared.compare(&request(TARGET, duplicate), clocks(), contracts.metadata())?;
            assert_eq!(result.passed(), !duplicate);
            assert_eq!(result.identity_pairs().len(), usize::from(!duplicate));
        }
        Ok(())
    }
}
