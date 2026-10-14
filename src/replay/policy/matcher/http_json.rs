//! Preview HTTP body normalization without consuming an exchange or rule usage.
use super::*;

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn preview_http_json(
        &self,
        context: &HttpPolicyContext<'_>,
        recorded_body: &[u8],
        actual_body: &[u8],
        decision: &mut DependencyRuleDecision,
    ) -> bool {
        let matching: Vec<_> = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Http
                    && rule
                        .http
                        .as_ref()
                        .is_some_and(|h| !h.json.unordered.is_empty())
                    && rule_matches_http(rule, context.target, context.method, context.recorded_uri)
            })
            .collect();
        if matching.is_empty() {
            return false;
        }
        // Value ordering never expands query matching, even with legacy global ignores.
        if crate::replay::http::uri_mismatch_reason(context.recorded_uri, context.actual_uri, &[])
            .is_some()
        {
            return false;
        }
        let (Ok(mut recorded), Ok(mut actual)) = (
            serde_json::from_slice::<Value>(recorded_body),
            serde_json::from_slice::<Value>(actual_body),
        ) else {
            return false;
        };
        let mut used = Vec::new();
        for rule in &matching {
            for field in &rule.http.as_ref().unwrap().json.unordered {
                if super::super::select_json_pointers(&field.pointer, &recorded, &actual)
                    .iter()
                    .any(|pointer| {
                        recorded.pointer(pointer).is_some_and(Value::is_array)
                            && actual.pointer(pointer).is_some_and(Value::is_array)
                            && recorded.pointer(pointer) != actual.pointer(pointer)
                    })
                {
                    used.push(rule.id.clone());
                }
                crate::replay::http_unordered::normalize_arrays(
                    &mut recorded,
                    &mut actual,
                    &field.pointer,
                );
            }
        }
        if recorded != actual {
            return false;
        }
        for id in used {
            decision.usage.entry(id).or_default().validations += 1;
        }
        true
    }
}
