//! Names identify a capability candidate; only consumer Source proof grants it.
use super::*;

pub(super) fn has_difference(facts: &Value) -> bool {
    facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|cluster| {
            let difference = &cluster["representative"]["difference"];
            cluster["protocol"] == "http"
                && matches!(
                    difference["kind"].as_str(),
                    Some("header_missing" | "header_added" | "header_value_mismatch")
                )
                && ["expected", "actual"].into_iter().any(|side| {
                    difference[side]["signature"]["header"]
                        .as_str()
                        .is_some_and(|name| {
                            crate::policy::native::HTTP_CLIENT_METADATA_HEADERS.contains(&name)
                        })
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn client_metadata_guidance_requires_consumer_proof_and_does_not_offer_unknown_headers() {
        let mut facts = json!({"clusters":[{"protocol":"http","representative":{"difference":{"kind":"header_missing",
            "expected":{"signature":{"header":"x-stainless-lang","protected":false}}}}}]});
        let hints = super::super::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
        let hint = hints
            .iter()
            .find(|h| h.capability == "http_client_metadata")
            .unwrap();
        assert!(hint.hint.contains("consumer/middleware") && hint.hint.contains("not acceptance"));
        let planners = super::super::applicable_rule_planners(
            Path::new("/target"),
            RewriteIssueKind::Dependency,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current",
        );
        assert!(
            planners
                .iter()
                .any(|p| p.capability == "http_client_metadata")
        );
        for name in ["x-stainless-api-key", "authorization", "tenant-id"] {
            facts["clusters"][0]["representative"]["difference"]["expected"]["signature"]["header"] =
                name.into();
            assert!(!has_difference(&facts));
        }
    }
}
