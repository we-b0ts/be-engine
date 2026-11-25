use super::*;
use serde_json::json;

fn current() -> TrafficPolicy {
    crate::policy::parse_policy(&json!({"format":"traffic-policy/v3","source_revision":"source",
        "signatures":{"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET_KEY"}}},
        "resources":{"storage":{"protocol":"http","endpoint":"storage.test:9100"}},
        "json":{"fields":{"/old":{"kind":"unordered"}}},
        "docx":{"fields":[{"kind":"timestamp","part":"docProps/core.xml","element":"dcterms:created","format":"rfc3339"}]},
        "api":{"GET /old":{"response":{"body":{"codec":"docx"}}}}
    }).to_string()).unwrap()
}

#[test]
fn trusted_context_cannot_override_named_definitions_or_supply_missing_new_source_proof() {
    let current = current();
    for partial in [
        json!({"format":"traffic-policy/v3","signatures":{"default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"OTHER_KEY"}}}}),
        json!({"format":"traffic-policy/v3","resources":{"storage":{"protocol":"http","endpoint":"other.test:9100"}}}),
    ] {
        assert!(resolve(&partial.to_string(), &current).is_err());
    }
    let partial = json!({"format":"traffic-policy/v3","api":{"GET /api":{"response":{"body":{"codec":"docx"}}}}});
    let resolved = resolve(&partial.to_string(), &current).unwrap();
    assert!(super::super::source_proof::validate_proposal(&resolved.input).is_err());
    assert!(
        crate::policy::require_source_proofs(
            &super::super::change::parse(&resolved.input).unwrap().policy
        )
        .is_err()
    );
}
