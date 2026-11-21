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
fn trusted_definition_context_does_not_inherit_existing_permissions_or_proof_requirements() {
    let current = current();
    let proof = json!({"source":"source.py:12","fact":"Source owns this new response or dependency contract"});
    for partial in [
        json!({"format":"traffic-policy/v3","json":{"fields":{"/token":{"kind":"jwt"}}}}),
        json!({"format":"traffic-policy/v3","api":{"GET /api":{"request":{"query":{"token":{"signature":"default","proof":proof}}}}}}),
        json!({"format":"traffic-policy/v3","http":{"requests":[{
            "host":"storage.test:9100","method":"PUT","path":"/files/*","proof":proof,
            "path_identity":{"segment":1,"template":"{nonce}","fields":{"nonce":{"hex":12}},"references":["storage"]}
        }]}}),
        json!({"format":"traffic-policy/v3","api":{"GET /api":{"response":{"body":{"codec":"docx","proof":proof}}}}}),
    ] {
        assert!(
            super::super::parse_proposal(&partial.to_string()).is_err(),
            "standalone proposal should need the missing current definition"
        );
        let resolved = resolve(&partial.to_string(), &current).unwrap();
        assert!(!resolved.explicit_resources);
        super::super::source_proof::validate_proposal(&resolved.input).unwrap();
        let proposal = super::super::change::parse(&resolved.input).unwrap().policy;
        assert!(proposal.rules.len() <= 1);
        assert!(
            proposal
                .rules
                .iter()
                .all(|rule| rule.as_native().unwrap().selector.api.as_deref() != Some("GET /old"))
        );
        assert!(
            !proposal
                .json
                .as_ref()
                .is_some_and(|json| json.fields.contains_key("/old"))
        );
        crate::policy::require_source_proofs(&proposal).unwrap();
    }
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
