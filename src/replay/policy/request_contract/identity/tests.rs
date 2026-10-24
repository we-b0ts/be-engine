use super::*;
use crate::{
    policy::{Codec, compile_policy, parse_policy},
    value_codec::CodecView,
};
use serde_json::json;

fn policy() -> crate::policy::CompiledPolicy {
    let document = json!({"format":"traffic-policy/v2", "responses":{"items":{
        "api":"GET /items", "proof":{"source":"fixture.py:1", "fact":"Generated entity IDs are shared by these items; external values stay exact"},
        "body":{"codec":"json", "fields":{
            "/items/*/id":{"kind":"conditional", "when":{"relative_pointer":"../kind", "equals":"generated"},
                "contract":{"kind":"identity", "binding":"entity", "prefix":"msg_", "format":"decimal"}}
        }}
    }}});
    compile_policy(&parse_policy(&document.to_string()).unwrap()).unwrap()
}

#[test]
fn read_payload_reuses_one_decode_preserves_unselected_values_and_commits_only_when_requested() {
    let compiled = policy();
    let rules = compiled.rules.iter().collect::<Vec<_>>();
    let owner = RequestContracts::default();
    let pending = owner
        .preview_identity_pairs(
            "case",
            &[IdentityPair {
                domain: "entity".into(),
                source: "11".into(),
                target: "1011".into(),
            }],
        )
        .unwrap();
    owner.commit_identity(pending).unwrap();
    let source = br#"{ "items":[{"id":"msg_11","kind":"generated","note":"msg_11"},{"id":"msg_12","kind":"external"},{"id":"msg_13","kind":"generated"}],"untouched":11 }"#;
    let ((rendered, decision), decodes) = crate::value_codec::measured_decodes(|| {
        let decoded = CodecView::decode(&Codec::Json, source).unwrap();
        owner
            .prepare_identity_payload("case", &decoded, &rules)
            .unwrap()
    });
    assert_eq!(decodes, 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&rendered).unwrap(),
        json!({"items":[
        {"id":"msg_1011","kind":"generated","note":"msg_11"},
        {"id":"msg_12","kind":"external"},
        {"id":"msg_13","kind":"generated"}
    ], "untouched":11})
    );
    let alternate = [IdentityPair {
        domain: "entity".into(),
        source: "13".into(),
        target: "1013".into(),
    }];
    assert!(owner.preview_identity_pairs("case", &alternate).is_ok());
    owner.clone().commit_identity(decision).unwrap();
    assert!(owner.preview_identity_pairs("case", &alternate).is_err());
    owner.clear_identities("case");
    assert!(!owner.has_identities("case"));
}

#[test]
fn historical_input_without_renaming_retains_original_json_bytes() {
    let compiled = policy();
    let rules = compiled.rules.iter().collect::<Vec<_>>();
    let owner = RequestContracts::default();
    let original =
        br#"{ "items" : [ { "id" : "msg_7", "kind" : "generated" } ], "raw" : "msg_7" }"#;
    let decoded = CodecView::decode(&Codec::Json, original).unwrap();
    let (rendered, decision) = owner
        .prepare_identity_payload("case", &decoded, &rules)
        .unwrap();
    assert_eq!(rendered, original);
    assert!(!owner.has_identities("case"));
    owner.commit_identity(decision).unwrap();
    assert!(owner.has_identities("case"));
}

#[test]
fn source_self_validation_does_not_implicitly_populate_the_runtime_bijection() {
    let compiled = policy();
    let rules = compiled.rules.iter().collect::<Vec<_>>();
    let source = br#"{"items":[{"id":"msg_7","kind":"generated"}]}"#;
    let checked =
        crate::value_contract::encoded::compare(source, source, &rules, Default::default())
            .unwrap();
    assert!(checked.passed());
    let owner = RequestContracts::default();
    assert!(!owner.has_identities("case"));
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[IdentityPair {
                    domain: "entity".into(),
                    source: "7".into(),
                    target: "1007".into(),
                }]
            )
            .is_ok()
    );
}
