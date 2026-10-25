use super::*;
use crate::{
    policy::{Codec, compile_policy, parse_policy},
    value_codec::CodecView,
};
use serde_json::json;

fn policy() -> crate::policy::CompiledPolicy {
    let document = json!({"format":"traffic-policy/v2", "json":{"fields":{
        "/items/*/id":{"kind":"identity","formats":[{"prefix":"msg_","format":"decimal"}]}
    }}});
    compile_policy(&parse_policy(&document.to_string()).unwrap()).unwrap()
}

#[test]
fn read_payload_reuses_one_decode_preserves_unselected_values_and_commits_only_when_requested() {
    let compiled = policy();
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    let pending = owner
        .preview_identity_pairs(
            "case",
            &[IdentityPair {
                source: serde_json::to_string("msg_11").unwrap(),
                target: serde_json::to_string("msg_1011").unwrap(),
            }],
        )
        .unwrap();
    owner.commit_identity(pending).unwrap();
    let source = br#"{ "items":[{"id":"msg_11","kind":"generated","note":"msg_11"},{"id":"msg_12","kind":"external"},{"id":"msg_13","kind":"generated"}],"untouched":11 }"#;
    let ((rendered, decision), decodes) = crate::value_codec::measured_decodes(|| {
        let decoded = CodecView::decode(&Codec::Json, source).unwrap();
        let mut logical = decoded.logical.clone();
        let (decision, pointers) = owner
            .translate_global_identity_logical("case", &decoded.logical, &mut logical)
            .unwrap();
        (decoded.encode(&logical, &pointers).unwrap(), decision)
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
        source: serde_json::to_string("msg_13").unwrap(),
        target: serde_json::to_string("msg_1013").unwrap(),
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
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    let original =
        br#"{ "items" : [ { "id" : "msg_7", "kind" : "generated" } ], "raw" : "msg_7" }"#;
    let decoded = CodecView::decode(&Codec::Json, original).unwrap();
    let mut logical = decoded.logical.clone();
    let (decision, pointers) = owner
        .translate_global_identity_logical("case", &decoded.logical, &mut logical)
        .unwrap();
    let rendered = decoded.encode(&logical, &pointers).unwrap();
    assert_eq!(rendered, original);
    assert!(!owner.has_identities("case"));
    owner.commit_identity(decision).unwrap();
    assert!(owner.has_identities("case"));
}

#[test]
fn source_self_validation_does_not_implicitly_populate_the_runtime_bijection() {
    let compiled = policy();
    let source = br#"{"items":[{"id":"msg_7","kind":"generated"}]}"#;
    let checked = crate::value_contract::global::compare(
        source,
        source,
        compiled.global_json.as_ref().unwrap(),
        &[],
        Default::default(),
    )
    .unwrap();
    assert!(checked.passed());
    let owner = RequestContracts::default();
    assert!(!owner.has_identities("case"));
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[IdentityPair {
                    source: serde_json::to_string("msg_7").unwrap(),
                    target: serde_json::to_string("msg_1007").unwrap(),
                }]
            )
            .is_ok()
    );
}

#[test]
fn delivery_preview_sees_staged_request_pairs_without_publishing_them() {
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(policy()))).unwrap();
    let pending = owner
        .preview_identity_pairs(
            "case",
            &[IdentityPair {
                source: json!("msg_7").to_string(),
                target: json!("msg_1007").to_string(),
            }],
        )
        .unwrap();
    let preview = owner.with_identity_proposals([&pending]).unwrap();
    let source = json!({"items":[{"id":"msg_7"},{"id":"msg_8"}]});
    let mut target = source.clone();
    let (delivery, _) = preview
        .translate_global_identity_logical("case", &source, &mut target)
        .unwrap();
    assert_eq!(target, json!({"items":[{"id":"msg_1007"},{"id":"msg_8"}]}));
    assert!(!owner.has_identities("case"));
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[IdentityPair {
                    source: json!("msg_7").to_string(),
                    target: json!("msg_2007").to_string(),
                }]
            )
            .is_ok()
    );
    // Only the enclosing candidate's final joint decision reaches the real map.
    let mut joint = Decision::default();
    owner.merge_identity_decision(&mut joint, pending).unwrap();
    owner.merge_identity_decision(&mut joint, delivery).unwrap();
    owner.commit(joint).unwrap();
    assert!(
        owner
            .knows_identity_value("case", &json!("msg_7"), &json!("msg_1007"))
            .unwrap()
    );
    assert!(
        owner
            .knows_identity_value("case", &json!("msg_8"), &json!("msg_8"))
            .unwrap()
    );
}
