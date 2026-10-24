use super::*;
use serde_json::json;

fn runtime() -> (DynamicValues, RequestContracts) {
    let rules = ["first", "second", "integer"].map(|id| serde_json::from_value(json!({
        "id":id,"api":"/items","targets":[{"host":"cache.test","port":6379}],
        "value_type":if id == "integer" { "integer" } else { "string" },
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
            "command":"SET","key":"items","argument_index":1},
        "source_evidence":"items.py:create generates a fresh identity and keeps all repeated references consistent"
    })).unwrap());
    let mut runtime = DynamicValues::new(rules.into(), BTreeMap::new());
    let owner = RequestContracts::default();
    runtime.configure_identities(owner.clone());
    (runtime, owner)
}

fn capture(id: &str, source: &str, target: &str) -> DynamicDecision {
    DynamicDecision {
        pairs: vec![(
            id.into(),
            IdentityPair {
                source: source.into(),
                target: target.into(),
            },
        )],
    }
}

#[test]
fn native_captures_and_format_fields_share_full_typed_source_correspondence() {
    let (runtime, owner) = runtime();
    runtime
        .commit("case", capture("first", "msg_aa", "msg_bb"))
        .unwrap();
    let conflict = TypedPair {
        source: json!("msg_aa").to_string(),
        target: json!("msg_cc").to_string(),
    };
    assert!(owner.preview_identity_pairs("case", &[conflict]).is_err());
    assert!(
        runtime
            .check_shared_pair(
                "case",
                &runtime.rules[1],
                &IdentityPair {
                    source: "msg_aa".into(),
                    target: "msg_cc".into()
                },
                &Default::default()
            )
            .is_err()
    );
    runtime
        .commit("case", capture("second", "pet_aa", "pet_cc"))
        .unwrap();
    runtime
        .commit("case", capture("integer", "1", "2"))
        .unwrap();
    runtime.commit("case", capture("second", "1", "3")).unwrap();
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[TypedPair {
                    source: "1".into(),
                    target: "3".into()
                }]
            )
            .is_err()
    );
    assert!(
        owner
            .preview_identity_pairs(
                "another-case",
                &[TypedPair {
                    source: "1".into(),
                    target: "3".into()
                }]
            )
            .is_ok()
    );
}

#[test]
fn native_and_global_candidate_conflicts_leave_both_stores_uncommitted() {
    let (runtime, owner) = runtime();
    let pending = capture("first", "source", "native-target");
    let mut decision = Decision::default();
    decision.identity = Some(
        owner
            .preview_identity_pairs(
                "case",
                &[TypedPair {
                    source: json!("source").to_string(),
                    target: json!("different-target").to_string(),
                }],
            )
            .unwrap(),
    );
    assert!(
        runtime
            .join_identities("case", &pending, &mut decision)
            .is_err()
    );
    assert!(!owner.has_identities("case"));
    assert!(runtime.bindings.lock().unwrap().is_empty());
    assert!(
        runtime
            .check_shared_pair(
                "case",
                &runtime.rules[1],
                &IdentityPair {
                    source: "source".into(),
                    target: "different-target".into()
                },
                &pending
            )
            .is_err()
    );
    let mut accepted = Decision::default();
    runtime
        .join_identities("case", &pending, &mut accepted)
        .unwrap();
    owner.commit(accepted).unwrap();
    runtime.commit_after_identities("case", pending);
    assert!(owner.has_identities("case"));
    assert_eq!(runtime.bindings.lock().unwrap()["case"]["first"].len(), 1);
}
