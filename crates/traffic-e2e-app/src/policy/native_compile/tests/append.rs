use serde_json::{Value, json};

fn rule() -> Value {
    json!({"id":"append","match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"APPEND","key":{"kind":"affix","prefix":"content:"}},"effect":{"kind":"redis_append_stream"},
        "proof":{"source":"session.py:42","fact":"Source batches nonempty text in key order and retains reads, resets and expiry obligations"}})
}

#[test]
fn append_capability_requires_bounded_key_scope_and_exclusive_payload_ownership() {
    for path in ["/match/resource/database", "/match/key", "/match/operation"] {
        let mut rule = rule();
        let (parent, key) = path.rsplit_once('/').unwrap();
        rule.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        let result = crate::policy::parse_policy(
            &json!({"format":"traffic-policy/v3","rules":[rule]}).to_string(),
        )
        .and_then(|p| crate::policy::compile_policy(&p));
        assert!(result.is_err(), "{path}");
    }
    let policy = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[rule()]}).to_string(),
    )
    .unwrap();
    let mut missing_proof = rule();
    missing_proof.as_object_mut().unwrap().remove("proof");
    let runtime = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[missing_proof]}).to_string(),
    )
    .unwrap();
    crate::policy::compile_policy(&runtime).unwrap();
    assert!(crate::policy::require_source_proofs(&runtime).is_err());
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    assert_eq!(
        compiled.native[0].rule.effect.capability_name(),
        "append_stream_equivalence"
    );
    let mut other = rule();
    other["id"] = json!("other");
    let result = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[rule(),other]}).to_string(),
    )
    .and_then(|policy| crate::policy::compile_policy(&policy));
    assert!(result.is_err());
    let mut discovered = rule();
    discovered["match"]
        .as_object_mut()
        .unwrap()
        .remove("resource");
    let key_only = json!({"format":"traffic-policy/v3","rules":[discovered.clone()]});
    assert!(crate::policy::parse_policy(&key_only.to_string()).is_ok());
    for field in ["path", "sql"] {
        let mut cross_protocol = discovered.clone();
        cross_protocol["match"][field] = json!("/other");
        assert!(
            crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v3","rules":[cross_protocol]}).to_string()
            )
            .is_err()
        );
    }
}
