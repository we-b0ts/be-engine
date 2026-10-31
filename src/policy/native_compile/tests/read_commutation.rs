use serde_json::{Value, json};

fn rule() -> Value {
    json!({"id":"poll","match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"GET","key":{"kind":"numeric","prefix":"cancel:"}},"effect":{"kind":"redis_read_commutation"},
        "proof":{"source":"poll.py:1; flush.py:2","fact":"Source independently polls an absent cancellation key while flushing unrelated content; reads stay finite"}})
}

#[test]
fn read_commutation_requires_bounded_scope_and_exclusive_unchanged_response() {
    for path in ["/match/resource/database", "/match/key", "/match/operation"] {
        let mut rule = rule();
        let (parent, key) = path.rsplit_once('/').unwrap();
        rule.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(compile(vec![rule]).is_err(), "{path}");
    }
    let mut missing_proof = rule();
    missing_proof.as_object_mut().unwrap().remove("proof");
    let runtime = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3","rules":[missing_proof]}).to_string(),
    )
    .unwrap();
    crate::policy::compile_policy(&runtime).unwrap();
    assert!(crate::policy::require_source_proofs(&runtime).is_err());
    let compiled = compile(vec![rule()]).unwrap();
    assert_eq!(
        compiled.native[0].rule.effect.capability_name(),
        "finite_read_commutation"
    );
    let mut duplicate = rule();
    duplicate["id"] = json!("duplicate");
    assert!(compile(vec![rule(), duplicate]).is_err());
    let mut other = rule();
    other["match"]["operation"] = json!("SET");
    assert!(compile(vec![other]).is_err());
    let mut other = rule();
    other["effect"]["optional"] = json!(true);
    assert!(compile(vec![other]).is_err());
    let mut discovered = rule();
    discovered["match"]
        .as_object_mut()
        .unwrap()
        .remove("resource");
    assert!(compile(vec![discovered]).is_ok());
}

fn compile(rules: Vec<Value>) -> anyhow::Result<crate::policy::CompiledPolicy> {
    crate::policy::parse_policy(&json!({"format":"traffic-policy/v3","rules":rules}).to_string())
        .and_then(|p| crate::policy::compile_policy(&p))
}

#[test]
fn nil_commutation_composes_only_with_one_get_read_back_owner() {
    let mut read_back = json!({"id":"identity","match":rule()["match"].clone(),
        "effect":{"kind":"identity","value_type":"string",
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}],
            "capture":{"kind":"redis_argument","index":1},
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,"state_epochs":true}]},
        "proof":{"source":"cache.py:1","fact":"Source reads back stored identities; nil responses have no payload to rewrite"}});
    read_back["match"]["operation"] = json!("SET");
    compile(vec![rule(), read_back.clone()]).unwrap();
    let mut second = read_back.clone();
    second["id"] = json!("second-identity");
    assert!(compile(vec![rule(), read_back.clone(), second]).is_err());
    let mut duplicate = rule();
    duplicate["id"] = json!("second-poll");
    assert!(compile(vec![rule(), read_back, duplicate]).is_err());
}

#[test]
fn absent_read_observation_has_an_exclusive_bounded_get_owner() {
    let mut observation = rule();
    observation["id"] = json!("absent-poll");
    observation["effect"] = json!({"kind":"redis_read_observation"});
    let compiled = compile(vec![observation.clone()]).unwrap();
    assert_eq!(
        compiled.native[0].rule.effect.capability_name(),
        "key_lifetime_absent_read"
    );
    assert!(compile(vec![observation.clone(), rule()]).is_err());
    observation["match"]["operation"] = json!("SET");
    assert!(compile(vec![observation.clone()]).is_err());
    observation["match"]["operation"] = json!("GET");
    observation["match"].as_object_mut().unwrap().remove("key");
    assert!(compile(vec![observation]).is_err());
}
