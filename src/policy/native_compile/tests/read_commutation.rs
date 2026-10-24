use serde_json::{Value, json};

fn rule() -> Value {
    json!({"id":"poll","match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"GET","key":{"kind":"numeric","prefix":"cancel:"}},"effect":{"kind":"redis_read_commutation"},
        "proof":{"source":"poll.py:1; flush.py:2","fact":"Source independently polls an absent cancellation key while flushing unrelated content; reads stay finite"}})
}

#[test]
fn read_commutation_requires_bounded_scope_and_exclusive_unchanged_response() {
    for path in [
        "/match/resource",
        "/match/resource/database",
        "/match/key",
        "/match/operation",
        "/proof",
    ] {
        let mut rule = rule();
        let (parent, key) = path.rsplit_once('/').unwrap();
        rule.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(compile(vec![rule]).is_err(), "{path}");
    }
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
}

fn compile(rules: Vec<Value>) -> anyhow::Result<crate::policy::CompiledPolicy> {
    crate::policy::parse_policy(&json!({"format":"traffic-policy/v2","rules":rules}).to_string())
        .and_then(|p| crate::policy::compile_policy(&p))
}
