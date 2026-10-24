use super::*;
use serde_json::{Value, json};

fn rule(kind: &str) -> Value {
    json!({"id":kind,"match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"RPUSH","key":{"kind":"affix","prefix":"blocks:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1,"json_pointer":"/id",
            "when":{"relative_pointer":"../type","equals":kind},
            "copies":[{"pointer":"/content_key","template":"content:{value}"}],
            "derived_from":{"pointer":"/timestamp","prefix":"text-"}},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}]},
        "proof":{"source":"blocks.py:create","fact":"Source text identities derive from epoch milliseconds and are copied into content keys"}})
}

fn compile(rules: Vec<Value>) -> Result<crate::policy::CompiledPolicy> {
    crate::policy::parse_and_compile_policy(&serde_yaml::to_string(
        &json!({"format":"traffic-policy/v2","rules":rules}),
    )?)
}

#[test]
fn conditional_identity_scopes_round_trip_and_allow_only_provably_disjoint_branches() {
    let a = rule("text");
    let b = rule("thinking");
    let compiled = compile(vec![a.clone(), b.clone()]).unwrap();
    let document = crate::policy::TrafficPolicy {
        format: crate::policy::POLICY_FORMAT.into(),
        source_revision: None,
        rules: compiled
            .native
            .into_iter()
            .map(|r| PolicyRule::Native(Box::new(r.rule)))
            .collect(),
        ..crate::policy::TrafficPolicy::default()
    };
    let yaml = crate::policy::render_policy(&document).unwrap();
    assert_eq!(crate::policy::parse_policy(&yaml).unwrap(), document);
    let mut overlap = b.clone();
    overlap["effect"]["capture"]["when"] = a["effect"]["capture"]["when"].clone();
    assert!(compile(vec![a.clone(), overlap]).is_err());
    let mut broad = b;
    broad["effect"]["capture"]
        .as_object_mut()
        .unwrap()
        .remove("when");
    assert!(compile(vec![a.clone(), broad]).is_err());
    let mut changed = a.clone();
    changed["effect"]["capture"]["when"]["equals"] = "other".into();
    assert_ne!(
        compile(vec![a]).unwrap().fingerprints.runtime,
        compile(vec![changed]).unwrap().fingerprints.runtime
    );
}

#[test]
fn conditional_identity_requires_a_distinct_sibling_in_the_selected_json_argument() {
    for change in ["root", "no-pointer", "self", "copy-discriminator"] {
        let mut r = rule("text");
        match change {
            "root" => r["effect"]["capture"]["json_pointer"] = "".into(),
            "no-pointer" => {
                r["effect"]["capture"]
                    .as_object_mut()
                    .unwrap()
                    .remove("json_pointer");
            }
            "self" => r["effect"]["capture"]["when"]["relative_pointer"] = "../id".into(),
            "copy-discriminator" => r["effect"]["capture"]["copies"][0]["pointer"] = "/type".into(),
            _ => unreachable!(),
        }
        assert!(compile(vec![r]).is_err(), "{change}");
    }
}
