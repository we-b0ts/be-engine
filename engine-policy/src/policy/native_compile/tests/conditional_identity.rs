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
        &json!({"format":"traffic-policy/v3","rules":rules}),
    )?)
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
