//! Author identity formats never expose named binding or reference declarations.
use serde_json::{Value, json};

fn redis_resource() -> Value {
    json!({"protocol":"redis","endpoint":"cache.test:6379","database":0})
}

fn mysql_resource() -> Value {
    json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"})
}

#[test]
fn native_key_reference_and_template_formats_never_accept_authored_binding() {
    let proof = json!({"source":"sessions.py:create","fact":"Source-generated sessions preserve fixed key and URL literals while sharing the same generated nonce"});
    let key = json!({"id":"key","match":{"resource":redis_resource(),"key":{"kind":"affix","prefix":"sessions:","suffix":""}},
        "effect":{"kind":"redis_sequence","key":{"kind":"capture","template":"sessions:{value}","format":{"kind":"uuid_v4"}},
            "commands":[{"operation":"SET","arguments":{"1":{"kind":"json","fields":{"/id":{"kind":"identity","template":"{value}","transform":"identity"}}}}}]},"proof":proof});
    let template = json!({"id":"url","match":{"api":"POST /sessions"},"effect":{"kind":"response_generated","fields":{"/url":{"kind":"template","template":"https://sessions.test/{token}","fields":{"token":{"format":"uuid"}}}}},"proof":proof});
    let compile = |rules: Vec<Value>| {
        crate::policy::parse_and_compile_policy(
            &json!({"format":"traffic-policy/v3","rules":rules}).to_string(),
        )
    };
    let compiled = compile(vec![key.clone(), template.clone()]).unwrap();
    assert!(
        !serde_json::to_string(&compiled)
            .unwrap()
            .contains("\"binding\"")
    );
    for pointer in ["/effect/key", "/effect/commands/0/arguments/1/fields/~1id"] {
        let mut invalid = key.clone();
        invalid
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("binding".into(), json!("removed"));
        assert!(compile(vec![invalid]).is_err());
    }
    let mut invalid = template;
    invalid["effect"]["fields"]["/url"]["fields"]["token"]["binding"] = json!("removed");
    assert!(compile(vec![invalid]).is_err());
}

#[test]
fn generated_scalar_formats_reject_named_binding_and_reference_authoring() {
    for kind in ["uuid", "uuid_v4", "non_empty"] {
        let document = |contract: Value| {
            json!({"format":"traffic-policy/v3","rules":[{
            "id":"generated","match":{"resource":mysql_resource(),"sql":"INSERT INTO events (id) VALUES (?)"},
            "effect":{"kind":"mysql_values","params":{"0":{"contract":contract,"proof":{
                "source":"events.py:create","fact":"Source generates and reuses the event identity"}}}},
            "proof":{"source":"events.py:create","fact":"Source generates and reuses the event identity"}}]})
        };
        let valid = document(json!({"kind":kind}));
        let compiled = crate::policy::parse_and_compile_policy(&valid.to_string()).unwrap();
        assert!(
            !serde_json::to_string(&compiled)
                .unwrap()
                .contains("\"binding\"")
        );
        for invalid in [
            json!({"kind":kind,"binding":"event"}),
            json!({"kind":"bind"}),
            json!({"kind":"reference"}),
        ] {
            assert!(
                crate::policy::parse_and_compile_policy(&document(invalid).to_string()).is_err()
            );
        }
    }
}

#[test]
fn mysql_identity_reads_reject_retired_per_select_delivery_declarations() {
    let rule = json!({"id":"identity","match":{"resource":mysql_resource(),"sql":"INSERT INTO events (id) VALUES (?)"},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"mysql_value","index":0},
            "references":[{"resource":mysql_resource()}],"mysql_read_back":[]},
        "proof":{"source":"events.py:1","fact":"Source generates an event identity"}});
    let document = json!({"format":"traffic-policy/v3","rules":[rule]});
    assert!(crate::policy::parse_policy(&document.to_string()).is_err());
}
