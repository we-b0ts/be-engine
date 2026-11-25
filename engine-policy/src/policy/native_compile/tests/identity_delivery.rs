//! Author identity formats never expose named binding or reference declarations.
use serde_json::{Value, json};

fn mysql_resource() -> Value {
    json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"})
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

#[test]
fn redis_effects_reject_retired_read_back_declarations() {
    for mut effect in [
        json!({"kind":"identity","value_type":"string",
            "capture":{"kind":"redis_argument","index":1},"references":[]}),
        json!({"kind":"redis_sequence","commands":[]}),
    ] {
        assert!(serde_json::from_value::<crate::policy::NativeEffect>(effect.clone()).is_ok());
        effect["read_back"] = json!([]);
        let error = serde_json::from_value::<crate::policy::NativeEffect>(effect).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `read_back`"),
            "{error}"
        );
    }
}
