//! Implicit identity translation is a delivery owner, even without delivery.rebase_time.
use serde_json::{Value, json};

fn redis_resource() -> Value {
    json!({"protocol":"redis","endpoint":"cache.test:6379","database":0})
}

fn mysql_resource() -> Value {
    json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"})
}

fn native(mysql: bool) -> Value {
    let mut rule = json!({"id":"native-id","match":{"resource":redis_resource(),
        "operation":if mysql {"SET"} else {"RPUSH"},"key":{"kind":"exact","value":"blocks"}},
        "effect":{"kind":"identity","value_type":"string",
            "capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":redis_resource()}]},
        "proof":{"source":"store.py:create,read","fact":"Source creates an ID and later reads the stored ID from this declared resource"}});
    if mysql {
        rule["effect"]["references"]
            .as_array_mut()
            .unwrap()
            .push(json!({"resource":mysql_resource()}));
        rule["effect"]["mysql_read_back"] = json!([{"resource":mysql_resource(),
            "sql":"SELECT payload FROM tasks WHERE id=?","column":"payload","json_pointers":["/id"]}]);
    } else {
        rule["effect"]["capture"]["json_pointer"] = json!("/id");
        rule["effect"]["read_back"] = json!([{"operation":"LRANGE","write_operation":"RPUSH",
            "argument_index":1,"json_pointers":["/id"]}]);
    }
    rule
}

fn value_rule(mysql: bool, conditional: bool, identity: bool) -> Value {
    let field = if identity {
        let identity = json!({"kind":"identity","binding":"stored-id","format":"uuid"});
        if conditional {
            json!({"kind":"conditional","when":{"relative_pointer":"../kind","equals":"generated"},"contract":identity})
        } else {
            identity
        }
    } else {
        json!({"relative_time":"unix_seconds"})
    };
    let pointer = if identity { "/id" } else { "/at" };
    json!({"id":"stored-value","surface":"dependency.response",
        "match":if mysql {json!({"resource":mysql_resource(),"tables":["tasks"]})}
            else {json!({"resource":redis_resource(),"key":{"exact":"blocks"}})},
        "slot":if mysql {json!({"sql_field":"payload"})} else {json!({"redis_value":"list"})},
        "codec":"json","contract":{pointer:field},
        "proof":{"source":"store.py:fields","fact":"These stored fields retain their Source-proven generated semantics; other values remain exact"}})
}

#[test]
fn generic_identity_reads_cannot_overlap_a_native_read_back_delivery_owner() {
    for mysql in [false, true] {
        for conditional in [false, true] {
            let compile = |identity| {
                crate::policy::parse_and_compile_policy(
                &json!({"format":"traffic-policy/v2","rules":[native(mysql),value_rule(mysql,conditional,identity)]}).to_string())
            };
            let comparison = compile(false);
            assert!(
                comparison.is_ok(),
                "comparison-only times can coexist with native read-back: {comparison:?}"
            );
            let error = compile(true).unwrap_err();
            assert!(format!("{error:#}").contains("delivery owner"), "{error:#}");
        }
    }
}

#[test]
fn mysql_disjoint_time_delivery_keeps_its_existing_native_read_back_composition() {
    for mysql in [false, true] {
        let mut time = value_rule(mysql, false, false);
        time["delivery"] = json!({"rebase_time":["/at"]});
        let result = crate::policy::parse_and_compile_policy(
            &json!({"format":"traffic-policy/v2","rules":[native(mysql),time]}).to_string(),
        );
        assert_eq!(result.is_ok(), mysql, "{result:?}");
    }
}
