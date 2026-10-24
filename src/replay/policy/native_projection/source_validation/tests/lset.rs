use super::*;

fn rules() -> Vec<Value> {
    vec![
        json!({"id":"lset-time","match":{"api":"POST /tasks","resource":resource(),"key":{"kind":"exact","value":"blocks:7"}},
            "effect":{"kind":"redis_sequence","commands":[{"operation":"LSET","arguments":{"2":{"kind":"json","fields":{"/timestamp":{"relative_time":"unix_milliseconds"}}}}}]},"proof":proof()}),
        json!({"id":"lset-id","match":{"api":"POST /tasks","resource":resource(),"operation":"LSET","key":{"kind":"exact","value":"blocks:7"}},
            "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":2,"json_pointer":"/id",
                "when":{"relative_pointer":"../type","equals":"text"},"copies":[{"pointer":"/content_key","template":"content:{value}"}],
                "derived_from":{"pointer":"/timestamp","prefix":"text-"}},"references":[{"resource":resource()}]},"proof":proof()}),
    ]
}

#[test]
fn lset_source_preflight_composes_json_time_and_conditional_identity_at_element_slot() {
    let policy = compile(rules());
    let mut lset = redis(
        "LSET",
        &[
            "blocks:7",
            "-1",
            r#"{"type":"text","id":"text-1000000","timestamp":1000000,"content_key":"content:text-1000000","status":"complete"}"#,
        ],
        1,
    );
    lset["response_kind"] = json!("simple_string");
    lset["response"]["data"] = json!("+OK\r\n");
    let reference = redis("APPEND", &["content:text-1000000", "hello"], 2);
    let checked = check(&policy, &[lset.clone(), reference.clone()]).unwrap();
    assert_eq!(checked.rules["lset-id"], 1);
    assert_eq!(checked.rules["lset-time"], 1);
    for scenario in ["extra", "missing", "copy", "derived", "duplicate"] {
        let mut invalid = lset.clone();
        match scenario {
            "extra" => invalid["args"]
                .as_array_mut()
                .unwrap()
                .push(json!({"encoding":"utf8","data":"extra"})),
            "missing" => {
                invalid["args"].as_array_mut().unwrap().pop();
            }
            "duplicate" => {
                invalid["args"][2]["data"] =
                    json!(r#"{"type":"text","type":"thinking","id":"text-1000000"}"#)
            }
            _ => {
                let mut body: Value =
                    serde_json::from_str(invalid["args"][2]["data"].as_str().unwrap()).unwrap();
                if scenario == "copy" {
                    body["content_key"] = json!("content:wrong");
                } else {
                    body["id"] = json!("text-1000001");
                }
                invalid["args"][2]["data"] = json!(body.to_string());
            }
        }
        assert!(
            check(&policy, &[invalid, reference.clone()]).is_err(),
            "{scenario}"
        );
    }
    for index in [0, 1, 3] {
        let mut definitions = rules();
        definitions[1]["effect"]["capture"]["index"] = json!(index);
        assert!(
            crate::policy::parse_and_compile_policy(
                &json!({"format":"traffic-policy/v2","rules":definitions}).to_string()
            )
            .is_err()
        );
    }
}
