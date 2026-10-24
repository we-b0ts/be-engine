use super::*;
use serde_json::json;

#[test]
fn mysql_wildcard_clocks_cover_variable_case_lengths_in_text_and_prepared_calls() {
    let template = "UPDATE results SET payload=? WHERE id=?";
    let document = json!({"format":"traffic-policy/v2","rules":[{
        "id":"times","match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":template},
        "effect":{"kind":"mysql_values","values":{"0":{"kind":"json","fields":{"/blocks/*/timestamp":{"relative_time":"unix_microseconds","clock_group":"block-create","clock_scope":"array_element"}}}}},
        "proof":{"source":"blocks.py:create","fact":"Every block is generated with an independent current timestamp"}
    }]});
    let compiled = crate::policy::parse_and_compile_policy(&document.to_string()).unwrap();
    let native = compiled.native.iter().collect::<Vec<_>>();
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    };
    let source_start = 1_577_836_800_000_000_i64;
    let target_start = 1_767_225_600_000_000_i64;
    for length in [0, 1, 8] {
        let payload = |start: i64, target: bool| json!({"blocks":(0..length).map(|index|json!({"id":index,"timestamp":start+index*1_000_000+if target{index*10_000}else{0},"text":"stable"})).collect::<Vec<_>>()});
        let source = payload(source_start, false);
        let actual = payload(target_start, true);
        let check = |target: &Value, prepared: bool| {
            if prepared {
                let params = |body: &Value| {
                    vec![
                        RecordedMysqlValue {
                            kind: "string".into(),
                            value: Some(Value::String(body.to_string())),
                            raw: None,
                        },
                        RecordedMysqlValue {
                            kind: "integer".into(),
                            value: Some(json!(7)),
                            raw: None,
                        },
                    ]
                };
                compare(
                    Some("app"),
                    Some(template),
                    Some(&params(&source)),
                    Some(template),
                    Some(&params(target)),
                    &[],
                    &native,
                    clocks,
                )
            } else {
                compare(
                    Some("app"),
                    Some(&format!(
                        "UPDATE results SET payload='{}' WHERE id=7",
                        source
                    )),
                    None,
                    Some(&format!(
                        "UPDATE results SET payload='{}' WHERE id=7",
                        target
                    )),
                    None,
                    &[],
                    &native,
                    clocks,
                )
            }
        };
        for prepared in [false, true] {
            let checked = check(&actual, prepared).unwrap();
            assert!(
                checked.passed(),
                "length {length}, prepared {prepared}: {:?}",
                checked.differences
            );
            let mut changed = actual.clone();
            changed["blocks"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":99,"timestamp":target_start}));
            assert!(!check(&changed, prepared).unwrap().passed());
            if length > 1 {
                changed = actual.clone();
                changed["blocks"].as_array_mut().unwrap().reverse();
                assert!(!check(&changed, prepared).unwrap().passed());
                changed = actual.clone();
                changed["blocks"][0]["text"] = json!("wrong");
                assert!(!check(&changed, prepared).unwrap().passed());
            }
        }
    }
}
