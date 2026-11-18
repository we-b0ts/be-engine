use serde_json::json;

#[test]
fn mysql_json_time_fields_accept_wildcard_leaves_but_reject_overlapping_owners() {
    let rule = json!({"id":"block-times","match":{"api":"POST /tasks","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":"UPDATE results SET payload=? WHERE id=?"},
        "effect":{"kind":"mysql_values","values":{"0":{"kind":"json","fields":{"/blocks/*/timestamp":{"relative_time":"unix_milliseconds"}}}}},
        "proof":{"source":"blocks.py:create","fact":"Each block carries a separately generated creation timestamp"}});
    let document = |rules| json!({"format":"traffic-policy/v3","rules":rules}).to_string();
    let compiled = crate::policy::parse_and_compile_policy(&document(vec![rule.clone()])).unwrap();
    assert_eq!(compiled.native.len(), 1);
    let mut duplicate = rule.clone();
    duplicate["id"] = json!("duplicate");
    duplicate["effect"]["values"]["0"]["fields"] =
        json!({"/blocks/0/timestamp":{"relative_time":"unix_milliseconds"}});
    assert!(crate::policy::parse_and_compile_policy(&document(vec![rule, duplicate])).is_err());
}
