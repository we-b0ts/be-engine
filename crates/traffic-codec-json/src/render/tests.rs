use super::*;
use serde_json::json;

#[test]
fn derived_tokens_preserve_member_order_whitespace_escapes_and_number_spelling() {
    let source = concat!(
        r#"  {"z":{"mcpServers":{"zeta":{"url":"https:\/\/z.invalid"},"alpha":{"baseUrl":"a"}}, "time": 100}, "a\u002fb":[1.00e+2, {"~time":100,"stable":"\u4e2d"}]} "#,
        "\n"
    ).as_bytes();
    let mut changed = super::super::parse(source).unwrap();
    changed["z"]["time"] = json!(200);
    changed["a/b"][1]["~time"] = json!(201);
    let expected = String::from_utf8(source.to_vec())
        .unwrap()
        .replace("\"time\": 100", "\"time\": 200")
        .replace("\"~time\":100", "\"~time\":201");
    assert_eq!(derived(source, &changed).unwrap(), expected.as_bytes());
}

#[test]
fn unchanged_scalars_and_root_scalar_delivery_keep_their_carriers() {
    for source in [b" [1.00, true, null] ".as_slice(), b"\n\"\\u4e2d\"\t"] {
        let logical = super::super::parse(source).unwrap();
        assert_eq!(derived(source, &logical).unwrap(), source);
    }
    assert_eq!(
        derived(b" \"old\"\n", &json!("new\nvalue")).unwrap(),
        b" \"new\\nvalue\"\n"
    );
}

#[test]
fn renderer_rejects_duplicate_members_shape_type_changes_and_invalid_json() {
    for (source, after) in [
        (r#"{"x":1,"x":2}"#, json!({"x":3})),
        (r#"{"x":1}"#, json!({"x":1,"y":2})),
        (r#"{"x":1}"#, json!({"x":"1"})),
        (r#"{"x":[1,2]}"#, json!({"x":[1]})),
        (r#"{"x":[]}"#, json!({"x":{}})),
        (r#"{"x":1} trailing"#, json!({"x":2})),
    ] {
        assert!(derived(source.as_bytes(), &after).is_err(), "{source}");
    }
}
