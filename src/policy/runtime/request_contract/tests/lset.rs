use super::*;

#[test]
fn lset_json_contract_owns_only_argument_two_and_preserves_exact_list_index() {
    let definition = rule(
        json!({"key":"blocks:7","commands":[{"command":"LSET","argument_values":{"2":{"json":{"/timestamp":{"time":"preserve_relative","format":"unix_milliseconds"}}}}}]}),
    );
    validate(&definition).unwrap();
    let runtime = runtime(definition.clone());
    let source = [
        "blocks:7",
        "-1",
        r#"{"timestamp":1000000,"status":"complete"}"#,
    ];
    let actual = [
        "blocks:7",
        "-1",
        r#"{"timestamp":2000000,"status":"complete"}"#,
    ];
    assert!(check(&runtime, "LSET", &source, &actual).is_ok());
    for changed in [
        vec!["blocks:7", "0", actual[2]],
        vec!["blocks:8", "-1", actual[2]],
        vec![
            "blocks:7",
            "-1",
            r#"{"timestamp":2000000,"status":"wrong"}"#,
        ],
        vec![
            "blocks:7",
            "-1",
            r#"{"timestamp":2000000,"timestamp":2000001}"#,
        ],
        vec!["blocks:7", "-1", actual[2], "extra"],
        vec!["blocks:7", "-1"],
    ] {
        assert!(check(&runtime, "LSET", &source, &changed).is_err());
    }
    for index in [0, 1, 3] {
        let invalid = rule(
            json!({"key":"blocks:7","commands":[{"command":"LSET","argument_values":{index.to_string():{"json":{"/timestamp":{"time":"preserve_relative","format":"unix_milliseconds"}}}}}]}),
        );
        assert!(validate(&invalid).is_err(), "{index}");
    }
}
