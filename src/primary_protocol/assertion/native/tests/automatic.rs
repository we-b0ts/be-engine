use super::*;

#[test]
fn protobuf_string_schema_uses_builtin_time_without_a_field_time_rule() {
    let mut context =
        NativeResponseContext::from_rules(&[], Path::new("."), Path::new(".")).unwrap();
    context.codec = Some(
        serde_yaml::from_str(
            "kind: protobuf\nfields:\n  /stamp: {field_path: [1], field_type: string}\n",
        )
        .unwrap(),
    );
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let field = |number: u8, text: &str| {
        let mut bytes = vec![number << 3 | 2, u8::try_from(text.len()).unwrap()];
        bytes.extend_from_slice(text.as_bytes());
        bytes
    };
    let source = [field(1, "1970-01-01T00:16:40.000Z"), field(2, "2000-01-01")].concat();
    let target = [field(1, "1970-01-01T00:33:20.000Z"), field(2, "2000-01-01")].concat();
    let clocks = AnchorClocks::for_response(Default::default(), clocks().dependency);
    let compare = |target: &[u8]| {
        context
            .compare_encoded_global(&source, target, &[], policy.global_json.as_ref(), clocks)
            .unwrap()
    };
    let passed = compare(&target);
    assert!(passed.passed(), "{:?}", passed.differences);
    assert!(
        passed
            .evaluated
            .contains(crate::value_contract::time::automatic::RULE_ID)
    );
    assert!(!passed.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
    for changed in [
        [field(1, "1970-01-01T00:33:30.000Z"), field(2, "2000-01-01")].concat(),
        [
            field(1, "1970-01-01T00:33:20.0000Z"),
            field(2, "2000-01-01"),
        ]
        .concat(),
        [field(1, "1970-01-01T00:33:20.000Z"), field(2, "2001-01-01")].concat(),
    ] {
        assert!(!compare(&changed).passed());
    }
}
