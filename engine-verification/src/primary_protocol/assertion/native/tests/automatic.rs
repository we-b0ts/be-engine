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

#[test]
fn protobuf_infers_auth_for_one_logical_string_and_preserves_wire_remainder() {
    const KEY: &str = "frozen-signing-key";
    let mut context =
        NativeResponseContext::from_rules(&[], Path::new("."), Path::new(".")).unwrap();
    context.codec = Some(
        serde_yaml::from_str(
            "kind: protobuf\nfields:\n  /credential: {field_path: [1], field_type: string}\n",
        )
        .unwrap(),
    );
    let mut policy = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\nsignatures:\n  issuer: {kind: jwt, algorithm: HS256, infer: true, key: {kind: target_env, name: KEY}}\n",
    )
    .unwrap();
    let global = policy.global_json.as_mut().unwrap();
    global.signatures = crate::policy::signatures::SignatureRegistry::for_test(
        policy.signatures.clone(),
        std::collections::BTreeMap::from([("issuer".into(), KEY.as_bytes().to_vec())]),
    );
    let response = |now: i64, key: &str, unknown: u8| {
        let jwt = crate::request_rules::tests::token(json!({"iat":now,"exp":now+60}), key);
        assert!(jwt.len() < 128);
        let mut body = vec![0x0a, u8::try_from(jwt.len()).unwrap()];
        body.extend_from_slice(jwt.as_bytes());
        body.extend([0x18, unknown]);
        body
    };
    let source = response(1_000, KEY, 1);
    let target = response(2_000, KEY, 1);
    let clocks = AnchorClocks::for_response(Default::default(), clocks().dependency);
    let compare = |context: &NativeResponseContext, target: &[u8]| {
        context
            .compare_encoded_global(&source, target, &[], Some(global), clocks)
            .unwrap()
    };

    let passed = compare(&context, &target);
    assert!(passed.passed(), "{:?}", passed.differences);
    assert!(
        passed
            .evaluated
            .contains(traffic_policy_value::auth::RULE_ID)
    );
    assert!(!compare(&context, &response(2_000, KEY, 2)).passed());
    assert!(!compare(&context, &response(2_000, "wrong-key", 1)).passed());

    let mut reencoded = source.clone();
    reencoded[1] |= 0x80;
    reencoded.insert(2, 0);
    assert!(!compare(&context, &reencoded).passed());

    context.fields.push((
        "exact-auth".into(),
        "/credential".into(),
        FieldContract::Exact,
    ));
    assert!(!compare(&context, &target).passed());
}
