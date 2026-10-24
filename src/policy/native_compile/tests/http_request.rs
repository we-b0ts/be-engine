use serde_json::{Value, json};

use crate::policy::{self, NativeEffect, TimeAnchor, native::HttpJsonField};

fn document(fields: Value) -> Value {
    json!({"format":"traffic-policy/v2","rules":[{
        "id":"signed-outbound", "match":{
            "api":"POST /requests",
            "resource":{"protocol":"http","endpoint":"upstream.test:80"},
            "operation":"POST", "path":"/invoke"
        },
        "effect":{"kind":"http_request","json":fields},
        "proof":{"source":"src/client.rs:send","fact":"Source signs request-relative claims and generates a bounded request identifier"}
    }]})
}

fn token() -> Value {
    json!({"kind":"jwt","algorithm":"HS256","signing_key":{"kind":"target_env","name":"TEST_SECRET"}})
}

fn compile(value: &Value) -> anyhow::Result<policy::CompiledPolicy> {
    policy::parse_and_compile_policy(&value.to_string())
}

#[test]
fn http_body_jwt_and_random_are_closed_typed_field_contracts() {
    let value = document(json!({
        "/metadata/request_id":{"kind":"random","format":"hex","length":8},
        "/metadata/auth_token":token()
    }));
    let compiled = compile(&value).unwrap();
    let NativeEffect::HttpRequest(effect) = &compiled.native[0].rule.effect else {
        panic!("HTTP request effect expected")
    };
    assert_eq!(effect.json.len(), 2);
    assert!(matches!(
        effect.json["/metadata/auth_token"].contract,
        HttpJsonField::Jwt {
            anchor: TimeAnchor::DependencyRequestStart,
            ..
        }
    ));
    assert_eq!(
        effect.json["/metadata/auth_token"].proof,
        compiled.native[0].rule.proof
    );
    let parsed = policy::parse_policy(&value.to_string()).unwrap();
    let rendered = policy::render_policy(&parsed).unwrap();
    assert!(!rendered.contains("anchor:"));
    assert_eq!(
        compile(&serde_json::to_value(&parsed).unwrap()).unwrap(),
        compiled
    );
    assert_eq!(
        policy::parse_and_compile_policy(&rendered).unwrap(),
        compiled
    );
}

#[test]
fn http_body_fields_require_exact_bounded_nonoverlapping_pointers_and_shapes() {
    for invalid in [
        json!({"":{"kind":"random","format":"hex","length":8}}),
        json!({"/items/*/id":{"kind":"random","format":"hex","length":8}}),
        json!({"/bad~escape":{"kind":"random","format":"hex","length":8}}),
        json!({"/metadata":{"kind":"random","format":"hex","length":8},"/metadata/token":token()}),
        json!({"/id":{"kind":"random","format":"hex","length":0}}),
        json!({"/id":{"kind":"random","format":"hex","length":1025}}),
        json!({"/id":{"kind":"random","format":"string","length":8}}),
        json!({"/id":{"kind":"random","format":"hex","length":8,"max_length":8}}),
        json!({"/id":{"kind":"identity","binding":"token"}}),
    ] {
        assert!(compile(&document(invalid.clone())).is_err(), "{invalid}");
    }
    let mut multipart = document(json!({"/token":token()}));
    multipart["rules"][0]["effect"]["multipart_boundary"] = true.into();
    assert!(compile(&multipart).is_err());
}

#[test]
fn http_body_jwt_requires_hmac_startup_key_fixed_dependency_clock_and_explicit_nonces() {
    for algorithm in ["HS256", "HS384", "HS512"] {
        let mut jwt = token();
        jwt["algorithm"] = algorithm.into();
        jwt["nonces"] = json!([{"pointer":"/jti","format":{"kind":"uuid_v4"}}]);
        let compiled = compile(&document(json!({"/token":jwt}))).unwrap();
        let NativeEffect::HttpRequest(effect) = &compiled.native[0].rule.effect else {
            unreachable!()
        };
        let HttpJsonField::Jwt { nonces, .. } = &effect.json["/token"].contract else {
            unreachable!()
        };
        assert_eq!(nonces[0].proof, compiled.native[0].rule.proof);
    }
    for (name, value) in [
        ("algorithm", json!("RS256")),
        ("signing_key", json!({"kind":"target_env","name":""})),
        ("anchor", json!("case.request_start")),
        ("relative_to", json!("/created_at")),
        (
            "nonces",
            json!([{"pointer":"/user","format":{"kind":"uuid_v4"}}]),
        ),
        (
            "nonces",
            json!([
                {"pointer":"/jti","format":{"kind":"uuid_v4"}},
                {"pointer":"/jti","format":{"kind":"uuid_v4"}}
            ]),
        ),
    ] {
        let mut jwt = token();
        jwt[name] = value;
        assert!(compile(&document(json!({"/token":jwt}))).is_err(), "{name}");
    }
    let mut parsed =
        policy::parse_policy(&document(json!({"/token":token()})).to_string()).unwrap();
    let policy::PolicyRule::Native(rule) = &mut parsed.rules[0] else {
        unreachable!()
    };
    let NativeEffect::HttpRequest(effect) = &mut rule.effect else {
        unreachable!()
    };
    let HttpJsonField::Jwt { anchor, .. } = &mut effect.json.get_mut("/token").unwrap().contract
    else {
        unreachable!()
    };
    *anchor = TimeAnchor::ApiRequestStart;
    let compiled = policy::compile_policy(&parsed).unwrap();
    let NativeEffect::HttpRequest(effect) = &compiled.native[0].rule.effect else {
        unreachable!()
    };
    assert!(matches!(
        effect.json["/token"].contract,
        HttpJsonField::Jwt {
            anchor: TimeAnchor::DependencyRequestStart,
            ..
        }
    ));
}

#[test]
fn http_body_native_ownership_rejects_a_second_permission_for_the_signed_field() {
    let mut value = document(json!({"/metadata/auth_token":token()}));
    let original = value["rules"][0].clone();
    let mut duplicate = original.clone();
    duplicate["id"] = "duplicate".into();
    value["rules"].as_array_mut().unwrap().push(duplicate);
    assert!(compile(&value).is_err());

    let mut value = document(json!({"/metadata/auth_token":token()}));
    let mut ordinary = json!({
        "id":"body-time", "surface":"dependency.request", "match":original["match"],
        "slot":"body", "codec":"json",
        "contract":{"/metadata/auth_token":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}},
        "proof":original["proof"]
    });
    value["rules"]
        .as_array_mut()
        .unwrap()
        .push(ordinary.clone());
    assert!(compile(&value).is_err());
    ordinary["contract"] = json!({"/metadata/created_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}});
    value["rules"][1] = ordinary.clone();
    assert!(compile(&value).is_ok());

    ordinary["codec"] = json!({"kind":"protobuf","fields":{
        "/metadata/created_at":{"field_path":[1],"field_type":"int64"}
    }});
    value["rules"][1] = ordinary.clone();
    assert!(compile(&value).is_err());
    ordinary["surface"] = "api.response".into();
    ordinary["match"] = json!({"api":"POST /requests"});
    value["rules"][1] = ordinary;
    assert!(compile(&value).is_ok());
}
