use super::*;
use crate::policy::native::*;
use crate::policy::{Proof, TimeAnchor, TimeRelation, TimestampFormat};
use serde_json::json;

fn clocks() -> AnchorClocks {
    AnchorClocks {
        case: super::super::RequestTimes {
            source: chrono::DateTime::from_timestamp(1_000, 0),
            target: chrono::DateTime::from_timestamp(2_000, 0),
        },
        dependency: super::super::RequestTimes {
            source: chrono::DateTime::from_timestamp(1_000, 0),
            target: chrono::DateTime::from_timestamp(2_000, 0),
        },
        ..Default::default()
    }
}

fn proof<T>(contract: T) -> Proven<T> {
    Proven {
        contract,
        proof: Some(Proof {
            source: "source/auth.rs:1".into(),
            fact: "Source emits authenticated tokens with generated nonces".into(),
        }),
    }
}

fn token(nonce: &str, now: i64, role: &str) -> String {
    crate::request_rules::tests::token(
        json!({"iat":now,"exp":now+60,"jti":nonce,"role":role}),
        "frozen-signing-key",
    )
}

#[test]
fn repeated_complete_signed_tokens_cannot_split_even_when_each_signature_and_time_is_valid() {
    let effect = ResponseJwtEffect {
        pointer: "/tokens/*".into(),
        location: None,
        algorithm: SignatureAlgorithm::HS256,
        signing_key: ResponseSigningKey::Startup {
            source: StartupKey::TargetEnv { name: "KEY".into() },
        },
        nonces: vec![],
        url_query_param: None,
        expires_at: None,
        expires_at_format: TimestampFormat::Rfc3339,
        issued_at: None,
        ttl: None,
    };
    let context = NativeResponseContext {
        header_jwt: vec![],
        generated: vec![],
        joined: vec![],
        fields: vec![],
        codec: Some(crate::policy::Codec::Json),
        codec_ids: vec![],
        jwt: vec![JwtField {
            id: "token".into(),
            rule: crate::replay::policy::native_projection::project_jwt(&effect, None).unwrap(),
            key: super::super::jwt::keys::VerificationKey::for_test(b"frozen-signing-key"),
        }],
    };
    let source = token("same", 1000, "reader");
    let first = token("same", 2000, "reader");
    let other = token("same", 2001, "reader");
    let source = json!({"tokens":[source,source]});
    assert!(
        context
            .compare_json(&source, &json!({"tokens":[first,first]}), &[], clocks())
            .unwrap()
            .passed()
    );
    assert!(
        !context
            .compare_json(&source, &json!({"tokens":[first,other]}), &[], clocks())
            .unwrap()
            .passed()
    );
}

#[test]
fn signed_native_tokens_compose_inside_unordered_items_without_speculative_nonce_leaks() {
    let effect = ResponseJwtEffect {
        pointer: "/items/*/auth".into(),
        location: None,
        algorithm: SignatureAlgorithm::HS256,
        signing_key: ResponseSigningKey::Startup {
            source: StartupKey::TargetEnv { name: "KEY".into() },
        },
        nonces: vec![proof(
            NonceClaim {
                pointer: "/jti".into(),
                format: NonceFormat::UuidV4,
            }
            .into(),
        )],
        url_query_param: None,
        expires_at: None,
        expires_at_format: TimestampFormat::Rfc3339,
        issued_at: None,
        ttl: None,
    };
    let context = NativeResponseContext {
        header_jwt: vec![],
        generated: vec![],
        joined: vec![],
        fields: vec![("order".into(), "/items".into(), FieldContract::Unordered)],
        codec: Some(crate::policy::Codec::Json),
        codec_ids: vec![],
        jwt: vec![JwtField {
            id: "token".into(),
            rule: crate::replay::policy::native_projection::project_jwt(
                &effect,
                proof(()).proof.as_ref(),
            )
            .unwrap(),
            key: super::super::jwt::keys::VerificationKey::for_test(b"frozen-signing-key"),
        }],
    };
    let source = json!({"items":[{"auth":token("11111111-1111-4111-8111-111111111111",1000,"reader"),"name":"A"},{"auth":token("22222222-2222-4222-8222-222222222222",1000,"reader"),"name":"B"}]});
    let target = json!({"items":[{"auth":token("44444444-4444-4444-8444-444444444444",2000,"reader"),"name":"B"},{"auth":token("33333333-3333-4333-8333-333333333333",2000,"reader"),"name":"A"}]});
    let compared = context
        .compare_json(&source, &target, &[], clocks())
        .unwrap();
    assert!(compared.passed(), "{:?}", compared.differences);
    assert_eq!(compared.time_validations["token"], 4);
    let mut collapsed = target.clone();
    collapsed["items"][0]["auth"] = collapsed["items"][1]["auth"].clone();
    assert!(
        !context
            .compare_json(&source, &collapsed, &[], clocks())
            .unwrap()
            .passed()
    );
    let mut changed = target;
    changed["items"][0]["auth"] =
        token("44444444-4444-4444-8444-444444444444", 2000, "admin").into();
    assert!(
        !context
            .compare_json(&source, &changed, &[], clocks())
            .unwrap()
            .passed()
    );
}

#[test]
fn global_expiry_formats_compose_with_signed_jwt_companion_proofs() {
    let effect = ResponseJwtEffect {
        pointer: "/access_token".into(),
        location: None,
        algorithm: SignatureAlgorithm::HS256,
        signing_key: ResponseSigningKey::Startup {
            source: StartupKey::TargetEnv { name: "KEY".into() },
        },
        nonces: vec![proof(
            NonceClaim {
                pointer: "/jti".into(),
                format: NonceFormat::UuidV4,
            }
            .into(),
        )],
        url_query_param: None,
        expires_at: Some("/expires_at".into()),
        expires_at_format: TimestampFormat::UnixSeconds,
        issued_at: Some("/issued_at".into()),
        ttl: None,
    };
    let context = NativeResponseContext {
        header_jwt: vec![],
        generated: vec![],
        joined: vec![],
        fields: vec![],
        codec: Some(crate::policy::Codec::Json),
        codec_ids: vec![],
        jwt: vec![JwtField {
            id: "token".into(),
            rule: crate::replay::policy::native_projection::project_jwt(
                &effect,
                proof(()).proof.as_ref(),
            )
            .unwrap(),
            key: super::super::jwt::keys::VerificationKey::for_test(b"frozen-signing-key"),
        }],
    };
    let global=serde_yaml::from_str::<crate::policy::JsonPolicy>("fields:\n  /access_token: {kind: identity, formats: [string]}\n  /expires_at: {kind: time, formats: [unix_seconds]}\n  /issued_at: {kind: time, formats: [unix_seconds]}\n").unwrap().compile().unwrap();
    let source = json!({"access_token":token("11111111-1111-4111-8111-111111111111",1000,"reader"),"expires_at":1060,"issued_at":1000});
    let target = json!({"access_token":token("22222222-2222-4222-8222-222222222222",2000,"reader"),"expires_at":2060,"issued_at":2000});
    let comparison = context
        .compare_values_global(&source, &target, &[], Some(&global), clocks())
        .unwrap();
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert!(comparison.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
    assert!(comparison.evaluated.contains("token"));
    let mut wrong_companion = target.clone();
    wrong_companion["expires_at"] = json!(2061);
    assert!(
        !context
            .compare_values_global(&source, &wrong_companion, &[], Some(&global), clocks())
            .unwrap()
            .passed()
    );
    let mut wrong_signature = target;
    wrong_signature["access_token"] = json!(format!(
        "{}x",
        wrong_signature["access_token"].as_str().unwrap()
    ));
    assert!(
        !context
            .compare_values_global(&source, &wrong_signature, &[], Some(&global), clocks())
            .unwrap()
            .passed()
    );
}

#[test]
fn protobuf_container_rule_and_generic_child_time_share_one_strict_codec() {
    let raw: serde_yaml::Value = serde_yaml::from_str(
        r#"
format: traffic-policy/v2
rules:
- id: child-time
  surface: api.response
  match: {api: 'GET /payload'}
  slot: body
  codec:
    kind: protobuf
    fields:
      /items: {field_path: [1], field_type: message, repeated: true}
      /items/*/created: {field_path: [1, 2], field_type: uint64}
  contract:
    /items/*/created: {kind: time, format: unix_seconds, relation: preserve_offset}
  proof: {source: 'source/payload.rs:1', fact: 'time comes from case clock'}
- id: item-order
  match: {api: 'GET /payload'}
  effect:
    kind: response_body
    codec: protobuf
    fields:
    - contract:
        kind: unordered
        selector: {kind: protobuf, field_path: [1], alias: /items, element_type: message}
      proof: {source: 'source/payload.rs:2', fact: 'items come from a set'}
  proof: {source: 'source/payload.rs:2', fact: 'items come from a set'}
"#,
    )
    .unwrap();
    let child: crate::policy::Rule = serde_yaml::from_value(raw["rules"][0].clone()).unwrap();
    let child = crate::policy::compile_rule(&child).unwrap();
    let policy = crate::policy::parse_policy(
        &serde_yaml::to_string(&serde_json::json!({
            "format":"traffic-policy/v2","rules":[raw["rules"][1].clone()]
        }))
        .unwrap(),
    )
    .unwrap();
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    let context = NativeResponseContext::load(
        &compiled,
        "GET",
        "/payload",
        None,
        Path::new("."),
        Path::new("."),
    )
    .unwrap();
    fn item(id: u8, time: u64) -> Vec<u8> {
        let mut bytes = vec![0x0a, 1, id, 0x10];
        let mut value = time;
        loop {
            let byte = (value & 127) as u8;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 128 });
            if value == 0 {
                break;
            }
        }
        [vec![0x0a, bytes.len() as u8], bytes].concat()
    }
    let source = [item(b'A', 1000), item(b'B', 1001)].concat();
    let target = [item(b'B', 2001), item(b'A', 2000)].concat();
    let rules = vec![&child];
    assert!(
        context
            .compare_encoded(&source, &target, &rules, clocks())
            .unwrap()
            .passed()
    );
    let changed = [item(b'C', 2001), item(b'A', 2000)].concat();
    assert!(
        !context
            .compare_encoded(&source, &changed, &rules, clocks())
            .unwrap()
            .passed()
    );
    let collapsed_delta = [item(b'B', 2002), item(b'A', 2000)].concat();
    assert!(
        !context
            .compare_encoded(&source, &collapsed_delta, &rules, clocks())
            .unwrap()
            .passed()
    );
    let _ = (
        TimeAnchor::DependencyRequestStart,
        TimeRelation::PreserveOffset,
    );
}
