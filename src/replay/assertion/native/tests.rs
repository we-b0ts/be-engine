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
        ..Default::default()
    }
}

fn proof<T>(contract: T) -> Proven<T> {
    Proven {
        contract,
        proof: Proof {
            source: "source/auth.rs:1".into(),
            fact: "Source emits authenticated tokens with generated nonces".into(),
        },
    }
}

fn token(nonce: &str, now: i64, role: &str) -> String {
    crate::request_rules::tests::token(
        json!({"iat":now,"exp":now+60,"jti":nonce,"role":role}),
        "frozen-signing-key",
    )
}

#[test]
fn signed_native_tokens_compose_inside_unordered_items_without_speculative_nonce_leaks() {
    let effect = ResponseJwtEffect {
        pointer: "/items/*/auth".into(),
        algorithm: SignatureAlgorithm::HS256,
        signing_key: ResponseSigningKey::Startup {
            source: StartupKey::TargetEnv { name: "KEY".into() },
        },
        nonces: vec![proof(NonceClaim {
            pointer: "/jti".into(),
            format: NonceFormat::UuidV4,
        })],
        url_query_param: None,
        expires_at: None,
        expires_at_format: TimestampFormat::Rfc3339,
        issued_at: None,
        ttl: None,
    };
    let context = NativeResponseContext {
        generated: vec![],
        joined: vec![],
        fields: vec![("order".into(), "/items".into(), FieldContract::Unordered)],
        codec: Some(crate::policy::Codec::Json),
        jwt: vec![JwtField {
            id: "token".into(),
            rule: crate::replay::policy::native_projection::project_jwt(&effect, &proof(()).proof)
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
fn protobuf_container_rule_and_generic_child_time_share_one_strict_codec() {
    let policy = crate::policy::parse_policy(r#"
format: traffic-policy/v1
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
    /items/*/created: {kind: time, format: unix_seconds, relation: preserve_offset, anchor: case.request_start}
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
"#).unwrap();
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
    let rules = compiled.rules.iter().collect::<Vec<_>>();
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
    let _ = (TimeAnchor::ApiRequestStart, TimeRelation::PreserveOffset);
}
