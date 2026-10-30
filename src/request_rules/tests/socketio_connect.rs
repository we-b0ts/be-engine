use super::*;
use crate::interaction::{
    model::{InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    policy::InteractionPolicy,
    socketio::{EngineIoPacket, decode_engine_io_text},
};

fn auth_rule() -> JwtRule {
    JwtRule {
        id: "namespace-auth".into(),
        header: None,
        scheme: None,
        query_param: None,
        socketio_connect: Some(SocketIoConnectLocation {
            namespace: "/runtime".into(),
            pointer: "/token".into(),
        }),
        profile: "session".into(),
    }
}
fn input(raw: &str) -> Value {
    let mut request = request(json!({"exp":2000}), "test-key", 1000);
    request["uri"] = format!("/socket.io/?EIO=4&transport=websocket&token={raw}").into();
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    for (index, message) in [
        format!("40/runtime,{}", json!({"token":raw,"stable":"keep"})),
        format!("40/other,{}", json!({"token":raw})),
        format!("42/runtime,0{}", json!(["echo",{"token":raw}])),
    ]
    .into_iter()
    .enumerate()
    {
        input.actions.push(InputAction {
            sequence: index as u64 + 1,
            offset_ms: index as u64 + 5,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(message),
            },
        });
    }
    request["interaction"] = serde_json::to_value(input).unwrap();
    request
}
fn auth(request: &Value) -> String {
    jwt::request_token(request, &auth_rule().location().unwrap())
        .unwrap()
        .unwrap()
}

#[test]
fn compiled_connect_rule_uses_frozen_startup_key_and_matches_query_translation() {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join(".traffic-e2e/local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("target.env"), "SECRET_KEY=test-key\n").unwrap();
    let document = crate::policy::parse_policy(
        r#"format: traffic-policy/v2
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
api:
  GET /socket.io/:
    request:
      query: {token: default}
      socketio_connect:
        /runtime:
          /token: default
"#,
    )
    .unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let mut runtime = RequestRuleRuntime::from_compiled(root.path(), &compiled).unwrap();
    let raw = token(json!({"exp":2000,"iat":900,"sub":"user"}), "test-key");
    let mut value = input(&raw);
    let original = value.clone();
    runtime.freeze_for_request(&value).unwrap();
    let now = Utc::now();
    assert_eq!(runtime.apply(&mut value, now).unwrap().len(), 2);
    let actual = auth(&value);
    let query = JwtTokenLocation::QueryParameter {
        query_param: "token".into(),
    };
    assert_eq!(actual, jwt::request_token(&value, &query).unwrap().unwrap());
    let claims = decode::<Value>(
        &actual,
        &DecodingKey::from_secret(b"test-key"),
        &Validation::default(),
    )
    .unwrap()
    .claims;
    assert_eq!(claims["exp"], now.timestamp() + 1000);
    assert_eq!(claims["iat"], now.timestamp() - 100);
    assert_eq!(claims["sub"], "user");
    assert_eq!(
        value["interaction"]["actions"][1],
        original["interaction"]["actions"][1]
    );
    assert_eq!(
        value["interaction"]["actions"][2],
        original["interaction"]["actions"][2]
    );
    let frame = value["interaction"]["actions"][0]["action"]["message"]["data"]
        .as_str()
        .unwrap();
    let EngineIoPacket::Message(packet) = decode_engine_io_text(frame, 100000).unwrap() else {
        panic!("CONNECT")
    };
    assert_eq!(packet.data.unwrap()["stable"], "keep");
    assert_eq!(
        runtime
            .derived_identity_pairs(&original, &value)
            .unwrap()
            .len(),
        1
    );
    runtime.ensure_frozen_inputs_current().unwrap();
}

#[test]
fn connect_credentials_keep_signature_and_recorded_expiry_failures() {
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(auth_rule(), profile(), b"test-key".to_vec())]);
    let now = Utc::now();
    for (key, exp) in [("wrong-key", 2000), ("test-key", 900)] {
        let raw = token(json!({"exp":exp,"sub":"user"}), key);
        let mut value = input(&raw);
        let source = value.clone();
        let observations = runtime.apply(&mut value, now).unwrap();
        let actual = auth(&value);
        let mut validation = Validation::default();
        validation.leeway = 0;
        assert!(
            decode::<Value>(&actual, &DecodingKey::from_secret(b"test-key"), &validation).is_err()
        );
        if key == "wrong-key" {
            assert_eq!(value, source);
            assert_eq!(
                observations[0].outcome,
                "original_signature_invalid_unchanged"
            );
        }
    }
}

#[test]
fn ambiguous_reconnect_credentials_are_rejected_without_token_disclosure() {
    let first = token(json!({"exp":2000,"sub":"first"}), "test-key");
    let second = token(json!({"exp":3000,"sub":"second"}), "test-key");
    let mut value = input(&first);
    value["interaction"]["actions"][1]["action"]["message"]["data"] =
        format!("40/runtime,{}", json!({"token":second})).into();
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(auth_rule(), profile(), b"test-key".to_vec())]);
    let error = runtime
        .apply(&mut value, Utc::now())
        .unwrap_err()
        .to_string();
    assert!(error.contains("ambiguous"));
    assert!(!error.contains(&first));
    assert!(!error.contains(&second));
}
