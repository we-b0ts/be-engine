use super::*;
use serde_json::json;

fn proof() -> Value {
    json!({"source":"source.rs:trace","fact":"The complete Source trace validates every selected relationship"})
}
fn compile(rules: Vec<Value>) -> CompiledPolicy {
    crate::policy::compile_policy(
        &serde_json::from_value(json!({"format":"traffic-policy/v3","rules":rules})).unwrap(),
    )
    .unwrap()
}
fn request() -> Value {
    json!({"method":"POST","uri":"/tasks","timestamp":"1970-01-01T00:16:40Z","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}})
}
#[test]
fn source_input_session_binds_actual_startup_key_files_and_rejects_unverified_tokens() {
    let policy = compile(vec![
        json!({"id":"input-token","match":{"api":"POST /tasks"},"effect":{"kind":"input_jwt","location":{"kind":"bearer_header","name":"authorization"},"algorithm":"HS256","time":"preserve_relative","signing_key":{"kind":"target_env","name":"TOKEN_KEY"}},"proof":proof()}),
    ]);
    let temp = tempfile::tempdir().unwrap();
    let environment = temp.path().join(crate::repository::LOCAL_TARGET_ENV_PATH);
    std::fs::create_dir_all(environment.parent().unwrap()).unwrap();
    std::fs::write(&environment, "TOKEN_KEY=source-key\n").unwrap();
    let token = |key: &[u8]| {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &json!({"exp":1300,"iat":1000,"sub":"kept","roles":["reader"]}),
            &jsonwebtoken::EncodingKey::from_secret(key),
        )
        .unwrap()
    };
    let mut source = request();
    source["headers"] = json!({"authorization":[format!("Bearer {}",token(b"source-key"))]});
    std::fs::write(temp.path().join("request.json"), source.to_string()).unwrap();
    let validate = |source: &Value| {
        validate_source_inputs(
            &policy,
            &BTreeSet::from(["input-token".into()]),
            temp.path(),
            &[SourceInputCase {
                id: "case",
                dir: temp.path(),
                request: source,
            }],
        )
    };
    let checked = validate(&source).unwrap();
    assert_eq!(checked.rules["input-token"], 1);
    assert!(
        checked
            .key_witnesses
            .iter()
            .any(|(path, _)| *path == environment)
    );
    source["headers"]["authorization"][0] = json!(format!("Bearer {}", token(b"other-key")));
    std::fs::write(temp.path().join("request.json"), source.to_string()).unwrap();
    assert!(validate(&source).is_err());
}
