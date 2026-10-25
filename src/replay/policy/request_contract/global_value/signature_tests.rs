//! Redis JSON goes through the shared JWT verifier before an identity commit.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

use crate::policy::{
    SignatureDefinition,
    native::{SignatureAlgorithm, StartupKey},
    signatures::SignatureRegistry,
};
use crate::request_rules::jwt::{Algorithm, sign};

const KEY: &[u8] = b"frozen-private-owner-signature-test-key";
const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";
const F: &str = "44444444-4444-4444-8444-444444444444";
const G: &str = "55555555-5555-4555-8555-555555555555";
const H: &str = "66666666-6666-4666-8666-666666666666";

fn owner() -> RequestContracts {
    let mut compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v2
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: JWT_TEST_KEY}}
json:
  fields:
    /token: {kind: jwt}
    /copy: {kind: jwt}
    /echo: {kind: jwt}
    /jti: {kind: identity, formats: [uuid]}
    /fresh: {kind: identity, formats: [uuid]}
"#,
    )
    .unwrap();
    compiled.global_json.as_mut().unwrap().signatures = SignatureRegistry::for_test(
        BTreeMap::from([(
            "default".into(),
            SignatureDefinition::Jwt {
                algorithm: SignatureAlgorithm::HS256,
                key: StartupKey::TargetEnv {
                    name: "JWT_TEST_KEY".into(),
                },
            },
        )]),
        BTreeMap::from([("default".into(), KEY.to_vec())]),
    );
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/unrelated-api".into(),
            source_uri: String::new(),
            source_input_error: None,
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            dir: PathBuf::new(),
            conditions: Default::default(),
            source_body: None,
        },
    );
    owner
}

fn token(at: i64, jti: &str, key: &[u8], reordered: bool) -> String {
    let header = if reordered {
        r#"{"typ":"JWT","kid":"key","alg":"HS256"}"#
    } else {
        r#"{"alg":"HS256","kid":"key","typ":"JWT"}"#
    };
    let claims = json!({"sub":"user-7","scope":"read","jti":jti,"iat":at,"exp":at+60});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = sign(Algorithm::HS256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn preview(
    owner: &RequestContracts,
    key: &str,
    actual_key: &str,
    source: &Value,
    target: &Value,
) -> Result<Decision> {
    let physical = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &physical, 7, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    owner
        .preview_redis_context(
            &context,
            &[key.as_bytes().to_vec(), serde_json::to_vec(source).unwrap()],
            &[
                actual_key.as_bytes().to_vec(),
                serde_json::to_vec(target).unwrap(),
            ],
        )
        .expect("a global JSON contract selects this ordinary Redis value")
}

#[test]
fn redis_jwt_authentication_and_native_key_checks_publish_no_partial_identity_state() {
    let owner = owner();
    let equally_bad = json!({"fresh":F,"token":token(1000,A,b"wrong-secret",false)});
    assert!(preview(&owner, "session", "session", &equally_bad, &equally_bad).is_err());
    assert!(
        !owner.has_identities("case"),
        "even equal invalid signatures cannot publish an identity anchor"
    );
    let source_token = token(1000, A, KEY, false);
    let target_token = token(2000, X, KEY, false);
    let source = json!({"fresh":F,"token":source_token,"stable":true});
    let bad_target = json!({"fresh":G,"token":token(2000,X,b"wrong-secret",false),"stable":true});
    assert!(preview(&owner, "session", "session", &source, &bad_target).is_err());
    assert!(
        !owner.has_identities("case"),
        "a preceding valid identity cannot leak from bad signature comparison"
    );

    let target = json!({"fresh":G,"token":target_token,"stable":true});
    assert!(preview(&owner, "session", "changed-key", &source, &target).is_err());
    assert!(
        !owner.has_identities("case"),
        "successful JWT comparison cannot bypass the native key contract or commit early"
    );

    // A different accepted value is still available after both failed previews.
    let target = json!({"fresh":H,"token":target_token,"stable":true});
    let staged = preview(&owner, "session", "session", &source, &target).unwrap();
    assert!(!owner.has_identities("case"));
    assert!(
        !owner
            .knows_identity_value("case", &json!(source_token), &json!(target_token))
            .unwrap()
    );
    owner.commit(staged).unwrap();
    assert!(
        owner
            .knows_identity_value("case", &json!(source_token), &json!(target_token))
            .unwrap()
    );
    assert!(
        owner
            .knows_identity_value("case", &json!(F), &json!(H))
            .unwrap()
    );
    assert!(
        !owner
            .knows_identity_value("case", &json!(F), &json!(G))
            .unwrap()
    );
}

#[test]
fn redis_json_token_copies_share_one_correspondence_across_fields_and_later_values() {
    let owner = owner();
    let source_token = token(1000, A, KEY, false);
    let target_token = token(2000, X, KEY, false);
    let another_valid_encoding = token(2000, X, KEY, true);
    assert_ne!(target_token, another_valid_encoding);
    let source = json!({"token":source_token,"copy":source_token,"jti":A});
    let inconsistent = json!({"token":target_token,"copy":another_valid_encoding,"jti":X});
    assert!(preview(&owner, "first", "first", &source, &inconsistent).is_err());
    assert!(!owner.has_identities("case"));
    let target = json!({"token":target_token,"copy":target_token,"jti":X});
    let staged = preview(&owner, "first", "first", &source, &target).unwrap();
    assert!(
        !owner.has_identities("case"),
        "comparison returns an uncommitted proposal"
    );
    owner.commit(staged).unwrap();

    let later = json!({"echo":source_token,"jti":A});
    let correct = json!({"echo":target_token,"jti":X});
    assert!(preview(&owner, "second", "second", &later, &correct).is_ok());
    let wrong = json!({"echo":another_valid_encoding,"jti":X});
    assert!(
        preview(&owner, "second", "second", &later, &wrong).is_err(),
        "a later field cannot rebind the complete Source token"
    );
    let same = json!({"echo":source_token,"jti":A});
    assert!(
        preview(&owner, "second", "second", &later, &same).is_err(),
        "byte equality cannot skip verification or an already committed identity relationship"
    );
    assert!(preview(&owner, "second", "second", &later, &correct).is_ok());
}
