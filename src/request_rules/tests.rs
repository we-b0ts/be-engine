use super::*;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::json;

fn rule() -> JwtRule {
    JwtRule {
        id: "session-jwt".into(),
        header: "authorization".into(),
        scheme: "bearer".into(),
        algorithm: JwtAlgorithm::HS256,
        time: JwtTime::PreserveRelative,
        signing_key_ref: "session-jwt".into(),
    }
}

pub(crate) fn token(claims: Value, key: &str) -> String {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap()
}

pub(crate) fn request(claims: Value, key: &str, recorded: i64) -> Value {
    json!({"method":"GET","uri":"/api","timestamp":DateTime::from_timestamp(recorded,0).unwrap(),
        "headers":{"authorization":[format!("Bearer {}",token(claims,key))]},"body":{"encoding":"utf8","data":"","truncated":false}})
}

#[test]
fn preserves_time_relationships_and_identity_with_independent_verification() {
    let recorded = 1_700_000_000;
    let now = Utc::now();
    let mut value = request(
        json!({"sub":"user","roles":["reader"],"exp":recorded+3600,"nbf":recorded-10,"iat":recorded-100}),
        "test-key",
        recorded,
    );
    let runtime = RequestRuleRuntime {
        rules: vec![(rule(), b"test-key".to_vec())],
    };
    let observations = runtime.apply(&mut value, now).unwrap();
    let raw = jwt::request_token(&value, "authorization")
        .unwrap()
        .unwrap();
    let mut validation = Validation::default();
    validation.validate_nbf = true;
    let claims = decode::<Value>(&raw, &DecodingKey::from_secret(b"test-key"), &validation)
        .unwrap()
        .claims;
    assert_eq!(claims["exp"], now.timestamp() + 3600);
    assert_eq!(claims["nbf"], now.timestamp() - 10);
    assert_eq!(claims["iat"], now.timestamp() - 100);
    assert_eq!(claims["roles"], json!(["reader"]));
    assert_eq!(observations[0].outcome, "time_shifted_signature_verified");
}

#[test]
fn recorded_expired_and_not_yet_valid_tokens_still_fail() {
    let now = Utc::now();
    let runtime = RequestRuleRuntime {
        rules: vec![(rule(), b"test-key".to_vec())],
    };
    for claims in [
        json!({"exp":900,"sub":"user"}),
        json!({"exp":2000,"nbf":1500,"sub":"user"}),
    ] {
        let mut value = request(claims, "test-key", 1000);
        runtime.apply(&mut value, now).unwrap();
        let raw = jwt::request_token(&value, "authorization")
            .unwrap()
            .unwrap();
        let mut validation = Validation::default();
        validation.leeway = 0;
        validation.validate_nbf = true;
        assert!(
            decode::<Value>(&raw, &DecodingKey::from_secret(b"test-key"), &validation).is_err()
        );
    }
}

#[test]
fn invalid_signatures_and_non_jwt_credentials_are_not_reissued() {
    let runtime = RequestRuleRuntime {
        rules: vec![(rule(), b"test-key".to_vec())],
    };
    let mut value = request(json!({"exp":2000}), "wrong-key", 1000);
    let before = value.clone();
    assert_eq!(
        runtime.apply(&mut value, Utc::now()).unwrap()[0].outcome,
        "original_signature_invalid_unchanged"
    );
    assert_eq!(value, before);
    for raw in [
        "Bearer api-key",
        "Basic abc",
        "Bearer eyJhbGciOiJub25lIn0.e30.",
    ] {
        value["headers"]["authorization"] = json!([raw]);
        let before = value.clone();
        assert!(runtime.apply(&mut value, Utc::now()).unwrap().is_empty());
        assert_eq!(value, before);
    }
}

#[test]
fn key_rotation_applies_only_one_matching_rule_and_preserves_absent_claims() {
    let mut old = rule();
    old.id = "old".into();
    old.signing_key_ref = "old".into();
    let runtime = RequestRuleRuntime {
        rules: vec![(rule(), b"new-key".to_vec()), (old, b"old-key".to_vec())],
    };
    let mut value = request(json!({"exp":2000,"sub":"user"}), "old-key", 1000);
    runtime
        .apply(&mut value, DateTime::from_timestamp(3000, 0).unwrap())
        .unwrap();
    let raw = jwt::request_token(&value, "authorization")
        .unwrap()
        .unwrap();
    let parsed = jwt::Token::parse(&raw).unwrap().unwrap();
    assert!(parsed.verify(b"old-key"));
    assert_eq!(parsed.claims["exp"], 4000);
    assert!(parsed.claims.get("iat").is_none());
    assert!(parsed.claims.get("nbf").is_none());
}

#[test]
fn rejects_unsupported_rule_shapes_and_keeps_other_policy_sections() {
    for input in [
        "jwt: [{id: a, header: authorization, scheme: bearer, algorithm: none, time: preserve_relative, signing_key_ref: k}]",
        "jwt: [{id: a, header: authorization, scheme: bearer, algorithm: HS256, time: ignore, signing_key_ref: k}]",
    ] {
        assert!(serde_yaml::from_str::<RequestRules>(input).is_err());
    }
    let original = "version: 3\nexpected_response: assertions_only\n# keep this comment\ndependency_rules: []\nresponse_rules: {}\n";
    let updated = policy::add(original, &rule()).unwrap();
    assert!(updated.starts_with(original));
    assert_eq!(policy::add(&updated, &rule()).unwrap(), updated);
    assert!(
        policy::add(
            "version: 1\nexpected_response: assertions_only\ndependency_rules: []\n",
            &rule()
        )
        .is_err()
    );
}
