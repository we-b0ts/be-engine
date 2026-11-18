use super::*;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

mod socketio_connect;

#[allow(dead_code)]
fn rule() -> JwtRule {
    JwtRule {
        id: "session-jwt".into(),
        header: Some("authorization".into()),
        scheme: Some("bearer".into()),
        query_param: None,
        socketio_connect: None,
        profile: "session".into(),
    }
}

#[allow(dead_code)]
fn profile() -> JwtProfile {
    JwtProfile {
        signing_key_ref: "session-jwt".into(),
        signing_key_source: None,
        algorithm: JwtAlgorithm::HS256,
        time: JwtTime::PreserveRelative,
    }
}

#[allow(dead_code)]
fn query_rule() -> JwtRule {
    JwtRule {
        id: "download-jwt".into(),
        header: None,
        scheme: None,
        query_param: Some("download_token".into()),
        socketio_connect: None,
        profile: "session".into(),
    }
}

pub fn token(claims: Value, key: &str) -> String {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap()
}

pub fn request(claims: Value, key: &str, recorded: i64) -> Value {
    json!({"method":"GET","uri":"/api","timestamp":DateTime::from_timestamp(recorded,0).unwrap(),
        "headers":{"authorization":[format!("Bearer {}",token(claims,key))]},"body":{"encoding":"utf8","data":"","truncated":false}})
}

#[test]
fn token_parser_rejects_duplicate_header_and_claim_members() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    for (header, claims) in [
        (r#"{"alg":"HS256","alg":"HS512"}"#, r#"{"exp":1000}"#),
        (r#"{"alg":"HS256"}"#, r#"{"exp":1000,"exp":2000}"#),
    ] {
        let raw = format!(
            "{}.{}.AA",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        assert!(jwt::Token::parse(&raw).unwrap().is_none());
    }
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
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(rule(), profile(), b"test-key".to_vec())]);
    let observations = runtime.apply(&mut value, now).unwrap();
    let raw = jwt::request_token(&value, &rule().location().unwrap())
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
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(rule(), profile(), b"test-key".to_vec())]);
    for claims in [
        json!({"exp":900,"sub":"user"}),
        json!({"exp":2000,"nbf":1500,"sub":"user"}),
    ] {
        let mut value = request(claims, "test-key", 1000);
        runtime.apply(&mut value, now).unwrap();
        let raw = jwt::request_token(&value, &rule().location().unwrap())
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
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(rule(), profile(), b"test-key".to_vec())]);
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
fn raw_header_keeps_representation_and_validates_signature_and_relative_lifetime() {
    let mut rule = rule();
    rule.header = Some("x-download-token".into());
    rule.scheme = Some("raw".into());
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(rule.clone(), profile(), b"test-key".to_vec())]);
    for (key, claims, should_shift) in [
        (
            "test-key",
            json!({"sub":"user","exp":1300,"iat":1000}),
            true,
        ),
        ("wrong-key", json!({"sub":"user","exp":1300}), false),
        ("test-key", json!({"sub":"user","exp":900}), true),
    ] {
        let original = token(claims.clone(), key);
        let mut value = request(json!({"exp":1300}), "test-key", 1000);
        value["headers"] = json!({"X-Download-Token":[original],"other":["stable"]});
        let before = value.clone();
        runtime
            .apply(&mut value, DateTime::from_timestamp(10000, 0).unwrap())
            .unwrap();
        let raw = value["headers"]["X-Download-Token"][0].as_str().unwrap();
        assert!(!raw.contains(' '));
        assert_eq!(value["headers"]["other"], before["headers"]["other"]);
        if should_shift {
            let parsed = jwt::Token::parse(raw).unwrap().unwrap();
            assert!(parsed.verify(b"test-key"));
            assert_eq!(parsed.claims["exp"], claims["exp"].as_i64().unwrap() + 9000);
            assert_eq!(parsed.claims["sub"], claims["sub"]);
        } else {
            assert_eq!(value, before);
        }
    }
    let location = rule.location().unwrap();
    let encoded = serde_json::to_string(&location).unwrap();
    assert_eq!(
        serde_json::from_str::<JwtTokenLocation>(&encoded).unwrap(),
        location
    );
    for value in [json!(["first", "second"]), json!(["Bearer abc.def.ghi"])] {
        let request = json!({"headers":{"x-download-token":value}});
        if request["headers"]["x-download-token"]
            .as_array()
            .unwrap()
            .len()
            > 1
        {
            assert!(jwt::request_token(&request, &location).is_err());
        } else {
            assert!(jwt::request_token(&request, &location).unwrap().is_none());
        }
    }
}

#[test]
fn key_rotation_applies_only_one_matching_rule_and_preserves_absent_claims() {
    let mut old = rule();
    old.id = "old".into();
    old.profile = "old".into();
    let old_profile = JwtProfile {
        signing_key_ref: "old".into(),
        signing_key_source: None,
        algorithm: JwtAlgorithm::HS256,
        time: JwtTime::PreserveRelative,
    };
    let runtime = RequestRuleRuntime::with_test_keys(vec![
        (rule(), profile(), b"new-key".to_vec()),
        (old, old_profile, b"old-key".to_vec()),
    ]);
    let mut value = request(json!({"exp":2000,"sub":"user"}), "old-key", 1000);
    runtime
        .apply(&mut value, DateTime::from_timestamp(3000, 0).unwrap())
        .unwrap();
    let raw = jwt::request_token(&value, &rule().location().unwrap())
        .unwrap()
        .unwrap();
    let parsed = jwt::Token::parse(&raw).unwrap().unwrap();
    assert!(parsed.verify(b"old-key"));
    assert_eq!(parsed.claims["exp"], 4000);
    assert!(parsed.claims.get("iat").is_none());
    assert!(parsed.claims.get("nbf").is_none());
}

#[test]
fn shifts_query_jwt_without_reencoding_the_rest_of_the_uri() {
    let recorded = 1_700_000_000;
    let mut value = request(
        json!({"sub":"user","exp":recorded+300,"iat":recorded}),
        "test-key",
        recorded,
    );
    let token = value["headers"]["authorization"][0]
        .as_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_string();
    value["headers"] = json!({});
    value["uri"] = json!(format!(
        "/api/export?message_ids=1%2C2&download_token={token}&name=a+b&empty=#fragment"
    ));
    let runtime =
        RequestRuleRuntime::with_test_keys(vec![(query_rule(), profile(), b"test-key".to_vec())]);
    let now = DateTime::from_timestamp(recorded + 3600, 0).unwrap();
    runtime.apply(&mut value, now).unwrap();
    let uri = value["uri"].as_str().unwrap();
    assert!(uri.starts_with("/api/export?message_ids=1%2C2&download_token="));
    assert!(uri.ends_with("&name=a+b&empty=#fragment"));
    let raw = jwt::request_token(&value, &query_rule().location().unwrap())
        .unwrap()
        .unwrap();
    let parsed = jwt::Token::parse(&raw).unwrap().unwrap();
    assert!(parsed.verify(b"test-key"));
    assert_eq!(parsed.claims["exp"], recorded + 3900);
    assert_eq!(parsed.claims["iat"], recorded + 3600);
}

#[test]
fn rejects_ambiguous_query_values_and_invalid_selector_shapes() {
    let request = json!({"uri":"/api?download_token=a&download_token=b"});
    assert!(
        jwt::request_token(&request, &query_rule().location().unwrap())
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    for input in [
        "jwt: [{id: a, header: authorization, scheme: bearer, query_param: token, algorithm: HS256, time: preserve_relative, signing_key_ref: k}]",
        "jwt: [{id: a, query_param: token, scheme: bearer, algorithm: HS256, time: preserve_relative, signing_key_ref: k}]",
        "jwt: [{id: a, query_param: 'bad name', algorithm: HS256, time: preserve_relative, signing_key_ref: k}]",
    ] {
        let rules: RequestRules = serde_yaml::from_str(input).unwrap();
        assert!(rules.validate().is_err(), "{input}");
    }
}

#[test]
fn rejects_unsupported_rule_shapes_and_retired_section_authoring() {
    for input in [
        "jwt: [{id: a, header: authorization, scheme: bearer, algorithm: none, time: preserve_relative, signing_key_ref: k}]",
        "jwt: [{id: a, header: authorization, scheme: bearer, algorithm: HS256, time: ignore, signing_key_ref: k}]",
    ] {
        assert!(serde_yaml::from_str::<RequestRules>(input).is_err());
    }
    let original = "format: traffic-policy/v3\n# preserve this document\nrules: []\n";
    let error = policy::add(original, &profile(), &rule()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
}

#[test]
fn shared_profile_owns_key_algorithm_and_time_policy() {
    let rules: RequestRules = serde_yaml::from_str(
        "jwt:\n  profiles:\n    session:\n      signing_key_ref: session-jwt\n      signing_key_source:\n        kind: target_env\n        name: SECRET_KEY\n      algorithm: HS256\n      time: preserve_relative\n  rules:\n  - id: session-bearer-header\n    header: authorization\n    scheme: bearer\n    profile: session\n  - id: download-token\n    query_param: download_token\n    profile: session\n",
    )
    .unwrap();
    rules.validate().unwrap();
    assert_eq!(rules.jwt.profiles.len(), 1);
    assert_eq!(rules.jwt.rules.len(), 2);
    let rendered = serde_yaml::to_string(&rules).unwrap();
    assert!(rendered.contains("profiles:"));
    assert!(rendered.contains("rules:"));
    assert!(!rendered.contains("challenge"));
}

#[test]
fn legacy_list_remains_readable_but_uses_independent_profiles() {
    let rules: RequestRules = serde_yaml::from_str(
        "jwt:\n- id: legacy\n  header: authorization\n  scheme: bearer\n  algorithm: HS256\n  time: preserve_relative\n  signing_key_ref: session-jwt\n",
    )
    .unwrap();
    rules.validate().unwrap();
    assert_eq!(rules.jwt.rules[0].profile, "legacy");
    assert_eq!(rules.jwt.profiles["legacy"].signing_key_ref, "session-jwt");
}

#[test]
fn configured_source_does_not_require_a_local_binding() {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join(".traffic-e2e/local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("target.env"), "SECRET_KEY=test-key\n").unwrap();
    let policy_path = root.path().join("policy.yaml");
    std::fs::write(
        &policy_path,
        serde_yaml::to_string(&json!({"format":"traffic-policy/v3","rules":[{
            "id":"bearer","match":{"api":"GET /api"},
            "effect":{"kind":"input_jwt","location":{"kind":"bearer_header","name":"authorization"},
                "algorithm":"HS256","time":"preserve_relative","signing_key":{"kind":"target_env","name":"SECRET_KEY"}},
            "proof":{"source":"auth.py:verify","fact":"Source verifies this signed input and uses relative JWT claim times"}
        }]})).unwrap(),
    )
    .unwrap();
    let runtime = RequestRuleRuntime::load(root.path(), &policy_path).unwrap();
    let mut no_token = json!({"headers": {}});
    assert!(runtime.apply(&mut no_token, Utc::now()).unwrap().is_empty());
    let mut opaque = json!({"headers": {"authorization": ["Bearer api-key"]}});
    assert!(runtime.apply(&mut opaque, Utc::now()).unwrap().is_empty());

    let mut matching = request(json!({"exp": 2_000}), "test-key", 1_000);
    let observations = runtime.apply(&mut matching, Utc::now()).unwrap();
    assert_eq!(observations[0].outcome, "time_shifted_signature_verified");
    assert!(
        !root
            .path()
            .join(".traffic-e2e/local/secrets/jwt-signing-keys.json")
            .exists()
    );
}

#[cfg(test)]
use jsonwebtoken::DecodingKey;
#[cfg(test)]
use jsonwebtoken::Validation;
#[cfg(test)]
use jsonwebtoken::decode;
