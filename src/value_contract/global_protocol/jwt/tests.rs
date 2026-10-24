use super::*;
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use crate::policy::{
    JsonPolicy, SignatureDefinition, native::StartupKey, signatures::SignatureRegistry,
};
use crate::value_contract::{
    global,
    identities::{IdentityDecision, IdentityStore},
    json::{AnchorClocks, Comparison},
    time::ClockPair,
};

const KEY: &[u8] = b"private-frozen-test-signing-material";
const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";
const Y: &str = "33333333-3333-4333-8333-333333333333";

fn plan(algorithm: SignatureAlgorithm) -> CompiledJsonPolicy {
    let json:JsonPolicy = serde_yaml::from_str("fields:\n  /token: {kind: jwt}\n  /copy: {kind: jwt}\n  /jti: {kind: identity, formats: [uuid]}\n  /nested_token: {kind: jwt}\n  /url: {kind: url, formats: [url]}\n").unwrap();
    let definitions = BTreeMap::from([(
        "default".into(),
        SignatureDefinition::Jwt {
            algorithm,
            key: StartupKey::TargetEnv {
                name: "JWT_TEST_KEY".into(),
            },
        },
    )]);
    let mut plan = json.compile_with_signatures(&definitions).unwrap();
    plan.signatures = SignatureRegistry::for_test(
        definitions,
        BTreeMap::from([("default".into(), KEY.to_vec())]),
    );
    plan
}

fn clocks(source: i64, target: i64) -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(source, 0),
            target: chrono::DateTime::from_timestamp(target, 0),
        },
        ..Default::default()
    }
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
    }
}

fn signed_raw(header: &str, claims: &str, key: &[u8], algorithm: Algorithm) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = crate::request_rules::jwt::sign(algorithm, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn signed(claims: &Value, algorithm: Algorithm) -> String {
    signed_raw(
        &json!({"alg":algorithm_name(algorithm),"typ":"JWT","kid":"test-key"}).to_string(),
        &claims.to_string(),
        KEY,
        algorithm,
    )
}

fn claims(at: i64, jti: &str) -> Value {
    json!({"iss":"auth.test","sub":"user-7","aud":"client-a","scope":["read","write"],
        "iat":at,"nbf":at,"exp":at+60,"jti":jti,"extra":{"stable":true}})
}

fn compared(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Comparison {
    global::compare_logical(source, target, plan, &[], clocks).unwrap()
}

fn leaf(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<LeafObservations, String> {
    compare(
        LeafContext {
            source,
            target,
            source_pointer: "/token",
            target_pointer: "/token",
            source_root: source,
            target_root: target,
            clocks,
        },
        plan,
        "default",
    )
}

#[test]
fn authenticated_claims_and_complete_tokens_share_the_global_atomic_correspondence() {
    let policy = plan(SignatureAlgorithm::HS256);
    let source_token = signed(&claims(1000, A), Algorithm::HS256);
    let target_token = signed(&claims(2000, X), Algorithm::HS256);
    let source = json!({"token":source_token,"copy":source_token,"jti":A});
    let target = json!({"token":target_token,"copy":target_token,"jti":X});
    let good = compared(&source, &target, &policy, clocks(1000, 2000));
    assert!(good.passed(), "{:?}", good.differences);
    assert_eq!(good.identity_pairs().len(), 2);
    assert_eq!(good.time_validations.values().sum::<usize>(), 6);

    let mut inconsistent = target.clone();
    inconsistent["jti"] = Y.into();
    assert!(!compared(&source, &inconsistent, &policy, clocks(1000, 2000)).passed());

    // Two independently valid encodings of equal protected JSON are still
    // distinct complete tokens. The same Source token cannot choose both.
    let same_claims_different_token = signed_raw(
        r#"{"typ":"JWT","kid":"test-key","alg":"HS256"}"#,
        &claims(2000, X).to_string(),
        KEY,
        Algorithm::HS256,
    );
    assert_ne!(same_claims_different_token, target_token);
    inconsistent = target.clone();
    inconsistent["copy"] = same_claims_different_token.into();
    assert!(!compared(&source, &inconsistent, &policy, clocks(1000, 2000)).passed());

    // Preview is pure. A later conflicting commit rejects the whole proposal,
    // so its otherwise fresh nonce cannot leak into the common store.
    let mut store = IdentityStore::default();
    store
        .commit(IdentityDecision::prepare("case", good.identity_pairs()).unwrap())
        .unwrap();
    let mut fresh_source = claims(1000, A);
    let mut fresh_target = claims(2000, Y);
    fresh_source["marker"] = "fresh".into();
    fresh_target["marker"] = "fresh".into();
    let fresh_source = json!(signed(&fresh_source, Algorithm::HS256));
    let fresh_target = json!(signed(&fresh_target, Algorithm::HS256));
    let observed = leaf(&fresh_source, &fresh_target, &policy, clocks(1000, 2000)).unwrap();
    assert!(
        store
            .commit(IdentityDecision::prepare("case", observed.identities).unwrap())
            .is_err()
    );
    assert!(
        !store
            .contains_pair(
                "case",
                IdentityPair {
                    source: json!(A).to_string(),
                    target: json!(Y).to_string()
                }
            )
            .unwrap()
    );
    assert!(
        !store
            .contains_pair(
                "case",
                IdentityPair {
                    source: fresh_source.to_string(),
                    target: fresh_target.to_string()
                }
            )
            .unwrap()
    );
}

#[test]
fn recognized_equal_tokens_must_authenticate_and_use_the_configured_algorithm() {
    let policy = plan(SignatureAlgorithm::HS256);
    let value = json!(signed(&claims(1000, A), Algorithm::HS256));
    assert!(leaf(&value, &value, &policy, clocks(1000, 1000)).is_ok());
    let bad = json!(signed_raw(
        r#"{"alg":"HS256","typ":"JWT","kid":"test-key"}"#,
        &claims(1000, A).to_string(),
        b"wrong-key",
        Algorithm::HS256
    ));
    let error = leaf(&bad, &bad, &policy, clocks(1000, 1000)).err().unwrap();
    assert!(error.contains("signature is invalid"));
    assert!(!error.contains(std::str::from_utf8(KEY).unwrap()));
    assert!(!error.contains(bad.as_str().unwrap()));

    let mut no_key = policy.clone();
    no_key.signatures = SignatureRegistry::default();
    assert!(leaf(&value, &value, &no_key, clocks(1000, 1000)).is_err());
    for algorithm in [Algorithm::HS384, Algorithm::HS512] {
        let wrong = json!(signed(&claims(1000, A), algorithm));
        assert!(leaf(&wrong, &wrong, &policy, clocks(1000, 1000)).is_err());
    }
    let none = json!(format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"sub":"7"}"#)
    ));
    assert!(leaf(&none, &none, &policy, Default::default()).is_err());
    let rsa = json!(format!(
        "{}.{}.AQ",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"sub":"7"}"#)
    ));
    assert!(
        leaf(
            &rsa,
            &rsa,
            &plan(SignatureAlgorithm::RS256),
            Default::default()
        )
        .is_err()
    );
}

#[test]
fn hmac_variants_and_optional_numeric_dates_reuse_the_same_validity_rules() {
    for (algorithm, definition) in [
        (Algorithm::HS256, SignatureAlgorithm::HS256),
        (Algorithm::HS384, SignatureAlgorithm::HS384),
        (Algorithm::HS512, SignatureAlgorithm::HS512),
    ] {
        let policy = plan(definition);
        for (source, target, expected_times) in [
            (json!({"sub":"7"}), json!({"sub":"7"}), 0),
            (
                json!({"iat":1000,"sub":"7"}),
                json!({"iat":2000,"sub":"7"}),
                1,
            ),
            (
                json!({"nbf":1000,"sub":"7"}),
                json!({"nbf":2000,"sub":"7"}),
                1,
            ),
            (
                json!({"exp":1060,"sub":"7"}),
                json!({"exp":2060,"sub":"7"}),
                1,
            ),
            (claims(1000, A), claims(2000, X), 3),
        ] {
            let dates = if expected_times == 0 {
                Default::default()
            } else {
                clocks(1000, 2000)
            };
            let result = leaf(
                &json!(signed(&source, algorithm)),
                &json!(signed(&target, algorithm)),
                &policy,
                dates,
            )
            .unwrap();
            assert_eq!(result.time_validations, expected_times);
        }
    }
    let policy = plan(SignatureAlgorithm::HS256);
    let source = json!(signed(&claims(1000, A), Algorithm::HS256));
    for target in [
        json!({"iat":2010,"nbf":2000,"exp":2060,"jti":X}),
        json!({"iat":2000,"nbf":2010,"exp":2060,"jti":X}),
        json!({"iat":2000,"nbf":2000,"exp":2000,"jti":X}),
        json!({"iat":2000,"nbf":2000,"exp":2070,"jti":X}),
        json!({"iat":2000,"nbf":2000,"exp":"2060","jti":X}),
        json!({"iat":2000,"nbf":2000,"exp":2060.5,"jti":X}),
        json!({"iat":2000,"exp":2060,"jti":X}),
    ] {
        let mut changed = claims(2000, X);
        for name in ["iat", "nbf", "exp"] {
            changed.as_object_mut().unwrap().remove(name);
        }
        changed
            .as_object_mut()
            .unwrap()
            .extend(target.as_object().unwrap().clone());
        assert!(
            leaf(
                &source,
                &json!(signed(&changed, Algorithm::HS256)),
                &policy,
                clocks(1000, 2000)
            )
            .is_err()
        );
    }
    assert!(
        leaf(&source, &source, &policy, Default::default()).is_ok(),
        "equal NumericDates still authenticate but need no clock relation"
    );
}

#[test]
fn global_jwt_dates_cover_historical_and_future_tokens_without_an_issuance_requirement() {
    let policy = plan(SignatureAlgorithm::HS256);
    for source in [
        json!({"sub":"7","iat":400,"nbf":450,"exp":500}),
        json!({"sub":"7","iat":1500,"nbf":1600,"exp":1700}),
        json!({"sub":"7","nbf":1600}),
    ] {
        let mut shifted = source.clone();
        for name in ["iat", "nbf", "exp"] {
            if let Some(value) = shifted.get_mut(name) {
                *value = json!(value.as_i64().unwrap() + 1000);
            }
        }
        let before = json!(signed(&source, Algorithm::HS256));
        let after = json!(signed(&shifted, Algorithm::HS256));
        assert!(leaf(&before, &before, &policy, Default::default()).is_ok());
        assert!(
            leaf(&before, &before, &policy, clocks(1000, 2000)).is_ok(),
            "equal data does not become a fresh issuance merely because clocks differ"
        );
        assert!(
            leaf(&before, &after, &policy, clocks(1000, 2000)).is_ok(),
            "past expiry and future activation are data formats with relative offsets"
        );
        assert!(
            leaf(&before, &after, &policy, Default::default()).is_err(),
            "different dates require independently observed clocks"
        );
        let changed = if shifted.get("nbf").is_some() {
            "nbf"
        } else {
            "exp"
        };
        shifted[changed] = json!(shifted[changed].as_i64().unwrap() + 10);
        assert!(
            leaf(
                &before,
                &json!(signed(&shifted, Algorithm::HS256)),
                &policy,
                clocks(1000, 2000)
            )
            .is_err(),
            "historical/future data cannot waive the relative offset check"
        );
    }
    for invalid in [json!(null), json!("500"), json!(500.5)] {
        let value = json!(signed(&json!({"sub":"7","exp":invalid}), Algorithm::HS256));
        assert!(
            leaf(&value, &value, &policy, Default::default()).is_err(),
            "equality does not make a malformed NumericDate valid"
        );
    }
    let source = json!(signed(&json!({"sub":"7","nbf":1600}), Algorithm::HS256));
    let target = json!(signed(&json!({"sub":"7"}), Algorithm::HS256));
    assert!(
        leaf(&source, &target, &policy, Default::default()).is_err(),
        "a present NumericDate cannot disappear"
    );
}

#[test]
fn headers_ordinary_claims_and_undeclared_nonces_remain_strict() {
    let policy = plan(SignatureAlgorithm::HS256);
    let source = json!(signed(&claims(1000, A), Algorithm::HS256));
    for (name, value) in [
        ("iss", json!("other.test")),
        ("sub", json!("user-8")),
        ("aud", json!("client-b")),
        ("scope", json!(["read"])),
        ("extra", json!({"stable":false})),
        ("jti", json!("bad-uuid")),
    ] {
        let mut changed = claims(2000, X);
        changed[name] = value;
        assert!(
            leaf(
                &source,
                &json!(signed(&changed, Algorithm::HS256)),
                &policy,
                clocks(1000, 2000)
            )
            .is_err(),
            "{name}"
        );
    }
    let changed_header = json!(signed_raw(
        r#"{"alg":"HS256","typ":"JWT","kid":"another-key"}"#,
        &claims(2000, X).to_string(),
        KEY,
        Algorithm::HS256
    ));
    assert!(leaf(&source, &changed_header, &policy, clocks(1000, 2000)).is_err());
    let mut undeclared = policy.clone();
    undeclared.fields.remove("/jti");
    assert!(
        leaf(
            &source,
            &json!(signed(&claims(2000, X), Algorithm::HS256)),
            &undeclared,
            clocks(1000, 2000)
        )
        .is_err()
    );
    let mut nested_source = claims(1000, A);
    let mut nested_target = claims(2000, X);
    nested_source["nested_token"] = source.clone();
    nested_target["nested_token"] = source.clone();
    nested_source["url"] = "https://auth.test/?jti=fixed".into();
    nested_target["url"] = nested_source["url"].clone();
    assert!(
        leaf(
            &json!(signed(&nested_source, Algorithm::HS256)),
            &json!(signed(&nested_target, Algorithm::HS256)),
            &policy,
            clocks(1000, 2000)
        )
        .is_ok()
    );
    nested_target["nested_token"] = changed_header;
    assert!(
        leaf(
            &json!(signed(&nested_source, Algorithm::HS256)),
            &json!(signed(&nested_target, Algorithm::HS256)),
            &policy,
            clocks(1000, 2000)
        )
        .is_err()
    );
}

#[test]
fn only_unrecognized_equal_values_keep_exact_fallback() {
    let mut policy = plan(SignatureAlgorithm::HS256);
    policy.signatures = SignatureRegistry::default();
    for value in [json!(null), json!(7), json!("opaque-non-jwt")] {
        assert!(leaf(&value, &value, &policy, Default::default()).is_ok());
        assert!(leaf(&value, &json!("different"), &policy, Default::default()).is_err());
    }
    let known = json!(signed(&claims(1000, A), Algorithm::HS256));
    assert!(
        leaf(
            &known,
            &json!("opaque-non-jwt"),
            &policy,
            clocks(1000, 2000)
        )
        .is_err()
    );
}

#[test]
fn native_profiles_still_require_exp_after_numeric_date_extraction() {
    let source = json!({"iat":1000,"sub":"7"});
    let target = json!({"iat":2000,"sub":"7"});
    assert!(matches!(
        contract::compare_authenticated_claims(
            source,
            target,
            [1_000_000_000_000, 2_000_000_000_000],
            TIME_TOLERANCE_NANOS,
            &[]
        ),
        Err(contract::Failure::Time)
    ));
    for (source, target) in [
        (json!({"iat":400,"exp":500}), json!({"iat":1400,"exp":1500})),
        (
            json!({"iat":1010,"nbf":1010,"exp":1060}),
            json!({"iat":2010,"nbf":2010,"exp":2060}),
        ),
    ] {
        assert!(
            matches!(
                contract::compare_authenticated_claims(
                    source,
                    target,
                    [1_000_000_000_000, 2_000_000_000_000],
                    TIME_TOLERANCE_NANOS,
                    &[]
                ),
                Err(contract::Failure::Time)
            ),
            "native API profiles must keep their original fresh issuance checks"
        );
    }
    for invalid in [json!(null), json!("1000"), json!(1000.5)] {
        let mut source = json!({"iat":invalid});
        let mut target = json!({"iat":invalid});
        assert!(
            contract::compare_numeric_dates(
                &mut source,
                &mut target,
                Some([1_000_000_000_000; 2]),
                TIME_TOLERANCE_NANOS,
                contract::NumericDateMode::Format
            )
            .is_err()
        );
    }
}

#[test]
fn signed_duplicate_json_members_cannot_escape_through_equal_value_fallback() {
    let policy = plan(SignatureAlgorithm::HS256);
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"test-key"}"#;
    for (protected, payload) in [
        (
            r#"{"alg":"HS256","alg":"HS256","typ":"JWT","kid":"test-key"}"#,
            r#"{"sub":"7"}"#,
        ),
        (header, r#"{"sub":"7","sub":"7"}"#),
        (header, r#"{"profile":{"name":"a","name":"a"}}"#),
    ] {
        let token = json!(signed_raw(protected, payload, KEY, Algorithm::HS256));
        assert!(
            super::super::looks_like_jwt(&token),
            "a compact JWS object remains recognized before strict JSON validation"
        );
        assert!(
            leaf(&token, &token, &policy, Default::default()).is_err(),
            "valid signature cannot make duplicate members safe"
        );
        let source = json!({"token":token});
        assert!(!compared(&source, &source, &policy, Default::default()).passed());
    }
}
