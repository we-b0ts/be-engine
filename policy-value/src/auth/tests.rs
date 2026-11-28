use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use traffic_contract::{compare, time::ClockPair};
use traffic_jwt::verification::Algorithm;

fn token(secret: &[u8], subject: &str, issued_at: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let claims = URL_SAFE_NO_PAD
        .encode(json!({"sub": subject, "iat": issued_at, "exp": issued_at + 600}).to_string());
    let input = format!("{header}.{claims}");
    let signature = traffic_jwt::sign(traffic_jwt::Algorithm::HS256, secret, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        observation: Some(ClockPair {
            source: chrono::DateTime::from_timestamp(100, 0),
            target: chrono::DateTime::from_timestamp(200, 0),
        }),
        ..Default::default()
    }
}

#[test]
fn trusted_profiles_and_logical_text_apply_without_field_names() {
    let matcher = Matcher::new(vec![
        PreparedKey::new(Algorithm::HS256, b"application key").unwrap(),
        PreparedKey::new(Algorithm::HS256, b"state key").unwrap(),
    ]);
    let source = token(b"state key", "subject", 100);
    let target = token(b"state key", "subject", 200);
    let compare = |target: &str| matcher.compare(&source, target, Carrier::Value, clocks());
    assert!(compare(&target).is_some());
    assert!(compare(&token(b"application key", "subject", 200)).is_none());
    assert!(compare(&token(b"state key", "different", 200)).is_none());
    assert!(compare(&token(b"state key", "subject", 220)).is_none());

    let auth = Metadata::new(&compare::ExplicitRules, Some(matcher));
    let source = serde_json::from_value(json!({"7": source})).unwrap();
    let target = serde_json::from_value(json!({"7": target})).unwrap();
    let result =
        compare::compare_logical_all(&source, &target, &[], &[], &[], clocks(), &[], auth.rules());
    assert!(result.passed());
    assert!(result.evaluated.contains(RULE_ID));
    assert_eq!(result.identity_pairs().len(), 1);

    let contract = traffic_contract::rule::FieldContract::Exact;
    let fields = [compare::Field {
        rule_id: "explicit",
        pointer: "/7",
        contract: &contract,
    }];
    assert!(
        !compare::compare_logical_all(
            &source,
            &target,
            &fields,
            &[],
            &[],
            clocks(),
            &[],
            auth.rules()
        )
        .passed()
    );
}

#[test]
fn auth_carriers_preserve_wire_remainder_and_reject_duplicate_query_names() {
    let matcher = Matcher::new(vec![
        PreparedKey::new(Algorithm::HS256, b"state key").unwrap(),
    ]);
    let source = token(b"state key", "subject", 100);
    let target = token(b"state key", "subject", 200);
    assert!(
        matcher
            .compare(
                &format!("Bearer {source}"),
                &format!("Bearer {target}"),
                Carrier::Authorization,
                clocks()
            )
            .is_some()
    );
    assert!(
        matcher
            .compare(
                &format!("/redirect?credential={source}&flag=1#same"),
                &format!("/redirect?credential={target}&flag=1#same"),
                Carrier::Value,
                clocks()
            )
            .is_some()
    );
    assert!(
        matcher
            .compare(
                &format!("/redirect?credential={source}&flag=1"),
                &format!("/redirect?credential={target}&flag=2"),
                Carrier::Value,
                clocks()
            )
            .is_none()
    );
    assert!(
        matcher
            .compare(
                &format!("/redirect?credential={source}&%63redential=1"),
                &format!("/redirect?credential={target}&%63redential=1"),
                Carrier::Value,
                clocks()
            )
            .is_none()
    );
}
