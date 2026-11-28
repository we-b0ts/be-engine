use super::*;
use serde_json::json;

const RSA_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwnPmo2sWbWkJuLAtJupI
qYkBQY6GoTEvaZ+0cchnd8A1asSh6lMloMPZ9RdYe3zwDoB42I9Tzw5F+HQy5Bq9
Q4Vacw7JacIs+9bdFCo3Bn3ZC5zNfkxemGOfy8yysLCZdk7hSGTzdCAWSIcGWY/m
NCfaR/eYQQCDylS4xQ6oQRgMiM6KlpIA/f8ffqi0chT0s8yBzhsM/hTvXNX+zBTi
F4xDEWfj86/JUvl5Qn6T6k/50uHVJI3UCGUDvoGX9+mrfg7ap7QOX2YwDckOXHhA
RO9eMqhRKrSccDEFSXUjjpfz/TNxq3ZwutW5S4tiFttXCf3aQcndxl+rVtkaoWr0
IQIDAQAB
-----END PUBLIC KEY-----
";
const RSA_MODULUS: &str = concat!(
    "wnPmo2sWbWkJuLAtJupIqYkBQY6GoTEvaZ-0cchnd8A1asSh6lMloMPZ9RdYe3zwDoB42I9Tzw5F-HQy5Bq9",
    "Q4Vacw7JacIs-9bdFCo3Bn3ZC5zNfkxemGOfy8yysLCZdk7hSGTzdCAWSIcGWY_mNCfaR_eYQQCDylS4xQ6oQRgMiM6KlpIA",
    "_f8ffqi0chT0s8yBzhsM_hTvXNX-zBTiF4xDEWfj86_JUvl5Qn6T6k_50uHVJI3UCGUDvoGX9-mrfg7ap7QOX2YwDckOXHhA",
    "RO9eMqhRKrSccDEFSXUjjpfz_TNxq3ZwutW5S4tiFttXCf3aQcndxl-rVtkaoWr0IQ",
);
const RSA_TOKEN: &str = concat!(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUta2V5In0.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiZXhhbXBsZSJ9.",
    "Lgwi_HnXQ5GqvX4HUEZllw-U4K3BiYdWQMh_ePkqXOpTB550hrhvxVyehCQXoVB0Tv5d1O3h5KGRB3zRuWagSkmjc-iJtAbeS9Ywa5-Bas858aehwX8qz9r10sRFk_k7_5j1L7H78VVXAKaaHBQykqINLqn96ka8UDvn5WU7tw3iIir3SxdyqZxHbj0xvwwehmsv1M1xvC2RUf5ghzVrfKFpHJdein5xZS6py-6fVQMoU-9JZLKSBWx7zb8fvRsdAaAb2sY0exFnfiXJV3Xtrn1ekVLGLoeNeMT47jcalSWNZibeSViLkjDdnRrwQdssJ3i-1--pmEeWbTrkNkNRAg",
);

fn hmac_token(algorithm: Algorithm, header: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(r#"{"z": {}, "sub":"example"}"#);
    let input = format!("{}.{payload}", URL_SAFE_NO_PAD.encode(header));
    let signature = crate::sign(algorithm.hmac().unwrap(), b"test-key", input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[test]
fn hmac_verifies_original_bytes_with_only_the_prepared_algorithm_and_key() {
    for algorithm in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let raw = hmac_token(algorithm, &format!(r#"{{ "alg": "{algorithm:?}" }}"#));
        let token = Token::parse(&raw).unwrap();
        assert_eq!(token.algorithm, algorithm);
        assert_eq!(token.claims["sub"], "example");
        assert!(
            PreparedKey::new(algorithm, b"test-key")
                .unwrap()
                .verify(&token)
        );
        assert!(
            !PreparedKey::new(algorithm, b"other-key")
                .unwrap()
                .verify(&token)
        );
        let other = if algorithm == Algorithm::HS256 {
            Algorithm::HS384
        } else {
            Algorithm::HS256
        };
        assert!(!PreparedKey::new(other, b"test-key").unwrap().verify(&token));
    }
}

#[test]
fn rejects_unsupported_or_ambiguous_compact_tokens_before_verifying() {
    for header in [
        r#"{"alg":"none"}"#,
        r#"{"alg":"HS256","alg":"HS256"}"#,
        r#"{"alg":"HS256","crit":[]}"#,
        r#"{"alg":"HS256","kid":14}"#,
    ] {
        assert!(Token::parse(&hmac_token(Algorithm::HS256, header)).is_none());
    }
}

fn jwk(kid: &str) -> Value {
    json!({"kty":"RSA", "kid":kid, "n":RSA_MODULUS, "e":"AQAB", "alg":"RS256", "use":"sig"})
}

#[test]
fn rsa_verifies_with_spki_or_a_trusted_jwks_entry_selected_by_kid() {
    let token = Token::parse(RSA_TOKEN).unwrap();
    let spki = PreparedKey::new(Algorithm::RS256, RSA_PEM).unwrap();
    assert!(spki.verify(&token));
    let tampered = RSA_TOKEN.replacen(".Lgwi_", ".Agwi_", 1);
    assert!(!spki.verify(&Token::parse(&tampered).unwrap()));

    let with_key = json!({"keys":[jwk("older-key"), jwk("fixture-key")]}).to_string();
    assert!(
        PreparedKey::new(Algorithm::RS256, with_key.as_bytes())
            .unwrap()
            .verify(&token)
    );
    let without_key = json!({"keys":[jwk("unrelated-key")]}).to_string();
    assert!(
        !PreparedKey::new(Algorithm::RS256, without_key.as_bytes())
            .unwrap()
            .verify(&token)
    );

    let duplicate = json!({"keys":[jwk("fixture-key"), jwk("fixture-key")]}).to_string();
    assert!(PreparedKey::new(Algorithm::RS256, duplicate.as_bytes()).is_err());
    let mut encryption_key = jwk("fixture-key");
    encryption_key["use"] = json!("enc");
    let encryption_only = json!({"keys":[encryption_key]}).to_string();
    assert!(PreparedKey::new(Algorithm::RS256, encryption_only.as_bytes()).is_err());
}
