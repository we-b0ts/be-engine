use super::*;
use crate::policy::native::{NonceFormat, SignatureAlgorithm};

fn definitions() -> BTreeMap<String, SignatureDefinition> {
    serde_yaml::from_str(
        r#"default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}
oidc: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: OIDC_STATE_SECRET_KEY}}
aidesk: {kind: md5_sorted_fields, key: {kind: target_env, name: AIDESK_SECRET_KEY}}
"#,
    )
    .unwrap()
}
fn expand_rules(raw: &str) -> Result<Vec<PolicyRule>> {
    expand(Some(serde_yaml::from_str(raw)?), &definitions())?
        .into_iter()
        .map(|value| Ok(PolicyRule::Native(Box::new(serde_yaml::from_value(value)?))))
        .collect()
}
fn rendered(rules: &[PolicyRule]) -> Value {
    let mut root = Mapping::new();
    for rule in rules {
        assert!(compact(rule, &definitions(), &mut root).unwrap());
    }
    root.into()
}

#[test]
fn request_positions_share_named_profiles_and_preserve_existing_rewriters() {
    let rules = expand_rules(
        r#"'*':
  request:
    headers:
      Authorization: {scheme: bearer}
      x-wegent-download-token: {signature: default}
    query:
      token: default
      download_token: {signature: default}
      state: oidc
POST /api/internal/auth/aidesk/login:
  request:
    body:
      signature: aidesk
      fields: {source: /source, timestamp: /timestamp, username: /username}
      timestamp_pointer: /timestamp
      signature_pointer: /sign
      secret_parameter: secret_key
"#,
    )
    .unwrap();
    assert_eq!(rules.len(), 6);
    let mut headers = 0;
    let mut query = 0;
    for rule in &rules {
        let native = rule.as_native().unwrap();
        match &native.effect {
            NativeEffect::InputJwt(effect) => {
                assert_eq!(effect.algorithm, SignatureAlgorithm::HS256);
                assert_eq!(effect.time, InputTokenTime::PreserveRelative);
                assert!(native.selector.api.is_none());
                match &effect.location {
                    InputTokenLocation::BearerHeader { name } => {
                        headers += 1;
                        assert_eq!(name, "authorization");
                    }
                    InputTokenLocation::RawHeader { name } => {
                        headers += 1;
                        assert_eq!(name, "x-wegent-download-token");
                    }
                    InputTokenLocation::Query { name } => {
                        query += 1;
                        let StartupKey::TargetEnv { name: key } = &effect.signing_key else {
                            panic!("environment key")
                        };
                        assert_eq!(
                            key,
                            if name == "state" {
                                "OIDC_STATE_SECRET_KEY"
                            } else {
                                "SECRET_KEY"
                            }
                        );
                    }
                }
            }
            NativeEffect::InputSignedTimestamp(effect) => {
                assert_eq!(
                    native.selector.api.as_deref(),
                    Some("POST /api/internal/auth/aidesk/login")
                );
                assert_eq!(effect.fields["timestamp"], "/timestamp");
                assert_eq!(effect.timestamp_pointer, "/timestamp");
                assert_eq!(effect.signature_pointer, "/sign");
                assert_eq!(effect.secret_parameter, "secret_key");
            }
            _ => panic!("input rewriters only"),
        }
    }
    assert_eq!((headers, query), (2, 3));
    let output = rendered(&rules);
    let reparsed: ApiDefinitions = serde_yaml::from_value(output["api"].clone()).unwrap();
    assert_eq!(
        native_values(&rules),
        expand(Some(reparsed), &definitions()).unwrap()
    );
    let text = serde_yaml::to_string(&output).unwrap();
    for forbidden in [
        "signing_key:",
        "algorithm:",
        "kind: input",
        "time:",
        "proof:",
    ] {
        assert!(!text.contains(forbidden), "{text}");
    }
}
fn native_values(rules: &[PolicyRule]) -> Vec<Value> {
    rules
        .iter()
        .map(|rule| serde_yaml::to_value(rule.as_native().unwrap()).unwrap())
        .collect()
}

#[test]
fn response_url_nonce_echo_and_signed_expiry_companions_survive_roundtrip() {
    let rules = expand_rules(
        r#"GET /api/auth/oidc/login:
  response:
    headers:
      Location:
        signature: oidc
        query: state
        nonces:
          - pointer: /nonce
            format: {kind: base64url, decoded_bytes: 32}
            echo_query_param: nonce
POST /api/smart-apps/*/download:
  response:
    json:
      /downloadUrl:
        signature: default
        query: token
        nonces:
          - pointer: /nonce
            format: {kind: base64url, decoded_bytes: 16}
        expires_at: /expiresAt
GET /api/tasks/*:
  response:
    json:
      /result/blocks/*/image_download_urls/*:
        signature: default
        query: token
        nonces: [{pointer: /nonce, format: {kind: base64url, decoded_bytes: 16}}]
"#,
    )
    .unwrap();
    assert_eq!(rules.len(), 3);
    let header = rules
        .iter()
        .find_map(|rule| match &rule.as_native()?.effect {
            NativeEffect::ResponseJwt(effect) if effect.location.is_some() => Some(effect),
            _ => None,
        })
        .unwrap();
    assert_eq!(header.location.as_ref().unwrap().header, "location");
    assert_eq!(header.url_query_param.as_deref(), Some("state"));
    assert_eq!(
        header.nonces[0].contract.echo_query_param.as_deref(),
        Some("nonce")
    );
    assert_eq!(
        header.nonces[0].contract.format,
        NonceFormat::Base64url { decoded_bytes: 32 }
    );
    let companion = rules
        .iter()
        .find_map(|rule| match &rule.as_native()?.effect {
            NativeEffect::ResponseJwt(effect) if effect.expires_at.is_some() => Some(effect),
            _ => None,
        })
        .unwrap();
    assert_eq!(companion.expires_at.as_deref(), Some("/expiresAt"));
    let output = rendered(&rules);
    let api = serde_yaml::from_value(output["api"].clone()).unwrap();
    assert_eq!(
        expand(Some(api), &definitions()).unwrap(),
        native_values(&rules)
    );
    let text = serde_yaml::to_string(&output).unwrap();
    assert!(text.contains("echo_query_param: nonce"));
    assert!(text.contains("expires_at: /expiresAt"));
    assert!(!text.contains("url_query_param:"));
    assert!(!text.contains("algorithm:"));
}

#[test]
fn proof_is_independent_from_ids_and_runtime_output_but_inherits_into_nonce_contracts() {
    let raw = r#"POST /tokens:
  response:
    json:
      /access_token:
        signature: default
        nonces: [{pointer: /nonce, format: {kind: base64url, decoded_bytes: 16}}]
        proof: {source: 'tokens.py:42', fact: 'Source issues a signed token with one random nonce'}
"#;
    let rules = expand_rules(raw).unwrap();
    let changed = expand_rules(&raw.replace("one random nonce", "a fresh bounded nonce")).unwrap();
    assert_eq!(rules[0].id(), changed[0].id());
    let effect = rules[0].as_native().unwrap();
    let NativeEffect::ResponseJwt(response) = &effect.effect else {
        panic!("JWT")
    };
    assert_eq!(response.nonces[0].proof, effect.proof);
    assert!(effect.proof.is_some());
    let output = rendered(&rules);
    assert!(!serde_yaml::to_string(&output).unwrap().contains("proof:"));
    let values = expand(
        Some(serde_yaml::from_value(output["api"].clone()).unwrap()),
        &definitions(),
    )
    .unwrap();
    let runtime: NativeRule = serde_yaml::from_value(values[0].clone()).unwrap();
    assert!(runtime.proof.is_none());
    assert_eq!(runtime, without_proofs(effect.clone()));
    let mut new_key = definitions();
    new_key.insert(
        "default".into(),
        SignatureDefinition::Jwt {
            algorithm: SignatureAlgorithm::HS256,
            key: StartupKey::TargetEnv {
                name: "OTHER_KEY".into(),
            },
        },
    );
    let changed = expand(Some(serde_yaml::from_str(raw).unwrap()), &new_key).unwrap();
    assert_ne!(changed[0]["id"], values[0]["id"]);
}

#[test]
fn strict_api_schema_rejects_missing_profiles_hidden_crypto_and_incompatible_positions() {
    for raw in [
        "'*': {request: {query: {token: unknown}}}",
        "'*': {request: {query: {token: {signature: default, algorithm: HS512}}}}",
        "'*': {request: {headers: {authorization: {signature: default, scheme: ignored}}}}",
        "'*': {request: {query: {token: aidesk}}}",
        "'*': {response: {json: {'/token': {signature: default}}}}",
        "GET /keys: {response: {headers: {location: {signature: default, expires_at: /expires_at}}}}",
        "GET /keys: {response: {json: {'/token': {signature: default, key: {kind: target_env, name: KEY}}}}}",
        "GET /keys: {request: {query: {token: default, token: oidc}}}",
        "GET /keys: {request: {headers: {Authorization: {signature: default}, authorization: {signature: oidc}}}}",
        "GET /keys: {request: {}, response: {}}",
        "GET /keys: {request: {body: {signature: default, fields: {time: /time}, timestamp_pointer: /time, signature_pointer: /sign, secret_parameter: secret}}}",
    ] {
        assert!(expand_rules(raw).is_err(), "{raw}");
    }
    let api = serde_yaml::from_str("'*': {request: {headers: {authorization: {scheme: bearer}}}}")
        .unwrap();
    assert!(
        expand(Some(api), &BTreeMap::new()).is_err(),
        "omitted signature names require an explicit default definition"
    );
}

#[test]
fn compact_preserves_additional_native_scope_and_requires_an_exact_profile_match() {
    let rules =
        expand_rules("POST /tokens: {response: {json: {'/token': {signature: default}}}}").unwrap();
    let mut constrained = rules[0].as_native().unwrap().clone();
    constrained.when =
        Some(serde_yaml::from_str("request_body_json: {'/mode': {equals: signed}}").unwrap());
    let mut root = Mapping::new();
    assert!(
        !compact(
            &PolicyRule::Native(Box::new(constrained)),
            &definitions(),
            &mut root
        )
        .unwrap()
    );
    assert!(root.is_empty());
    assert!(!compact(&rules[0], &BTreeMap::new(), &mut root).unwrap());
    assert!(root.is_empty());
    let mut modified = rules[0].as_native().unwrap().clone();
    modified.id = "native-extra-crypto".into();
    assert!(
        !compact(
            &PolicyRule::Native(Box::new(modified)),
            &definitions(),
            &mut root
        )
        .unwrap()
    );
}
