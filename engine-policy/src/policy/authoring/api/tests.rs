use crate::policy::{self, NativeEffect, native::*};

const DOCUMENT: &str = r#"format: traffic-policy/v3
json:
  fields:
    /expire_at: {kind: time, formats: [unix_seconds]}
docx:
  fields:
    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}
api:
  GET /runtime:
    response:
      json:
        /user:
          encoding:
            envelope: base64_iv_aes_cbc_pkcs7
            key: {kind: startup, source: {kind: target_env, name: USER_AES_KEY}}
  GET /exports/docx:
    response:
      headers:
        content-disposition: {kind: date, parameter: filename, format: '%Y-%m-%d'}
      body: {codec: docx}
"#;

#[test]
fn response_bindings_preserve_native_contracts_and_share_content_definitions() {
    let policy = policy::parse_policy(DOCUMENT).unwrap();
    assert_eq!(policy.rules.len(), 3);
    for rule in &policy.rules {
        let rule = rule.as_native().unwrap();
        match &rule.effect {
            NativeEffect::ResponseGenerated(effect) => {
                assert_eq!(rule.selector.api.as_deref(), Some("GET /runtime"));
                let GeneratedResponse::EncryptedJson { fields, .. } =
                    &effect.fields["/user"].contract
                else {
                    panic!("cipher binding")
                };
                assert!(fields.is_empty(), "plaintext uses the global JSON contract");
            }
            NativeEffect::ResponseHeaderDate(effect) => {
                assert_eq!(rule.selector.api.as_deref(), Some("GET /exports/docx"));
                assert_eq!(effect.parameter.as_deref(), Some("filename"));
                assert_eq!(effect.format, "%Y-%m-%d");
            }
            NativeEffect::ResponseBody(effect) => {
                assert_eq!(rule.selector.api.as_deref(), Some("GET /exports/docx"));
                assert_eq!(effect.codec, BodyCodec::Docx);
                assert_eq!(effect.fields.len(), 1);
            }
            _ => panic!("unexpected binding"),
        }
    }
    let rendered = policy::render_policy(&policy).unwrap();
    assert!(rendered.contains("docx:"));
    assert!(rendered.contains("encoding:"));
    assert!(rendered.contains("body: {codec: docx}"));
    assert!(!rendered.contains("response_generated"));
    assert!(!rendered.contains("response_header_date"));
    assert_eq!(
        policy::parse_and_compile_policy(&rendered).unwrap(),
        policy::compile_policy(&policy).unwrap()
    );
}

#[test]
fn codec_bindings_keep_local_source_proof_and_proof_independent_ids() {
    let bare = policy::parse_policy(DOCUMENT).unwrap();
    assert!(policy::require_source_proofs(&bare).is_err());
    let proof = "{source: exporter.rs:10, fact: Source generates this response using its current request clock}";
    let explained = DOCUMENT
        .replace(
            "          encoding:",
            &format!("          proof: {proof}\n          encoding:"),
        )
        .replace(
            "kind: date, parameter:",
            &format!("proof: {proof}, kind: date, parameter:"),
        )
        .replace(
            "body: {codec: docx}",
            &format!("body: {{codec: docx, proof: {proof}}}"),
        );
    let explained = policy::parse_policy(&explained).unwrap();
    policy::require_source_proofs(&explained).unwrap();
    assert_eq!(
        policy::compile_policy(&bare).unwrap().fingerprints,
        policy::compile_policy(&explained).unwrap().fingerprints
    );
    assert_eq!(
        policy::render_policy(&bare).unwrap(),
        policy::render_policy(&explained).unwrap()
    );
}

#[test]
fn bindings_reject_empty_unknown_ambiguous_or_unbound_declarations() {
    for bad in [
        DOCUMENT.replace("codec: docx", "codec: unknown"),
        DOCUMENT.replace("envelope: base64_iv_aes_cbc_pkcs7", "envelope: unknown"),
        DOCUMENT.replace(
            "parameter: filename",
            "parameter: filename, unrecognized: true",
        ),
        format!("{DOCUMENT}  GET /empty: {{response: {{json: {{}}}}}}\n"),
        "format: traffic-policy/v3\ndocx: {fields: []}\n".into(),
        "format: traffic-policy/v3\napi: {'GET /docx': {response: {body: {codec: docx}}}}\n".into(),
        DOCUMENT.replace("GET /runtime:", "'*':"),
    ] {
        assert!(policy::parse_policy(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn root_docx_definition_renders_once_when_two_apis_bind_the_same_codec() {
    let document =
        format!("{DOCUMENT}  POST /other/export:\n    response:\n      body: {{codec: docx}}\n");
    let parsed = policy::parse_policy(&document).unwrap();
    let bodies = parsed
        .rules
        .iter()
        .filter_map(|rule| {
            let rule = rule.as_native()?;
            matches!(rule.effect, NativeEffect::ResponseBody(_)).then_some(rule)
        })
        .collect::<Vec<_>>();
    assert_eq!(bodies.len(), 2);
    assert_ne!(bodies[0].selector.api, bodies[1].selector.api);
    let rendered = policy::render_policy(&parsed).unwrap();
    assert_eq!(rendered.lines().filter(|line| *line == "docx:").count(), 1);
    assert_eq!(rendered.matches("body: {codec: docx}").count(), 2);
    assert_eq!(rendered.matches("dcterms:created").count(), 1);
    assert_eq!(
        policy::parse_and_compile_policy(&rendered).unwrap(),
        policy::compile_policy(&parsed).unwrap()
    );
}

#[test]
fn typed_api_positions_reject_nested_duplicate_keys_before_crypto_forwarding() {
    let prefix = "format: traffic-policy/v3\nsignatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: KEY}}\napi:\n  GET /api:\n";
    for positions in [
        "    request:\n      query: {token: default, token: default}\n",
        "    request:\n      query: {token: {signature: default, signature: default}}\n",
        "    request:\n      headers: {authorization: {signature: default, signature: default}}\n",
        "    request:\n      body: {signature: default, fields: {at: /at, at: /other}, timestamp_pointer: /at, signature_pointer: /sig, secret_parameter: secret}\n",
        "    response:\n      json: {'/token': {signature: default, signature: default}}\n",
        "    response:\n      headers: {location: {signature: default, query: token, query: other}}\n",
        "    response:\n      json: {'/token': {signature: default, nonces: [{pointer: /nonce, pointer: /jti, format: uuid_v4}]}}\n",
        "    response:\n      json: {'/user': {encoding: {envelope: base64_iv_aes_cbc_pkcs7, envelope: base64_iv_aes_cbc_pkcs7, key: {kind: startup, source: {kind: target_env, name: KEY}}}}}\n",
        "    response:\n      headers: {content-disposition: {kind: date, parameter: filename, format: '%Y-%m-%d', format: '%Y%m%d'}}\n",
        "    response:\n      body: {codec: docx, codec: docx}\n",
    ] {
        assert!(
            policy::parse_policy(&format!("{prefix}{positions}")).is_err(),
            "accepted duplicate in {positions}"
        );
    }
    let document = DOCUMENT.replace(
        "element: 'dcterms:created'",
        "element: 'dcterms:created', element: 'dcterms:modified'",
    );
    assert!(policy::parse_policy(&document).is_err());
}

#[test]
fn canonical_response_header_aliases_and_docx_field_aliases_cannot_overlap() {
    for headers in [
        "Content-Disposition: {kind: date, parameter: filename, format: '%Y-%m-%d'}\n        content-disposition: {kind: date, parameter: filename, format: '%Y-%m-%d'}",
        "Content-Disposition: {kind: date, parameter: filename, format: '%Y-%m-%d'}\n        content-disposition: {signature: default}",
    ] {
        let document = format!(
            "format: traffic-policy/v3\nsignatures:\n  default: {{kind: jwt, algorithm: HS256, key: {{kind: target_env, name: KEY}}}}\napi:\n  GET /api:\n    response:\n      headers:\n        {headers}\n"
        );
        assert!(
            policy::parse_policy(&document).is_err(),
            "accepted {document}"
        );
    }
    let duplicate = DOCUMENT.replace(
        "    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}",
        "    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}\n    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: amz_date}",
    );
    assert!(policy::parse_policy(&duplicate).is_err());
}

#[test]
fn signed_and_decoded_json_positions_share_one_api_without_weakening_either_shape() {
    let document = DOCUMENT
        .replacen("json:\n", "signatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: JWT_KEY}}\njson:\n", 1)
        .replacen("        /user:", "        /token: {signature: default}\n        /user:", 1);
    let parsed = policy::parse_policy(&document).unwrap();
    assert_eq!(parsed.rules.len(), 4);
    assert!(parsed.rules.iter().any(|rule| matches!(
        rule.as_native().map(|rule| &rule.effect),
        Some(NativeEffect::ResponseJwt(_))
    )));
    assert!(parsed.rules.iter().any(|rule| matches!(
        rule.as_native().map(|rule| &rule.effect),
        Some(NativeEffect::ResponseGenerated(_))
    )));
    let rendered = policy::render_policy(&parsed).unwrap();
    assert!(rendered.contains("signature: default"));
    assert!(rendered.contains("encoding:"));
    assert_eq!(
        policy::parse_and_compile_policy(&rendered).unwrap(),
        policy::compile_policy(&parsed).unwrap()
    );
    let mixed = document.replace(
        "          encoding:",
        "          signature: default\n          encoding:",
    );
    assert!(
        policy::parse_policy(&mixed).is_err(),
        "one position cannot silently select one of two owners"
    );
}

#[test]
fn docx_leaf_proof_does_not_authorize_an_unproven_api_codec_binding() {
    let proof = "{source: exporter.rs:10, fact: Source writes the generated creation date in this DOCX package}";
    let document = format!(
        "format: traffic-policy/v3\ndocx:\n  fields:\n    - {{kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339, proof: {proof}}}\napi:\n  GET /docx:\n    response:\n      body: {{codec: docx}}\n"
    );
    let parsed = policy::parse_policy(&document).unwrap();
    assert!(policy::require_source_proofs(&parsed).is_err());
    let explained = document.replace(
        "body: {codec: docx}",
        &format!("body: {{codec: docx, proof: {proof}}}"),
    );
    policy::require_source_proofs(&policy::parse_policy(&explained).unwrap()).unwrap();
}
